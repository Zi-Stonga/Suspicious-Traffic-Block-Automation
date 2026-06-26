"""
record_ip/handler.py

Step 1 of the automation workflow.

Validates the source IP, checks DynamoDB for an active duplicate, and writes
an audit record with a TTL-enforced expiry.

Environment variables (all required unless noted):
    DYNAMODB_TABLE   Name of the DynamoDB audit table
    ENVIRONMENT      Deployment environment label (prod/staging/dev)
    BLOCK_TTL_HOURS  Optional. Hours until block expires. Default: 24
    LOG_LEVEL        Optional. Python log level. Default: INFO
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, TypedDict

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from .finding_parser import extract_finding_metadata, extract_source_ip
from .ip_validation import is_valid_public_ip

_LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO").upper()


def _init_logger(name: str) -> logging.Logger:
    """Return a configured logger safe for repeated Lambda invocations."""
    lgr = logging.getLogger(name)
    lgr.setLevel(_LOG_LEVEL)
    if not lgr.handlers:
        h = logging.StreamHandler()
        h.setLevel(_LOG_LEVEL)
        lgr.addHandler(h)
    lgr.propagate = False
    return lgr


logger = _init_logger(__name__)

DYNAMODB_TABLE: str = os.environ["DYNAMODB_TABLE"]
ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "unknown")
BLOCK_TTL_HOURS: int = int(os.environ.get("BLOCK_TTL_HOURS", "24"))

_dynamodb = boto3.resource("dynamodb")
_table = _dynamodb.Table(DYNAMODB_TABLE)


class BlockRecord(TypedDict):
    """Fields attached to the event after a block record is written or found."""

    source_ip: str
    already_blocked: bool
    blocked_at: str
    expiry_time: int
    metadata: dict


class _BlockArgs(TypedDict):
    """Input bundle for _make_block_record. Groups scalar args into one object."""

    source_ip: str
    already_blocked: bool
    now_iso: str
    expiry_ts: int
    metadata: dict


def _query_active_block(source_ip: str) -> bool:
    """Query DynamoDB for a non-expired record for this IP.

    Args:
        source_ip: Validated IPv4 string.

    Returns:
        True if an active record exists.

    Raises:
        ClientError: Propagated to caller for handling.
    """
    now_unix = int(time.time())
    response = _table.query(
        KeyConditionExpression=Key("source_ip").eq(source_ip),
        FilterExpression=Attr("expiry_time").gt(now_unix),
        ProjectionExpression="expiry_time",
        Limit=1,
    )
    return bool(response.get("Items"))


def is_already_blocked(source_ip: str) -> bool:
    """Return True if an active DynamoDB record exists for this IP.

    Falls back to False on ClientError so a transient read failure does
    not silently prevent the block from being applied.

    Args:
        source_ip: Validated IPv4 address string.

    Returns:
        True if a record with a future expiry_time exists.
    """
    try:
        return _query_active_block(source_ip)
    except ClientError as exc:
        logger.warning(
            "duplicate_check_failed code=%s action=proceed_with_block",
            exc.response["Error"]["Code"],
        )
        return False


def _write_audit_record(source_ip: str, now_iso: str, expiry_ts: int, metadata: dict) -> None:
    """Write a new block record to DynamoDB with a conditional guard.

    A ConditionalCheckFailedException means a concurrent execution already
    wrote the record. This is treated as success.

    Args:
        source_ip: Validated IPv4 address.
        now_iso: ISO-8601 blocked_at timestamp.
        expiry_ts: Unix epoch TTL integer.
        metadata: Finding metadata dict.

    Raises:
        ClientError: For any error other than a conditional conflict.
    """
    try:
        _table.put_item(
            Item={
                "source_ip": source_ip,
                "blocked_at": now_iso,
                "expiry_time": expiry_ts,
                "environment": ENVIRONMENT,
                **metadata,
            },
            ConditionExpression=(
                "attribute_not_exists(source_ip) AND attribute_not_exists(blocked_at)"
            ),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info("concurrent_write_race_resolved action=treat_as_duplicate")
            return True
        logger.error("dynamodb_write_failed code=%s", exc.response["Error"]["Code"])
        raise


def _make_block_record(args: _BlockArgs) -> BlockRecord:
    """Build the BlockRecord TypedDict to merge into the Step Functions event.

    Args:
        args: _BlockArgs bundle with all required fields.

    Returns:
        BlockRecord TypedDict for merging into the event payload.
    """
    return BlockRecord(
        source_ip=args["source_ip"],
        already_blocked=args["already_blocked"],
        blocked_at=args["now_iso"],
        expiry_time=args["expiry_ts"],
        metadata=args["metadata"],
    )


def lambda_handler(event: dict, context: Any) -> dict:
    """Lambda entry point for the RecordIP state.

    Args:
        event: EventBridge event dict (Security Hub finding format).
        context: Lambda context object.

    Returns:
        Input event enriched with source_ip, already_blocked, blocked_at,
        expiry_time, and metadata.

    Raises:
        ValueError: If no valid public IP can be extracted.
        ClientError: If DynamoDB write fails unexpectedly.
    """
    logger.info("record_ip_invoked request_id=%s", getattr(context, "aws_request_id", "local"))

    source_ip = extract_source_ip(event)
    if not source_ip:
        raise ValueError("No source IP found in Security Hub finding event")

    source_ip = source_ip.strip()
    if not is_valid_public_ip(source_ip):
        raise ValueError("Extracted IP failed public-address validation")

    metadata = extract_finding_metadata(event)
    now_unix = int(time.time())
    now_iso = datetime.fromtimestamp(now_unix, tz=timezone.utc).isoformat()
    expiry_ts = now_unix + (BLOCK_TTL_HOURS * 3600)

    if is_already_blocked(source_ip):
        logger.info("duplicate_block_skipped environment=%s", ENVIRONMENT)
        return {**event, **_make_block_record(
            _BlockArgs(source_ip=source_ip, already_blocked=True,
                       now_iso=now_iso, expiry_ts=expiry_ts, metadata=metadata)
        )}

    is_race_duplicate = _write_audit_record(source_ip, now_iso, expiry_ts, metadata)
    logger.info("audit_record_written environment=%s", ENVIRONMENT)
    return {**event, **_make_block_record(
        _BlockArgs(source_ip=source_ip, already_blocked=bool(is_race_duplicate),
                   now_iso=now_iso, expiry_ts=expiry_ts, metadata=metadata)
    )}
