"""
notify/handler.py

Step 3 of the automation workflow.

Publishes a structured JSON alert to SNS on success and failure paths.
Step Functions passes notify_status (not status) to avoid collision with
any status key already in the workflow payload.

SNS publish failures are logged but not re-raised because the block rule
has already been applied. Retrying would create a duplicate block.

Environment variables (all required unless noted):
    SNS_TOPIC_ARN  ARN of the SNS alerts topic
    ENVIRONMENT    Deployment environment label
    LOG_LEVEL      Optional. Python log level. Default: INFO
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

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

SNS_TOPIC_ARN: str = os.environ["SNS_TOPIC_ARN"]
ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "unknown")

_sns = boto3.client("sns")


def _resolve_action(payload: dict) -> str:
    """Return a human-readable action string for the success message body.

    Args:
        payload: Merged output from all previous workflow states.

    Returns:
        Action description string.
    """
    if payload.get("already_blocked") is True:
        return "duplicate detected, no new rule added"
    if payload.get("firewall_updated"):
        return f"DROP rule added priority={payload.get('rule_priority', 'unknown')}"
    return f"skipped: {payload.get('reason', 'rule already present')}"


def _build_success_body(payload: dict) -> dict:
    """Return the JSON-serialisable body dict for a successful block.

    Args:
        payload: Merged output from all previous workflow states.

    Returns:
        Dict with status, action, IP, timestamps, and finding metadata.
    """
    metadata = payload.get("metadata", {})
    return {
        "status": "SUCCESS",
        "environment": ENVIRONMENT,
        "source_ip": payload.get("source_ip", "unknown"),
        "action": _resolve_action(payload),
        "blocked_at": str(payload.get("blocked_at", datetime.now(timezone.utc).isoformat())),
        "expiry_time": str(payload.get("expiry_time", "unknown")),
        "finding_title": metadata.get("title", "unknown"),
        "finding_severity": metadata.get("severity", "unknown"),
        "finding_type": metadata.get("finding_type", "unknown"),
        "aws_account": metadata.get("account_id", "unknown"),
        "aws_region": metadata.get("region", "unknown"),
    }


def build_success_message(payload: dict) -> tuple[str, str]:
    """Build the SNS subject and JSON body for a successful block or skip.

    Args:
        payload: Merged output from all previous workflow states.

    Returns:
        Tuple of (subject string, JSON body string).
    """
    subject = f"[{ENVIRONMENT.upper()}] AutoIPBlocker: IP Blocked"
    return subject, json.dumps(_build_success_body(payload), indent=2, default=str)


def build_failure_message(payload: dict) -> tuple[str, str]:
    """Build the SNS subject and JSON body for a workflow failure.

    Args:
        payload: Event dict containing an error key from Step Functions.

    Returns:
        Tuple of (subject string, JSON body string).
    """
    error = payload.get("error", {})
    subject = f"[{ENVIRONMENT.upper()}] AutoIPBlocker: WORKFLOW FAILURE"
    body = {
        "status": "FAILURE",
        "environment": ENVIRONMENT,
        "error_type": str(error.get("Error", "unknown")),
        "error_cause": str(error.get("Cause", "unknown"))[:1000],
    }
    return subject, json.dumps(body, indent=2, default=str)


def _publish_to_sns(subject: str, message: str, notify_status: str) -> None:
    """Publish a message to the configured SNS topic.

    Failures are logged but not re-raised. See module docstring.

    Args:
        subject: SNS message subject (truncated to 100 chars).
        message: SNS message body string.
        notify_status: Status string for MessageAttributes filter.
    """
    try:
        _sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
            MessageAttributes={
                "environment": {"DataType": "String", "StringValue": ENVIRONMENT},
                "notify_status": {"DataType": "String", "StringValue": notify_status},
            },
        )
        logger.info("sns_notification_published status=%s", notify_status)
    except ClientError as exc:
        logger.error("sns_publish_failed_non_fatal code=%s", exc.response["Error"]["Code"])


def lambda_handler(event: dict, context: Any) -> dict:
    """Lambda entry point for NotifySuccess and NotifyFailure states.

    Args:
        event: Dict with notify_status and payload keys injected by Step Functions.
        context: Lambda context object.

    Returns:
        Input event with notification_sent key added.
    """
    logger.info("notify_invoked request_id=%s", getattr(context, "aws_request_id", "local"))
    notify_status = event.get("notify_status", "SUCCESS")
    payload = event.get("payload", event)

    if notify_status == "SUCCESS":
        subject, message = build_success_message(payload)
    else:
        subject, message = build_failure_message(payload)

    _publish_to_sns(subject, message, notify_status)
    return {**event, "notification_sent": True}
