"""
block_traffic/handler.py

Step 2 of the automation workflow.

Adds a stateless DROP rule to the Network Firewall rule group using the
UpdateToken optimistic concurrency mechanism. Picks the lowest available
priority slot to prevent monotonic growth toward the AWS limit of 65535.

Environment variables (all required unless noted):
    RULE_GROUP_ARN   ARN of the Network Firewall stateless rule group
    RULE_GROUP_NAME  Name of the rule group
    MAX_RULES        Optional. Capacity ceiling. Default: 1000
    ENVIRONMENT      Deployment environment label
    LOG_LEVEL        Optional. Python log level. Default: INFO
"""

from __future__ import annotations

import logging
import os
import re
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

RULE_GROUP_ARN: str = os.environ["RULE_GROUP_ARN"]
RULE_GROUP_NAME: str = os.environ["RULE_GROUP_NAME"]
MAX_RULES: int = int(os.environ.get("MAX_RULES", "1000"))
ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "unknown")

_CAPACITY_WARN_THRESHOLD: float = 0.90
_NFW_MAX_PRIORITY: int = 65535
_NFW_PLACEHOLDER_PRIORITY: int = 1

_IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_nfw = boto3.client("network-firewall")


def is_valid_ipv4(ip: str) -> bool:
    """Return True iff ip is a syntactically valid IPv4 string.

    Args:
        ip: Candidate IP string.

    Returns:
        True if ip matches the IPv4 octet pattern.
    """
    return bool(ip and isinstance(ip, str) and _IPV4_RE.match(ip.strip()))


def fetch_rule_group() -> tuple[dict, str]:
    """Fetch the current rule group state and its UpdateToken.

    Returns:
        Tuple of (RuleGroup dict, UpdateToken string).

    Raises:
        ClientError: If the describe call fails.
    """
    response = _nfw.describe_rule_group(RuleGroupArn=RULE_GROUP_ARN, Type="STATELESS")
    return response["RuleGroup"], response["UpdateToken"]


def get_stateless_rules(rule_group: dict) -> list:
    """Extract the stateless rule list from a rule group dict.

    Args:
        rule_group: RuleGroup dict from describe_rule_group.

    Returns:
        List of stateless rule dicts (may be empty).
    """
    return (
        rule_group.get("RulesSource", {})
        .get("StatelessRulesAndCustomActions", {})
        .get("StatelessRules", [])
    )


def has_rule_for_ip(source_ip: str, rules: list) -> bool:
    """Return True if a DROP rule for source_ip/32 already exists.

    Args:
        source_ip: IPv4 address without CIDR notation.
        rules: Current list of stateless rule dicts.

    Returns:
        True if the /32 CIDR is already present as a source.
    """
    cidr = f"{source_ip}/32"
    for rule in rules:
        for src in (
            rule.get("RuleDefinition", {}).get("MatchAttributes", {}).get("Sources", [])
        ):
            if src.get("AddressDefinition") == cidr:
                return True
    return False


def pick_lowest_available_priority(rules: list) -> int:
    """Return the lowest unused priority in [2, 65535].

    Finds the first gap rather than appending max+1, reclaiming slots
    freed by cleanup and preventing overflow.

    Args:
        rules: Current list of stateless rule dicts.

    Returns:
        Integer priority slot for the new rule.

    Raises:
        RuntimeError: If no slot is available.
    """
    used = {r.get("Priority", 0) for r in rules}
    for candidate in range(_NFW_PLACEHOLDER_PRIORITY + 1, _NFW_MAX_PRIORITY + 1):
        if candidate not in used:
            return candidate
    raise RuntimeError(f"No available priority slot in [2, {_NFW_MAX_PRIORITY}].")


def build_drop_rule(source_ip: str, priority: int) -> dict:
    """Build a stateless DROP rule for a /32 host CIDR.

    Args:
        source_ip: IPv4 address without CIDR notation.
        priority: Priority slot for this rule.

    Returns:
        Stateless rule dict for UpdateRuleGroup.
    """
    return {
        "Priority": priority,
        "RuleDefinition": {
            "MatchAttributes": {
                "Sources": [{"AddressDefinition": f"{source_ip}/32"}],
                "Destinations": [{"AddressDefinition": "0.0.0.0/0"}],
            },
            "Actions": ["aws:drop"],
        },
    }


def _assert_capacity(current_count: int) -> None:
    """Raise RuntimeError if the rule group is at or above the warn threshold.

    Args:
        current_count: Number of rules currently in the group.

    Raises:
        RuntimeError: If current_count >= capacity threshold.
    """
    limit = int(MAX_RULES * _CAPACITY_WARN_THRESHOLD)
    if current_count >= limit:
        raise RuntimeError(
            f"rule_group_near_capacity current={current_count} max={MAX_RULES} "
            "action=run_cleanup_rules_sh"
        )


def _apply_rule_update(update_token: str, updated_rules: list) -> None:
    """Push the updated rule list to Network Firewall.

    Args:
        update_token: Optimistic concurrency token from describe_rule_group.
        updated_rules: Full replacement list of stateless rule dicts.

    Raises:
        ClientError: If the update call fails.
    """
    try:
        _nfw.update_rule_group(
            RuleGroupArn=RULE_GROUP_ARN,
            Type="STATELESS",
            UpdateToken=update_token,
            RuleGroup={
                "RulesSource": {
                    "StatelessRulesAndCustomActions": {"StatelessRules": updated_rules}
                }
            },
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "InvalidTokenException":
            logger.warning("optimistic_lock_conflict action=step_functions_will_retry")
        logger.error("firewall_update_failed code=%s", code)
        raise


def _validate_and_fetch(source_ip: str) -> tuple[list, str]:
    """Validate the IP, fetch the rule group, and check capacity.

    Args:
        source_ip: IP string from the event payload.

    Returns:
        Tuple of (existing_rules list, update_token string).

    Raises:
        ValueError: If source_ip is invalid.
        RuntimeError: If the rule group is near capacity.
        ClientError: If the describe call fails.
    """
    if not is_valid_ipv4(source_ip):
        raise ValueError("source_ip is missing or not a valid IPv4 address")
    try:
        rule_group, update_token = fetch_rule_group()
    except ClientError as exc:
        logger.error("rule_group_fetch_failed code=%s", exc.response["Error"]["Code"])
        raise
    existing_rules = get_stateless_rules(rule_group)
    _assert_capacity(len(existing_rules))
    return existing_rules, update_token


def lambda_handler(event: dict, context: Any) -> dict:
    """Lambda entry point for the BlockTraffic state.

    Args:
        event: Enriched event dict from record_ip.
        context: Lambda context object.

    Returns:
        Input event enriched with firewall_updated and rule_priority or reason.

    Raises:
        ValueError: If source_ip is missing or invalid.
        RuntimeError: If the rule group is near capacity.
        ClientError: If a Network Firewall API call fails.
    """
    logger.info("block_traffic_invoked request_id=%s", getattr(context, "aws_request_id", "local"))
    source_ip = event.get("source_ip", "")

    # is True guards against Step Functions serialising bool as string.
    if event.get("already_blocked") is True:
        logger.info("duplicate_skip action=no_firewall_update")
        return {**event, "firewall_updated": False, "reason": "duplicate"}

    existing_rules, update_token = _validate_and_fetch(source_ip)

    if has_rule_for_ip(source_ip, existing_rules):
        logger.info("firewall_rule_already_exists action=skip")
        return {**event, "firewall_updated": False, "reason": "rule_exists"}

    priority = pick_lowest_available_priority(existing_rules)
    updated_rules = existing_rules + [build_drop_rule(source_ip, priority)]
    _apply_rule_update(update_token, updated_rules)

    logger.info("drop_rule_added priority=%d total=%d env=%s", priority, len(updated_rules), ENVIRONMENT)
    return {**event, "firewall_updated": True, "rule_priority": priority, "rules_total": len(updated_rules)}
