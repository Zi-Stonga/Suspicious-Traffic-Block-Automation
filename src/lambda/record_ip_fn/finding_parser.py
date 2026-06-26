"""
record_ip/finding_parser.py

Security Hub finding parser for the record_ip workflow step.

Navigates the GuardDuty-via-Security-Hub finding structure to extract
the attacking source IP and bounded audit metadata.
"""

from __future__ import annotations

import logging
import os

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


def _extract_from_nca(finding: dict) -> str | None:
    """Return the source IP from a NetworkConnectionAction finding.

    Args:
        finding: Single finding dict from the Security Hub event.

    Returns:
        IPv4 address string or None.
    """
    return (
        finding.get("Service", {})
        .get("Action", {})
        .get("NetworkConnectionAction", {})
        .get("RemoteIpDetails", {})
        .get("IpAddressV4")
    )


def _extract_from_ppa(finding: dict) -> str | None:
    """Return the source IP from a PortProbeAction finding.

    Args:
        finding: Single finding dict from the Security Hub event.

    Returns:
        IPv4 address string or None.
    """
    details = (
        finding.get("Service", {})
        .get("Action", {})
        .get("PortProbeAction", {})
        .get("PortProbeDetails", [])
    )
    if not details:
        return None
    return details[0].get("RemoteIpDetails", {}).get("IpAddressV4")


def _extract_from_interface(finding: dict) -> str | None:
    """Return the source IP from an AwsEc2NetworkInterface resource detail.

    Args:
        finding: Single finding dict from the Security Hub event.

    Returns:
        IPv4 address string or None.
    """
    for resource in finding.get("Resources", []):
        addresses = (
            resource.get("Details", {})
            .get("AwsEc2NetworkInterface", {})
            .get("IpV4Addresses", [])
        )
        if addresses and addresses[0]:
            return addresses[0]
    return None


def extract_source_ip(event: dict) -> str | None:
    """Walk the Security Hub finding and return the source IP.

    Tries three action types in priority order:
      1. NetworkConnectionAction
      2. PortProbeAction
      3. AwsEc2NetworkInterface resource detail

    Args:
        event: Full EventBridge event dict.

    Returns:
        Source IP string or None if not found.
    """
    try:
        findings = event.get("detail", {}).get("findings", [])
        if not findings:
            return None
        finding = findings[0]
        return (
            _extract_from_nca(finding)
            or _extract_from_ppa(finding)
            or _extract_from_interface(finding)
        )
    except (KeyError, IndexError, TypeError) as exc:
        logger.warning("ip_extraction_error type=%s", type(exc).__name__)
        return None


def extract_finding_metadata(event: dict) -> dict:
    """Return a bounded, sanitized subset of the finding for audit storage.

    Args:
        event: Full EventBridge event dict.

    Returns:
        Dict with finding_id, severity, title, finding_type, region, account_id.
    """
    try:
        finding = event.get("detail", {}).get("findings", [{}])[0]
        return {
            "finding_id": str(finding.get("Id", "unknown"))[:256],
            "severity": finding.get("Severity", {}).get("Label", "UNKNOWN"),
            "title": str(finding.get("Title", "unknown"))[:512],
            "finding_type": str((finding.get("Types") or ["unknown"])[0])[:256],
            "region": str(finding.get("Region", "unknown")),
            "account_id": str(finding.get("AwsAccountId", "unknown")),
        }
    except (KeyError, IndexError, TypeError):
        return {}
