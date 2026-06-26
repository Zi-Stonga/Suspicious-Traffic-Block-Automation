"""
record_ip/ip_validation.py

IP address validation for the record_ip workflow step.

Provides is_valid_public_ip(), which checks syntactic correctness
and that the address falls outside all reserved ranges.
"""

from __future__ import annotations

import re

_IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Ranges that must never be blocked: private, loopback, link-local, RFC-5737.
_FORBIDDEN_RANGES: list[re.Pattern[str]] = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^0\."),
    re.compile(r"^192\.0\.2\."),
    re.compile(r"^198\.51\.100\."),
    re.compile(r"^203\.0\.113\."),
    re.compile(r"^::1$"),
    re.compile(r"^fc", re.IGNORECASE),
    re.compile(r"^fd", re.IGNORECASE),
    re.compile(r"^fe80", re.IGNORECASE),
]


def is_valid_public_ip(ip: str) -> bool:
    """Return True iff ip is syntactically valid and publicly routable.

    Args:
        ip: Raw string from the finding event.

    Returns:
        True if ip passes IPv4 format check and is not a reserved range.
    """
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not _IPV4_RE.match(ip):
        return False
    return not any(p.match(ip) for p in _FORBIDDEN_RANGES)
