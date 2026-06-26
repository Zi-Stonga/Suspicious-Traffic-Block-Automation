"""
tests/unit/test_record_ip_handler.py

Unit tests for src/handlers/record_ip/handler.py.

Coverage:
    is_valid_public_ip      happy path, private ranges, RFC test-nets, edge cases
    extract_source_ip       all three finding paths, missing paths, malformed input
    extract_finding_metadata  happy path, missing keys, truncation
    is_already_blocked      found, not found, ClientError fallback
    lambda_handler          happy path, duplicate, race condition, invalid IP,
                            missing IP, DynamoDB failure
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("DYNAMODB_TABLE", "test-table")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("BLOCK_TTL_HOURS", "24")

from botocore.exceptions import ClientError

import src.handlers.record_ip.handler as handler


def _make_finding_event(ip: str) -> dict:
    """Return a minimal Security Hub finding event for a given source IP."""
    return {
        "detail": {
            "findings": [{
                "Id": "test-finding-001",
                "Title": "Test finding",
                "Severity": {"Label": "HIGH"},
                "Types": ["TTPs/Discovery/Recon:EC2-PortProbeUnprotectedPort"],
                "Region": "us-east-1",
                "AwsAccountId": "123456789012",
                "Service": {
                    "Action": {
                        "NetworkConnectionAction": {
                            "RemoteIpDetails": {"IpAddressV4": ip}
                        }
                    }
                },
            }]
        }
    }


def _client_error(code: str) -> ClientError:
    """Build a ClientError with the given error code."""
    return ClientError({"Error": {"Code": code, "Message": "test"}}, "operation")


@pytest.fixture()
def mock_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-request-id"
    return ctx


class TestIsValidPublicIp:
    def test_valid_public_ipv4_returns_true(self):
        assert handler.is_valid_public_ip("1.2.3.4") is True

    def test_private_10_block_rejected(self):
        assert handler.is_valid_public_ip("10.0.0.1") is False

    def test_private_172_16_block_rejected(self):
        assert handler.is_valid_public_ip("172.16.0.1") is False

    def test_private_192_168_block_rejected(self):
        assert handler.is_valid_public_ip("192.168.1.1") is False

    def test_loopback_rejected(self):
        assert handler.is_valid_public_ip("127.0.0.1") is False

    def test_link_local_rejected(self):
        assert handler.is_valid_public_ip("169.254.0.1") is False

    def test_rfc5737_testnet_1_rejected(self):
        assert handler.is_valid_public_ip("192.0.2.1") is False

    def test_rfc5737_testnet_2_rejected(self):
        assert handler.is_valid_public_ip("198.51.100.1") is False

    def test_rfc5737_testnet_3_rejected(self):
        assert handler.is_valid_public_ip("203.0.113.1") is False

    def test_empty_string_rejected(self):
        assert handler.is_valid_public_ip("") is False

    def test_none_rejected(self):
        assert handler.is_valid_public_ip(None) is False

    def test_malformed_ip_rejected(self):
        assert handler.is_valid_public_ip("not-an-ip") is False

    def test_octet_out_of_range_rejected(self):
        assert handler.is_valid_public_ip("256.1.1.1") is False


class TestExtractSourceIp:
    def test_extracts_from_network_connection_action(self):
        assert handler.extract_source_ip(_make_finding_event("8.8.8.8")) == "8.8.8.8"

    def test_extracts_from_port_probe_action(self):
        event = {"detail": {"findings": [{"Service": {"Action": {"PortProbeAction": {
            "PortProbeDetails": [{"RemoteIpDetails": {"IpAddressV4": "5.5.5.5"}}]
        }}}}]}}
        assert handler.extract_source_ip(event) == "5.5.5.5"

    def test_extracts_from_ec2_network_interface(self):
        event = {"detail": {"findings": [{"Resources": [{
            "Details": {"AwsEc2NetworkInterface": {"IpV4Addresses": ["6.6.6.6"]}}
        }]}]}}
        assert handler.extract_source_ip(event) == "6.6.6.6"

    def test_returns_none_when_no_findings(self):
        assert handler.extract_source_ip({"detail": {"findings": []}}) is None

    def test_returns_none_when_detail_missing(self):
        assert handler.extract_source_ip({}) is None

    def test_returns_none_when_all_paths_empty(self):
        assert handler.extract_source_ip(
            {"detail": {"findings": [{"Service": {"Action": {}}}]}}
        ) is None


class TestExtractFindingMetadata:
    def test_returns_expected_keys(self):
        result = handler.extract_finding_metadata(_make_finding_event("1.2.3.4"))
        assert result["finding_id"] == "test-finding-001"
        assert result["severity"] == "HIGH"
        assert result["region"] == "us-east-1"
        assert result["account_id"] == "123456789012"

    def test_returns_defaults_on_empty_input(self):
        result = handler.extract_finding_metadata({})
        assert result["finding_id"] == "unknown"
        assert result["severity"] == "UNKNOWN"

    def test_truncates_long_finding_id(self):
        event = {"detail": {"findings": [{"Id": "x" * 300}]}}
        assert len(handler.extract_finding_metadata(event)["finding_id"]) == 256


class TestIsAlreadyBlocked:
    @patch.object(handler, "_table")
    def test_returns_true_when_active_record_exists(self, mock_table):
        # Mocks DynamoDB Table resource to avoid real AWS calls.
        mock_table.query.return_value = {"Items": [{"expiry_time": 9999999999}]}
        assert handler.is_already_blocked("1.2.3.4") is True

    @patch.object(handler, "_table")
    def test_returns_false_when_no_active_record(self, mock_table):
        mock_table.query.return_value = {"Items": []}
        assert handler.is_already_blocked("1.2.3.4") is False

    @patch.object(handler, "_table")
    def test_returns_false_on_client_error(self, mock_table):
        # ClientError must not prevent the block from proceeding.
        mock_table.query.side_effect = _client_error("ProvisionedThroughputExceededException")
        assert handler.is_already_blocked("1.2.3.4") is False


class TestLambdaHandler:
    @patch.object(handler, "_table")
    def test_happy_path_writes_record_and_returns_enriched_event(
        self, mock_table, mock_context
    ):
        # Arrange
        mock_table.query.return_value = {"Items": []}
        mock_table.put_item.return_value = {}
        event = _make_finding_event("8.8.8.8")

        # Act
        result = handler.lambda_handler(event, mock_context)

        # Assert
        assert result["source_ip"] == "8.8.8.8"
        assert result["already_blocked"] is False
        assert "blocked_at" in result
        mock_table.put_item.assert_called_once()

    @patch.object(handler, "_table")
    def test_duplicate_skips_write_and_sets_already_blocked_true(
        self, mock_table, mock_context
    ):
        # Arrange
        mock_table.query.return_value = {"Items": [{"expiry_time": 9999999999}]}

        # Act
        result = handler.lambda_handler(_make_finding_event("8.8.8.8"), mock_context)

        # Assert
        assert result["already_blocked"] is True
        mock_table.put_item.assert_not_called()

    @patch.object(handler, "_table")
    def test_conditional_check_failure_treated_as_duplicate(
        self, mock_table, mock_context
    ):
        # Arrange
        mock_table.query.return_value = {"Items": []}
        mock_table.put_item.side_effect = _client_error("ConditionalCheckFailedException")

        # Act
        result = handler.lambda_handler(_make_finding_event("8.8.8.8"), mock_context)

        # Assert
        assert result["already_blocked"] is True

    @patch.object(handler, "_table")
    def test_raises_value_error_when_no_ip_extractable(self, mock_table, mock_context):
        with pytest.raises(ValueError, match="No source IP"):
            handler.lambda_handler({"detail": {"findings": []}}, mock_context)

    @patch.object(handler, "_table")
    def test_raises_value_error_for_private_ip(self, mock_table, mock_context):
        with pytest.raises(ValueError, match="validation"):
            handler.lambda_handler(_make_finding_event("192.168.1.1"), mock_context)

    @patch.object(handler, "_table")
    def test_raises_client_error_for_unexpected_dynamodb_failure(
        self, mock_table, mock_context
    ):
        # Arrange
        mock_table.query.return_value = {"Items": []}
        mock_table.put_item.side_effect = _client_error("InternalServerError")

        # Act / Assert
        with pytest.raises(ClientError):
            handler.lambda_handler(_make_finding_event("8.8.8.8"), mock_context)
