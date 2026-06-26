"""
tests/unit/test_block_traffic_handler.py

Unit tests for src/handlers/block_traffic/handler.py.

Coverage:
    is_valid_ipv4                    happy path, edge cases
    has_rule_for_ip                  found, not found
    pick_lowest_available_priority   gaps reclaimed, full group error
    build_drop_rule                  structure validation
    lambda_handler                   happy path, duplicate flag, rule exists,
                                     capacity exceeded, client error
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("RULE_GROUP_ARN", "arn:aws:network-firewall:us-east-1:123:stateless-rulegroup/test")
os.environ.setdefault("RULE_GROUP_NAME", "test-rule-group")
os.environ.setdefault("MAX_RULES", "100")
os.environ.setdefault("ENVIRONMENT", "test")

from botocore.exceptions import ClientError

import src.handlers.block_traffic.handler as handler


def _client_error(code: str) -> ClientError:
    """Build a ClientError with the given error code."""
    return ClientError({"Error": {"Code": code, "Message": "test"}}, "operation")


def _make_rule(priority: int, cidr: str) -> dict:
    """Return a minimal stateless rule dict for testing."""
    return {
        "Priority": priority,
        "RuleDefinition": {
            "MatchAttributes": {
                "Sources": [{"AddressDefinition": cidr}],
                "Destinations": [{"AddressDefinition": "0.0.0.0/0"}],
            },
            "Actions": ["aws:drop"],
        },
    }


@pytest.fixture()
def mock_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-request-id"
    return ctx


@pytest.fixture()
def empty_rule_group() -> dict:
    """Rule group with only the placeholder rule at priority 1."""
    return {
        "RulesSource": {
            "StatelessRulesAndCustomActions": {
                "StatelessRules": [_make_rule(1, "192.0.2.1/32")]
            }
        }
    }


class TestIsValidIpv4:
    def test_valid_ipv4_returns_true(self):
        assert handler.is_valid_ipv4("1.2.3.4") is True

    def test_empty_string_returns_false(self):
        assert handler.is_valid_ipv4("") is False

    def test_none_returns_false(self):
        assert handler.is_valid_ipv4(None) is False

    def test_malformed_returns_false(self):
        assert handler.is_valid_ipv4("not.an.ip.addr") is False


class TestHasRuleForIp:
    def test_returns_true_when_matching_rule_exists(self):
        assert handler.has_rule_for_ip("8.8.8.8", [_make_rule(2, "8.8.8.8/32")]) is True

    def test_returns_false_when_no_matching_rule(self):
        assert handler.has_rule_for_ip("8.8.8.8", [_make_rule(2, "1.1.1.1/32")]) is False

    def test_returns_false_for_empty_rules(self):
        assert handler.has_rule_for_ip("8.8.8.8", []) is False


class TestPickLowestAvailablePriority:
    def test_returns_2_when_only_placeholder_exists(self):
        assert handler.pick_lowest_available_priority([_make_rule(1, "192.0.2.1/32")]) == 2

    def test_returns_3_when_1_and_2_are_used(self):
        rules = [_make_rule(1, "192.0.2.1/32"), _make_rule(2, "1.1.1.1/32")]
        assert handler.pick_lowest_available_priority(rules) == 3

    def test_reclaims_gap_when_priority_3_is_missing(self):
        rules = [
            _make_rule(1, "192.0.2.1/32"),
            _make_rule(2, "1.1.1.1/32"),
            _make_rule(4, "2.2.2.2/32"),
        ]
        assert handler.pick_lowest_available_priority(rules) == 3

    def test_raises_when_all_slots_used(self):
        rules = [{"Priority": i} for i in range(1, handler._NFW_MAX_PRIORITY + 1)]
        with pytest.raises(RuntimeError, match="No available priority slot"):
            handler.pick_lowest_available_priority(rules)


class TestBuildDropRule:
    def test_returns_correct_structure(self):
        # Arrange / Act
        rule = handler.build_drop_rule("8.8.8.8", 2)

        # Assert
        assert rule["Priority"] == 2
        assert rule["RuleDefinition"]["Actions"] == ["aws:drop"]
        assert rule["RuleDefinition"]["MatchAttributes"]["Sources"][0]["AddressDefinition"] == "8.8.8.8/32"


class TestLambdaHandler:
    @patch.object(handler, "_nfw")
    def test_happy_path_adds_rule_and_returns_updated_event(
        self, mock_nfw, mock_context, empty_rule_group
    ):
        # Arrange
        # mock_nfw stands in for the boto3 Network Firewall client.
        mock_nfw.describe_rule_group.return_value = {
            "RuleGroup": empty_rule_group,
            "UpdateToken": "token-abc",
        }
        mock_nfw.update_rule_group.return_value = {}

        # Act
        result = handler.lambda_handler(
            {"source_ip": "8.8.8.8", "already_blocked": False}, mock_context
        )

        # Assert
        assert result["firewall_updated"] is True
        assert result["rule_priority"] == 2
        mock_nfw.update_rule_group.assert_called_once()

    @patch.object(handler, "_nfw")
    def test_already_blocked_flag_short_circuits_without_api_call(
        self, mock_nfw, mock_context
    ):
        # Arrange / Act
        result = handler.lambda_handler(
            {"source_ip": "8.8.8.8", "already_blocked": True}, mock_context
        )

        # Assert
        assert result["firewall_updated"] is False
        assert result["reason"] == "duplicate"
        mock_nfw.describe_rule_group.assert_not_called()

    @patch.object(handler, "_nfw")
    def test_rule_exists_skips_update(self, mock_nfw, mock_context):
        # Arrange
        rule_group = {"RulesSource": {"StatelessRulesAndCustomActions": {
            "StatelessRules": [_make_rule(2, "8.8.8.8/32")]
        }}}
        mock_nfw.describe_rule_group.return_value = {
            "RuleGroup": rule_group,
            "UpdateToken": "token-abc",
        }

        # Act
        result = handler.lambda_handler(
            {"source_ip": "8.8.8.8", "already_blocked": False}, mock_context
        )

        # Assert
        assert result["firewall_updated"] is False
        assert result["reason"] == "rule_exists"
        mock_nfw.update_rule_group.assert_not_called()

    @patch.object(handler, "_nfw")
    def test_raises_runtime_error_when_capacity_exceeded(self, mock_nfw, mock_context):
        # Arrange: MAX_RULES=100, threshold=90, 91 rules exceeds it
        rules = [_make_rule(i, f"1.1.1.{i}/32") for i in range(1, 92)]
        rule_group = {"RulesSource": {"StatelessRulesAndCustomActions": {
            "StatelessRules": rules
        }}}
        mock_nfw.describe_rule_group.return_value = {
            "RuleGroup": rule_group,
            "UpdateToken": "token-abc",
        }

        # Act / Assert
        with pytest.raises(RuntimeError, match="near_capacity"):
            handler.lambda_handler(
                {"source_ip": "8.8.8.8", "already_blocked": False}, mock_context
            )

    @patch.object(handler, "_nfw")
    def test_raises_value_error_for_missing_source_ip(self, mock_nfw, mock_context):
        with pytest.raises(ValueError, match="source_ip"):
            handler.lambda_handler({"already_blocked": False}, mock_context)

    @patch.object(handler, "_nfw")
    def test_raises_client_error_on_update_failure(
        self, mock_nfw, mock_context, empty_rule_group
    ):
        # Arrange
        mock_nfw.describe_rule_group.return_value = {
            "RuleGroup": empty_rule_group,
            "UpdateToken": "token-abc",
        }
        mock_nfw.update_rule_group.side_effect = _client_error("InternalServerError")

        # Act / Assert
        with pytest.raises(ClientError):
            handler.lambda_handler(
                {"source_ip": "8.8.8.8", "already_blocked": False}, mock_context
            )
