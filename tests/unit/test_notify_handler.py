"""
tests/unit/test_notify_handler.py

Unit tests for src/handlers/notify/handler.py.

Coverage:
    build_success_message   all three action branches (new rule, duplicate, skip)
    build_failure_message   error fields present, missing key graceful
    lambda_handler          success path, failure path, SNS error non-fatal,
                            missing notify_status defaults to SUCCESS
"""

from __future__ import annotations

import copy
import json
import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123:test-topic")
os.environ.setdefault("ENVIRONMENT", "test")

from botocore.exceptions import ClientError

import src.handlers.notify.handler as handler


def _client_error(code: str) -> ClientError:
    """Build a ClientError with the given error code."""
    return ClientError({"Error": {"Code": code, "Message": "test"}}, "operation")


@pytest.fixture()
def mock_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-request-id"
    return ctx


@pytest.fixture()
def success_payload() -> dict:
    """Standard workflow output for a successful new block.

    Returns a deep copy on every call so tests cannot leak mutations
    into each other via shared fixture state.
    """
    return copy.deepcopy({
        "source_ip": "8.8.8.8",
        "already_blocked": False,
        "firewall_updated": True,
        "rule_priority": 2,
        "blocked_at": "2025-01-01T00:00:00+00:00",
        "expiry_time": 9999999999,
        "metadata": {
            "title": "Test Finding",
            "severity": "HIGH",
            "finding_type": "TTPs/Discovery",
            "account_id": "123456789012",
            "region": "us-east-1",
        },
    })


class TestBuildSuccessMessage:
    def test_new_rule_action_includes_priority(self, success_payload):
        # Arrange / Act
        subject, body_str = handler.build_success_message(success_payload)
        body = json.loads(body_str)

        # Assert
        assert "priority=2" in body["action"]
        assert body["status"] == "SUCCESS"
        assert body["source_ip"] == "8.8.8.8"

    def test_duplicate_action_message(self, success_payload):
        # Arrange
        payload = {**success_payload, "already_blocked": True, "firewall_updated": False}

        # Act
        _, body_str = handler.build_success_message(payload)

        # Assert
        assert "duplicate" in json.loads(body_str)["action"]

    def test_skip_action_includes_reason(self, success_payload):
        # Arrange
        payload = {
            **success_payload,
            "already_blocked": False,
            "firewall_updated": False,
            "reason": "rule_exists",
        }

        # Act
        _, body_str = handler.build_success_message(payload)

        # Assert
        assert "rule_exists" in json.loads(body_str)["action"]

    def test_subject_includes_environment(self, success_payload):
        # Arrange / Act
        subject, _ = handler.build_success_message(success_payload)

        # Assert
        assert "TEST" in subject


class TestBuildFailureMessage:
    def test_returns_failure_status_and_error_fields(self):
        # Arrange / Act
        subject, body_str = handler.build_failure_message(
            {"error": {"Error": "ValueError", "Cause": "bad input"}}
        )
        body = json.loads(body_str)

        # Assert
        assert body["status"] == "FAILURE"
        assert body["error_type"] == "ValueError"
        assert body["error_cause"] == "bad input"
        assert "FAILURE" in subject

    def test_handles_missing_error_key_gracefully(self):
        # Arrange / Act
        _, body_str = handler.build_failure_message({})

        # Assert
        assert json.loads(body_str)["error_type"] == "unknown"


class TestLambdaHandler:
    @patch.object(handler, "_sns")
    def test_success_path_publishes_to_sns(self, mock_sns, mock_context, success_payload):
        # Arrange
        # mock_sns stands in for the boto3 SNS client to avoid real AWS calls.
        mock_sns.publish.return_value = {"MessageId": "msg-001"}
        event = {"notify_status": "SUCCESS", "payload": success_payload}

        # Act
        result = handler.lambda_handler(event, mock_context)

        # Assert
        assert result["notification_sent"] is True
        call_kwargs = mock_sns.publish.call_args[1]
        assert call_kwargs["TopicArn"] == os.environ["SNS_TOPIC_ARN"]
        assert "IP Blocked" in call_kwargs["Subject"]

    @patch.object(handler, "_sns")
    def test_failure_path_publishes_failure_message(self, mock_sns, mock_context):
        # Arrange
        mock_sns.publish.return_value = {"MessageId": "msg-002"}
        event = {
            "notify_status": "FAILURE",
            "payload": {"error": {"Error": "RuntimeError", "Cause": "capacity exceeded"}},
        }

        # Act
        result = handler.lambda_handler(event, mock_context)

        # Assert
        assert result["notification_sent"] is True
        assert "FAILURE" in mock_sns.publish.call_args[1]["Subject"]

    @patch.object(handler, "_sns")
    def test_sns_client_error_is_non_fatal(self, mock_sns, mock_context, success_payload):
        # SNS failures must not re-raise. The block rule is already applied.
        mock_sns.publish.side_effect = _client_error("KMSDisabledException")
        result = handler.lambda_handler(
            {"notify_status": "SUCCESS", "payload": success_payload}, mock_context
        )
        assert result["notification_sent"] is True

    @patch.object(handler, "_sns")
    def test_defaults_to_success_when_notify_status_missing(
        self, mock_sns, mock_context, success_payload
    ):
        # Arrange
        mock_sns.publish.return_value = {}

        # Act
        handler.lambda_handler({"payload": success_payload}, mock_context)

        # Assert
        assert "IP Blocked" in mock_sns.publish.call_args[1]["Subject"]
