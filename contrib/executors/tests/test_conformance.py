"""Conformance tests for the contrib ActionAdapter implementations.

The GitHub adapter (the conformance reference that stays in the core) and the
third-party example are covered by `tests/test_conformance.py` in the repository root.
"""

from tempus_ddb.testing import AdapterConformanceHarness
from tempus_executors import (
    HttpActionAdapter,
    PaymentActionAdapter,
    SlackActionAdapter,
)


class MockHttpTransport:
    def request(self, method, url, headers, payload):
        return {"status": "ok", "delivered": True}


class MockSlackTransport:
    def request(self, endpoint, token, payload):
        return {
            "ok": True,
            "ts": "1234567890.000100",
            "message": {"text": payload.get("text")},
        }


def test_http_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: HttpActionAdapter(
            auth_header="Bearer secret_token",
            allowed_domains={"api.example.com"},
            transport=MockHttpTransport(),
        ),
        valid_action_type="http.post",
        valid_resource="https://api.example.com/webhook",
        valid_input={"event": "user.signup", "id": 42},
    )
    harness.run_all_checks()


def test_slack_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: SlackActionAdapter(
            token="xoxb-mock-token",
            transport=MockSlackTransport(),
        ),
        valid_action_type="slack.post_message",
        valid_resource="#security-alerts",
        valid_input={"text": "System operational"},
    )
    harness.run_all_checks()


def test_payment_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: PaymentActionAdapter(
            secret_key="sk_live_isolated_secret",
        ),
        valid_action_type="finance.disburse",
        valid_resource="res://treasury/main",
        valid_input={"invoice_id": "inv_9981"},
        valid_money={"amount": "10000", "asset": "USD", "beneficiary": "vendor_corp"},
    )
    harness.run_all_checks()
