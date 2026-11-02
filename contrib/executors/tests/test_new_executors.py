import json
import os
import tempfile
import time
from typing import Any, Dict

import pytest
from tempus_ddb import TempusDDB, gen_keys
from tempus_executors import (
    HttpExecutorAdapter,
    PaymentExecutorAdapter,
    SlackExecutorAdapter,
)


class MockHttpTransport:
    def __init__(self):
        self.calls = []

    def request(
        self, method: str, url: str, headers: Dict[str, str], payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        self.calls.append(
            {"method": method, "url": url, "headers": headers, "payload": payload}
        )
        return {"status": "ok", "url_called": url, "received_method": method}


class MockSlackTransport:
    def __init__(self):
        self.messages = []

    def request(
        self, endpoint: str, token: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        self.messages.append({"endpoint": endpoint, "token": token, "payload": payload})
        return {
            "ok": True,
            "ts": "1725000000.000100",
            "message": {"text": payload.get("text")},
        }


class MockPaymentTransport:
    def __init__(self):
        self.transfers = []

    def disburse(
        self,
        secret_key: str,
        amount: str,
        asset: str,
        beneficiary: str,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        self.transfers.append(
            {"amount": amount, "asset": asset, "beneficiary": beneficiary}
        )
        return {
            "status": "SETTLED",
            "tx_id": "tx_mock_123",
            "amount": amount,
            "asset": asset,
            "beneficiary": beneficiary,
        }


def _setup_gate_and_agents(tmpdir, tenant_id="tenant-test"):
    gate_db = os.path.join(tmpdir, "gate.db")
    exec_db = os.path.join(tmpdir, "exec.db")
    gate_key = os.path.join(tmpdir, "gate.keys.json")
    agent_key = os.path.join(tmpdir, "agent.keys.json")
    exec_key = os.path.join(tmpdir, "executor.keys.json")

    gen_keys(gate_key)
    gen_keys(agent_key)
    gen_keys(exec_key)

    gate = TempusDDB(gate_db, gate_key)

    with open(gate_key, "r", encoding="utf-8") as f:
        gate_id = json.load(f)["public_key"]
    with open(agent_key, "r", encoding="utf-8") as f:
        agent_id = json.load(f)["public_key"]
    with open(exec_key, "r", encoding="utf-8") as f:
        exec_id = json.load(f)["public_key"]

    gate.register_agent(gate_id, "gate-root", '{"can_delegate":true}')
    gate.install_allow_all_dev_policy()  # explicit dev opt-in (default is deny-all)
    gate.register_agent(agent_id, "test-agent", "{}")
    gate.register_agent(exec_id, "test-executor", "{}")

    return gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key


def test_http_executor_adapter():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant_id = "tenant-http"
        gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant_id)
        )

        transport = MockHttpTransport()
        adapter = HttpExecutorAdapter(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant_id,
            auth_header="Bearer secret-isolated-token",
            allowed_domains={"api.example.com"},
            transport=transport,
        )

        intent = {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "idempotency_key": "http-001",
            "action_type": "http.post",
            "resource": "https://api.example.com/v1/webhook",
            "requested_at": int(time.time() * 1_000_000),
            "input": {"event": "user.signup", "user_id": 123},
        }

        auth_resp_str = gate.request_action(json.dumps(intent), agent_key, 60)
        auth_resp = json.loads(auth_resp_str)
        assert auth_resp["authorization"]["decision"] == "ALLOWED"

        # Execute permit
        outcome_receipt_str = adapter.execute_permit(auth_resp_str)
        outcome_receipt = json.loads(outcome_receipt_str)
        assert outcome_receipt["status"] == "SUCCEEDED"

        # Verify transport received isolated auth header
        assert len(transport.calls) == 1
        assert (
            transport.calls[0]["headers"]["Authorization"]
            == "Bearer secret-isolated-token"
        )
        assert transport.calls[0]["payload"]["user_id"] == 123

        # Replay attempt fails closed
        with pytest.raises(Exception):
            adapter.execute_permit(auth_resp_str)

        del gate
        del adapter


def test_slack_executor_adapter():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant_id = "tenant-slack"
        gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant_id)
        )

        transport = MockSlackTransport()
        adapter = SlackExecutorAdapter(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant_id,
            token="xoxb-isolated-slack-token",
            transport=transport,
        )

        intent = {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "idempotency_key": "slack-001",
            "action_type": "slack.post_message",
            "resource": "#alerts-prod",
            "requested_at": int(time.time() * 1_000_000),
            "input": {"text": "Production deployment completed successfully."},
        }

        auth_resp_str = gate.request_action(json.dumps(intent), agent_key, 60)
        auth_resp = json.loads(auth_resp_str)
        assert auth_resp["authorization"]["decision"] == "ALLOWED"

        # Execute permit
        outcome_receipt_str = adapter.execute_permit(auth_resp_str)
        outcome_receipt = json.loads(outcome_receipt_str)
        assert outcome_receipt["status"] == "SUCCEEDED"

        assert len(transport.messages) == 1
        assert transport.messages[0]["token"] == "xoxb-isolated-slack-token"
        assert transport.messages[0]["payload"]["channel"] == "#alerts-prod"

        del gate
        del adapter


def test_payment_executor_adapter():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tenant_id = "tenant-pay"
        gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
            _setup_gate_and_agents(tmpdir, tenant_id)
        )

        transport = MockPaymentTransport()
        adapter = PaymentExecutorAdapter(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=tenant_id,
            secret_key="sk_live_isolated_secret_key",
            transport=transport,
        )

        intent = {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "idempotency_key": "pay-001",
            "action_type": "finance.disburse",
            "resource": "treasury/main",
            "requested_at": int(time.time() * 1_000_000),
            "input": {"invoice_id": "INV-2026-99"},
            "money": {
                "amount": "250.00",
                "asset": "USD",
                "beneficiary": "contractor-1",
            },
        }

        auth_resp_str = gate.request_action(json.dumps(intent), agent_key, 60)
        auth_resp = json.loads(auth_resp_str)
        assert auth_resp["authorization"]["decision"] == "ALLOWED"

        # Execute permit
        outcome_receipt_str = adapter.execute_permit(auth_resp_str)
        outcome_receipt = json.loads(outcome_receipt_str)
        assert outcome_receipt["status"] == "SUCCEEDED"

        assert len(transport.transfers) == 1
        assert transport.transfers[0]["amount"] == "250.00"
        assert transport.transfers[0]["beneficiary"] == "contractor-1"

        del gate
        del adapter
