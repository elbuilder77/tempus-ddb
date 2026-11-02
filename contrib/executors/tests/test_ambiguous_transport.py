"""Ambiguous transport outcomes are UNKNOWN in the contrib executors.

Classification uses the exception type. A validation error stays FAILED. The classifier
itself (`is_ambiguous_transport_error`) is tested in `tests/test_ambiguous_transport.py`
in the repository root.
"""

import http.client
import json
import ssl
import time
from urllib import error

import pytest
from tempus_ddb import TempusDDB, gen_keys
from tempus_ddb.executor_runtime import UnknownExecutionError
from tempus_executors import (
    HttpExecutorAdapter,
    PaymentExecutorAdapter,
    SlackExecutorAdapter,
)

AMBIGUOUS = [
    TimeoutError("timed out"),
    ConnectionResetError(104, "Connection reset by peer"),
    ssl.SSLError("tls handshake failed"),
    EOFError("unexpected eof"),
    http.client.RemoteDisconnected("Remote end closed connection without response"),
    http.client.IncompleteRead(b"partial"),
    http.client.BadStatusLine(""),
    error.URLError(TimeoutError("timed out")),
    error.URLError(ConnectionResetError(104, "reset")),
    error.URLError(ssl.SSLError("eof in violation of protocol")),
]


def _gate(tmp_path, tenant_id):
    for name in ("gate", "agent", "executor"):
        gen_keys(str(tmp_path / f"{name}.keys.json"))
    ids = {
        name: json.loads((tmp_path / f"{name}.keys.json").read_text())["public_key"]
        for name in ("gate", "agent", "executor")
    }
    gate = TempusDDB(str(tmp_path / "gate.db"), str(tmp_path / "gate.keys.json"))
    gate.register_agent(ids["gate"], "gate", '{"can_delegate":true}')
    gate.install_allow_all_dev_policy()
    gate.register_agent(ids["agent"], "agent", "{}")
    gate.register_agent(ids["executor"], "executor", "{}")
    return (
        gate,
        ids["gate"],
        ids["agent"],
        str(tmp_path / "exec.db"),
        str(tmp_path / "executor.keys.json"),
        str(tmp_path / "agent.keys.json"),
        tenant_id,
    )


def _permit(gate, tenant_id, agent_id, agent_keys, action, resource, key, money=None):
    intent = {
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "idempotency_key": key,
        "action_type": action,
        "resource": resource,
        "requested_at": int(time.time() * 1_000_000),
        "input": {"text": "hello", "invoice_id": "INV-1"},
    }
    if money is not None:
        intent["money"] = money
    raw = gate.request_action(json.dumps(intent), agent_keys, 60)
    assert json.loads(raw)["authorization"]["decision"] == "ALLOWED"
    return raw


def _state(adapter, permit):
    authorization_id = json.loads(permit)["authorization"]["authorization_id"]
    return json.loads(adapter._runtime.raw_executor.get_execution_state(authorization_id))


def test_urllib_http_transport_records_ambiguous_errors_as_unknown(tmp_path, monkeypatch):
    holder = {}

    def boom(*_args, **_kwargs):
        raise holder["exc"]

    monkeypatch.setattr("tempus_executors.http.open_request", boom)
    gate, gate_id, agent_id, exec_db, exec_key, agent_keys, tenant = _gate(
        tmp_path, "tenant-http-unknown"
    )
    adapter = HttpExecutorAdapter(
        executor_db=exec_db,
        executor_keyfile=exec_key,
        trusted_gate_id=gate_id,
        trusted_tenant_id=tenant,
        allowed_domains={"example.com"},
    )
    first = None
    for index, exc in enumerate(AMBIGUOUS):
        holder["exc"] = exc
        permit = _permit(
            gate,
            tenant,
            agent_id,
            agent_keys,
            "http.post",
            "https://example.com/hook",
            f"http-amb-{index}",
        )
        if first is None:
            first = permit
        with pytest.raises(UnknownExecutionError) as caught:
            adapter.execute_permit(permit)
        observation = json.loads(caught.value.observation)
        assert observation["status"] == "UNKNOWN", type(exc)
        assert _state(adapter, permit)["status"] == "UNKNOWN"

    with pytest.raises(Exception, match="consumed|already"):
        adapter.execute_permit(first)

    for index, exc in enumerate(
        (
            ValueError("amount 500.00 is not a transport failure"),
            ConnectionRefusedError(111, "Connection refused"),
            error.HTTPError("https://example.com/hook", 404, "missing", None, None),
        )
    ):
        holder["exc"] = exc
        permit = _permit(
            gate,
            tenant,
            agent_id,
            agent_keys,
            "http.post",
            "https://example.com/hook",
            f"http-fail-{index}",
        )
        receipt = json.loads(adapter.execute_permit(permit))
        assert receipt["status"] == "FAILED", type(exc)
        assert _state(adapter, permit)["status"] == "FAILED"

    holder["exc"] = error.HTTPError(
        "https://example.com/hook", 500, "unavailable", None, None
    )
    permit = _permit(
        gate,
        tenant,
        agent_id,
        agent_keys,
        "http.post",
        "https://example.com/hook",
        "http-500",
    )
    with pytest.raises(UnknownExecutionError):
        adapter.execute_permit(permit)
    assert _state(adapter, permit)["status"] == "UNKNOWN"


class _RaisingPayment:
    def __init__(self):
        self.exc = None

    def disburse(self, secret_key, amount, asset, beneficiary, metadata):
        raise self.exc


def test_payment_transport_errors_follow_the_same_rule(tmp_path):
    gate, gate_id, agent_id, exec_db, exec_key, agent_keys, tenant = _gate(
        tmp_path, "tenant-pay-unknown"
    )
    transport = _RaisingPayment()
    adapter = PaymentExecutorAdapter(
        executor_db=exec_db,
        executor_keyfile=exec_key,
        trusted_gate_id=gate_id,
        trusted_tenant_id=tenant,
        secret_key="sk_test",
        transport=transport,
    )
    money = {"amount": "1.00", "asset": "USD", "beneficiary": "ada"}
    for index, exc in enumerate(
        (
            TimeoutError("timed out"),
            ConnectionResetError(104, "reset"),
            ssl.SSLError("tls"),
            EOFError("eof"),
            http.client.RemoteDisconnected("closed"),
        )
    ):
        transport.exc = exc
        permit = _permit(
            gate,
            tenant,
            agent_id,
            agent_keys,
            "finance.disburse",
            "treasury/main",
            f"pay-amb-{index}",
            money,
        )
        with pytest.raises(UnknownExecutionError):
            adapter.execute_permit(permit)
        assert _state(adapter, permit)["status"] == "UNKNOWN", type(exc)

    transport.exc = ValueError("provider rejected amount 500.00 after validation")
    permit = _permit(
        gate,
        tenant,
        agent_id,
        agent_keys,
        "finance.disburse",
        "treasury/main",
        "pay-validation",
        money,
    )
    receipt = json.loads(adapter.execute_permit(permit))
    assert receipt["status"] == "FAILED"
    assert _state(adapter, permit)["status"] == "FAILED"


def test_slack_urllib_transport_records_ambiguous_errors_as_unknown(
    tmp_path, monkeypatch
):
    holder = {}

    def boom(*_args, **_kwargs):
        raise holder["exc"]

    monkeypatch.setattr("tempus_executors.slack.open_request", boom)
    gate, gate_id, agent_id, exec_db, exec_key, agent_keys, tenant = _gate(
        tmp_path, "tenant-slack-unknown"
    )
    adapter = SlackExecutorAdapter(
        executor_db=exec_db,
        executor_keyfile=exec_key,
        trusted_gate_id=gate_id,
        trusted_tenant_id=tenant,
        token="xoxb-test",
    )
    for index, exc in enumerate(
        (TimeoutError("timed out"), ssl.SSLError("tls"), EOFError("eof"))
    ):
        holder["exc"] = exc
        permit = _permit(
            gate,
            tenant,
            agent_id,
            agent_keys,
            "slack.post_message",
            "C0123ABCD",
            f"slack-amb-{index}",
        )
        with pytest.raises(UnknownExecutionError):
            adapter.execute_permit(permit)
        assert _state(adapter, permit)["status"] == "UNKNOWN"

    holder["exc"] = ValueError("channel check failed for code 500.00")
    permit = _permit(
        gate,
        tenant,
        agent_id,
        agent_keys,
        "slack.post_message",
        "C0123ABCD",
        "slack-validation",
    )
    receipt = json.loads(adapter.execute_permit(permit))
    assert receipt["status"] == "FAILED"
    assert _state(adapter, permit)["status"] == "FAILED"
