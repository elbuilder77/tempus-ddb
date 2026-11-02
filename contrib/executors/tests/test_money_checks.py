"""Money checks shared by the gate, the Rust executor and the Python runtime.
"""

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time

import pytest
from support import _setup_gate_and_agents
from tempus_ddb import TempusExecutor
from tempus_ddb.executor_runtime import ExecutorRuntime, ExecutorRuntimeError
from tempus_executors.payment import (
    PaymentActionAdapter,
    PaymentExecutorError,
    canonical_money,
)
from test_money_binding import RecordingTransport

TENANT = "tenant-money-adv"
_PAYMENT_ACTIONS = ("finance.disburse", "finance.transfer", "payment.charge")


def _constraints(**extra):
    constraints = {
        "allowed_action_types": list(_PAYMENT_ACTIONS) + ["custom.note"],
        "allowed_resources": ["*"],
        "allowed_executors": ["*"],
        "max_ttl_seconds": 60,
        "max_input_bytes": 4096,
        "allowed_currencies": ["USD"],
        "max_money_amount_minor": 1_000_000,
    }
    constraints.update(extra)
    return constraints


def _world(tmpdir, **extra):
    gate, gate_id, agent_id, _exec_id, exec_db, exec_key, agent_key = (
        _setup_gate_and_agents(tmpdir, TENANT)
    )
    gate.install_policy(
        json.dumps(
            {
                "schema_version": "tempus.policy-bundle.v1",
                "policy_version": "money-adv-v1",
                "tenant_id": TENANT,
                "constraints": _constraints(**extra),
            }
        )
    )
    return gate, gate_id, agent_id, exec_db, exec_key, agent_key


def _intent(agent_id, key, money, action="payment.charge"):
    return json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": TENANT,
            "agent_id": agent_id,
            "idempotency_key": key,
            "action_type": action,
            "resource": "treasury/main",
            "requested_at": time.time_ns() // 1000,
            "input": {},
            "money": money,
        }
    )


def _raw_intent(agent_id, key, money_json, action="payment.charge", input_json="{}"):
    return (
        '{"schema_version":"tempus.action-intent.v1","tenant_id":"%s","agent_id":"%s",'
        '"idempotency_key":"%s","action_type":"%s","resource":"treasury/main",'
        '"requested_at":%d,"input":%s,"money":%s}'
    ) % (
        TENANT,
        agent_id,
        key,
        action,
        time.time_ns() // 1000,
        input_json,
        money_json,
    )


def _refused(exc):
    text = str(exc.value)
    assert "TEMPUS_INVALID_CONTRACT" in text or "NON_EXACT_NUMBER" in text, text
    return text


def _canonical(value):
    """Match the gate's canonical JSON for the ASCII objects these tests sign."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + _canonical(value[key])
                for key in sorted(value)
            )
            + "}"
        )
    raise TypeError(type(value))


def _sign_ed25519(seed_hex, message: bytes) -> str:
    seed = bytes.fromhex(seed_hex)
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        + base64.encodebytes(der).decode()
        + "-----END PRIVATE KEY-----\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        message_path = os.path.join(tmp, "msg.bin")
        with open(key_path, "w", encoding="utf-8") as handle:
            handle.write(pem)
        with open(message_path, "wb") as handle:
            handle.write(message)
        signature = subprocess.check_output(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                key_path,
                "-rawin",
                "-in",
                message_path,
            ]
        )
    return signature.hex()


def _resign_authorization(permit, gate_key_path, other_intent):
    """Return the permit after one authorization field is rewritten and re-signed."""
    document = json.loads(permit)
    assert _canonical(document) == permit
    authorization = dict(document["authorization"])
    authorization_id = authorization.pop("authorization_id")
    authorization.pop("gate_signature")
    assert (
        hashlib.sha256(_canonical(authorization).encode()).hexdigest() == authorization_id
    )
    private_key = json.loads(open(gate_key_path, encoding="utf-8").read())["private_key"]
    assert (
        _sign_ed25519(private_key, bytes.fromhex(authorization_id))
        == document["authorization"]["gate_signature"]
    )
    authorization["intent"] = other_intent
    body = _canonical(authorization)
    new_id = hashlib.sha256(body.encode()).hexdigest()
    authorization["authorization_id"] = new_id
    authorization["gate_signature"] = _sign_ed25519(private_key, bytes.fromhex(new_id))
    document["authorization"] = authorization
    return _canonical(document)


@pytest.mark.parametrize(
    "money",
    [
        {"amount": "99999.00", "amount_minor": 1, "asset": "USD"},
        {"amount": "1.00", "currency": "USD", "asset": "EUR"},
    ],
)
def test_money_fields_must_match(money):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(
                _intent(agent_id, "k-disagree", {**money, "beneficiary": "b"}),
                agent_key,
                30,
            )
    assert "TEMPUS_INVALID_CONTRACT" in str(excinfo.value)
    with pytest.raises(PaymentExecutorError):
        canonical_money(money)


@pytest.mark.parametrize("asset", ["usd", "USD ", "USD\u200b", "\uff35\uff33\uff24"])
def test_currency_codes_must_be_exact(asset):
    money = {"amount": "1.00", "asset": asset, "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(_intent(agent_id, f"k-{asset!r}", money), agent_key, 30)
    assert "exact 3-letter currency code" in _refused(excinfo)
    with pytest.raises(PaymentExecutorError, match="exact 3-letter currency code"):
        canonical_money(money)


@pytest.mark.parametrize("currencies", [["US*"], ["*"], ["usd"]])
def test_currency_lists_must_be_exact_codes(currencies):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, *_ = _world(tmpdir)
        spec = {
            "schema_version": "tempus.policy-bundle.v1",
            "policy_version": "wild-v1",
            "tenant_id": TENANT,
            "constraints": _constraints(allowed_currencies=currencies),
        }
        with pytest.raises(Exception) as excinfo:
            gate.install_policy(json.dumps(spec))
    text = str(excinfo.value)
    assert "TEMPUS_POLICY_INVALID" in text
    assert "exact currency codes" in text


def test_amount_limit_boundary_and_leading_zeros_reach_the_transport_as_written():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_db, exec_key, agent_key = _world(
            tmpdir, max_money_amount_minor=5000
        )
        allowed = json.loads(
            gate.request_action(
                _intent(
                    agent_id,
                    "k-50",
                    {"amount": "50.00", "asset": "USD", "beneficiary": "b"},
                ),
                agent_key,
                30,
            )
        )
        assert allowed["authorization"]["decision"] == "ALLOWED"
        blocked = json.loads(
            gate.request_action(
                _intent(
                    agent_id,
                    "k-5001",
                    {"amount": "50.01", "asset": "USD", "beneficiary": "b"},
                ),
                agent_key,
                30,
            )
        )
        assert blocked["authorization"]["decision"] == "BLOCKED"
        assert "POLICY_MONEY_DENIED" in blocked["authorization"]["reason_codes"]

        permit = gate.request_action(
            _intent(
                agent_id,
                "k-zeros",
                {"amount": "00050.00", "asset": "USD", "beneficiary": "b"},
            ),
            agent_key,
            30,
        )
        assert json.loads(permit)["authorization"]["decision"] == "ALLOWED"
        transport = RecordingTransport()
        runtime = ExecutorRuntime(exec_db, exec_key, gate_id, TENANT)
        receipt = json.loads(
            runtime.execute_permit(permit, PaymentActionAdapter(transport=transport))
        )
        assert receipt["status"] == "SUCCEEDED", receipt
        # The transport is paid the amount string as written.
        assert transport.calls == [("00050.00", "USD", "b")]


@pytest.mark.parametrize(
    "amount",
    ["1e3", "-1.00", "+1.00", "1,00", " 1.00", "1.000", "5.", ".5", "\uff11.\uff10\uff10"],
)
def test_invalid_amount_strings_are_blocked_in_the_gate_and_canonical_money(amount):
    money = {"amount": amount, "asset": "USD", "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(_intent(agent_id, "k-bad-amount", money), agent_key, 30)
    assert "TEMPUS_INVALID_CONTRACT" in str(excinfo.value)
    with pytest.raises(PaymentExecutorError):
        canonical_money({"amount": amount, "asset": "USD"})


def test_amount_overflow_is_blocked_in_the_gate_and_canonical_money():
    amount = "184467440737095516.16"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(
                _intent(
                    agent_id,
                    "k-overflow",
                    {"amount": amount, "asset": "USD", "beneficiary": "b"},
                ),
                agent_key,
                30,
            )
    assert "too large" in str(excinfo.value)
    with pytest.raises(PaymentExecutorError, match="too large"):
        canonical_money({"amount": amount, "asset": "USD"})


@pytest.mark.parametrize(
    "minor,raw_minor",
    [
        (100.0, "100.0"),
        (1e2, "1e2"),
        (-1, "-1"),
        ("100", '"100"'),
        (True, "true"),
        (2**64, "18446744073709551616"),
    ],
)
def test_invalid_amount_minor_is_blocked_in_canonical_money_and_the_gate(minor, raw_minor):
    with pytest.raises(PaymentExecutorError, match="amount_minor"):
        canonical_money({"amount_minor": minor, "asset": "USD"})
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        raw = _raw_intent(
            agent_id,
            "k-minor",
            '{"amount_minor":%s,"asset":"USD","beneficiary":"b"}' % raw_minor,
        )
        with pytest.raises(Exception) as excinfo:
            gate.request_action(raw, agent_key, 30)
    _refused(excinfo)


@pytest.mark.parametrize("action", ["finance.disburse", "finance.transfer"])
@pytest.mark.parametrize("amount", ["0", "0.00", "000"])
def test_a_zero_amount_is_refused_for_disburse_and_transfer(action, amount):
    money = {"amount": amount, "asset": "USD", "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(
                _intent(agent_id, f"k-zero-{action}-{amount}", money, action=action),
                agent_key,
                30,
            )
    assert "non-zero" in _refused(excinfo)
    transport = RecordingTransport()
    with pytest.raises(PaymentExecutorError, match="non-zero"):
        PaymentActionAdapter(transport=transport).execute_action(
            {"action_type": action, "money": money}
        )
    assert transport.calls == []


@pytest.mark.parametrize("amount", ["0", "0.00", "000"])
def test_a_zero_payment_is_refused(amount):
    money = {"amount": amount, "asset": "USD", "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(_intent(agent_id, "k-zero", money), agent_key, 30)
    assert "non-zero" in _refused(excinfo)
    transport = RecordingTransport()
    with pytest.raises(PaymentExecutorError, match="non-zero"):
        PaymentActionAdapter(transport=transport).execute_action(
            {"action_type": "payment.charge", "money": money}
        )
    assert transport.calls == []


@pytest.mark.parametrize("action", _PAYMENT_ACTIONS)
@pytest.mark.parametrize("money_json", [None, "null"])
def test_a_payment_without_money_is_refused(action, money_json):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        if money_json is None:
            body = {
                "schema_version": "tempus.action-intent.v1",
                "tenant_id": TENANT,
                "agent_id": agent_id,
                "idempotency_key": f"k-nomoney-{action}",
                "action_type": action,
                "resource": "treasury/main",
                "requested_at": time.time_ns() // 1000,
                "input": {},
            }
            raw = json.dumps(body)
        else:
            raw = _raw_intent(agent_id, f"k-null-{action}", "null", action=action)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(raw, agent_key, 30)
    assert "requires a money object" in _refused(excinfo)
    transport = RecordingTransport()
    with pytest.raises(PaymentExecutorError, match="money"):
        PaymentActionAdapter(transport=transport).execute_action(
            {"action_type": action, "money": None}
        )
    assert transport.calls == []


@pytest.mark.parametrize(
    "name,money",
    [
        ("null-amount", {"amount": None, "asset": "USD"}),
        ("null-asset", {"amount": "1.00", "asset": None}),
    ],
)
def test_null_amount_or_asset_is_blocked_in_rust_and_python(name, money):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(
                _intent(agent_id, f"k-{name}", {**money, "beneficiary": "b"}),
                agent_key,
                30,
            )
    assert "TEMPUS_INVALID_CONTRACT" in str(excinfo.value)
    with pytest.raises(PaymentExecutorError):
        canonical_money(money)


def test_payment_amount_comes_from_the_money_object():
    class Remembering(RecordingTransport):
        def __init__(self):
            super().__init__()
            self.metadata = []

        def disburse(self, secret_key, amount, asset, beneficiary, metadata):
            self.metadata.append(metadata)
            return super().disburse(secret_key, amount, asset, beneficiary, metadata)

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_db, exec_key, agent_key = _world(tmpdir)
        intent = json.loads(
            _intent(
                agent_id,
                "k-nested",
                {"amount": "25.00", "asset": "USD", "beneficiary": "b"},
            )
        )
        intent["input"] = {"amount": "99999.00"}
        permit = gate.request_action(json.dumps(intent), agent_key, 30)
        assert json.loads(permit)["authorization"]["decision"] == "ALLOWED"
        transport = Remembering()
        receipt = json.loads(
            ExecutorRuntime(exec_db, exec_key, gate_id, TENANT).execute_permit(
                permit, PaymentActionAdapter(transport=transport)
            )
        )
        assert receipt["status"] == "SUCCEEDED", receipt
        assert transport.calls == [("25.00", "USD", "b")]
        assert transport.metadata == [{"amount": "99999.00"}]


@pytest.mark.parametrize(
    "name,beneficiary,blocked_by",
    [
        ("space", "vendor-1 ", "policy"),
        ("case", "VENDOR-1", "policy"),
        ("null", None, "contract"),
        ("number", 7, "contract"),
    ],
)
def test_beneficiary_must_match_the_allowlist(name, beneficiary, blocked_by):
    money = {"amount": "1.00", "asset": "USD", "beneficiary": beneficiary}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(
            tmpdir, allowed_beneficiaries=["vendor-1"]
        )
        if blocked_by == "policy":
            result = json.loads(
                gate.request_action(_intent(agent_id, f"k-{name}", money), agent_key, 30)
            )
            assert result["authorization"]["decision"] == "BLOCKED"
            assert "POLICY_MONEY_DENIED" in result["authorization"]["reason_codes"]
        else:
            with pytest.raises(Exception) as excinfo:
                gate.request_action(_intent(agent_id, f"k-{name}", money), agent_key, 30)
            assert "beneficiary" in _refused(excinfo)
    transport = RecordingTransport()
    adapter = PaymentActionAdapter(
        transport=transport, allowed_beneficiaries={"vendor-1"}
    )
    with pytest.raises(PaymentExecutorError):
        adapter.execute_action({"action_type": "payment.charge", "money": money})
    assert transport.calls == []


def test_repeated_object_keys_are_rejected():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_db, exec_key, agent_key = _world(tmpdir)
        money = {"amount": "25.00", "asset": "USD", "beneficiary": "b"}
        for label, money_json in (
            ("amount", '{"amount":"9999.00","amount":"25.00","asset":"USD","beneficiary":"b"}'),
            ("asset", '{"amount":"25.00","asset":"EUR","asset":"USD","beneficiary":"b"}'),
            (
                "money",
                '{"amount":"1.00","asset":"USD","beneficiary":"b"}',
            ),
        ):
            if label == "money":
                raw = _raw_intent(agent_id, f"k-dup-{label}", money_json).replace(
                    '"money":',
                    '"money":{"amount":"9999.00","asset":"EUR","beneficiary":"x"},"money":',
                    1,
                )
            else:
                raw = _raw_intent(agent_id, f"k-dup-{label}", money_json)
            with pytest.raises(Exception) as excinfo:
                gate.request_action(raw, agent_key, 30)
            assert "DUPLICATE_JSON_KEY" in str(excinfo.value), label

        permit = gate.request_action(_intent(agent_id, "k-clean", money), agent_key, 30)
        samples = (
            permit.replace('"amount":"25.00"', '"amount":"9999.00","amount":"25.00"', 1),
            permit.replace('"asset":"USD"', '"asset":"EUR","asset":"USD"', 1),
            permit.replace(
                '"money":',
                '"money":{"amount":"9999.00","asset":"EUR","beneficiary":"x"},"money":',
                1,
            ),
        )
        for raw in samples:
            assert raw != permit
        executor = TempusExecutor(exec_db, exec_key, gate_id, TENANT)
        runtime = ExecutorRuntime(exec_db, exec_key, gate_id, TENANT)
        transport = RecordingTransport()
        adapter = PaymentActionAdapter(transport=transport)
        for raw in samples:
            with pytest.raises(Exception) as excinfo:
                executor.verify_and_consume_permit(raw)
            assert "DUPLICATE_JSON_KEY" in str(excinfo.value)
            with pytest.raises(ExecutorRuntimeError) as excinfo:
                runtime.execute_permit(raw, adapter)
            assert "DUPLICATE_JSON_KEY" in str(excinfo.value)
        assert transport.calls == []
        receipt = json.loads(runtime.execute_permit(permit, adapter))
        assert receipt["status"] == "SUCCEEDED", receipt
        assert transport.calls == [("25.00", "USD", "b")]


def test_runtime_uses_the_top_level_intent():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_db, exec_key, agent_key = _world(tmpdir)
        permit = gate.request_action(
            _intent(
                agent_id,
                "k-verified",
                {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-1"},
            ),
            agent_key,
            30,
        )
        rewritten = _resign_authorization(
            permit,
            os.path.join(tmpdir, "gate.keys.json"),
            {
                "action_type": "payment.charge",
                "money": {
                    "amount": "9999.00",
                    "asset": "USD",
                    "beneficiary": "other-vendor",
                },
            },
        )
        assert json.loads(rewritten)["intent"]["money"]["amount"] == "25.00"
        assert (
            json.loads(rewritten)["authorization"]["intent"]["money"]["amount"] == "9999.00"
        )
        transport = RecordingTransport()
        receipt = json.loads(
            ExecutorRuntime(exec_db, exec_key, gate_id, TENANT).execute_permit(
                rewritten, PaymentActionAdapter(transport=transport)
            )
        )
        assert receipt["status"] == "SUCCEEDED", receipt
        assert transport.calls == [("25.00", "USD", "vendor-1")]
