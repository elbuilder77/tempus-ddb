"""The gate and the payment executor read an amount in the decimals the signed policy gives it.

`"500"` is 500 yen when the policy says JPY has no decimals, and `"1.234"` is 1234 fils when it
says KWD has three. If the two disagreed, the gate would allow an amount the executor then
refuses (burning a single-use permit) or the transport would be sent a different sum than the
limit saw. `RecordingTransport`, `_intent` and the tenant are shared with `test_money_binding.py`.
"""

import json
import tempfile

import pytest
from support import _setup_gate_and_agents
from tempus_ddb.executor_runtime import ExecutorRuntime
from tempus_executors.payment import (
    PaymentActionAdapter,
    PaymentExecutorError,
    canonical_money,
)
from test_money_amount_parity import _gate_verdict
from test_money_binding import TENANT, RecordingTransport, _intent

EXPONENTS = {"JPY": 0, "KWD": 3, "XTS": 8}
LIMIT = 1000


def _world(tmpdir, exponents=EXPONENTS):
    gate, gate_id, agent_id, _, exec_db, exec_key, agent_key = _setup_gate_and_agents(
        tmpdir, TENANT
    )
    gate.install_policy(
        json.dumps(
            {
                "schema_version": "tempus.policy-bundle.v1",
                "policy_version": "exponents-v1",
                "tenant_id": TENANT,
                "constraints": {
                    "allowed_action_types": ["payment.charge"],
                    "allowed_resources": ["*"],
                    "allowed_executors": ["*"],
                    "max_ttl_seconds": 60,
                    "max_input_bytes": 1024,
                    "allowed_currencies": ["JPY", "KWD", "USD", "XTS"],
                    "currency_exponents": exponents,
                    "max_money_amount_minor": LIMIT,
                },
            }
        )
    )
    return gate, gate_id, agent_id, exec_db, exec_key, agent_key


def _executor_verdict(money):
    transport = RecordingTransport()
    adapter = PaymentActionAdapter(transport=transport)
    try:
        adapter.execute_action(
            {"action_type": "payment.charge", "money": money},
            currency_exponents=EXPONENTS,
        )
        return True
    except PaymentExecutorError:
        assert transport.calls == []
        return False


BOTH_ACCEPT = [
    ("500", "JPY"),
    ("0500", "JPY"),
    ("1", "KWD"),
    ("1.2", "KWD"),
    ("1.234", "KWD"),
    ("5.5", "USD"),
    ("5.50", "USD"),
    ("5", "USD"),
    ("0.00000001", "XTS"),
    ("18446744073709551615", "JPY"),
    ("18446744073709551.615", "KWD"),
]

BOTH_REFUSE = [
    ("5.5", "JPY"),
    ("5.00", "JPY"),
    ("5.", "JPY"),
    ("18446744073709551616", "JPY"),
    ("1.2345", "KWD"),
    ("18446744073709551.616", "KWD"),
    ("1.234", "USD"),
    ("0.000000001", "XTS"),
    ("0", "JPY"),
    ("0.000", "KWD"),
    ("0.00000000", "XTS"),
    ("٥", "JPY"),
    ("5.٥", "KWD"),
]


@pytest.mark.parametrize(
    "amount,asset,accepted",
    [(a, b, True) for a, b in BOTH_ACCEPT] + [(a, b, False) for a, b in BOTH_REFUSE],
)
def test_gate_and_executor_agree_on_every_amount_under_the_exponents(
    amount, asset, accepted
):
    money = {"amount": amount, "asset": asset, "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        gate_verdict = _gate_verdict(gate, agent_id, agent_key, "k-exp", money)
    assert gate_verdict == accepted, f"gate on {amount!r} {asset}"
    assert _executor_verdict(money) == accepted, f"executor on {amount!r} {asset}"


@pytest.mark.parametrize(
    "money,expected",
    [
        ({"amount_minor": 500, "asset": "JPY"}, ("500", "JPY")),
        ({"amount_minor": 1234, "asset": "KWD"}, ("1.234", "KWD")),
        ({"amount_minor": 1, "asset": "KWD"}, ("0.001", "KWD")),
        ({"amount_minor": 2500, "asset": "USD"}, ("25.00", "USD")),
        ({"amount_minor": 1, "asset": "XTS"}, ("0.00000001", "XTS")),
        ({"amount": "500", "amount_minor": 500, "asset": "JPY"}, ("500", "JPY")),
        ({"amount": "1.2", "amount_minor": 1200, "asset": "KWD"}, ("1.2", "KWD")),
    ],
)
def test_canonical_money_spells_an_amount_in_the_currency(money, expected):
    assert canonical_money(money, EXPONENTS) == expected


@pytest.mark.parametrize(
    "money",
    [
        {"amount": "500", "amount_minor": 50000, "asset": "JPY"},
        {"amount": "1.234", "amount_minor": 123, "asset": "KWD"},
    ],
)
def test_two_spellings_must_agree_under_the_exponents(money):
    with pytest.raises(PaymentExecutorError, match="disagree"):
        canonical_money(money, EXPONENTS)


@pytest.mark.parametrize("exponent", [9, -1, "2", True, 1.5, None])
def test_an_unreadable_exponent_is_refused(exponent):
    with pytest.raises(PaymentExecutorError, match="currency_exponents.JPY"):
        canonical_money({"amount": "5", "asset": "JPY"}, {"JPY": exponent})


def test_without_exponents_every_currency_has_two_decimals():
    assert canonical_money({"amount_minor": 50000, "asset": "JPY"}) == ("500.00", "JPY")
    with pytest.raises(PaymentExecutorError, match="at most two"):
        canonical_money({"amount": "1.234", "asset": "KWD"})


@pytest.mark.parametrize(
    "money,sent",
    [
        ({"amount": "500", "asset": "JPY"}, ("500", "JPY")),
        ({"amount_minor": 1000, "asset": "JPY"}, ("1000", "JPY")),
        ({"amount": "0.999", "asset": "KWD"}, ("0.999", "KWD")),
        ({"amount_minor": 1000, "asset": "KWD"}, ("1.000", "KWD")),
        ({"amount": "9.99", "asset": "USD"}, ("9.99", "USD")),
    ],
)
def test_the_runtime_passes_the_signed_decimals_to_the_executor(money, sent):
    money = {**money, "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_db, exec_key, agent_key = _world(tmpdir)
        permit = gate.request_action(_intent(agent_id, "k-run", money), agent_key, 30)
        assert json.loads(permit)["authorization"]["decision"] == "ALLOWED", permit
        transport = RecordingTransport()
        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=TENANT,
        )
        result = json.loads(
            runtime.execute_permit(permit, PaymentActionAdapter(transport=transport))
        )
    assert result["status"] == "SUCCEEDED", result
    assert transport.calls == [(*sent, "b")]


@pytest.mark.parametrize(
    "money",
    [
        {"amount": "1001", "asset": "JPY"},
        {"amount": "1.001", "asset": "KWD"},
        {"amount": "10.01", "asset": "USD"},
        {"amount_minor": 1001, "asset": "JPY"},
    ],
)
def test_the_limit_is_in_the_minor_units_of_the_currency(money):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        permit = json.loads(
            gate.request_action(
                _intent(agent_id, "k-limit", {**money, "beneficiary": "b"}), agent_key, 30
            )
        )
    assert permit["authorization"]["reason_codes"] == ["POLICY_MONEY_DENIED"]


def test_stating_two_decimals_for_yen_keeps_the_old_reading_on_both_sides():
    money = {"amount": "500", "asset": "JPY", "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir, exponents={"JPY": 2, "KWD": 3, "XTS": 8})
        permit = json.loads(
            gate.request_action(_intent(agent_id, "k-old", money), agent_key, 30)
        )
    # 50 000 minor units against a limit of 1000.
    assert permit["authorization"]["reason_codes"] == ["POLICY_MONEY_DENIED"]
    assert canonical_money({"amount_minor": 50000, "asset": "JPY"}, {"JPY": 2}) == (
        "500.00",
        "JPY",
    )
