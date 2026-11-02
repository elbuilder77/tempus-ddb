"""N5-3: `money.beneficiary` is a non-empty string for the gate and the payment executor.

If the gate allows what the executor then refuses, the single-use permit is consumed and
the receipt is FAILED (and a null beneficiary was paid as the string "None"). The cases
below run through the real gate and `canonical_money` / `PaymentActionAdapter`, and the
verdicts must be equal. Attacks: forge-5 audit (`n5.py`, `variants.py`).
"""

import json
import tempfile

import pytest
from tempus_executors.payment import (
    PaymentActionAdapter,
    PaymentExecutorError,
)
from test_money_binding import RecordingTransport, _intent, _world

BAD_BENEFICIARIES = [
    ("null", None),
    ("empty", ""),
    ("number", 123),
    ("zero", 0),
    ("true", True),
    ("false", False),
    ("list", ["alice"]),
    ("object", {"name": "alice"}),
]


@pytest.mark.parametrize("name,beneficiary", BAD_BENEFICIARIES)
def test_beneficiary_must_be_a_non_empty_string_in_gate_and_executor(name, beneficiary):
    money = {"amount": "1.00", "asset": "USD", "beneficiary": beneficiary}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(_intent(agent_id, f"k-{name}", money), agent_key, 30)
    assert "TEMPUS_INVALID_CONTRACT" in str(excinfo.value)
    assert "beneficiary" in str(excinfo.value)
    transport = RecordingTransport()
    with pytest.raises(PaymentExecutorError, match="beneficiary"):
        PaymentActionAdapter(transport=transport).execute_action(
            {"action_type": "payment.charge", "money": money}
        )
    assert transport.calls == [], "null must never be paid as the string 'None'"


def test_a_string_beneficiary_still_flows_end_to_end():
    money = {"amount": "1.00", "asset": "USD", "beneficiary": "alice"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        permit = gate.request_action(_intent(agent_id, "k-ok", money), agent_key, 30)
    assert json.loads(permit)["authorization"]["decision"] == "ALLOWED"
    transport = RecordingTransport()
    result = PaymentActionAdapter(transport=transport).execute_action(
        {"action_type": "payment.charge", "money": money}
    )
    assert result.status == "SUCCEEDED"
    assert transport.calls == [("1.00", "USD", "alice")]
