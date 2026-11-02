"""The policy and the payment executor must read the same money fields.

The policy used to evaluate `money.amount_minor` and `money.currency` when present, while
the payment executor sent `money.amount` and `money.asset`: `{"amount":"99999.00",
"amount_minor":1}` was ALLOWED under a limit of 10000.00 and the transport received
99999.00, and `{"currency":"USD","asset":"EUR"}` passed a USD-only list and paid in EUR.
The gate now refuses an intent whose money fields disagree (before anything is signed;
see `tests/test_money_binding.py` in the repository root), and the payment executor
derives amount and asset from the same canonical reading.

`RecordingTransport`, `_world`, `_intent` and the money tables are shared with
`test_money_amount_parity.py`, `test_money_beneficiary_type.py` and `test_money_checks.py`.
"""

import json
import tempfile
import time

import pytest
from support import _setup_gate_and_agents
from tempus_ddb.executor_runtime import ExecutorRuntime
from tempus_executors.payment import PaymentActionAdapter, PaymentExecutorError

TENANT = "tenant-money"


class RecordingTransport:
    def __init__(self):
        self.calls = []

    def disburse(self, secret_key, amount, asset, beneficiary, metadata):
        self.calls.append((amount, asset, beneficiary))
        return {"status": "SETTLED"}


def _world(tmpdir):
    gate, gate_id, agent_id, exec_id, exec_db, exec_key, agent_key = (
        _setup_gate_and_agents(tmpdir, TENANT)
    )
    gate.install_policy(
        json.dumps(
            {
                "schema_version": "tempus.policy-bundle.v1",
                "policy_version": "money-v1",
                "tenant_id": TENANT,
                "constraints": {
                    "allowed_action_types": ["payment.charge"],
                    "allowed_resources": ["*"],
                    "allowed_executors": ["*"],
                    "max_ttl_seconds": 60,
                    "max_input_bytes": 1024,
                    "allowed_currencies": ["USD"],
                    "max_money_amount_minor": 1000000,
                },
            }
        )
    )
    return gate, gate_id, agent_id, exec_db, exec_key, agent_key


def _intent(agent_id, key, money):
    return json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": TENANT,
            "agent_id": agent_id,
            "idempotency_key": key,
            "action_type": "payment.charge",
            "resource": "treasury/main",
            "requested_at": int(time.time() * 1_000_000),
            "input": {},
            "money": money,
        }
    )


INCOHERENT = [
    # the policy read amount_minor=1, the executor sent 99999.00
    ("amount-vs-minor", {"amount": "99999.00", "amount_minor": 1, "asset": "USD"}),
    (
        "amount-vs-minor-over",
        {"amount": "1.00", "amount_minor": 100000000, "asset": "USD"},
    ),
    # the policy read currency=USD, the executor sent asset=EUR
    ("currency-vs-asset", {"amount": "1.00", "currency": "USD", "asset": "EUR"}),
    ("case-differs", {"amount": "1.00", "currency": "USD", "asset": "usd"}),
    # fields the policy skipped because of their type, but the executor stringified
    ("minor-as-string", {"amount": "99999.00", "amount_minor": "1", "asset": "USD"}),
    ("minor-negative", {"amount": "99999.00", "amount_minor": -1, "asset": "USD"}),
    ("currency-not-string", {"amount": "1.00", "currency": 1, "asset": "USD"}),
    ("asset-not-string", {"amount": "1.00", "currency": "USD", "asset": ["EUR"]}),
    ("amount-not-string", {"amount": 99999, "amount_minor": 1, "asset": "USD"}),
]


COHERENT = [
    ("amount-asset", {"amount": "25.00", "asset": "USD"}, ("25.00", "USD")),
    (
        "one-decimal",
        {"amount": "25.5", "amount_minor": 2550, "currency": "USD"},
        ("25.5", "USD"),
    ),
    ("minor-currency", {"amount_minor": 2500, "currency": "USD"}, ("25.00", "USD")),
    (
        "both-same",
        {"amount": "25.00", "amount_minor": 2500, "currency": "USD", "asset": "USD"},
        ("25.00", "USD"),
    ),
]


@pytest.mark.parametrize("name,money,sent", COHERENT, ids=[c[0] for c in COHERENT])
def test_coherent_money_is_allowed_and_the_executor_sends_what_the_policy_read(
    name, money, sent
):
    money = {**money, "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_db, exec_key, agent_key = _world(tmpdir)
        permit = gate.request_action(
            _intent(agent_id, f"k-{name}", money), agent_key, 30
        )
        assert json.loads(permit)["authorization"]["decision"] == "ALLOWED"
        transport = RecordingTransport()
        runtime = ExecutorRuntime(
            executor_db=exec_db,
            executor_keyfile=exec_key,
            trusted_gate_id=gate_id,
            trusted_tenant_id=TENANT,
        )
        adapter = PaymentActionAdapter(transport=transport)
        receipt = json.loads(runtime.execute_permit(permit, adapter))
        assert receipt["status"] == "SUCCEEDED", receipt
        assert transport.calls == [(sent[0], sent[1], "b")]


@pytest.mark.parametrize("name,money", INCOHERENT, ids=[n for n, _ in INCOHERENT])
def test_payment_adapter_refuses_disagreeing_fields_on_its_own(name, money):
    """Defence in depth for an adapter used outside the gate's re-evaluation."""
    transport = RecordingTransport()
    adapter = PaymentActionAdapter(transport=transport)
    with pytest.raises(PaymentExecutorError):
        adapter.execute_action(
            {"action_type": "payment.charge", "money": {**money, "beneficiary": "b"}}
        )
    assert transport.calls == []
