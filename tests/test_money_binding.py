"""The policy and the executors must read the same money fields.

The policy used to evaluate `money.amount_minor` and `money.currency` when present, while
the payment executor sent `money.amount` and `money.asset`: `{"amount":"99999.00",
"amount_minor":1}` was ALLOWED under a limit of 10000.00 and the transport received
99999.00, and `{"currency":"USD","asset":"EUR"}` passed a USD-only list and paid in EUR.
The gate now refuses an intent whose money fields disagree (before anything is signed).
The executor side (the payment adapter derives amount and asset from the same canonical
reading) is in `contrib/executors/tests/test_money_binding.py`.
"""

import json
import tempfile
import time

import pytest
from test_executor_runtime import _setup_gate_and_agents

TENANT = "tenant-money"


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


@pytest.mark.parametrize("name,money", INCOHERENT, ids=[n for n, _ in INCOHERENT])
def test_gate_refuses_money_fields_that_disagree(name, money):
    money = {**money, "beneficiary": "b"}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        with pytest.raises(Exception) as excinfo:
            gate.request_action(_intent(agent_id, f"k-{name}", money), agent_key, 30)
        assert "TEMPUS_INVALID_CONTRACT" in str(excinfo.value), excinfo.value


def test_policy_still_blocks_what_it_reads_over_the_limit():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, _, agent_id, _, _, agent_key = _world(tmpdir)
        for key, money in (
            ("over-amount", {"amount": "10000.01", "asset": "USD"}),
            ("over-minor", {"amount_minor": 1000001, "currency": "USD"}),
            ("wrong-asset", {"amount": "1.00", "asset": "EUR"}),
        ):
            money["beneficiary"] = "b"
            result = json.loads(
                gate.request_action(_intent(agent_id, key, money), agent_key, 30)
            )
            assert result["authorization"]["decision"] == "BLOCKED", key
            assert "POLICY_MONEY_DENIED" in result["authorization"]["reason_codes"]


def test_a_bundle_signed_by_the_old_gate_with_disagreeing_money_no_longer_verifies():
    """Fixture built with 31e51d7: amount 99999.00 / amount_minor 1 was ALLOWED then."""
    from pathlib import Path

    from test_cli import run_cli

    here = Path(__file__).parent
    key = "8a9aa692f69dff06944ac6e57b57f6d07f24d6db700a7f5865948bd835058423"
    code, out, err = run_cli(
        [
            "verify-bundle",
            "--bundle",
            str(here / "fixtures" / "legacy_money_bypass_bundle.json"),
            "--gate-public-key",
            key,
        ]
    )
    result = json.loads(out)
    assert code == 2 and result["status"] == "INVALID", (out, err)
    assert any("amount_minor" in e and "disagree" in e for e in result["errors"])
