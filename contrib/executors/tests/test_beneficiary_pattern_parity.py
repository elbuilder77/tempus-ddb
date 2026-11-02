"""The payment allowlist and the policy use one wildcard rule.

A pattern that is not a whole-component wildcard authorizes nobody on either side.
"""

import json
import time

import pytest
from tempus_ddb import TempusDDB, gen_keys
from tempus_executors.payment import PaymentActionAdapter, PaymentExecutorError


class _Recorder:
    def __init__(self):
        self.calls = []

    def disburse(self, secret_key, amount, asset, beneficiary, metadata):
        self.calls.append(beneficiary)
        return {"status": "SETTLED", "beneficiary": beneficiary}


def _gate(tmp_path):
    for name in ("gate", "agent"):
        gen_keys(str(tmp_path / f"{name}.keys.json"))
    ids = {
        name: json.loads((tmp_path / f"{name}.keys.json").read_text())["public_key"]
        for name in ("gate", "agent")
    }
    gate = TempusDDB(str(tmp_path / "tempus.db"), str(tmp_path / "gate.keys.json"))
    gate.register_agent(ids["gate"], "gate", '{"can_delegate":true}')
    gate.register_agent(ids["agent"], "agent", "{}")
    return gate, ids["agent"], str(tmp_path / "agent.keys.json")


def _policy_allows(gate, agent_id, agent_keys, patterns, beneficiary, key):
    gate.install_policy(
        json.dumps(
            {
                "schema_version": "tempus.policy-bundle.v1",
                "policy_version": f"beneficiaries-{key}",
                "tenant_id": "acme",
                "constraints": {
                    "allowed_action_types": ["payment.charge"],
                    "allowed_resources": ["*"],
                    "allowed_executors": ["*"],
                    "max_ttl_seconds": 60,
                    "max_input_bytes": 1024,
                    "allowed_currencies": ["USD"],
                    "max_money_amount_minor": 100000,
                    "allowed_beneficiaries": patterns,
                },
            }
        )
    )
    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "acme",
            "agent_id": agent_id,
            "idempotency_key": key,
            "action_type": "payment.charge",
            "resource": "treasury/main",
            "requested_at": time.time_ns() // 1_000,
            "input": {},
            "money": {"amount": "1.00", "asset": "USD", "beneficiary": beneficiary},
        }
    )
    authorization = json.loads(gate.request_action(intent, agent_keys, 60))["authorization"]
    return authorization["decision"] == "ALLOWED", authorization["reason_codes"]


def _allowlist_allows(patterns, beneficiary):
    recorder = _Recorder()
    adapter = PaymentActionAdapter(
        transport=recorder, allowed_beneficiaries=set(patterns)
    )
    try:
        result = adapter.execute_action(
            {
                "action_type": "payment.charge",
                "money": {"amount": "1.00", "asset": "USD", "beneficiary": beneficiary},
            }
        )
    except PaymentExecutorError:
        assert recorder.calls == []
        return False
    assert result.status == "SUCCEEDED"
    assert recorder.calls == [beneficiary]
    return True


@pytest.mark.parametrize(
    ("patterns", "beneficiary", "allowed"),
    [
        pytest.param(["ada"], "ada", True, id="exact"),
        pytest.param(["ada"], "ada-2", False, id="exact-neighbor"),
        pytest.param(["Ada"], "ada", False, id="case"),
        pytest.param(["*"], "vendor-42", True, id="bare-star"),
        pytest.param(["vendor/*"], "vendor/42", True, id="segment"),
        pytest.param(["vendor/*"], "vendor/42/extra", True, id="segment-nested"),
        pytest.param(["vendor/*"], "vendor-42", False, id="segment-not-prefix"),
        pytest.param(["vendor.*"], "vendor.42", True, id="dot-component"),
        pytest.param(["*.vendor"], "a.vendor", True, id="leading-label"),
        pytest.param(["*.vendor"], "vendor", False, id="leading-label-not-apex"),
        pytest.param(["vendor-*"], "vendor-42", False, id="glued-star"),
        pytest.param(["vendor-*"], "vendor", False, id="glued-star-exact-name"),
        pytest.param(["vendor-*"], "other", False, id="glued-star-other"),
        pytest.param(["vendor-*", "ada"], "ada", True, id="list-keeps-exact"),
        pytest.param(["vendor-*", "ada"], "vendor-42", False, id="list-glued-still-closed"),
    ],
)
def test_policy_and_payment_allowlist_agree(tmp_path, patterns, beneficiary, allowed):
    gate, agent_id, agent_keys = _gate(tmp_path)
    policy_allows, reasons = _policy_allows(
        gate, agent_id, agent_keys, patterns, beneficiary, "parity"
    )
    assert _allowlist_allows(patterns, beneficiary) is allowed
    assert policy_allows is allowed, reasons
    if not allowed:
        assert "POLICY_MONEY_DENIED" in reasons
