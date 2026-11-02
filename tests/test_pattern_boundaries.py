"""Policy patterns match on component boundaries.

A `*` is a whole component split on `/` and `.`. A `*` that is not its own
component matches nothing. The HTTP executor allowlist applies the same rule; see
`contrib/executors/tests/test_pattern_boundaries.py`.
"""

import json
import time

import pytest
from tempus_ddb import TempusDDB, gen_keys


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


def _decision(gate, agent_id, agent_keys, patterns, resource, key):
    gate.install_policy(
        json.dumps(
            {
                "schema_version": "tempus.policy-bundle.v1",
                "policy_version": f"patterns-{key}",
                "tenant_id": "acme",
                "constraints": {
                    "allowed_action_types": ["probe"],
                    "allowed_resources": patterns,
                    "allowed_executors": ["*"],
                    "max_ttl_seconds": 60,
                    "max_input_bytes": 1024,
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
            "action_type": "probe",
            "resource": resource,
            "requested_at": time.time_ns() // 1_000,
            "input": {},
        }
    )
    result = json.loads(gate.request_action(intent, agent_keys, 60))
    return result["authorization"]["decision"], result["authorization"]["reason_codes"]


@pytest.mark.parametrize(
    ("patterns", "resource", "allowed"),
    [
        pytest.param(["host*"], "host.evil.com", False, id="host-star-other"),
        pytest.param(["host*"], "host", False, id="host-star-exact"),
        pytest.param(["*.example.com"], "a.example.com", True, id="wildcard-subdomain"),
        pytest.param(["*.example.com"], "a.b.example.com", True, id="wildcard-nested"),
        pytest.param(["*.example.com"], "evilexample.com", False, id="wildcard-no-dot"),
        pytest.param(
            ["*.example.com"], "example.com.evil.com", False, id="wildcard-extra-labels"
        ),
        pytest.param(["*.example.com"], "example.com", False, id="wildcard-not-apex"),
        pytest.param(["/api*"], "/apifoo", False, id="glued-path-star"),
        pytest.param(["/api*"], "/api/foo", False, id="glued-path-star-child"),
        pytest.param(["/api/*"], "/apifoo", False, id="segment-star-not-prefix"),
        pytest.param(["/api/*"], "/api/foo", True, id="segment-star-one"),
        pytest.param(["/api/*"], "/api/foo/bar", True, id="segment-star-nested"),
        pytest.param(
            ["https://api.example.com*"],
            "https://api.example.com.evil.com/x",
            False,
            id="url-glued-star-other",
        ),
        pytest.param(
            ["https://api.example.com*"],
            "https://api.example.com/x",
            False,
            id="url-glued-star-same-host",
        ),
        pytest.param(
            ["https://api.example.com/*"],
            "https://api.example.com/v1/users",
            True,
            id="url-path-star",
        ),
        pytest.param(
            ["https://api.example.com/*"],
            "https://api.example.com.evil.com/v1",
            False,
            id="url-path-star-other",
        ),
        pytest.param(
            ["https://*.example.com/*"],
            "https://a.example.com/v1",
            True,
            id="url-host-wildcard",
        ),
        pytest.param(
            ["https://*.example.com/*"],
            "https://example.com.evil.com/v1",
            False,
            id="url-host-wildcard-other",
        ),
        pytest.param(["acme/*"], "acme/repo", True, id="owner-star"),
        pytest.param(["vendor-api/*"], "vendor-api/credits", True, id="vendor-api-star"),
        pytest.param(["vendor-*"], "vendor-42", False, id="glued-beneficiary-star"),
        pytest.param(
            ["*"], "https://api.example.com.evil.com/x", True, id="bare-star"
        ),
    ],
)
def test_gate_matches_patterns_on_component_boundaries(
    tmp_path, patterns, resource, allowed
):
    gate, agent_id, agent_keys = _gate(tmp_path)
    decision, reasons = _decision(
        gate, agent_id, agent_keys, patterns, resource, f"k-{abs(hash(resource))}"
    )
    if allowed:
        assert decision == "ALLOWED", reasons
    else:
        assert decision == "BLOCKED", reasons
        assert "POLICY_RESOURCE_DENIED" in reasons
