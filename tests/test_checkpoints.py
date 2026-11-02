"""Tests for Monotonic Checkpoints and Append-Only EventStream verification."""

import json
import os
import tempfile
import time

from tempus_ddb import TempusDDB, gen_keys


def _setup_gate(tmpdir, tenant_id="tenant-checkpoint-test"):
    gate_db = os.path.join(tmpdir, "gate.db")
    gate_key = os.path.join(tmpdir, "gate.keys.json")
    agent_key = os.path.join(tmpdir, "agent.keys.json")
    exec_key = os.path.join(tmpdir, "exec.keys.json")

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

    gate.register_agent(
        gate_id, "gate-root", json.dumps({"can_delegate": True, "tenant_id": tenant_id})
    )
    gate.install_allow_all_dev_policy()  # explicit dev opt-in (default is deny-all)
    gate.register_agent(agent_id, "agent-coder", json.dumps({"tenant_id": tenant_id}))
    gate.register_agent(exec_id, "exec-runner", json.dumps({"tenant_id": tenant_id}))

    return gate, gate_id, agent_id, exec_id, gate_key, agent_key, exec_key, tenant_id


def test_event_stream_hash_chain():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_id, gate_key, agent_key, exec_key, tenant_id = (
            _setup_gate(tmpdir)
        )

        # Export event stream
        stream_str = gate.export_event_stream(tenant_id, 1, 100)
        events = json.loads(stream_str)

        assert (
            len(events) >= 3
        )  # gate root, agent-coder, exec-runner registrations + policy
        assert events[0]["sequence_number"] == 1
        assert (
            events[0]["prev_event_hash"]
            == "0000000000000000000000000000000000000000000000000000000000000000"
        )

        # Check contiguous hash links
        for i in range(1, len(events)):
            assert events[i]["sequence_number"] == events[i - 1]["sequence_number"] + 1
            assert events[i]["prev_event_hash"] == events[i - 1]["event_digest"]


def test_create_and_verify_checkpoint():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_id, gate_key, agent_key, exec_key, tenant_id = (
            _setup_gate(tmpdir)
        )

        # Submit an authorized action
        intent = {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "idempotency_key": "chk-action-01",
            "action_type": "github.create_issue",
            "resource": "tempus-protocol/tempus-ddb",
            "requested_at": int(time.time() * 1_000_000),
            "input": {"title": "Checkpoints in 0.5"},
        }
        auth_resp_str = gate.request_action(json.dumps(intent), agent_key, 60)
        auth_resp = json.loads(auth_resp_str)
        auth_id = auth_resp["authorization"]["authorization_id"]

        # Commit outcome
        outcome = {
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": auth_id,
            "action_id": auth_resp["authorization"]["action_id"],
            "executor_id": exec_id,
            "status": "SUCCEEDED",
            "output": {
                "html_url": "https://github.com/tempus-protocol/tempus-ddb/issues/101"
            },
            "completed_at": int(time.time() * 1_000_000),
        }
        gate.commit_outcome(auth_id, json.dumps(outcome), exec_key)

        # Create monotonic checkpoint
        chk_str = gate.create_checkpoint(tenant_id)
        chk = json.loads(chk_str)

        assert chk["schema_version"] == "tempus.checkpoint.v1"
        assert chk["checkpoint_sequence"] == 1
        assert chk["total_events"] >= 5
        assert chk["signature"]

        # Export stream and verify offline
        stream_str = gate.export_event_stream(tenant_id, 1, 1000)
        verify_result_str = gate.verify_checkpoint_stream(chk_str, stream_str)
        verify_result = json.loads(verify_result_str)

        assert verify_result["status"] == "VERIFIED"
        assert verify_result["reason_code"] == "CHECKPOINT_VALID"
        assert verify_result["events_verified"] == chk["total_events"]


def test_adversarial_tamper_event_detection():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_id, gate_key, agent_key, exec_key, tenant_id = (
            _setup_gate(tmpdir)
        )

        chk_str = gate.create_checkpoint(tenant_id)
        stream_str = gate.export_event_stream(tenant_id, 1, 100)
        events = json.loads(stream_str)

        # Tamper payload_hash of an event
        events[1]["payload_hash"] = (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )

        verify_result_str = gate.verify_checkpoint_stream(chk_str, json.dumps(events))
        verify_result = json.loads(verify_result_str)

        assert verify_result["status"] == "INVALID"
        assert verify_result["reason_code"] in {
            "ERR_EVENT_TAMPERED",
            "ERR_STREAM_HASH_MISMATCH",
        }


def test_adversarial_signature_tamper_detection():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        gate, gate_id, agent_id, exec_id, gate_key, agent_key, exec_key, tenant_id = (
            _setup_gate(tmpdir)
        )

        chk_str = gate.create_checkpoint(tenant_id)
        chk = json.loads(chk_str)
        # Invalidate signature
        chk["signature"] = "00" * 64
        stream_str = gate.export_event_stream(tenant_id, 1, 100)

        verify_result_str = gate.verify_checkpoint_stream(json.dumps(chk), stream_str)
        verify_result = json.loads(verify_result_str)

        assert verify_result["status"] == "INVALID"
        assert verify_result["reason_code"] == "ERR_SIGNATURE_INVALID"
