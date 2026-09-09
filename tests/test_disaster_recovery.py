"""Executable boundaries of the documented backup/restore procedure."""

import json
import sqlite3
import time
from pathlib import Path

import pytest
from tempus_ddb import TempusDDB, TempusExecutor, gen_keys
from tempus_ddb.executor_runtime import ExecutionResult, ExecutorRuntime


def backup(source, target):
    with sqlite3.connect(Path(source).resolve().as_uri() + "?mode=ro", uri=True) as src:
        with sqlite3.connect(target) as dst:
            src.backup(dst)


@pytest.fixture
def recovery(tmp_path):
    keys = {}
    for role in ("gate", "agent", "executor"):
        file = tmp_path / f"{role}.keys.json"
        gen_keys(str(file))
        keys[role] = json.loads(file.read_text())["public_key"]
    gate = TempusDDB(str(tmp_path / "gate.db"), str(tmp_path / "gate.keys.json"))
    for role in keys:
        gate.register_agent(
            keys[role],
            role,
            json.dumps({"tenant_id": "acme", "can_delegate": role == "gate"}),
        )
    return tmp_path, gate, keys


def permit_for(root, gate, keys):
    return gate.request_action(
        json.dumps(
            {
                "schema_version": "tempus.action-intent.v1",
                "tenant_id": "acme",
                "agent_id": keys["agent"],
                "idempotency_key": "restore-001",
                "action_type": "local.write",
                "resource": "local/example",
                "requested_at": time.time_ns() // 1000,
                "input": {},
            }
        ),
        str(root / "agent.keys.json"),
        300,
    )


def test_external_files_can_verify_while_restored_database_is_stale(recovery):
    root, gate, keys = recovery
    backup(root / "gate.db", root / "old-gate.db")
    permit_for(root, gate, keys)
    checkpoint = gate.create_checkpoint("acme")
    metadata = json.loads(checkpoint)
    archived_events = gate.export_event_stream(
        "acme", metadata["first_sequence"], metadata["total_events"]
    )
    restored = TempusDDB(str(root / "old-gate.db"), str(root / "gate.keys.json"))
    # --db does not bind a file-to-file verification to that database.
    assert (
        json.loads(restored.verify_checkpoint_stream(checkpoint, archived_events))[
            "status"
        ]
        == "VERIFIED"
    )
    restored_events = restored.export_event_stream(
        "acme", metadata["first_sequence"], metadata["total_events"]
    )
    result = json.loads(restored.verify_checkpoint_stream(checkpoint, restored_events))
    assert result["status"] == "INVALID"
    assert result["reason_code"] == "ERR_ROLLBACK_DETECTED"
    backup(root / "gate.db", root / "current-gate.db")
    current = TempusDDB(str(root / "current-gate.db"), str(root / "gate.keys.json"))
    fresh_export = current.export_event_stream(
        "acme", metadata["first_sequence"], metadata["total_events"]
    )
    assert (
        json.loads(current.verify_checkpoint_stream(checkpoint, fresh_export))["status"]
        == "VERIFIED"
    )


def test_executor_backup_preserves_consumption_and_missing_gate_receipt_can_be_committed(
    recovery,
):
    root, gate, keys = recovery
    permit = permit_for(root, gate, keys)
    authorization = json.loads(permit)["authorization"]
    runtime = ExecutorRuntime(
        str(root / "executor.db"),
        str(root / "executor.keys.json"),
        keys["gate"],
        "acme",
    )
    backup(root / "executor.db", root / "stale-executor.db")

    class LocalEffect:
        supported_actions = {"local.write"}
        calls = 0

        def execute_action(self, intent):
            self.calls += 1
            return ExecutionResult("SUCCEEDED", {"written": True})

    adapter = LocalEffect()
    runtime.execute_permit(permit, adapter)
    backup(root / "executor.db", root / "restored-executor.db")
    restored = ExecutorRuntime(
        str(root / "restored-executor.db"),
        str(root / "executor.keys.json"),
        keys["gate"],
        "acme",
    )
    state = json.loads(
        restored.raw_executor.get_execution_state(authorization["authorization_id"])
    )
    assert state["status"] == "SUCCEEDED"
    with pytest.raises(PermissionError, match="already consumed"):
        restored.execute_permit(permit, adapter)
    assert adapter.calls == 1
    # Reconcile the already signed outcome, never replay the external action.
    gate.commit_outcome_signed(
        authorization["authorization_id"], json.dumps(state["outcome"])
    )
    assert (
        json.loads(gate.verify_trace(authorization["action_id"]))["status"]
        == "VERIFIED"
    )
    checkpoint = gate.create_checkpoint("acme")
    assert (
        json.loads(
            gate.verify_checkpoint_stream(
                checkpoint, gate.export_event_stream("acme", 1, 1000)
            )
        )["status"]
        == "VERIFIED"
    )
    stale = TempusExecutor(
        str(root / "stale-executor.db"),
        str(root / "executor.keys.json"),
        keys["gate"],
        "acme",
    )
    with pytest.raises(Exception, match="Consumption not found"):
        stale.get_execution_state(authorization["authorization_id"])
    # Gate verification above cannot establish freshness of the executor DB.


def test_restored_started_consumption_becomes_unknown_and_stays_consumed(recovery):
    root, gate, keys = recovery
    permit = permit_for(root, gate, keys)
    executor = TempusExecutor(
        str(root / "executor.db"),
        str(root / "executor.keys.json"),
        keys["gate"],
        "acme",
    )
    executor.verify_and_consume_permit(permit)
    backup(root / "executor.db", root / "restored-executor.db")
    restored = TempusExecutor(
        str(root / "restored-executor.db"),
        str(root / "executor.keys.json"),
        keys["gate"],
        "acme",
    )
    observations = json.loads(restored.recover_incomplete(0))
    assert len(observations) == 1 and observations[0]["status"] == "UNKNOWN"
    assert observations[0]["executor_signature"]
    with pytest.raises(PermissionError, match="already consumed"):
        restored.verify_and_consume_permit(permit)
