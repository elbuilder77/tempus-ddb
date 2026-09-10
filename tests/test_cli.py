"""
CLI integration tests using subprocess.

Run with: pytest tests/test_cli.py -v  (after `pip install -e .`)
"""

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


def run_cli(args, cwd=None):
    """Run the tempus CLI and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, "-m", "tempus_ddb.cli"] + args
    env = os.environ.copy()
    source_path = str(Path(__file__).parent.parent / "python")
    if env.get("PYTHONPATH"):
        env["PYTHONPATH"] = env["PYTHONPATH"] + os.pathsep + source_path
    else:
        env["PYTHONPATH"] = source_path
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, env=env, encoding="utf-8"
    )
    return result.returncode, result.stdout, result.stderr


def test_cli_version():
    code, out, _ = run_cli(["--version"])
    assert code == 0
    assert out.strip().startswith("tempus 0.5.")


def test_cli_help():
    code, out, _ = run_cli(["--help"])
    assert code == 0
    assert "init" in out and "record" in out and "status" in out and "verify" in out
    assert "request-action" in out and "commit-outcome" in out and "verify-trace" in out


def test_cli_init_creates_files(tmp_path):
    code, out, _ = run_cli(["init"], cwd=tmp_path)
    assert code == 0
    assert (tmp_path / "keys.json").exists()
    assert (tmp_path / "tempus.db").exists()
    assert "ready" in out.lower()


def test_cli_keygen_is_machine_readable_and_refuses_overwrite(tmp_path):
    code, out, err = run_cli(["keygen", "--output", "agent.keys.json"], cwd=tmp_path)
    assert code == 0, out + err
    payload = json.loads(out)
    assert payload["schema_version"] == "tempus.identity-key.v1"
    assert len(payload["public_key"]) == 64
    code, out, err = run_cli(["keygen", "--output", "agent.keys.json"], cwd=tmp_path)
    assert code != 0
    assert "overwrite" in (out + err).lower()


def test_cli_status_before_and_after_init(tmp_path):
    code, out, _ = run_cli(["status"], cwd=tmp_path)
    assert code == 0
    assert "not found" in out.lower() or "Keys" in out

    run_cli(["init"], cwd=tmp_path)
    code2, out2, _ = run_cli(["status"], cwd=tmp_path)
    assert code2 == 0
    assert "Keys file" in out2 and "Database" in out2


def test_cli_record_genesis_and_verify(tmp_path):
    run_cli(["init"], cwd=tmp_path)
    payload = json.dumps({"action": "test_cli", "value": 123})
    rules = json.dumps({"approved": True})

    code, out, _ = run_cli(
        ["record", "--payload", payload, "--rules", rules, "--genesis"], cwd=tmp_path
    )
    assert code == 0
    assert "recorded successfully" in out.lower() or "success" in out.lower()

    code_v, out_v, _ = run_cli(["verify"], cwd=tmp_path)
    assert code_v == 0
    assert "valid" in out_v.lower() or "successful" in out_v.lower()


def test_cli_record_requires_payload_and_rules(tmp_path):
    run_cli(["init"], cwd=tmp_path)
    code, out, err = run_cli(["record", "--payload", "{}", "--rules", ""], cwd=tmp_path)
    combined = (out + err).lower()
    assert code != 0
    assert "rules" in combined or "required" in combined


def test_cli_record_invalid_json(tmp_path):
    run_cli(["init"], cwd=tmp_path)
    code, out, err = run_cli(
        ["record", "--payload", "not-json", "--rules", "{}", "--genesis"], cwd=tmp_path
    )
    combined = (out + err).lower()
    assert code != 0
    assert "json" in combined


def test_cli_record_without_keys_fails(tmp_path):
    code, out, err = run_cli(
        ["record", "--payload", "{}", "--rules", "{}", "--genesis"], cwd=tmp_path
    )
    combined = (out + err).lower()
    assert code != 0
    assert "keys" in combined or "init" in combined


def test_cli_status_after_record(tmp_path):
    run_cli(["init"], cwd=tmp_path)
    run_cli(
        ["record", "--payload", '{"a":1}', "--rules", "{}", "--genesis"], cwd=tmp_path
    )
    code, out, _ = run_cli(["status"], cwd=tmp_path)
    assert code == 0
    assert "Chain integrity" in out or "VALID" in out


def test_cli_record_multiple_and_verify(tmp_path):
    code_init, out_init, err_init = run_cli(["init"], cwd=tmp_path)
    assert code_init == 0, out_init + err_init

    code_1, out_1, err_1 = run_cli(
        ["record", "--payload", '{"step":1}', "--rules", "{}", "--genesis"],
        cwd=tmp_path,
    )
    assert code_1 == 0, out_1 + err_1

    code_2, out_2, err_2 = run_cli(
        ["record", "--payload", '{"step":2}', "--rules", "{}"], cwd=tmp_path
    )
    assert code_2 == 0, out_2 + err_2

    code, out, err = run_cli(["verify"], cwd=tmp_path)
    assert code == 0, out + err
    assert "total_records" in out or "valid" in out.lower()


def test_cli_record_with_file_inputs(tmp_path):
    run_cli(["init"], cwd=tmp_path)
    pfile = tmp_path / "p.json"
    rfile = tmp_path / "r.json"
    pfile.write_text(json.dumps({"from": "file"}))
    rfile.write_text(json.dumps({"ok": True}))

    code, out, _ = run_cli(
        ["record", "--payload", str(pfile), "--rules", str(rfile), "--genesis"],
        cwd=tmp_path,
    )
    assert code == 0
    assert "recorded" in out.lower()


def test_cli_verify_reports_error_on_corrupt(tmp_path):
    run_cli(["init"], cwd=tmp_path)
    run_cli(["record", "--payload", "{}", "--rules", "{}", "--genesis"], cwd=tmp_path)
    db = tmp_path / "tempus.db"
    conn = sqlite3.connect(db)
    try:
        conn.execute("UPDATE decisions SET payload = ?", ('{"tampered":true}',))
        conn.commit()
    finally:
        conn.close()

    code, out, err = run_cli(["verify"], cwd=tmp_path)
    combined = (out + err).lower()
    assert (
        code != 0
        or "invalid" in combined
        or "error" in combined
        or "mismatch" in combined
    )


def test_cli_status_shows_helpful_next_steps(tmp_path):
    code, out, _ = run_cli(["status"], cwd=tmp_path)
    assert code == 0
    assert "Next steps" in out or "init" in out.lower()


def test_cli_b2a_authorization_execution_flow(tmp_path):
    from tempus_ddb import gen_keys

    code, out, err = run_cli(["init"], cwd=tmp_path)
    assert code == 0, out + err
    agent_keyfile = tmp_path / "agent.keys.json"
    executor_keyfile = tmp_path / "executor.keys.json"
    gen_keys(str(agent_keyfile))
    gen_keys(str(executor_keyfile))
    agent_id = json.loads(agent_keyfile.read_text())["public_key"]

    for alias, keyfile in [
        ("buyer-agent", agent_keyfile),
        ("purchase-executor", executor_keyfile),
    ]:
        code, out, err = run_cli(
            ["register-agent", "--alias", alias, "--agent-keyfile", str(keyfile)],
            cwd=tmp_path,
        )
        assert code == 0, out + err

    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "cli-test",
            "agent_id": agent_id,
            "idempotency_key": "cli-action-001",
            "action_type": "send_email",
            "resource": "mailbox/outbox",
            "requested_at": time.time_ns() // 1_000,
            "input": {"to": "ops@example.com"},
        }
    )
    code, out, err = run_cli(
        [
            "request-action",
            "--intent",
            intent,
            "--agent-keyfile",
            str(agent_keyfile),
        ],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    authorization = json.loads(out)
    assert authorization["authorization"]["decision"] == "ALLOWED"
    authorization_id = authorization["authorization"]["authorization_id"]
    action_id = authorization["authorization"]["action_id"]

    outcome = json.dumps(
        {
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": authorization_id,
            "action_id": action_id,
            "status": "SUCCEEDED",
            "external_reference": "mail-42",
        }
    )
    code, out, err = run_cli(
        [
            "commit-outcome",
            "--authorization-id",
            authorization_id,
            "--outcome",
            outcome,
            "--executor-keyfile",
            str(executor_keyfile),
        ],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    assert json.loads(out)["receipt"]["status"] == "SUCCEEDED"

    code, out, err = run_cli(["verify-trace", "--action-id", action_id], cwd=tmp_path)
    assert code == 0, out + err
    verification = json.loads(out)
    assert verification["status"] == "VERIFIED"
    assert verification["phase"] == "COMPLETED"


def test_cli_phase3_doctor_conformance_policy_and_identity_lifecycle(tmp_path):
    code, out, err = run_cli(["init"], cwd=tmp_path)
    assert code == 0, out + err

    code, out, err = run_cli(["doctor", "--json"], cwd=tmp_path)
    assert code == 0, out + err
    assert json.loads(out)["status"] == "PASS"

    code, out, err = run_cli(["conformance", "--signer"], cwd=tmp_path)
    assert code == 0, out + err
    conformance = json.loads(out)
    assert conformance["status"] == "PASS"
    assert conformance["signer"]["checks"]["exact_bytes"] == "PASS"

    code, out, err = run_cli(["list-policies"], cwd=tmp_path)
    assert code == 0, out + err
    policies = json.loads(out)
    assert policies[0]["schema_version"] == "tempus.policy-bundle.v1"
    assert policies[0]["status"] == "ACTIVE"

    for filename in ["agent-v1.keys.json", "agent-v2.keys.json"]:
        code, out, err = run_cli(["keygen", "--output", filename], cwd=tmp_path)
        assert code == 0, out + err
    agent_v1 = json.loads((tmp_path / "agent-v1.keys.json").read_text())["public_key"]
    agent_v2 = json.loads((tmp_path / "agent-v2.keys.json").read_text())["public_key"]
    code, out, err = run_cli(
        [
            "register-agent",
            "--alias",
            "phase3-agent",
            "--agent-keyfile",
            "agent-v1.keys.json",
            "--metadata",
            '{"tenant_id":"acme"}',
        ],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    code, out, err = run_cli(
        [
            "rotate-agent",
            "--current-public-key",
            agent_v1,
            "--new-keyfile",
            "agent-v2.keys.json",
        ],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    assert json.loads(out)["event"]["event_type"] == "ROTATE"
    code, out, err = run_cli(
        ["revoke-agent", "--public-key", agent_v2, "--reason", "test revocation"],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    assert json.loads(out)["event"]["event_type"] == "REVOKE"
    code, out, err = run_cli(["identity-events"], cwd=tmp_path)
    assert code == 0, out + err
    assert len(json.loads(out)) == 2


def test_cli_checkpoint_workflow(tmp_path):
    # 1. Initialize
    code, out, err = run_cli(["init"], cwd=tmp_path)
    assert code == 0, out + err

    # 2. Keygen for agent and executor
    run_cli(["keygen", "--output", "agent.keys.json"], cwd=tmp_path)
    run_cli(["keygen", "--output", "exec.keys.json"], cwd=tmp_path)

    agent_pubkey = json.loads((tmp_path / "agent.keys.json").read_text())["public_key"]
    exec_pubkey = json.loads((tmp_path / "exec.keys.json").read_text())["public_key"]
    run_cli(
        ["register-agent", "--alias", "agent1", "--public-key", agent_pubkey],
        cwd=tmp_path,
    )
    run_cli(
        ["register-agent", "--alias", "exec1", "--public-key", exec_pubkey],
        cwd=tmp_path,
    )

    # 3. Request action
    intent_path = tmp_path / "intent.json"
    intent_path.write_text(
        json.dumps(
            {
                "schema_version": "tempus.action-intent.v1",
                "tenant_id": "acme",
                "agent_id": agent_pubkey,
                "idempotency_key": "cli-chk-001",
                "action_type": "read",
                "resource": "orders",
                "requested_at": time.time_ns() // 1_000,
                "input": {"rows": 42},
            }
        )
    )

    code, out, err = run_cli(
        [
            "request-action",
            "--intent",
            str(intent_path),
            "--agent-keyfile",
            "agent.keys.json",
        ],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    permit = json.loads(out)
    auth_id = permit["authorization"]["authorization_id"]
    action_id = permit["authorization"]["action_id"]

    # 4. Commit outcome
    outcome_path = tmp_path / "outcome.json"
    outcome_path.write_text(
        json.dumps(
            {
                "schema_version": "tempus.action-outcome.v1",
                "authorization_id": auth_id,
                "action_id": action_id,
                "status": "SUCCEEDED",
                "external_reference": "ref-42",
            }
        )
    )

    code, out, err = run_cli(
        [
            "commit-outcome",
            "--authorization-id",
            auth_id,
            "--outcome",
            str(outcome_path),
            "--executor-keyfile",
            "exec.keys.json",
        ],
        cwd=tmp_path,
    )
    assert code == 0, out + err

    # 5. Create Checkpoint
    chk_file = tmp_path / "chk.json"
    code, out, err = run_cli(
        ["checkpoint", "create", "--tenant-id", "acme", "--out", str(chk_file)],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    assert chk_file.exists()
    chk_obj = json.loads(chk_file.read_text())
    assert chk_obj["schema_version"] == "tempus.checkpoint.v1"
    assert chk_obj["tenant_id"] == "acme"
    assert chk_obj["total_events"] == 2  # authorization + outcome

    # 6. Export Event Stream
    stream_file = tmp_path / "stream.json"
    code, out, err = run_cli(
        [
            "checkpoint",
            "export",
            "--tenant-id",
            "acme",
            "--from-seq",
            "1",
            "--out",
            str(stream_file),
        ],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    assert stream_file.exists()
    events = json.loads(stream_file.read_text())
    assert len(events) == 2

    # 7. Verify Checkpoint and Stream
    code, out, err = run_cli(
        [
            "checkpoint",
            "verify",
            "--checkpoint",
            str(chk_file),
            "--stream",
            str(stream_file),
        ],
        cwd=tmp_path,
    )
    assert code == 0, out + err
    ver_res = json.loads(out)
    assert ver_res["status"] == "VERIFIED"
    assert ver_res["events_verified"] == 2

    # 8. Tamper adversarial test on stream
    events[0]["sequence_number"] = 999
    tampered_stream = tmp_path / "stream_tampered.json"
    tampered_stream.write_text(json.dumps(events))

    code, out, err = run_cli(
        [
            "checkpoint",
            "verify",
            "--checkpoint",
            str(chk_file),
            "--stream",
            str(tampered_stream),
        ],
        cwd=tmp_path,
    )
    assert code != 0
    ver_tampered = json.loads(out)
    assert ver_tampered["status"] == "INVALID"
    assert "ERR_SEQUENCE_GAP" in ver_tampered["reason_code"]
