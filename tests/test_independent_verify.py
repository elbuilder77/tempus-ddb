"""Independent verification: the verifier pins the gate public key and does not
trust the root of trust that ships inside the database being verified."""

import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from tempus_ddb import (
    TempusDDB,
    gen_keys,
    verify_bundle,
    verify_checkpoint,
    verify_receipt,
)
from test_cli import run_cli

TENANT = "indep-test"


def _pub(path):
    return json.loads(path.read_text())["public_key"]


def make_world(base, name, amount="25.00", status="SUCCEEDED", execute=True):
    """A complete gate with its own keys: init, register, authorize, execute."""
    root = base / name
    root.mkdir()
    code, out, err = run_cli(["init", "--allow-all-dev"], cwd=root)
    assert code == 0, out + err
    agent_keys, executor_keys = root / "agent.keys.json", root / "executor.keys.json"
    gen_keys(str(agent_keys))
    gen_keys(str(executor_keys))
    for alias, keys in (("buyer", agent_keys), ("payer", executor_keys)):
        code, out, err = run_cli(
            ["register-agent", "--alias", alias, "--agent-keyfile", str(keys)],
            cwd=root,
        )
        assert code == 0, out + err
    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": TENANT,
            "agent_id": _pub(agent_keys),
            "idempotency_key": "pay-1",
            "action_type": "purchase",
            "resource": "vendor/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {},
            "money": {"amount": amount, "asset": "USD", "beneficiary": "v-1"},
        }
    )
    code, out, err = run_cli(
        ["request-action", "--intent", intent, "--agent-keyfile", str(agent_keys)],
        cwd=root,
    )
    assert code == 0, out + err
    permit = json.loads(out)
    receipt = permit["authorization"]
    outcome = json.dumps(
        {
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": receipt["authorization_id"],
            "action_id": receipt["action_id"],
            "status": status,
            "external_reference": "tx-1",
        }
    )
    if not execute:
        (root / "trace.json").write_text(
            run_cli(["trace", "--action-id", receipt["action_id"]], cwd=root)[1]
        )
        return {
            "root": root,
            "gate": _pub(root / "keys.json"),
            "executor": _pub(executor_keys),
            "action_id": receipt["action_id"],
            "permit": permit,
        }
    code, out, err = run_cli(
        [
            "commit-outcome",
            "--authorization-id",
            receipt["authorization_id"],
            "--outcome",
            outcome,
            "--executor-keyfile",
            str(executor_keys),
        ],
        cwd=root,
    )
    assert code == 0, out + err
    execution = json.loads(out)
    code, out, err = run_cli(["trace", "--action-id", receipt["action_id"]], cwd=root)
    assert code == 0, out + err
    trace = json.loads(out)
    (root / "trace.json").write_text(json.dumps(trace))
    return {
        "root": root,
        "gate": _pub(root / "keys.json"),
        "executor": _pub(executor_keys),
        "action_id": receipt["action_id"],
        "permit": permit,
        "execution": execution,
        "trace": trace,
    }


@pytest.fixture(scope="module")
def worlds(tmp_path_factory):
    base = tmp_path_factory.mktemp("indep")
    return make_world(base, "real"), make_world(base, "forged", amount="9999.00")


def _verify_trace(world, *extra):
    return run_cli(
        ["verify-trace", "--action-id", world["action_id"], *extra], cwd=world["root"]
    )


def test_forged_full_database_is_verified_without_a_key_but_marked_not_independent(
    worlds,
):
    _, forged = worlds
    code, out, err = _verify_trace(forged)
    assert code == 0, out + err  # the self-attested result is unchanged...
    result = json.loads(out)
    assert result["status"] == "VERIFIED"
    assert result["trust"]["independent"] is False  # ...but clearly not independent
    assert "NOT INDEPENDENT" in err


def test_forged_full_database_is_invalid_with_the_real_gate_key_pinned(worlds):
    real, forged = worlds
    code, out, err = _verify_trace(forged, "--gate-public-key", real["gate"])
    assert code == 2, out + err
    result = json.loads(out)
    assert result["status"] == "INVALID"
    assert "GATE_KEY_NOT_PINNED" in result["errors"]
    assert "NOT INDEPENDENT" not in err


def test_genuine_database_verifies_with_its_own_pinned_key_and_executor(worlds):
    real, _ = worlds
    code, out, err = _verify_trace(
        real,
        "--gate-public-key",
        real["gate"],
        "--executor-public-key",
        real["executor"],
    )
    assert code == 0, out + err
    result = json.loads(out)
    assert result["status"] == "VERIFIED"
    assert result["trust"] == {
        "mode": "PINNED_GATE_KEY",
        "independent": True,
        "gate_public_key": real["gate"],
        "executor_keys_pinned": 1,
        "not_checked": result["trust"]["not_checked"],
    }


def test_wrong_gate_or_executor_key_is_invalid(worlds):
    real, forged = worlds
    code, out, _ = _verify_trace(real, "--gate-public-key", forged["gate"])
    assert code == 2 and json.loads(out)["status"] == "INVALID"
    code, out, _ = _verify_trace(
        real,
        "--gate-public-key",
        real["gate"],
        "--executor-public-key",
        forged["executor"],
    )
    assert code == 2
    assert "EXECUTOR_KEY_NOT_PINNED" in json.loads(out)["errors"]


def test_strict_requires_a_pinned_key_and_bad_keys_are_rejected(worlds):
    real, _ = worlds
    code, out, err = _verify_trace(real, "--strict")
    assert code == 1
    assert "--gate-public-key" in err and out == ""
    for bad in ("zz", "ab" * 31, "not-a-file"):
        code, out, err = _verify_trace(real, "--gate-public-key", bad)
        assert code == 1, (bad, out, err)
        assert "64 hex" in err
    code, _, err = _verify_trace(real, "--executor-public-key", real["executor"])
    assert code == 1 and "requires --gate-public-key" in err


def test_gate_public_key_can_be_a_file(worlds):
    real, forged = worlds
    pub_file = real["root"] / "gate.pub"
    pub_file.write_text(real["gate"] + "\n")
    code, out, err = _verify_trace(real, "--gate-public-key", str(pub_file))
    assert code == 0, out + err
    # A key file with a "public_key" field works too; only the public part is read.
    code, out, err = _verify_trace(
        real, "--gate-public-key", str(real["root"] / "keys.json")
    )
    assert code == 0, out + err
    assert "private" not in out + err
    code, out, _ = _verify_trace(forged, "--gate-public-key", str(pub_file))
    assert code == 2


def test_verify_receipt_standalone_in_an_empty_directory(worlds, tmp_path):
    real, _ = worlds
    for name, doc in (
        ("trace", real["trace"]),
        ("permit", real["permit"]),
        ("outcome", real["execution"]),
    ):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(doc))
        code, out, err = run_cli(
            [
                "verify-receipt",
                "--receipt",
                str(path),
                "--gate-public-key",
                real["gate"],
            ],
            cwd=tmp_path,
        )
        assert code == 0, (name, out, err)
        assert json.loads(out)["status"] == "VERIFIED"
    assert list(tmp_path.glob("*.db")) == []  # no database was needed or created


def test_verify_receipt_rejects_tampering_wrong_key_and_forged_database(
    worlds, tmp_path
):
    real, forged = worlds

    def run(doc, key):
        path = tmp_path / "r.json"
        path.write_text(json.dumps(doc))
        return run_cli(
            ["verify-receipt", "--receipt", str(path), "--gate-public-key", key],
            cwd=tmp_path,
        )

    tampered = copy.deepcopy(real["trace"])
    tampered["authorization"]["intent"]["money"]["amount"] = "9999.00"
    code, out, _ = run(tampered, real["gate"])
    assert code == 2 and json.loads(out)["status"] == "INVALID"

    tampered = copy.deepcopy(real["trace"])
    tampered["execution"]["outcome"]["status"] = "FAILED"
    tampered["execution"]["receipt"]["status"] = "FAILED"
    code, out, _ = run(tampered, real["gate"])
    assert code == 2 and json.loads(out)["status"] == "INVALID"

    code, out, _ = run(real["trace"], forged["gate"])  # wrong key
    assert code == 2 and json.loads(out)["status"] == "INVALID"

    code, out, _ = run(forged["trace"], real["gate"])  # attacker's complete trace
    assert code == 2
    assert "GATE_KEY_NOT_PINNED" in json.loads(out)["errors"]

    code, out, _ = run(forged["trace"], forged["gate"])  # valid only for its own key
    assert code == 0 and json.loads(out)["status"] == "VERIFIED"


def test_verify_receipt_requires_key_and_reads_stdin(worlds, tmp_path):
    real, _ = worlds
    code, _, err = run_cli(["verify-receipt", "--receipt", "x.json"], cwd=tmp_path)
    assert code == 1 and "--gate-public-key" in err  # usage error: required
    cmd = [
        sys.executable,
        "-m",
        "tempus_ddb.cli",
        "verify-receipt",
        "--receipt",
        "-",
        "--gate-public-key",
        real["gate"],
    ]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path(__file__).parent.parent / "python"), env.get("PYTHONPATH", "")]
    )
    result = subprocess.run(
        cmd,
        input=json.dumps(real["permit"]),
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["kind"] == "authorization"
    code, _, err = run_cli(
        ["verify-receipt", "--receipt", "nope.json", "--gate-public-key", real["gate"]],
        cwd=tmp_path,
    )
    assert code == 1 and "not found" in err


def test_checkpoint_verify_with_public_key_needs_no_database_or_private_key(
    worlds, tmp_path
):
    real, forged = worlds
    chk, stream = real["root"] / "chk.json", real["root"] / "stream.json"
    code, out, err = run_cli(
        ["checkpoint", "create", "--tenant-id", TENANT, "--out", str(chk)],
        cwd=real["root"],
    )
    assert code == 0, out + err
    code, out, err = run_cli(
        ["checkpoint", "export", "--tenant-id", TENANT, "--out", str(stream)],
        cwd=real["root"],
    )
    assert code == 0, out + err

    elsewhere = ["--checkpoint", str(chk), "--stream", str(stream)]
    code, out, err = run_cli(
        ["checkpoint", "verify", *elsewhere, "--gate-public-key", real["gate"]],
        cwd=tmp_path,  # no keys.json, no tempus.db here
    )
    assert code == 0, out + err
    result = json.loads(out)
    assert result["status"] == "VERIFIED"
    assert result["trust"]["independent"] is True
    assert not (tmp_path / "tempus.db").exists()

    code, out, _ = run_cli(
        ["checkpoint", "verify", *elsewhere, "--gate-public-key", forged["gate"]],
        cwd=tmp_path,
    )
    assert code == 2 and json.loads(out)["status"] == "INVALID"

    code, out, err = run_cli(
        ["checkpoint", "verify", *elsewhere, "--strict"], cwd=real["root"]
    )
    assert code == 1 and "--gate-public-key" in err

    code, out, err = run_cli(["checkpoint", "verify", *elsewhere], cwd=real["root"])
    assert code == 0, out + err  # legacy local-key behaviour is kept but flagged
    assert json.loads(out)["trust"]["independent"] is False
    assert "NOT INDEPENDENT" in err


def test_python_api_pinned_verification(worlds):
    real, forged = worlds
    db = TempusDDB(str(forged["root"] / "tempus.db"), str(forged["root"] / "keys.json"))
    assert json.loads(db.verify_trace(forged["action_id"]))["status"] == "VERIFIED"
    pinned = json.loads(db.verify_trace(forged["action_id"], real["gate"]))
    assert pinned["status"] == "INVALID"
    with pytest.raises(RuntimeError):
        db.verify_trace(forged["action_id"], "zz")
    with pytest.raises(RuntimeError):
        db.verify_trace(forged["action_id"], None, [real["executor"]])
    result = json.loads(verify_receipt(json.dumps(real["trace"]), real["gate"]))
    assert result["status"] == "VERIFIED"
    result = json.loads(
        verify_receipt(json.dumps(real["trace"]), real["gate"], [forged["executor"]])
    )
    assert result["status"] == "INVALID"
    with pytest.raises(RuntimeError):
        verify_checkpoint("{}", "[]", "zz")


# ---- evidence bundles -------------------------------------------------------


def _export(world, name, *extra):
    out = world["root"] / name
    code, stdout, stderr = run_cli(
        ["export-bundle", "--action-id", world["action_id"], "--out", str(out), *extra],
        cwd=world["root"],
    )
    return code, stdout, stderr, out


def _verify_bundle(path, key, cwd, *extra):
    return run_cli(
        ["verify-bundle", "--bundle", str(path), "--gate-public-key", key, *extra],
        cwd=cwd,
    )


def test_bundle_without_checkpoint_exports_and_verifies_offline(tmp_path):
    real = make_world(tmp_path, "fresh")  # no checkpoint exists yet
    code, out, err, path = _export(real, "plain.bundle.json")
    assert code == 0, out + err
    summary = json.loads(out)
    assert summary["schema_version"] == "tempus.evidence-bundle.v1"
    assert summary["checkpoint_included"] is False
    assert "--create-checkpoint" in err
    # Copy the single file to an empty directory: no DB, no keys.
    empty = tmp_path / "empty"
    empty.mkdir()
    copy_path = empty / "bundle.json"
    copy_path.write_text(path.read_text())
    code, out, err = _verify_bundle(copy_path, real["gate"], empty)
    assert code == 0, out + err
    result = json.loads(out)
    assert result["status"] == "VERIFIED" and result["kind"] == "bundle"
    assert result["checks"]["checkpoint"] == "NOT_PRESENT"
    assert any("LEDGER_INCLUSION" in item for item in result["trust"]["not_checked"])
    assert sorted(p.name for p in empty.iterdir()) == ["bundle.json"]


def test_bundle_with_checkpoint_verifies_ledger_inclusion(worlds, tmp_path):
    real, _ = worlds
    code, out, err, path = _export(real, "chk.bundle.json", "--create-checkpoint")
    assert code == 0, out + err
    assert json.loads(out)["checkpoint_included"] is True
    code, out, err = _verify_bundle(
        path,
        real["gate"],
        tmp_path,
        "--executor-public-key",
        real["executor"],
    )
    assert code == 0, out + err
    result = json.loads(out)
    assert result["checks"] == {
        "authorization": "VERIFIED",
        "execution": "VERIFIED",
        "checkpoint": "VERIFIED",
        "anchor": "NOT_PRESENT",
    }
    # Refuses to clobber existing evidence unless --force.
    code, _, err, _ = _export(real, "chk.bundle.json")
    assert code == 1 and "already exists" in err
    code, _, err, _ = _export(real, "chk.bundle.json", "--force")
    assert code == 0, err


def test_bundle_oversized_stream_is_omitted(worlds):
    real, _ = worlds
    code, out, err, path = _export(
        real, "small.bundle.json", "--create-checkpoint", "--max-stream-events", "1"
    )
    assert code == 0, out + err
    assert json.loads(out)["checkpoint_included"] is False
    assert json.loads(path.read_text())["checkpoint"] is None


def test_forged_database_bundle_is_invalid_with_the_real_key(worlds, tmp_path):
    real, forged = worlds
    code, out, err, path = _export(forged, "forged.bundle.json", "--create-checkpoint")
    assert code == 0, out + err
    code, out, _ = _verify_bundle(path, real["gate"], tmp_path)
    assert code == 2
    errors = json.loads(out)["errors"]
    assert "GATE_KEY_NOT_PINNED" in errors
    assert "CHECKPOINT_ERR_UNTRUSTED_SIGNER" in errors
    # It is only consistent for the attacker's own key.
    code, out, _ = _verify_bundle(path, forged["gate"], tmp_path)
    assert code == 0 and json.loads(out)["status"] == "VERIFIED"


def test_bundle_wrong_keys_and_bad_usage(worlds, tmp_path):
    real, forged = worlds
    code, out, err, path = _export(real, "keys.bundle.json", "--create-checkpoint")
    assert code == 0, out + err
    code, out, _ = _verify_bundle(path, forged["gate"], tmp_path)
    assert code == 2 and json.loads(out)["status"] == "INVALID"
    code, out, _ = _verify_bundle(
        path, real["gate"], tmp_path, "--executor-public-key", forged["executor"]
    )
    assert code == 2 and "EXECUTOR_KEY_NOT_PINNED" in json.loads(out)["errors"]
    code, _, err = _verify_bundle(path, "not-a-key", tmp_path)
    assert code == 1 and "64 hex" in err
    code, _, err = run_cli(["verify-bundle", "--bundle", str(path)], cwd=tmp_path)
    assert code == 1 and "--gate-public-key" in err  # usage error: required
    code, _, err = _verify_bundle(tmp_path / "missing.json", real["gate"], tmp_path)
    assert code == 1 and "not found" in err
    not_a_bundle = tmp_path / "x.json"
    not_a_bundle.write_text("{}")
    code, _, err = _verify_bundle(not_a_bundle, real["gate"], tmp_path)
    assert code == 1 and "SCHEMA_UNKNOWN" in err


def _set(doc, path, value):
    node = doc
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


@pytest.mark.parametrize(
    "path,value",
    [
        (["trace", "authorization", "intent", "money", "amount"], "9999.00"),
        (["trace", "authorization", "authorization", "decision"], "BLOCKED"),
        (
            [
                "trace",
                "authorization",
                "policy_bundle",
                "constraints",
                "max_ttl_seconds",
            ],
            9,
        ),
        (["trace", "authorization", "agent_signature"], "00" * 64),
        (["trace", "execution", "outcome", "status"], "FAILED"),
        (["trace", "execution", "outcome", "external_reference"], "tx-forged"),
        (["trace", "execution", "receipt", "status"], "FAILED"),
        (["trace", "action_id"], "00"),
        (["action_id"], "00"),
        (["checkpoint", "checkpoint", "stream_root_hash"], "00" * 32),
        (["checkpoint", "checkpoint", "signature"], "00" * 64),
        (["checkpoint", "stream", 0, "payload_hash"], "00" * 32),
    ],
    ids=[
        "money-amount",
        "decision",
        "max-ttl",
        "agent-signature",
        "outcome-status",
        "external-reference",
        "receipt-status",
        "trace-action-id",
        "bundle-action-id",
        "stream-root",
        "checkpoint-signature",
        "payload-hash",
    ],
)
def test_tampered_bundle_field_is_invalid(worlds, tmp_path, path, value):
    real, _ = worlds
    code, out, err, bundle_path = _export(
        real, "tamper.bundle.json", "--create-checkpoint", "--force"
    )
    assert code == 0, out + err
    bundle = json.loads(bundle_path.read_text())
    _set(bundle, path, value)
    tampered = tmp_path / "t.json"
    tampered.write_text(json.dumps(bundle))
    code, out, err = _verify_bundle(tampered, real["gate"], tmp_path)
    assert code == 2, (path, out, err)
    assert json.loads(out)["status"] == "INVALID"


def test_bundle_contains_no_private_key_material(worlds):
    real, _ = worlds
    code, out, err, path = _export(real, "secrets.bundle.json", "--create-checkpoint")
    assert code == 0, out + err
    text = path.read_text()
    assert "private_key" not in text
    for name in ("keys.json", "agent.keys.json", "executor.keys.json"):
        secret = json.loads((real["root"] / name).read_text())["private_key"]
        assert len(secret) >= 64 and secret not in text
    assert real["gate"] in text  # public identities are expected


def test_python_api_bundle_roundtrip(worlds):
    real, forged = worlds
    db = TempusDDB(str(real["root"] / "tempus.db"), str(real["root"] / "keys.json"))
    bundle = db.export_bundle(real["action_id"])
    assert json.loads(verify_bundle(bundle, real["gate"]))["status"] == "VERIFIED"
    assert json.loads(verify_bundle(bundle, forged["gate"]))["status"] == "INVALID"
    with pytest.raises(RuntimeError):
        verify_bundle(bundle, "zz")
    with pytest.raises(RuntimeError):
        db.export_bundle("no-such-action")
