"""Generate the conformance evidence fixtures in ``conformance/evidence/``.

The fixtures are real documents produced by a throwaway gate: a signed permit, a signed
outcome, a gate-signed checkpoint, and the evidence bundle that holds them, plus
tampered variants and the verdict every conforming verifier must return for each one.
The browser verifier (``site/verify.html``), the CLI (``tempus verify-bundle``) and
third-party implementations of ``SPEC.md`` are checked against the same files.

The gate private key is generated here and discarded; only the public key is written.

Usage (from the repository root, with the package installed):

    python scripts/generate_conformance_evidence.py
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "evidence"

# Fixtures must be reproducible in meaning, not in bytes: timestamps and keys differ on
# every run, so the expected verdicts name statuses and error codes, never digests. The
# gate refuses an intent whose `requested_at` is not close to its clock, so the permit
# carries a real timestamp and expires; a permit-only document is therefore AUTHORIZED
# today and EXPIRED later, and the expectations accept either (both are VERIFIED).


def main() -> int:
    from tempus_ddb import (
        TempusDDB,
        bundle_digest,
        gen_keys,
        verify_bundle,
        verify_receipt,
    )

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        keys = {}
        for name in ("gate", "agent", "executor"):
            path = tmp_path / f"{name}.keys.json"
            gen_keys(str(path))
            keys[name] = (path, json.loads(path.read_text(encoding="utf-8"))["public_key"])
        gate_key, gate_id = keys["gate"]
        agent_key, agent_id = keys["agent"]
        executor_key, executor_id = keys["executor"]

        gate = TempusDDB(str(tmp_path / "gate.db"), str(gate_key))
        gate.register_agent(gate_id, "conformance-gate", json.dumps({"can_delegate": True}))
        gate.install_allow_all_dev_policy()
        gate.register_agent(agent_id, "conformance-agent", "{}")
        gate.register_agent(executor_id, "conformance-executor", "{}")

        intent = {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "conformance",
            "agent_id": agent_id,
            "idempotency_key": "conformance-purchase-1",
            "action_type": "purchase",
            "resource": "vendor-api/credits",
            "requested_at": time.time_ns() // 1_000,
            "input": {"sku": "compute-credits", "quantity": 1},
            "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"},
        }
        permit = json.loads(gate.request_action(json.dumps(intent), str(agent_key), 3_600))
        assert permit["authorization"]["decision"] == "ALLOWED", permit
        authorization_id = permit["authorization"]["authorization_id"]
        action_id = permit["authorization"]["action_id"]
        outcome = {
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": authorization_id,
            "action_id": action_id,
            "status": "SUCCEEDED",
            "external_reference": "vendor-tx-1",
        }
        gate.commit_outcome(authorization_id, json.dumps(outcome), str(executor_key))
        gate.create_checkpoint("conformance")

        bundle_text = gate.export_bundle(action_id, None)
        bundle = json.loads(bundle_text)
        trace_text = gate.get_trace(action_id)

        OUT.mkdir(parents=True, exist_ok=True)
        for stale in OUT.glob("*.json"):
            stale.unlink()
        (OUT / "gate_public_key.txt").write_text(gate_id + "\n", encoding="utf-8")
        (OUT / "executor_public_key.txt").write_text(executor_id + "\n", encoding="utf-8")

        cases = []

        def emit(name, document, expected, note):
            text = (
                document
                if isinstance(document, str)
                else json.dumps(document, separators=(",", ":"), sort_keys=True)
            )
            (OUT / f"{name}.json").write_text(text + "\n", encoding="utf-8")
            cases.append({"file": f"{name}.json", "note": note, **expected})

        emit(
            "bundle",
            bundle_text,
            {
                "kind": "bundle",
                "status": "VERIFIED",
                "phase": "COMPLETED",
                "checks": {
                    "authorization": "VERIFIED",
                    "execution": "VERIFIED",
                    "checkpoint": "VERIFIED",
                },
                "errors": [],
            },
            "The bundle as the gate exported it: permit, outcome, signed checkpoint and the "
            "stream it commits to. verify_url carries the bundle digest.",
        )

        permit_only = copy.deepcopy(bundle)
        permit_only["trace"]["execution"] = None
        permit_only.pop("verify_url")
        emit(
            "bundle_permit_only",
            permit_only,
            {
                "kind": "bundle",
                "status": "VERIFIED",
                "phase_any": ["AUTHORIZED", "EXPIRED"],
                "checks": {
                    "authorization": "VERIFIED",
                    "execution": "NOT_PRESENT",
                    "checkpoint": "VERIFIED",
                },
                "errors": [],
            },
            "The same bundle without its outcome and without verify_url. Still valid "
            "evidence of the permit; the verifier says the outcome is NOT_PRESENT and "
            "cannot prove nothing was hidden (trust.not_checked lists COMPLETENESS).",
        )

        tampered_decision = copy.deepcopy(bundle)
        tampered_decision["trace"]["authorization"]["authorization"]["decision"] = "BLOCKED"
        emit(
            "bundle_tampered_decision",
            tampered_decision,
            {
                "kind": "bundle",
                "status": "INVALID",
                "errors_include": [
                    "AUTHORIZATION_ID_MISMATCH",
                    "BUNDLE_VERIFY_URL_MISMATCH",
                ],
            },
            "One signed field edited after the fact (decision). The receipt hash no longer "
            "matches and the verify link no longer names this file.",
        )

        tampered_amount = copy.deepcopy(bundle)
        tampered_amount["trace"]["authorization"]["intent"]["money"]["amount"] = "25000.00"
        emit(
            "bundle_tampered_amount",
            tampered_amount,
            {
                "kind": "bundle",
                "status": "INVALID",
                "errors_include": ["INTENT_HASH_MISMATCH"],
            },
            "The agent's intent edited after signing (amount). The intent hash in the "
            "signed receipt no longer matches the intent in the file.",
        )

        stale_link = copy.deepcopy(bundle)
        stale_link["verify_url"] = (
            "https://tempus-protocol.github.io/tempus-ddb/verify.html#bundle=" + "0" * 64
        )
        emit(
            "bundle_wrong_verify_url",
            stale_link,
            {
                "kind": "bundle",
                "status": "INVALID",
                "errors_include": ["BUNDLE_VERIFY_URL_MISMATCH"],
            },
            "Every signed document is intact but the verify link names another bundle. "
            "A link and a file that do not belong together are not evidence.",
        )

        emit(
            "trace",
            trace_text,
            {
                "kind": "trace",
                "status": "VERIFIED",
                "phase": "COMPLETED",
                "checks": {"authorization": "VERIFIED", "execution": "VERIFIED"},
                "errors": [],
            },
            "The action trace (tempus.action-trace.v1) verified as a receipt: no checkpoint, "
            "so ledger inclusion is in trust.not_checked.",
        )

        emit(
            "permit",
            permit,
            {
                "kind": "authorization",
                "status": "VERIFIED",
                "phase_any": ["AUTHORIZED", "EXPIRED"],
                "checks": {"authorization": "VERIFIED", "execution": "NOT_PRESENT"},
                "errors": [],
            },
            "The permit alone (tempus.authorization-result.v1), as the agent received it.",
        )

        # Sanity-check every expectation with the native verifier before writing it down.
        for case in cases:
            text = (OUT / case["file"]).read_text(encoding="utf-8")
            raw = (
                verify_bundle(text, gate_id, None)
                if case["kind"] == "bundle"
                else verify_receipt(text, gate_id, None)
            )
            result = json.loads(raw)
            check(case, result)

        expected = {
            "schema_version": "tempus.conformance-evidence.v1",
            "gate_public_key_file": "gate_public_key.txt",
            "executor_public_key_file": "executor_public_key.txt",
            "action_id": action_id,
            "bundle_digest": bundle_digest(bundle_text),
            "verify_url": bundle["verify_url"],
            "cases": cases,
        }
        (OUT / "expected.json").write_text(
            json.dumps(expected, indent=2) + "\n", encoding="utf-8"
        )
        # The site's verify page offers the same bundle and key as loadable samples.
        site_data = ROOT / "site" / "data" / "evidence"
        site_data.mkdir(parents=True, exist_ok=True)
        for name in ("bundle.json", "bundle_tampered_decision.json"):
            (site_data / name).write_text(
                (OUT / name).read_text(encoding="utf-8"), encoding="utf-8"
            )
        (site_data / "gate_public_key.txt").write_text(gate_id + "\n", encoding="utf-8")
        del gate  # release the SQLite handle before the directory is removed
    print(f"wrote {len(cases)} cases to {OUT.relative_to(ROOT)} and site/data/evidence")
    return 0


def check(case: dict, result: dict) -> None:
    """Assert that ``result`` (a trace-verification document) matches ``case``."""
    assert result["kind"] == case["kind"], (case["file"], result["kind"])
    assert result["status"] == case["status"], (case["file"], result)
    if "phase" in case:
        assert result["phase"] == case["phase"], (case["file"], result["phase"])
    if "phase_any" in case:
        assert result["phase"] in case["phase_any"], (case["file"], result["phase"])
    for name, value in case.get("checks", {}).items():
        assert result["checks"][name] == value, (case["file"], name, result["checks"])
    if "errors" in case:
        assert result["errors"] == case["errors"], (case["file"], result["errors"])
    for code in case.get("errors_include", []):
        assert code in result["errors"], (case["file"], code, result["errors"])
    assert result["trust"]["independent"] is True, case["file"]


if __name__ == "__main__":
    os.environ.pop("TEMPUS_VERIFY_URL", None)
    sys.exit(main())
