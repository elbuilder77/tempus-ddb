"""Generate the conformance evidence fixtures in ``conformance/evidence/``.

The fixtures are real documents produced by a throwaway gate: a signed permit, a signed
outcome, a gate-signed checkpoint, and the evidence bundle that holds them, plus
tampered variants and the verdict every conforming verifier must return for each one.
The browser verifier (``site/verify.html``), the CLI (``tempus verify-bundle``) and
third-party implementations of ``SPEC.md`` are checked against the same files.

The gate private key is generated here and discarded; only the public key is written. The
anchor fixtures come from the throwaway log and timestamp authority in
``anchor_test_authority.py``: only someone who pins its roots (``anchor_roots.json``) reads
them as verified, and those keys die with this process too.

Usage (from the repository root, with the package installed):

    python scripts/generate_conformance_evidence.py
"""

from __future__ import annotations

import copy
import hashlib
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
    from anchor_test_authority import Authority
    from tempus_ddb import (
        TempusDDB,
        anchor_checkpoint_digest,
        bundle_digest,
        gen_keys,
        verify_anchor,
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

        # --- rules: the same gate key, a policy whose rule looks at the amount ---
        rules_gate = TempusDDB(str(tmp_path / "rules.db"), str(gate_key))
        rules_gate.register_agent(gate_id, "conformance-gate", json.dumps({"can_delegate": True}))
        rules_gate.register_agent(agent_id, "conformance-agent", "{}")
        rules_gate.install_policy(
            json.dumps(
                {
                    "schema_version": "tempus.policy-bundle.v1",
                    "policy_version": "conformance-rules-v1",
                    "tenant_id": "conformance",
                    "constraints": {
                        "allowed_action_types": ["purchase"],
                        "allowed_resources": ["*"],
                        "allowed_executors": ["*"],
                        "max_ttl_seconds": 3_600,
                        "max_input_bytes": 4_096,
                        "currency_exponents": {"JPY": 0},
                    },
                    "rules": [
                        {
                            "id": "purchase.under-ten",
                            "logic": {"<=": [{"var": "money.amount_minor"}, 1000]},
                        }
                    ],
                }
            )
        )

        def rules_permit(key, amount, asset="USD"):
            return json.loads(
                rules_gate.request_action(
                    json.dumps(
                        {
                            **intent,
                            "idempotency_key": key,
                            "money": {**intent["money"], "amount": amount, "asset": asset},
                        }
                    ),
                    str(agent_key),
                    3_600,
                )
            )

        allowed_by_rule = rules_permit("conformance-rules-allowed", "9.99")
        assert allowed_by_rule["authorization"]["decision"] == "ALLOWED", allowed_by_rule
        emit(
            "permit_rules_allowed",
            allowed_by_rule,
            {
                "kind": "authorization",
                "status": "VERIFIED",
                "checks": {"authorization": "VERIFIED"},
                "errors": [],
            },
            "A policy with a rule on the amount, and an amount under it. The verifier runs the "
            "rule again.",
        )
        yen = rules_permit("conformance-rules-yen", "500", "JPY")
        assert yen["authorization"]["decision"] == "ALLOWED", yen
        emit(
            "permit_rules_yen",
            yen,
            {
                "kind": "authorization",
                "status": "VERIFIED",
                "checks": {"authorization": "VERIFIED"},
                "errors": [],
            },
            "500 yen under the same limit of 1000 minor units: the signed policy says JPY has no "
            "decimals. Read in hundredths it would be 50000, over the limit, and this permit "
            "would not reproduce.",
        )
        denied_by_rule = rules_permit("conformance-rules-denied", "25.00")
        assert denied_by_rule["authorization"]["reason_codes"] == ["POLICY_RULES_DENIED"], (
            denied_by_rule
        )
        emit(
            "permit_rules_denied",
            denied_by_rule,
            {
                "kind": "authorization",
                "status": "VERIFIED",
                "checks": {"authorization": "VERIFIED"},
                "errors": [],
            },
            "The same policy and an amount over it: a true record of a refusal "
            "(POLICY_RULES_DENIED) is valid evidence.",
        )
        forged_allow = copy.deepcopy(denied_by_rule)
        forged_allow["authorization"]["decision"] = "ALLOWED"
        forged_allow["authorization"]["reason_codes"] = ["IDENTITY_VERIFIED", "POLICY_ALLOWED"]
        resign_authorization(forged_allow, gate_key)
        emit(
            "permit_rules_forged_allow",
            forged_allow,
            {
                "kind": "authorization",
                "status": "INVALID",
                "errors_include": [
                    "AUTHORIZATION_POLICY_DECISION_MISMATCH",
                    "AUTHORIZATION_DECISION_NOT_REPRODUCIBLE",
                    "AUTHORIZATION_REASON_CODES_NOT_REPRODUCIBLE",
                ],
            },
            "The gate's own key signs an ALLOWED that its own rule denies. Every signature is "
            "good; only running the rule again finds the lie.",
        )
        edited_rule = copy.deepcopy(denied_by_rule)
        edited_rule["policy_bundle"]["rules"][0]["logic"]["<="][1] = 1_000_000
        emit(
            "permit_rules_edited",
            edited_rule,
            {
                "kind": "authorization",
                "status": "INVALID",
                "errors_include": ["TEMPUS_POLICY_DIGEST_MISMATCH"],
            },
            "The limit in the rule edited after the gate signed the policy.",
        )
        rules_gate = None  # release the SQLite handle before the directory is removed

        # --- anchors: the bundle's checkpoint, proved to a log and a timestamp authority ---
        authority = Authority()
        checkpoint = bundle["checkpoint"]["checkpoint"]
        digest = anchor_checkpoint_digest(json.dumps(checkpoint))
        anchor = {
            "schema_version": "tempus.anchor.v1",
            "checkpoint_id": checkpoint["checkpoint_id"],
            "tenant_id": checkpoint["tenant_id"],
            "checkpoint_digest": digest,
            "proofs": [authority.rekor_proof(digest), authority.rfc3161_proof(digest)],
        }
        roots_text = json.dumps(authority.roots())
        (OUT / "anchor_roots.json").write_text(roots_text + "\n", encoding="utf-8")
        anchor_cases = []

        def emit_anchor(name, document, roots, expected, note):
            (OUT / f"{name}.json").write_text(
                json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            anchor_cases.append(
                {"anchor": f"{name}.json", "roots": roots, "note": note, **expected}
            )

        emit_anchor(
            "anchor",
            anchor,
            "anchor_roots.json",
            {"status": "VERIFIED", "proofs": ["VERIFIED", "VERIFIED"], "errors": []},
            "A Rekor proof and a timestamp token for the checkpoint in bundle.json, with the "
            "reader's roots pinned: the checkpoint existed no later than anchored_at.",
        )
        emit_anchor(
            "anchor",
            anchor,
            None,
            {"status": "NOT_CHECKED", "proofs": ["NOT_CHECKED", "NOT_CHECKED"], "errors": []},
            "The same anchor with nothing pinned. It is about the right checkpoint, but nothing "
            "says who signed it, so no date is claimed.",
        )
        tampered_time = copy.deepcopy(anchor)
        tampered_time["proofs"][0]["integrated_time"] += 86_400
        emit_anchor(
            "anchor_tampered_time",
            tampered_time,
            "anchor_roots.json",
            {
                "status": "INVALID",
                "proofs": ["FAILED", "VERIFIED"],
                "errors": ["ANCHOR_REKOR_SET_INVALID"],
            },
            "The log's time edited after the fact: its signed entry timestamp no longer "
            "verifies. One failed proof sinks the anchor however good the others are.",
        )
        tampered_token = copy.deepcopy(anchor)
        tampered_token["proofs"][1]["token"] = tampered_token["proofs"][0]["log_id"]
        emit_anchor(
            "anchor_tampered_token",
            tampered_token,
            "anchor_roots.json",
            {
                "status": "INVALID",
                "proofs": ["VERIFIED", "FAILED"],
                "errors": ["ANCHOR_TSA_TOKEN_MALFORMED"],
            },
            "The timestamp token replaced by other bytes.",
        )
        gate_other = json.loads(gate.create_checkpoint("conformance"))
        other_digest = anchor_checkpoint_digest(json.dumps(gate_other))
        other = {
            "schema_version": "tempus.anchor.v1",
            "checkpoint_id": gate_other["checkpoint_id"],
            "tenant_id": gate_other["tenant_id"],
            "checkpoint_digest": other_digest,
            "proofs": [authority.rekor_proof(other_digest)],
        }
        emit_anchor(
            "anchor_other_checkpoint",
            other,
            "anchor_roots.json",
            {
                "status": "INVALID",
                "proofs": ["FAILED"],
                "errors": ["ANCHOR_CHECKPOINT_MISMATCH", "ANCHOR_REKOR_ENTRY_MISMATCH"],
            },
            "A valid anchor for a later checkpoint of the same tenant, read against this one. "
            "The wrapper names the other checkpoint, and so does the logged entry.",
        )
        unknown_log = {
            **anchor,
            "proofs": [Authority().rekor_proof(digest)],
        }
        emit_anchor(
            "anchor_unknown_log",
            unknown_log,
            "anchor_roots.json",
            {
                "status": "INVALID",
                "proofs": ["FAILED"],
                "errors": ["ANCHOR_REKOR_LOG_UNKNOWN"],
            },
            "A well-formed proof from a log the reader did not pin.",
        )
        for case in anchor_cases:
            text = (OUT / case["anchor"]).read_text(encoding="utf-8")
            roots = roots_text if case["roots"] else ""
            check_anchor(
                case,
                json.loads(verify_anchor(text, json.dumps(checkpoint), roots)),
                json.loads(verify_bundle(bundle_text, gate_id, None, text, roots)),
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
            "anchor_bundle": "bundle.json",
            "anchor_cases": anchor_cases,
        }
        (OUT / "expected.json").write_text(
            json.dumps(expected, indent=2) + "\n", encoding="utf-8"
        )
        # The site's verify page offers the same bundle and key as loadable samples.
        site_data = ROOT / "site" / "data" / "evidence"
        site_data.mkdir(parents=True, exist_ok=True)
        for name in (
            "bundle.json",
            "bundle_tampered_decision.json",
            "anchor.json",
            "anchor_roots.json",
        ):
            (site_data / name).write_text(
                (OUT / name).read_text(encoding="utf-8"), encoding="utf-8"
            )
        (site_data / "gate_public_key.txt").write_text(gate_id + "\n", encoding="utf-8")
        del gate  # release the SQLite handle before the directory is removed
    print(f"wrote {len(cases)} cases to {OUT.relative_to(ROOT)} and site/data/evidence")
    return 0


def resign_authorization(permit: dict, gate_key: Path) -> None:
    """Sign what the permit now says with the gate's own key, as a lying gate would."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    authorization = permit["authorization"]
    authorization.pop("authorization_id")
    authorization.pop("gate_signature")
    canonical = json.dumps(authorization, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    private_key = json.loads(gate_key.read_text(encoding="utf-8"))["private_key"]
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    authorization["authorization_id"] = digest
    authorization["gate_signature"] = key.sign(bytes.fromhex(digest)).hex()


def check_anchor(case: dict, alone: dict, in_bundle: dict) -> None:
    """Assert an anchor case on its own and alongside the bundle it belongs to."""
    assert alone["schema_version"] == "tempus.anchor-verification.v1", case["anchor"]
    assert alone["status"] == case["status"], (case["anchor"], alone)
    assert [proof["status"] for proof in alone["proofs"]] == case["proofs"], (case["anchor"], alone)
    assert alone["errors"] == case["errors"], (case["anchor"], alone)
    assert (alone["anchored_at"] is not None) == (case["status"] == "VERIFIED"), case["anchor"]
    expected_check = {"VERIFIED": "VERIFIED", "NOT_CHECKED": "NOT_CHECKED", "INVALID": "FAILED"}
    assert in_bundle["checks"]["anchor"] == expected_check[case["status"]], (case["anchor"], in_bundle)
    assert in_bundle["status"] == ("INVALID" if case["status"] == "INVALID" else "VERIFIED"), (
        case["anchor"],
        in_bundle,
    )
    for code in case["errors"]:
        assert code in in_bundle["errors"], (case["anchor"], in_bundle)


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
