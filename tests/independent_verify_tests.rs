//! Independent verification: the verifier pins the gate public key out of band
//! and never trusts the root of trust stored in the database being verified.

use _tempus_ddb::{
    bundle_digest, generate_keypair, verify_bundle, verify_checkpoint, verify_receipt,
    SqliteStorage,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn public_key(path: &Path) -> String {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    value["public_key"].as_str().unwrap().to_string()
}

fn parse(value: &str) -> Value {
    serde_json::from_str(value).unwrap()
}

struct World {
    _temp: tempfile::TempDir,
    storage: SqliteStorage,
    gate_id: String,
    executor_id: String,
    action_id: String,
    permit: Value,
    outcome: Value,
    trace: Value,
    /// Private key values of the gate, agent and executor (must never leak).
    secrets: Vec<String>,
}

fn keyfile(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    generate_keypair(path.to_str().unwrap()).unwrap();
    path
}

/// A complete gate: its own gate/agent/executor keys, a permissive dev policy,
/// one purchase of `amount` USD, authorized and executed.
fn world(amount: &str) -> World {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let gate_key = keyfile(dir, "gate.keys.json");
    let agent_key = keyfile(dir, "agent.keys.json");
    let executor_key = keyfile(dir, "executor.keys.json");
    let (gate_id, agent_id, executor_id) = (
        public_key(&gate_key),
        public_key(&agent_key),
        public_key(&executor_key),
    );
    let storage = SqliteStorage::new(
        dir.join("tempus.db").to_str().unwrap().to_string(),
        gate_key.to_str().unwrap().to_string(),
    )
    .unwrap();
    storage
        .register_agent(&gate_id, "gate", r#"{"can_delegate":true}"#)
        .unwrap();
    storage.install_allow_all_dev_policy().unwrap();
    storage.register_agent(&agent_id, "agent", "{}").unwrap();
    storage
        .register_agent(&executor_id, "executor", "{}")
        .unwrap();
    let requested_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let intent = json!({
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "acme",
        "agent_id": agent_id,
        "idempotency_key": "pay-1",
        "action_type": "purchase",
        "resource": "vendor-api/credits",
        "requested_at": requested_at,
        "input": {"sku": "compute-credits"},
        "money": {"amount": amount, "asset": "USD", "beneficiary": "vendor-42"}
    });
    let permit = parse(
        &storage
            .request_action(&intent.to_string(), agent_key.to_str().unwrap(), 60)
            .unwrap(),
    );
    assert_eq!(permit["authorization"]["decision"], "ALLOWED");
    let authorization_id = permit["authorization"]["authorization_id"]
        .as_str()
        .unwrap()
        .to_string();
    let action_id = permit["authorization"]["action_id"]
        .as_str()
        .unwrap()
        .to_string();
    let outcome = parse(
        &storage
            .commit_outcome(
                &authorization_id,
                &json!({
                    "schema_version": "tempus.action-outcome.v1",
                    "authorization_id": authorization_id,
                    "action_id": action_id,
                    "status": "SUCCEEDED",
                    "external_reference": "vendor-tx-1",
                })
                .to_string(),
                executor_key.to_str().unwrap(),
            )
            .unwrap(),
    );
    let trace = parse(&storage.get_trace(&action_id).unwrap());
    let secrets = [&gate_key, &agent_key, &executor_key]
        .iter()
        .map(|path| {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            value["private_key"].as_str().unwrap().to_string()
        })
        .collect();
    World {
        _temp: temp,
        storage,
        gate_id,
        executor_id,
        action_id,
        permit,
        outcome,
        trace,
        secrets,
    }
}

type Mutation = Box<dyn Fn(&mut Value)>;

fn check(receipt: &Value, gate: &str, executors: &[String]) -> Value {
    parse(&verify_receipt(&receipt.to_string(), gate, executors).unwrap())
}

fn has_error(result: &Value, code: &str) -> bool {
    result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error == code)
}

#[test]
fn valid_receipts_verify_with_the_pinned_gate_key_and_no_database() {
    let w = world("25.00");
    for (receipt, kind) in [
        (&w.trace, "trace"),
        (&w.permit, "authorization"),
        (&w.outcome, "execution"),
    ] {
        let result = check(receipt, &w.gate_id, &[]);
        assert_eq!(result["status"], "VERIFIED", "{kind}: {result}");
        assert_eq!(result["kind"], kind);
        assert_eq!(result["trust"]["mode"], "PINNED_GATE_KEY");
        assert_eq!(result["trust"]["independent"], true);
    }
    // Pinning the executor as well still verifies.
    let result = check(&w.trace, &w.gate_id, std::slice::from_ref(&w.executor_id));
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["trust"]["executor_keys_pinned"], 1);
    // Upper-case hex of the pinned key is accepted.
    let result = check(&w.trace, &w.gate_id.to_uppercase(), &[]);
    assert_eq!(result["status"], "VERIFIED", "{result}");
    // The standalone outcome says what it could not link.
    let outcome = check(&w.outcome, &w.gate_id, &[]);
    let not_checked = outcome["trust"]["not_checked"].to_string();
    assert!(not_checked.contains("PERMIT_LINKAGE"), "{not_checked}");
}

#[test]
fn pinned_database_trace_verification_matches_the_standalone_verifier() {
    let w = world("25.00");
    let result = parse(
        &w.storage
            .verify_trace_pinned(&w.action_id, &w.gate_id, &[])
            .unwrap(),
    );
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["trust"]["independent"], true);
}

#[test]
fn legacy_database_verification_is_marked_not_independent() {
    let w = world("25.00");
    let result = parse(&w.storage.verify_trace(&w.action_id).unwrap());
    assert_eq!(result["status"], "VERIFIED");
    assert_eq!(result["trust"]["independent"], false);
    assert_eq!(result["trust"]["mode"], "DATABASE_SELF_ATTESTED");
}

#[test]
fn fully_forged_database_verifies_against_itself_but_not_against_the_real_gate_key() {
    let real = world("25.00");
    // The attacker builds a complete, internally consistent gate with its own
    // keys and a fake $9,999 payment.
    let forged = world("9999.00");
    assert_ne!(real.gate_id, forged.gate_id);

    // Old behaviour: the forged DB is VERIFIED because it vouches for itself.
    let self_attested = parse(&forged.storage.verify_trace(&forged.action_id).unwrap());
    assert_eq!(self_attested["status"], "VERIFIED");
    assert_eq!(self_attested["trust"]["independent"], false);

    // With the real gate key pinned, the same forged evidence is INVALID.
    let pinned_db = parse(
        &forged
            .storage
            .verify_trace_pinned(&forged.action_id, &real.gate_id, &[])
            .unwrap(),
    );
    assert_eq!(pinned_db["status"], "INVALID", "{pinned_db}");
    assert!(has_error(&pinned_db, "GATE_KEY_NOT_PINNED"));
    let pinned_doc = check(&forged.trace, &real.gate_id, &[]);
    assert_eq!(pinned_doc["status"], "INVALID", "{pinned_doc}");
    assert!(has_error(&pinned_doc, "GATE_KEY_NOT_PINNED"));
    assert!(has_error(&pinned_doc, "EXECUTION_GATE_KEY_NOT_PINNED"));
}

#[test]
fn forger_cannot_relabel_a_forged_receipt_with_the_real_gate_id() {
    let real = world("25.00");
    let forged = world("9999.00");
    let text = forged
        .trace
        .to_string()
        .replace(&forged.gate_id, &real.gate_id);
    let result = parse(&verify_receipt(&text, &real.gate_id, &[]).unwrap());
    assert_eq!(result["status"], "INVALID", "{result}");
}

#[test]
fn wrong_gate_public_key_is_invalid() {
    let w = world("25.00");
    let other = world("1.00");
    for receipt in [&w.trace, &w.permit, &w.outcome] {
        let result = check(receipt, &other.gate_id, &[]);
        assert_eq!(result["status"], "INVALID", "{result}");
    }
    assert!(verify_receipt(&w.trace.to_string(), "not-hex", &[]).is_err());
    assert!(verify_receipt(&w.trace.to_string(), "abcd", &[]).is_err());
}

#[test]
fn wrong_executor_public_key_is_invalid() {
    let w = world("25.00");
    let other = world("1.00");
    let result = check(
        &w.trace,
        &w.gate_id,
        std::slice::from_ref(&other.executor_id),
    );
    assert_eq!(result["status"], "INVALID", "{result}");
    assert!(has_error(&result, "EXECUTOR_KEY_NOT_PINNED"));
}

#[test]
fn tampered_receipts_are_invalid() {
    let w = world("25.00");
    for path in [
        "/authorization/intent/money/amount",
        "/authorization/authorization/decision",
        "/authorization/authorization/expires_at",
        "/execution/outcome/status",
        "/execution/outcome/external_reference",
        "/execution/receipt/status",
        "/execution/receipt/gate_signature",
    ] {
        assert!(
            w.trace.pointer(path).is_some(),
            "trace shape changed: {path}"
        );
    }
    let mutations: Vec<(&str, Mutation)> = vec![
        (
            "amount in the signed intent",
            Box::new(|v| v["authorization"]["intent"]["money"]["amount"] = json!("9999.00")),
        ),
        (
            "decision flipped",
            Box::new(|v| v["authorization"]["authorization"]["decision"] = json!("BLOCKED")),
        ),
        (
            "permit expiry extended",
            Box::new(|v| v["authorization"]["authorization"]["expires_at"] = json!(u64::MAX / 4)),
        ),
        (
            "outcome status",
            Box::new(|v| v["execution"]["outcome"]["status"] = json!("FAILED")),
        ),
        (
            "outcome reference",
            Box::new(|v| v["execution"]["outcome"]["external_reference"] = json!("tx-forged")),
        ),
        (
            "receipt status",
            Box::new(|v| v["execution"]["receipt"]["status"] = json!("FAILED")),
        ),
        (
            "gate signature",
            Box::new(|v| {
                let sig = v["execution"]["receipt"]["gate_signature"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let flipped = if sig.starts_with('0') { "1" } else { "0" };
                v["execution"]["receipt"]["gate_signature"] =
                    json!(format!("{flipped}{}", &sig[1..]));
            }),
        ),
    ];
    for (label, mutate) in mutations {
        let mut trace = w.trace.clone();
        mutate(&mut trace);
        let result = check(&trace, &w.gate_id, &[]);
        assert_eq!(result["status"], "INVALID", "{label}: {result}");
    }
    // Same for the standalone documents.
    let mut permit = w.permit.clone();
    permit["intent"]["money"]["amount"] = json!("9999.00");
    assert_eq!(check(&permit, &w.gate_id, &[])["status"], "INVALID");
    let mut outcome = w.outcome.clone();
    outcome["outcome"]["external_reference"] = json!("tx-forged");
    assert_eq!(check(&outcome, &w.gate_id, &[])["status"], "INVALID");
}

#[test]
fn unknown_or_malformed_receipts_are_errors_not_verified() {
    let w = world("25.00");
    assert!(verify_receipt("{}", &w.gate_id, &[])
        .unwrap_err()
        .contains("TEMPUS_RECEIPT_SCHEMA_UNKNOWN"));
    assert!(verify_receipt("not json", &w.gate_id, &[]).is_err());
    let mut stripped = w.trace.clone();
    stripped["authorization"] = Value::Null;
    assert_eq!(check(&stripped, &w.gate_id, &[])["status"], "INVALID");
}

#[test]
fn checkpoint_verification_requires_the_pinned_public_key() {
    let w = world("25.00");
    let other = world("1.00");
    let checkpoint = w.storage.create_checkpoint("acme").unwrap();
    let stream = w.storage.export_event_stream("acme", 1, 1000).unwrap();
    let ok = parse(&verify_checkpoint(&checkpoint, &stream, &w.gate_id).unwrap());
    assert_eq!(ok["status"], "VERIFIED", "{ok}");
    let wrong = parse(&verify_checkpoint(&checkpoint, &stream, &other.gate_id).unwrap());
    assert_eq!(wrong["status"], "INVALID", "{wrong}");
    assert!(verify_checkpoint(&checkpoint, &stream, "zz").is_err());
}

// ---- evidence bundles -------------------------------------------------------

fn export(w: &World) -> Value {
    parse(&w.storage.export_bundle(&w.action_id, None).unwrap())
}

fn check_bundle(bundle: &Value, gate: &str, executors: &[String]) -> Value {
    parse(&verify_bundle(&bundle.to_string(), gate, executors).unwrap())
}

#[test]
fn bundle_without_checkpoint_verifies_and_says_what_it_cannot_show() {
    let w = world("25.00");
    let bundle = export(&w);
    assert_eq!(bundle["schema_version"], "tempus.evidence-bundle.v1");
    assert!(bundle["checkpoint"].is_null());
    let result = check_bundle(&bundle, &w.gate_id, &[]);
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["kind"], "bundle");
    assert_eq!(result["checks"]["checkpoint"], "NOT_PRESENT");
    let not_checked = result["trust"]["not_checked"].to_string();
    assert!(not_checked.contains("LEDGER_INCLUSION"), "{not_checked}");
    assert!(not_checked.contains("COMPLETENESS"), "{not_checked}");
    let pinned = check_bundle(&bundle, &w.gate_id, std::slice::from_ref(&w.executor_id));
    assert_eq!(pinned["status"], "VERIFIED", "{pinned}");
}

#[test]
fn bundle_with_checkpoint_proves_ledger_inclusion() {
    let w = world("25.00");
    w.storage.create_checkpoint("acme").unwrap();
    let bundle = export(&w);
    assert!(bundle["checkpoint"]["checkpoint"].is_object());
    assert!(bundle["checkpoint"]["stream"].is_array());
    let result = check_bundle(&bundle, &w.gate_id, &[]);
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["checks"]["checkpoint"], "VERIFIED");
    let not_checked = result["trust"]["not_checked"].to_string();
    assert!(!not_checked.contains("LEDGER_INCLUSION"), "{not_checked}");
}

#[test]
fn oversized_streams_are_omitted_not_truncated() {
    let w = world("25.00");
    w.storage.create_checkpoint("acme").unwrap();
    assert!(export(&w)["checkpoint"].is_object());
    let capped = parse(&w.storage.export_bundle(&w.action_id, Some(1)).unwrap());
    assert!(capped["checkpoint"].is_null());
}

#[test]
fn bundle_of_a_forged_database_is_invalid_with_the_real_key() {
    let real = world("25.00");
    let plain = world("9999.00");
    let with_checkpoint = world("9999.00");
    with_checkpoint.storage.create_checkpoint("acme").unwrap();
    for forged in [&plain, &with_checkpoint] {
        let bundle = export(forged);
        // Self-consistent for the attacker's own key...
        let own = check_bundle(&bundle, &forged.gate_id, &[]);
        assert_eq!(own["status"], "VERIFIED", "{own}");
        // ...but not for the real gate key.
        let result = check_bundle(&bundle, &real.gate_id, &[]);
        assert_eq!(result["status"], "INVALID", "{result}");
        assert!(has_error(&result, "GATE_KEY_NOT_PINNED"));
    }
    let result = check_bundle(&export(&with_checkpoint), &real.gate_id, &[]);
    assert!(has_error(&result, "CHECKPOINT_ERR_UNTRUSTED_SIGNER"));
}

#[test]
fn bundle_with_the_wrong_keys_is_invalid() {
    let w = world("25.00");
    w.storage.create_checkpoint("acme").unwrap();
    let other = world("1.00");
    let bundle = export(&w);
    assert_eq!(
        check_bundle(&bundle, &other.gate_id, &[])["status"],
        "INVALID"
    );
    let result = check_bundle(
        &bundle,
        &w.gate_id,
        std::slice::from_ref(&other.executor_id),
    );
    assert_eq!(result["status"], "INVALID");
    assert!(has_error(&result, "EXECUTOR_KEY_NOT_PINNED"));
    assert!(verify_bundle(&bundle.to_string(), "zz", &[]).is_err());
}

#[test]
fn every_tampered_bundle_field_is_invalid() {
    let w = world("25.00");
    w.storage.create_checkpoint("acme").unwrap();
    let bundle = export(&w);
    assert_eq!(check_bundle(&bundle, &w.gate_id, &[])["status"], "VERIFIED");

    // A stale checkpoint (taken before this action) must not pass as proof of inclusion.
    let early = world("5.00");
    early.storage.create_checkpoint("acme").unwrap();
    let early_bundle = export(&early);
    let mut swapped = bundle.clone();
    swapped["checkpoint"] = early_bundle["checkpoint"].clone();

    let flip = |sig: &str| {
        let first = if sig.starts_with('0') { "1" } else { "0" };
        format!("{first}{}", &sig[1..])
    };
    let mutations: Vec<(&str, Mutation)> = vec![
        (
            "bundle action_id",
            Box::new(|b| b["action_id"] = json!("00")),
        ),
        (
            "trace action_id wrapper",
            Box::new(|b| b["trace"]["action_id"] = json!("00")),
        ),
        (
            "intent amount",
            Box::new(|b| {
                b["trace"]["authorization"]["intent"]["money"]["amount"] = json!("9999.00")
            }),
        ),
        (
            "permit decision",
            Box::new(|b| {
                b["trace"]["authorization"]["authorization"]["decision"] = json!("BLOCKED")
            }),
        ),
        (
            "permit expiry",
            Box::new(|b| {
                b["trace"]["authorization"]["authorization"]["expires_at"] = json!(u64::MAX / 4)
            }),
        ),
        (
            "policy constraints",
            Box::new(|b| {
                b["trace"]["authorization"]["policy_bundle"]["constraints"]["max_ttl_seconds"] =
                    json!(999_999)
            }),
        ),
        (
            "policy signature",
            Box::new(move |b| {
                let sig = b["trace"]["authorization"]["policy_bundle"]["signature"]
                    .as_str()
                    .unwrap()
                    .to_string();
                b["trace"]["authorization"]["policy_bundle"]["signature"] = json!(flip(&sig));
            }),
        ),
        (
            "agent signature",
            Box::new(|b| b["trace"]["authorization"]["agent_signature"] = json!("00".repeat(64))),
        ),
        (
            "outcome status",
            Box::new(|b| b["trace"]["execution"]["outcome"]["status"] = json!("FAILED")),
        ),
        (
            "outcome reference",
            Box::new(|b| {
                b["trace"]["execution"]["outcome"]["external_reference"] = json!("tx-forged")
            }),
        ),
        (
            "receipt status",
            Box::new(|b| b["trace"]["execution"]["receipt"]["status"] = json!("FAILED")),
        ),
        (
            "checkpoint root hash",
            Box::new(|b| {
                b["checkpoint"]["checkpoint"]["stream_root_hash"] = json!("00".repeat(32))
            }),
        ),
        (
            "checkpoint signature",
            Box::new(|b| b["checkpoint"]["checkpoint"]["signature"] = json!("00".repeat(64))),
        ),
        (
            "checkpoint tenant",
            Box::new(|b| b["checkpoint"]["checkpoint"]["tenant_id"] = json!("other")),
        ),
        (
            "stream event payload hash",
            Box::new(|b| b["checkpoint"]["stream"][0]["payload_hash"] = json!("00".repeat(32))),
        ),
        (
            "stream event dropped",
            Box::new(|b| {
                b["checkpoint"]["stream"].as_array_mut().unwrap().remove(0);
            }),
        ),
        (
            "stream truncated",
            Box::new(|b| {
                b["checkpoint"]["stream"].as_array_mut().unwrap().pop();
            }),
        ),
    ];
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for (label, mutate) in mutations {
        let mut mutated = bundle.clone();
        mutate(&mut mutated);
        cases.push((label, mutated));
    }
    cases.push(("checkpoint swapped for an unrelated one", swapped));
    for (label, mutated) in cases {
        let result = check_bundle(&mutated, &w.gate_id, &[]);
        assert_eq!(result["status"], "INVALID", "{label}: {result}");
    }
}

#[test]
fn bundle_never_contains_private_key_material() {
    let w = world("25.00");
    w.storage.create_checkpoint("acme").unwrap();
    let text = w.storage.export_bundle(&w.action_id, None).unwrap();
    assert!(!text.contains("private_key"));
    for secret in &w.secrets {
        assert!(secret.len() >= 64);
        assert!(
            !text.contains(secret.as_str()),
            "bundle leaks a private key"
        );
    }
    // Public identities are expected to be present.
    assert!(text.contains(&w.gate_id));
}

#[test]
fn unknown_bundle_schema_is_an_error() {
    let w = world("25.00");
    assert!(verify_bundle("{}", &w.gate_id, &[])
        .unwrap_err()
        .contains("TEMPUS_BUNDLE_SCHEMA_UNKNOWN"));
    assert!(verify_bundle("nope", &w.gate_id, &[]).is_err());
    let mut bundle = export(&w);
    bundle.as_object_mut().unwrap().remove("trace");
    assert!(verify_bundle(&bundle.to_string(), &w.gate_id, &[]).is_err());
}

#[test]
fn omitting_the_outcome_is_not_detectable_and_is_reported_as_phase_authorized() {
    // Documented limit: a bundle that simply leaves out the outcome is a valid
    // permit-only bundle. The verifier reports what is present (execution
    // NOT_PRESENT, phase AUTHORIZED/EXPIRED); it cannot prove nothing was hidden.
    let w = world("25.00");
    w.storage.create_checkpoint("acme").unwrap();
    let mut bundle = export(&w);
    bundle["trace"]["execution"] = Value::Null;
    // The verify link is unsigned, so whoever strips the outcome can drop it too.
    bundle.as_object_mut().unwrap().remove("verify_url");
    let result = check_bundle(&bundle, &w.gate_id, &[]);
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["checks"]["execution"], "NOT_PRESENT");
    assert_ne!(result["phase"], "COMPLETED");
    assert!(result["trust"]["not_checked"]
        .to_string()
        .contains("COMPLETENESS"));
}

#[test]
fn bundle_verify_url_names_the_bundle_digest_and_the_public_verifier() {
    let w = world("25.00");
    let text = w.storage.export_bundle(&w.action_id, None).unwrap();
    let bundle = parse(&text);
    let digest = bundle_digest(&text).unwrap();
    assert_eq!(digest.len(), 64);
    assert_eq!(
        bundle["verify_url"],
        json!(format!(
            "https://tempus-protocol.github.io/tempus-ddb/verify.html#bundle={digest}"
        ))
    );
    let result = check_bundle(&bundle, &w.gate_id, &[]);
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["bundle_digest"], json!(digest));
    assert_eq!(result["verify_url"], bundle["verify_url"]);

    // Without the link the bundle is still complete evidence.
    let mut unlinked = bundle.clone();
    unlinked.as_object_mut().unwrap().remove("verify_url");
    let result = check_bundle(&unlinked, &w.gate_id, &[]);
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["bundle_digest"], json!(digest));
    assert!(result.get("verify_url").is_none());
}

#[test]
fn bundle_whose_content_no_longer_matches_its_verify_url_is_invalid() {
    let w = world("25.00");
    w.storage.create_checkpoint("acme").unwrap();
    let mut bundle = export(&w);
    bundle["trace"]["execution"] = Value::Null;
    let result = check_bundle(&bundle, &w.gate_id, &[]);
    assert_eq!(result["status"], "INVALID", "{result}");
    assert!(result["errors"]
        .as_array()
        .unwrap()
        .contains(&json!("BUNDLE_VERIFY_URL_MISMATCH")));

    let mut bundle = export(&w);
    bundle["verify_url"] = json!("https://example.com/verify.html");
    let result = check_bundle(&bundle, &w.gate_id, &[]);
    assert_eq!(result["status"], "INVALID", "{result}");
    assert!(result["errors"]
        .as_array()
        .unwrap()
        .contains(&json!("BUNDLE_VERIFY_URL_INVALID")));

    let mut bundle = export(&w);
    bundle["verify_url"] = json!(42);
    let result = check_bundle(&bundle, &w.gate_id, &[]);
    assert_eq!(result["status"], "INVALID", "{result}");
}

#[test]
fn receipts_carry_a_signed_verify_url_for_their_action() {
    let w = world("25.00");
    let trace = parse(&w.storage.get_trace(&w.action_id).unwrap());
    let expected = format!(
        "https://tempus-protocol.github.io/tempus-ddb/verify.html#action={}",
        w.action_id
    );
    assert_eq!(
        trace["authorization"]["authorization"]["verify_url"],
        json!(expected)
    );
    assert_eq!(trace["execution"]["receipt"]["verify_url"], json!(expected));
    // The link is inside the signed body: changing it breaks the gate signature.
    let mut forged = trace.clone();
    forged["authorization"]["authorization"]["verify_url"] = json!("https://evil.example/v");
    let result = parse(&verify_receipt(&forged.to_string(), &w.gate_id, &[]).unwrap());
    assert_eq!(result["status"], "INVALID", "{result}");
}
