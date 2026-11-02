//! End-to-end flow through the internal dev CLI (`tempus-ddb`): keys, gate, agent and
//! executor registration, a permit, an outcome, and independent verification of the
//! exported evidence against the pinned gate key.

use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

fn run_cli(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_tempus-ddb"))
        .args(args)
        .output()
        .expect("Failed to execute process");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), stdout, stderr)
}

fn public_key(path: &Path) -> String {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    value["public_key"].as_str().unwrap().to_string()
}

#[test]
fn test_end_to_end_flow() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("tempus.db");
    let db = db.to_str().unwrap();
    let gate_key = dir.path().join("gate.keys.json");
    let agent_key = dir.path().join("agent.keys.json");
    let executor_key = dir.path().join("executor.keys.json");
    let gate_key_s = gate_key.to_str().unwrap();
    let agent_key_s = agent_key.to_str().unwrap();
    let executor_key_s = executor_key.to_str().unwrap();

    let (success, _, stderr) = run_cli(&["init", "--db", db]);
    assert!(success, "Init failed: {stderr}");
    for key in [gate_key_s, agent_key_s, executor_key_s] {
        let (success, stdout, stderr) = run_cli(&["gen-keys", "--output", key]);
        assert!(success, "Gen keys failed: {stderr}");
        let printed: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(printed["public_key"].as_str().unwrap().len(), 64);
        assert!(
            !stdout.contains("private_key"),
            "stdout leaks the private key"
        );
    }
    let (gate_id, agent_id, executor_id) = (
        public_key(&gate_key),
        public_key(&agent_key),
        public_key(&executor_key),
    );

    // The gate registers itself as a delegating identity, then its policy and agents.
    for (key, alias, metadata) in [
        (&gate_id, "gate", r#"{"can_delegate":true}"#),
        (&agent_id, "agent", "{}"),
        (&executor_id, "executor", "{}"),
    ] {
        let (success, _, stderr) = run_cli(&[
            "register-agent",
            "--db",
            db,
            "--keyfile",
            gate_key_s,
            "--public-key",
            key,
            "--alias",
            alias,
            "--metadata",
            metadata,
        ]);
        assert!(success, "register-agent {alias} failed: {stderr}");
    }
    let (success, _, stderr) = run_cli(&[
        "install-allow-all-dev",
        "--db",
        db,
        "--gate-keyfile",
        gate_key_s,
    ]);
    assert!(success, "install-allow-all-dev failed: {stderr}");
    let (success, stdout, _) = run_cli(&["list-agents", "--db", db]);
    assert!(success);
    let agents: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(agents.as_array().unwrap().len(), 3);

    // Permit.
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
        "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"}
    })
    .to_string();
    let (success, stdout, stderr) = run_cli(&[
        "request-action",
        "--db",
        db,
        "--gate-keyfile",
        gate_key_s,
        "--agent-keyfile",
        agent_key_s,
        "--intent",
        &intent,
    ]);
    assert!(success, "request-action failed: {stderr}");
    let permit: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(permit["authorization"]["decision"], "ALLOWED");
    let authorization_id = permit["authorization"]["authorization_id"]
        .as_str()
        .unwrap()
        .to_string();
    let action_id = permit["authorization"]["action_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        permit["authorization"]["verify_url"],
        json!(format!(
            "https://tempus-protocol.github.io/tempus-ddb/verify.html#action={action_id}"
        ))
    );

    // Outcome. Re-committing the identical outcome is idempotent; a different
    // outcome for the same permit must be refused (single use).
    let outcome_for = |reference: &str| {
        json!({
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": authorization_id,
            "action_id": action_id,
            "status": "SUCCEEDED",
            "external_reference": reference,
        })
        .to_string()
    };
    let commit = |outcome: &str| {
        run_cli(&[
            "commit-outcome",
            "--db",
            db,
            "--gate-keyfile",
            gate_key_s,
            "--authorization-id",
            &authorization_id,
            "--outcome",
            outcome,
            "--executor-keyfile",
            executor_key_s,
        ])
    };
    let first = outcome_for("vendor-tx-1");
    assert!(commit(&first).0, "commit-outcome failed");
    assert!(
        commit(&first).0,
        "re-committing the same outcome is idempotent"
    );
    let (success, _, stderr) = commit(&outcome_for("vendor-tx-2"));
    assert!(!success, "a permit must be single use");
    assert!(
        stderr.contains("TEMPUS_PERMIT_ALREADY_CONSUMED"),
        "unexpected refusal: {stderr}"
    );

    // Trace from the database, verified independently against the pinned gate key.
    let (success, stdout, stderr) = run_cli(&[
        "verify-trace",
        "--db",
        db,
        "--gate-keyfile",
        gate_key_s,
        "--action-id",
        &action_id,
        "--gate-public-key",
        &gate_id,
        "--executor-public-key",
        &executor_id,
    ]);
    assert!(success, "verify-trace failed: {stderr}");
    let verdict: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(verdict["status"], "VERIFIED", "{verdict}");
    assert_eq!(verdict["phase"], "COMPLETED");
    assert_eq!(verdict["trust"]["independent"], true);

    // Evidence bundle: exported once, verified with no database at all.
    let bundle_path = dir.path().join("evidence.json");
    let bundle_path = bundle_path.to_str().unwrap();
    let (success, _, stderr) = run_cli(&[
        "export-bundle",
        "--db",
        db,
        "--gate-keyfile",
        gate_key_s,
        "--action-id",
        &action_id,
        "--out",
        bundle_path,
    ]);
    assert!(success, "export-bundle failed: {stderr}");
    let bundle_text = std::fs::read_to_string(bundle_path).unwrap();
    assert!(!bundle_text.contains("private_key"));
    let bundle: Value = serde_json::from_str(&bundle_text).unwrap();
    assert_eq!(bundle["schema_version"], "tempus.evidence-bundle.v1");
    let digest = _tempus_ddb::bundle_digest(&bundle_text).unwrap();
    assert_eq!(
        bundle["verify_url"],
        json!(format!(
            "https://tempus-protocol.github.io/tempus-ddb/verify.html#bundle={digest}"
        ))
    );

    let (success, stdout, stderr) = run_cli(&[
        "verify-bundle",
        "--bundle",
        bundle_path,
        "--gate-public-key",
        &gate_id,
    ]);
    assert!(success, "verify-bundle failed: {stderr}");
    let verdict: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(verdict["status"], "VERIFIED", "{verdict}");
    assert_eq!(verdict["bundle_digest"], json!(digest));

    // Wrong pinned key: the same file is INVALID and the CLI exits non-zero.
    let other = public_key(&agent_key);
    let (success, stdout, _) = run_cli(&[
        "verify-bundle",
        "--bundle",
        bundle_path,
        "--gate-public-key",
        &other,
    ]);
    assert!(!success, "verification with the wrong key must fail");
    let verdict: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(verdict["status"], "INVALID", "{verdict}");

    // A tampered file is INVALID even when its verify_url is left in place.
    let mut tampered = bundle.clone();
    tampered["trace"]["authorization"]["authorization"]["decision"] = json!("DENIED");
    let tampered_path = dir.path().join("tampered.json");
    std::fs::write(&tampered_path, tampered.to_string()).unwrap();
    let (success, stdout, _) = run_cli(&[
        "verify-bundle",
        "--bundle",
        tampered_path.to_str().unwrap(),
        "--gate-public-key",
        &gate_id,
    ]);
    assert!(!success, "a tampered bundle must not verify");
    let verdict: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(verdict["status"], "INVALID", "{verdict}");
    let errors = verdict["errors"].to_string();
    assert!(errors.contains("AUTHORIZATION_ID_MISMATCH"), "{errors}");
    assert!(errors.contains("BUNDLE_VERIFY_URL_MISMATCH"), "{errors}");
}
