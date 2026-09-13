use _tempus_ddb::{generate_keypair, SqliteStorage};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn public_key(path: &Path) -> String {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    value["public_key"].as_str().unwrap().to_string()
}

fn parse(value: &str) -> Value {
    serde_json::from_str(value).unwrap()
}

fn intent(agent_id: &str, idempotency_key: &str, resource: &str) -> String {
    let requested_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    json!({
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "acme",
        "agent_id": agent_id,
        "idempotency_key": idempotency_key,
        "action_type": "purchase",
        "resource": resource,
        "requested_at": requested_at,
        "input": {"sku": "compute-credits"},
        "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"}
    })
    .to_string()
}

#[test]
fn b2a_authorize_execute_verify_and_replay_guards() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("tempus.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_keyfile = temp.path().join("agent.keys.json");
    let executor_keyfile = temp.path().join("executor.keys.json");
    let other_keyfile = temp.path().join("other.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(executor_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(other_keyfile.to_str().unwrap()).unwrap();

    let gate_id = public_key(&gate_keyfile);
    let agent_id = public_key(&agent_keyfile);
    let executor_id = public_key(&executor_keyfile);
    let other_id = public_key(&other_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();

    let root = parse(
        &storage
            .register_agent(&gate_id, "tempus-gate", r#"{"can_delegate":true}"#)
            .unwrap(),
    );
    assert_eq!(root["registration"]["registered_by"], gate_id);
    assert!(storage.verify_agent(&gate_id).unwrap());
    storage
        .register_agent(&agent_id, "buyer-agent", "{}")
        .unwrap();
    storage
        .register_agent(&executor_id, "purchase-executor", "{}")
        .unwrap();
    assert!(storage.verify_agent(&agent_id).unwrap());
    assert!(storage
        .register_agent(&agent_id, "renamed-agent", "{}")
        .unwrap_err()
        .contains("TEMPUS_AGENT_ALREADY_REGISTERED"));

    let request = intent(&agent_id, "purchase-001", "vendor-api/credits");
    let authorization_json = storage
        .request_action(&request, agent_keyfile.to_str().unwrap(), 60)
        .unwrap();
    let authorization = parse(&authorization_json);
    assert_eq!(
        authorization["schema_version"],
        "tempus.authorization-result.v1"
    );
    assert_eq!(authorization["authorization"]["decision"], "ALLOWED");
    let authorization_id = authorization["authorization"]["authorization_id"]
        .as_str()
        .unwrap();
    let action_id = authorization["authorization"]["action_id"]
        .as_str()
        .unwrap();

    let duplicate = storage
        .request_action(&request, agent_keyfile.to_str().unwrap(), 60)
        .unwrap();
    assert_eq!(
        parse(&duplicate)["authorization"]["authorization_id"],
        authorization_id
    );
    let conflict = intent(&agent_id, "purchase-001", "different-resource");
    assert!(storage
        .request_action(&conflict, agent_keyfile.to_str().unwrap(), 60)
        .unwrap_err()
        .contains("TEMPUS_IDEMPOTENCY_CONFLICT"));

    let outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": authorization_id,
        "action_id": action_id,
        "status": "SUCCEEDED",
        "external_reference": "vendor-tx-9182",
        "output": {"credits_added": 1000}
    })
    .to_string();
    let execution_json = storage
        .commit_outcome(
            authorization_id,
            &outcome,
            executor_keyfile.to_str().unwrap(),
        )
        .unwrap();
    let execution = parse(&execution_json);
    assert_eq!(execution["receipt"]["status"], "SUCCEEDED");

    let duplicate_execution = storage
        .commit_outcome(
            authorization_id,
            &outcome,
            executor_keyfile.to_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        parse(&duplicate_execution)["receipt"]["receipt_id"],
        execution["receipt"]["receipt_id"]
    );
    let conflicting_outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": authorization_id,
        "action_id": action_id,
        "status": "FAILED",
        "error": "late conflicting result"
    })
    .to_string();
    assert!(storage
        .commit_outcome(
            authorization_id,
            &conflicting_outcome,
            executor_keyfile.to_str().unwrap(),
        )
        .unwrap_err()
        .contains("TEMPUS_PERMIT_ALREADY_CONSUMED"));

    let verification = parse(&storage.verify_trace(action_id).unwrap());
    assert_eq!(verification["status"], "VERIFIED");
    assert_eq!(verification["phase"], "COMPLETED");
    let trace = parse(&storage.get_trace(action_id).unwrap());
    assert_eq!(trace["execution"]["receipt"]["executor_id"], executor_id);

    let unregistered_intent = intent(&other_id, "unregistered-001", "email/send");
    let blocked = parse(
        &storage
            .request_action(&unregistered_intent, other_keyfile.to_str().unwrap(), 60)
            .unwrap(),
    );
    assert_eq!(blocked["authorization"]["decision"], "BLOCKED");
    let blocked_action = blocked["authorization"]["action_id"].as_str().unwrap();
    let blocked_verification = parse(&storage.verify_trace(blocked_action).unwrap());
    assert_eq!(blocked_verification["status"], "VERIFIED");
    assert_eq!(blocked_verification["phase"], "BLOCKED");

    let stale_intent = json!({
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "acme",
        "agent_id": agent_id,
        "idempotency_key": "stale-001",
        "action_type": "send_email",
        "resource": "mail/outbox",
        "requested_at": 1,
        "input": {}
    })
    .to_string();
    let stale = parse(
        &storage
            .request_action(&stale_intent, agent_keyfile.to_str().unwrap(), 60)
            .unwrap(),
    );
    assert_eq!(stale["authorization"]["decision"], "BLOCKED");
    assert_eq!(stale["authorization"]["reason_codes"][0], "REQUEST_STALE");

    let invalid_signature_intent = intent(&agent_id, "invalid-signature-001", "mail/outbox");
    let invalid_signature = parse(
        &storage
            .request_action_signed(&invalid_signature_intent, &agent_id, &"00".repeat(64), 60)
            .unwrap(),
    );
    assert_eq!(invalid_signature["authorization"]["decision"], "BLOCKED");
    let invalid_signature_action = invalid_signature["authorization"]["action_id"]
        .as_str()
        .unwrap();
    assert_eq!(
        parse(&storage.verify_trace(invalid_signature_action).unwrap())["status"],
        "VERIFIED"
    );

    let agent_storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        agent_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();
    assert!(agent_storage
        .register_agent(&other_id, "unauthorized-delegation", "{}")
        .unwrap_err()
        .contains("TEMPUS_REGISTRAR_NOT_AUTHORIZED"));
}

#[test]
fn trace_verification_detects_receipt_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("tempus.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_keyfile = temp.path().join("agent.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();
    let gate_id = public_key(&gate_keyfile);
    let agent_id = public_key(&agent_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();
    storage.register_agent(&gate_id, "gate", "{}").unwrap();
    storage.register_agent(&agent_id, "agent", "{}").unwrap();
    let authorization = parse(
        &storage
            .request_action(
                &intent(&agent_id, "tamper-001", "calendar/create"),
                agent_keyfile.to_str().unwrap(),
                60,
            )
            .unwrap(),
    );
    let action_id = authorization["authorization"]["action_id"]
        .as_str()
        .unwrap();

    let connection = Connection::open(&db_path).unwrap();
    connection
        .execute(
            "UPDATE action_authorizations
             SET authorization_json = replace(authorization_json, 'POLICY_ALLOWED', 'POLICY_BYPASSED')
             WHERE action_id = ?1",
            [action_id],
        )
        .unwrap();
    let verification = parse(&storage.verify_trace(action_id).unwrap());
    assert_eq!(verification["status"], "INVALID");
    assert!(verification["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error == "AUTHORIZATION_ID_MISMATCH"));
}

#[test]
fn phase2_receipts_remain_historically_verifiable_but_not_consumable() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("migration.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_keyfile = temp.path().join("agent.keys.json");
    let executor_keyfile = temp.path().join("executor.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(executor_keyfile.to_str().unwrap()).unwrap();
    let gate_id = public_key(&gate_keyfile);
    let agent_id = public_key(&agent_keyfile);
    let executor_id = public_key(&executor_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();
    storage.register_agent(&gate_id, "gate", "{}").unwrap();
    storage.register_agent(&agent_id, "agent", "{}").unwrap();
    storage
        .register_agent(&executor_id, "executor", "{}")
        .unwrap();
    let mut result = parse(
        &storage
            .request_action(
                &intent(&agent_id, "phase2-history", "legacy/resource"),
                agent_keyfile.to_str().unwrap(),
                60,
            )
            .unwrap(),
    );
    let action_id = result["authorization"]["action_id"]
        .as_str()
        .unwrap()
        .to_string();
    let old_authorization_id = result["authorization"]["authorization_id"]
        .as_str()
        .unwrap()
        .to_string();
    result.as_object_mut().unwrap().remove("policy_bundle");
    let authorization = result["authorization"].as_object_mut().unwrap();
    authorization.remove("authorization_id");
    authorization.remove("gate_signature");
    authorization.remove("policy_digest");
    authorization.remove("evidence_digest");
    authorization.remove("executor_constraints");
    authorization.remove("gate_signer");
    authorization.insert(
        "policy_version".to_string(),
        json!("tempus.identity-gate.v1"),
    );
    let authorization_body = serde_json::to_string(&result["authorization"]).unwrap();
    let authorization_id = hex::encode(Sha256::digest(authorization_body.as_bytes()));
    let key_value: Value =
        serde_json::from_str(&std::fs::read_to_string(&gate_keyfile).unwrap()).unwrap();
    let private_bytes: [u8; 32] = hex::decode(key_value["private_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let gate_key = SigningKey::from_bytes(&private_bytes);
    let signature = gate_key.sign(&hex::decode(&authorization_id).unwrap());
    result["authorization"]["authorization_id"] = json!(authorization_id);
    result["authorization"]["gate_signature"] = json!(hex::encode(signature.to_bytes()));
    let legacy_json = serde_json::to_string(&result).unwrap();
    let connection = Connection::open(&db_path).unwrap();
    connection
        .execute(
            "UPDATE action_authorizations
             SET authorization_id = ?1, authorization_json = ?2
             WHERE authorization_id = ?3",
            rusqlite::params![authorization_id, legacy_json, old_authorization_id],
        )
        .unwrap();

    let verification = parse(&storage.verify_trace(&action_id).unwrap());
    assert_eq!(verification["status"], "VERIFIED");
    let outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": authorization_id,
        "action_id": action_id,
        "status": "SUCCEEDED",
        "output": {}
    })
    .to_string();
    assert!(storage
        .commit_outcome(
            &authorization_id,
            &outcome,
            executor_keyfile.to_str().unwrap()
        )
        .unwrap_err()
        .contains("TEMPUS_POLICY_BUNDLE_MISSING"));
}

#[test]
fn phase3_policy_rotation_and_emergency_revocation_are_enforced() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("phase3.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_v1_keyfile = temp.path().join("agent-v1.keys.json");
    let agent_v2_keyfile = temp.path().join("agent-v2.keys.json");
    let executor_keyfile = temp.path().join("executor.keys.json");
    let denied_executor_keyfile = temp.path().join("denied-executor.keys.json");
    for keyfile in [
        &gate_keyfile,
        &agent_v1_keyfile,
        &agent_v2_keyfile,
        &executor_keyfile,
        &denied_executor_keyfile,
    ] {
        generate_keypair(keyfile.to_str().unwrap()).unwrap();
    }
    let gate_id = public_key(&gate_keyfile);
    let agent_v1 = public_key(&agent_v1_keyfile);
    let agent_v2 = public_key(&agent_v2_keyfile);
    let executor_id = public_key(&executor_keyfile);
    let denied_executor_id = public_key(&denied_executor_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();
    storage
        .register_agent(&gate_id, "gate", r#"{"can_delegate":true}"#)
        .unwrap();
    storage
        .register_agent(&agent_v1, "agent", r#"{"tenant_id":"acme"}"#)
        .unwrap();
    storage
        .register_agent(&executor_id, "executor", r#"{"tenant_id":"acme"}"#)
        .unwrap();
    storage
        .register_agent(
            &denied_executor_id,
            "denied-executor",
            r#"{"tenant_id":"acme"}"#,
        )
        .unwrap();

    let policy = json!({
        "schema_version": "tempus.policy-bundle.v1",
        "policy_version": "acme-github-v1",
        "tenant_id": "acme",
        "constraints": {
            "allowed_action_types": ["purchase"],
            "allowed_resources": ["vendor-api/*"],
            "allowed_executors": [executor_id],
            "max_ttl_seconds": 30,
            "max_input_bytes": 1024,
            "allowed_currencies": ["USD"],
            "max_money_amount_minor": 3000
        }
    });
    let installed = parse(&storage.install_policy(&policy.to_string()).unwrap());
    assert_eq!(installed["policy_version"], "acme-github-v1");
    assert_eq!(installed["signer"]["algorithm"], "Ed25519");

    let ttl_denied = parse(
        &storage
            .request_action(
                &intent(&agent_v1, "phase3-ttl-denied", "vendor-api/credits"),
                agent_v1_keyfile.to_str().unwrap(),
                60,
            )
            .unwrap(),
    );
    assert_eq!(ttl_denied["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        ttl_denied["authorization"]["reason_codes"][0],
        "POLICY_TTL_DENIED"
    );

    let mut money_denied_intent = parse(&intent(
        &agent_v1,
        "phase3-money-denied",
        "vendor-api/credits",
    ));
    money_denied_intent["money"]["amount"] = json!("40.00");
    let money_denied = parse(
        &storage
            .request_action(
                &money_denied_intent.to_string(),
                agent_v1_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    assert_eq!(money_denied["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        money_denied["authorization"]["reason_codes"][0],
        "POLICY_MONEY_DENIED"
    );

    let mut nondeterministic_intent = parse(&intent(
        &agent_v1,
        "phase3-float-denied",
        "vendor-api/credits",
    ));
    nondeterministic_intent["input"]["ratio"] = json!(1.5);
    let nondeterministic = parse(
        &storage
            .request_action(
                &nondeterministic_intent.to_string(),
                agent_v1_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    assert_eq!(nondeterministic["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        nondeterministic["authorization"]["reason_codes"][0],
        "POLICY_NON_DETERMINISTIC_INPUT"
    );

    let mut cross_tenant_intent = parse(&intent(
        &agent_v1,
        "phase3-cross-tenant",
        "vendor-api/credits",
    ));
    cross_tenant_intent["tenant_id"] = json!("other-tenant");
    let cross_tenant = parse(
        &storage
            .request_action(
                &cross_tenant_intent.to_string(),
                agent_v1_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    assert_eq!(cross_tenant["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        cross_tenant["authorization"]["reason_codes"][0],
        "AGENT_TENANT_SCOPE_DENIED"
    );

    let permit = parse(
        &storage
            .request_action(
                &intent(&agent_v1, "phase3-rotate", "vendor-api/credits"),
                agent_v1_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    assert_eq!(permit["authorization"]["decision"], "ALLOWED");
    assert_eq!(
        permit["policy_bundle"]["policy_digest"],
        permit["authorization"]["policy_digest"]
    );
    assert_eq!(
        permit["authorization"]["evidence_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let authorization_id = permit["authorization"]["authorization_id"]
        .as_str()
        .unwrap();
    let action_id = permit["authorization"]["action_id"].as_str().unwrap();

    let rotation = parse(&storage.rotate_agent(&agent_v1, &agent_v2).unwrap());
    assert_eq!(rotation["event"]["event_type"], "ROTATE");
    assert!(!storage.verify_agent(&agent_v1).unwrap());
    assert!(storage.verify_agent(&agent_v2).unwrap());
    assert_eq!(
        parse(&storage.verify_trace(action_id).unwrap())["status"],
        "VERIFIED"
    );

    let outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": authorization_id,
        "action_id": action_id,
        "status": "SUCCEEDED",
        "output": {"ok": true}
    })
    .to_string();
    assert!(storage
        .commit_outcome(
            authorization_id,
            &outcome,
            denied_executor_keyfile.to_str().unwrap()
        )
        .unwrap_err()
        .contains("TEMPUS_EXECUTOR_POLICY_DENIED"));
    storage
        .commit_outcome(
            authorization_id,
            &outcome,
            executor_keyfile.to_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        parse(&storage.verify_trace(action_id).unwrap())["status"],
        "VERIFIED"
    );

    let open_permit = parse(
        &storage
            .request_action(
                &intent(&agent_v2, "phase3-revoke", "vendor-api/credits"),
                agent_v2_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    let open_authorization = open_permit["authorization"]["authorization_id"]
        .as_str()
        .unwrap();
    let open_action = open_permit["authorization"]["action_id"].as_str().unwrap();
    let revocation = parse(
        &storage
            .revoke_agent(&agent_v2, "operator emergency revocation")
            .unwrap(),
    );
    assert_eq!(revocation["event"]["event_type"], "REVOKE");
    assert_eq!(revocation["revoked_unconsumed_permits"], 1);
    assert!(!storage.verify_agent(&agent_v2).unwrap());
    let blocked_outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": open_authorization,
        "action_id": open_action,
        "status": "SUCCEEDED",
        "output": {"should_not_run": true}
    })
    .to_string();
    assert!(storage
        .commit_outcome(
            open_authorization,
            &blocked_outcome,
            executor_keyfile.to_str().unwrap()
        )
        .unwrap_err()
        .contains("TEMPUS_PERMIT_REVOKED"));
    assert_eq!(
        parse(&storage.verify_trace(open_action).unwrap())["status"],
        "VERIFIED"
    );
    assert_eq!(
        parse(&storage.list_identity_events().unwrap())
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn test_segregation_of_duties_proposer_cannot_execute() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("gate.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_keyfile = temp.path().join("agent.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();

    let gate_id = public_key(&gate_keyfile);
    let agent_id = public_key(&agent_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();

    storage
        .register_agent(&gate_id, "gate", r#"{"can_delegate":true}"#)
        .unwrap();
    storage
        .register_agent(&agent_id, "agent-both", "{}")
        .unwrap();

    let req = intent(&agent_id, "action-self", "transfer");
    let auth_json = storage
        .request_action(&req, agent_keyfile.to_str().unwrap(), 60)
        .unwrap();
    let auth = parse(&auth_json);
    let auth_id = auth["authorization"]["authorization_id"].as_str().unwrap();
    let act_id = auth["authorization"]["action_id"].as_str().unwrap();

    let outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": auth_id,
        "action_id": act_id,
        "status": "SUCCEEDED",
        "output": {}
    })
    .to_string();

    let err = storage
        .commit_outcome(auth_id, &outcome, agent_keyfile.to_str().unwrap())
        .unwrap_err();
    assert!(
        err.contains("TEMPUS_EXECUTOR_INVALID"),
        "Expected TEMPUS_EXECUTOR_INVALID error, got: {err}"
    );
}

#[test]
fn test_copy_pyd_binary() {
    let candidates = [
        "target/debug/deps/_tempus_ddb.dll",
        "target/debug/_tempus_ddb.dll",
        "target/release/deps/_tempus_ddb.dll",
        "target/release/_tempus_ddb.dll",
    ];
    let pyd_path = std::path::Path::new("python/tempus_ddb/_tempus_ddb.pyd");
    for cand in candidates {
        let dll_path = std::path::Path::new(cand);
        if dll_path.exists() {
            let _ = std::fs::copy(dll_path, pyd_path);
            break;
        }
    }
}
