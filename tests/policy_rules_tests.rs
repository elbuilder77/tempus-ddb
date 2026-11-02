//! Rules in a policy, from the install to a reader who trusts nothing but the gate's key.

use _tempus_ddb::{generate_keypair, verify_bundle, verify_receipt, SqliteStorage};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn key_field(path: &Path, field: &str) -> String {
    parse(&std::fs::read_to_string(path).unwrap())[field]
        .as_str()
        .unwrap()
        .to_string()
}

fn canonical(value: &Value) -> String {
    // serde_json's map is ordered by key here, and these documents are plain ASCII.
    serde_json::to_string(value).unwrap()
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

struct World {
    _temp: tempfile::TempDir,
    storage: SqliteStorage,
    gate_id: String,
    gate_key: PathBuf,
    agent_id: String,
    agent_key: PathBuf,
}

impl World {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let gate_key = temp.path().join("gate.keys.json");
        let agent_key = temp.path().join("agent.keys.json");
        generate_keypair(gate_key.to_str().unwrap()).unwrap();
        generate_keypair(agent_key.to_str().unwrap()).unwrap();
        let (gate_id, agent_id) = (
            key_field(&gate_key, "public_key"),
            key_field(&agent_key, "public_key"),
        );
        let storage = SqliteStorage::new(
            temp.path().join("tempus.db").to_str().unwrap().to_string(),
            gate_key.to_str().unwrap().to_string(),
        )
        .unwrap();
        storage
            .register_agent(&gate_id, "gate", r#"{"can_delegate":true}"#)
            .unwrap();
        storage.register_agent(&agent_id, "agent", "{}").unwrap();
        World {
            _temp: temp,
            storage,
            gate_id,
            gate_key,
            agent_id,
            agent_key,
        }
    }

    fn install(&self, rules: Value) -> Value {
        parse(
            &self
                .storage
                .install_policy(&spec(rules).to_string())
                .unwrap(),
        )
    }

    fn intent(&self, key: &str) -> Value {
        json!({
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "acme",
            "agent_id": self.agent_id,
            "idempotency_key": key,
            "action_type": "purchase",
            "resource": "vendor-api/credits",
            "requested_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64,
            "input": {"sku": "compute-credits", "quantity": 3},
            "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"},
        })
    }

    fn request(&self, intent: &Value) -> Value {
        parse(
            &self
                .storage
                .request_action(&intent.to_string(), self.agent_key.to_str().unwrap(), 60)
                .unwrap(),
        )
    }

    fn purchase(&self, key: &str) -> Value {
        self.request(&self.intent(key))
    }

    /// What a pinned reader says about this permit on its own.
    fn read(&self, permit: &Value) -> Value {
        parse(&verify_receipt(&permit.to_string(), &self.gate_id, &[]).unwrap())
    }

    fn signing_key(&self) -> SigningKey {
        let bytes = hex::decode(key_field(&self.gate_key, "private_key")).unwrap();
        SigningKey::from_bytes(&bytes.try_into().unwrap())
    }

    /// The gate itself signs whatever `edit` left in the authorization: its key cannot make
    /// a decision reproducible.
    fn resign(&self, permit: &mut Value, edit: impl FnOnce(&mut Value)) {
        let authorization = &mut permit["authorization"];
        edit(authorization);
        let fields = authorization.as_object_mut().unwrap();
        fields.remove("authorization_id");
        fields.remove("gate_signature");
        let id = sha256_hex(&canonical(authorization));
        let signature = self.signing_key().sign(&hex::decode(&id).unwrap());
        authorization["authorization_id"] = json!(id);
        authorization["gate_signature"] = json!(hex::encode(signature.to_bytes()));
    }

    /// The gate signs a different policy too, and points the permit at it.
    fn resign_policy(&self, permit: &mut Value, edit: impl FnOnce(&mut Value)) {
        let bundle = &mut permit["policy_bundle"];
        edit(bundle);
        let fields = bundle.as_object_mut().unwrap();
        fields.remove("policy_digest");
        fields.remove("signature");
        fields.remove("status");
        fields.remove("retired_at");
        let digest = sha256_hex(&canonical(bundle));
        let signature = self.signing_key().sign(&hex::decode(&digest).unwrap());
        bundle["policy_digest"] = json!(digest);
        bundle["signature"] = json!(hex::encode(signature.to_bytes()));
        let digest = bundle["policy_digest"].clone();
        self.resign(permit, |authorization| {
            authorization["policy_digest"] = digest;
        });
    }
}

fn spec(rules: Value) -> Value {
    json!({
        "schema_version": "tempus.policy-bundle.v1",
        "policy_version": "rules-v1",
        "tenant_id": "acme",
        "constraints": {
            "allowed_action_types": ["purchase", "report.read"],
            "allowed_resources": ["*"],
            "allowed_executors": ["*"],
            "max_ttl_seconds": 3600,
            "max_input_bytes": 4096,
        },
        "rules": rules,
    })
}

fn under(minor: u64) -> Value {
    json!([{"id": "purchase.limit", "logic": {"<=": [{"var": "money.amount_minor"}, minor]}}])
}

fn errors(result: &Value) -> Vec<String> {
    result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_rule_that_holds_allows_and_a_reader_agrees() {
    let world = World::new();
    let installed = world.install(under(2500));
    assert_eq!(installed["rules"], under(2500));
    let permit = world.purchase("holds");
    assert_eq!(permit["authorization"]["decision"], "ALLOWED");
    assert_eq!(
        permit["authorization"]["reason_codes"],
        json!(["IDENTITY_VERIFIED", "POLICY_ALLOWED"])
    );
    assert_eq!(permit["policy_bundle"]["rules"], under(2500));
    let read = world.read(&permit);
    assert_eq!(read["status"], "VERIFIED", "{read}");
}

#[test]
fn a_rule_that_fails_blocks_and_every_reader_agrees() {
    let world = World::new();
    world.install(under(2499));
    let permit = world.purchase("fails");
    assert_eq!(permit["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        permit["authorization"]["reason_codes"],
        json!(["POLICY_RULES_DENIED"])
    );
    let read = world.read(&permit);
    assert_eq!(read["status"], "VERIFIED", "{read}");

    let action_id = permit["authorization"]["action_id"].as_str().unwrap();
    let local = parse(&world.storage.verify_trace(action_id).unwrap());
    assert_eq!(local["status"], "VERIFIED", "{local}");
    let bundle = world.storage.export_bundle(action_id, None).unwrap();
    let independent = parse(&verify_bundle(&bundle, &world.gate_id, &[]).unwrap());
    assert_eq!(independent["status"], "VERIFIED", "{independent}");
}

#[test]
fn a_rule_outside_its_types_blocks_with_its_own_code_and_a_reader_agrees() {
    let world = World::new();
    world.install(json!([
        {"id": "sku.is.text", "logic": {"<": [{"var": "intent.input.sku"}, 10]}}
    ]));
    let permit = world.purchase("types");
    assert_eq!(permit["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        permit["authorization"]["reason_codes"],
        json!(["POLICY_RULES_ERROR"])
    );
    let read = world.read(&permit);
    assert_eq!(read["status"], "VERIFIED", "{read}");
}

#[test]
fn a_gate_cannot_sign_an_allowed_its_own_rule_denies() {
    let world = World::new();
    world.install(under(100));
    let mut permit = world.purchase("forged-allow");
    world.resign(&mut permit, |authorization| {
        authorization["decision"] = json!("ALLOWED");
        authorization["reason_codes"] = json!(["IDENTITY_VERIFIED", "POLICY_ALLOWED"]);
    });
    let read = world.read(&permit);
    assert_eq!(read["status"], "INVALID");
    let found = errors(&read);
    for code in [
        "AUTHORIZATION_POLICY_DECISION_MISMATCH",
        "AUTHORIZATION_DECISION_NOT_REPRODUCIBLE",
        "AUTHORIZATION_REASON_CODES_NOT_REPRODUCIBLE",
    ] {
        assert!(found.iter().any(|error| error == code), "{found:?}");
    }
    // Only the rule's re-execution can tell: the receipt, its signature and the policy are good.
    assert!(
        !found.iter().any(|error| error.contains("SIGNATURE")),
        "{found:?}"
    );
}

#[test]
fn a_gate_cannot_sign_a_denial_its_rules_allow() {
    let world = World::new();
    world.install(under(2500));
    let mut permit = world.purchase("forged-denial");
    world.resign(&mut permit, |authorization| {
        authorization["decision"] = json!("BLOCKED");
        authorization["reason_codes"] = json!(["POLICY_RULES_DENIED"]);
    });
    let read = world.read(&permit);
    assert_eq!(read["status"], "INVALID");
    let found = errors(&read);
    assert!(
        found.contains(&"AUTHORIZATION_DECISION_NOT_REPRODUCIBLE".to_string()),
        "{found:?}"
    );
}

#[test]
fn editing_a_rule_after_signing_is_detected() {
    let world = World::new();
    world.install(under(100));
    let mut permit = world.purchase("edited");
    permit["policy_bundle"]["rules"][0]["logic"]["<="][1] = json!(1_000_000);
    let read = world.read(&permit);
    assert_eq!(read["status"], "INVALID", "{read}");
}

#[test]
fn removing_the_rules_from_a_signed_policy_is_detected() {
    let world = World::new();
    world.install(under(100));
    let mut permit = world.purchase("removed");
    permit["policy_bundle"]
        .as_object_mut()
        .unwrap()
        .remove("rules");
    let read = world.read(&permit);
    assert_eq!(read["status"], "INVALID", "{read}");
}

#[test]
fn a_signed_policy_outside_the_grammar_is_refused_by_a_reader_and_never_evaluated() {
    let world = World::new();
    world.install(under(2500));
    for logic in [
        json!({"==": [1, "1"]}),
        json!({"log": "hello"}),
        json!({"substr": [1, 2, 3, 4]}),
        json!({"reduce": [1, 2]}),
        json!({"<": ["10", 9]}),
    ] {
        let mut permit = world.purchase(&format!("hostile-{logic}"));
        world.resign_policy(&mut permit, |bundle| {
            bundle["rules"][0]["logic"] = logic.clone();
        });
        let read = world.read(&permit);
        assert_eq!(read["status"], "INVALID", "{logic}");
        assert!(
            errors(&read)
                .iter()
                .any(|error| error.contains("TEMPUS_POLICY_RULES_INVALID")),
            "{logic}: {read}"
        );
    }
}

#[test]
fn a_policy_without_rules_is_the_policy_it_always_was() {
    let world = World::new();
    let mut plain = spec(json!([]));
    plain.as_object_mut().unwrap().remove("rules");
    let installed = parse(&world.storage.install_policy(&plain.to_string()).unwrap());
    assert!(installed.get("rules").is_none(), "{installed}");
    let digest = {
        let mut body = installed.clone();
        let fields = body.as_object_mut().unwrap();
        for field in ["policy_digest", "signature", "status", "retired_at"] {
            fields.remove(field);
        }
        sha256_hex(&canonical(&body))
    };
    assert_eq!(installed["policy_digest"], json!(digest));
    let permit = world.purchase("plain");
    assert_eq!(permit["authorization"]["decision"], "ALLOWED");
    assert_eq!(world.read(&permit)["status"], "VERIFIED");
}

#[test]
fn an_empty_list_of_rules_decides_nothing() {
    let world = World::new();
    let installed = world.install(json!([]));
    assert_eq!(installed["rules"], json!([]));
    assert_eq!(
        world.purchase("empty")["authorization"]["decision"],
        "ALLOWED"
    );
}

#[test]
fn an_invalid_rule_is_refused_at_install_and_changes_nothing() {
    let world = World::new();
    world.install(under(2500));
    for rules in [
        json!("nope"),
        json!([{"id": "r", "logic": {"==": [1, 1]}}]),
        json!([{"id": "r", "logic": {"var": "secrets.key"}}]),
        json!([{"id": "R", "logic": true}]),
        json!([{"id": "r", "logic": true, "extra": 1}]),
        json!([{"id": "r", "logic": true}, {"id": "r", "logic": false}]),
    ] {
        let mut replacement = spec(rules.clone());
        replacement["policy_version"] = json!("rules-v2");
        let error = world
            .storage
            .install_policy(&replacement.to_string())
            .unwrap_err();
        assert!(
            error.contains("TEMPUS_POLICY_RULES_INVALID"),
            "{rules}: {error}"
        );
    }
    assert_eq!(
        world.purchase("still-v1")["policy_bundle"]["policy_version"],
        "rules-v1"
    );
}

#[test]
fn a_rule_and_a_constraint_both_report() {
    let world = World::new();
    let mut both = spec(under(100));
    both["constraints"]["max_money_amount_minor"] = json!(100);
    world.storage.install_policy(&both.to_string()).unwrap();
    let permit = world.purchase("both");
    assert_eq!(
        permit["authorization"]["reason_codes"],
        json!(["POLICY_MONEY_DENIED", "POLICY_RULES_DENIED"])
    );
    assert_eq!(world.read(&permit)["status"], "VERIFIED");
}

#[test]
fn an_action_without_money_passes_a_guarded_rule_and_fails_an_unguarded_one() {
    let world = World::new();
    let guarded = json!({"if": [{"!": {"missing": ["money"]}},
                                {"<=": [{"var": "money.amount_minor"}, 100]},
                                true]});
    world.install(json!([{"id": "guarded", "logic": guarded}]));
    let mut read_only = world.intent("no-money");
    read_only.as_object_mut().unwrap().remove("money");
    read_only["action_type"] = json!("report.read");
    let permit = world.request(&read_only);
    assert_eq!(permit["authorization"]["decision"], "ALLOWED", "{permit}");
    assert_eq!(world.read(&permit)["status"], "VERIFIED");

    let mut with_null = read_only.clone();
    with_null["idempotency_key"] = json!("null-money");
    with_null["money"] = Value::Null;
    let permit = world.request(&with_null);
    assert_eq!(permit["authorization"]["decision"], "ALLOWED", "{permit}");

    // The same purchase the guard does look at.
    let permit = world.purchase("with-money");
    assert_eq!(
        permit["authorization"]["reason_codes"],
        json!(["POLICY_RULES_DENIED"])
    );

    let unguarded = World::new();
    unguarded.install(under(100));
    let mut read_only = unguarded.intent("unguarded");
    read_only.as_object_mut().unwrap().remove("money");
    read_only["action_type"] = json!("report.read");
    assert_eq!(
        unguarded.request(&read_only)["authorization"]["reason_codes"],
        json!(["POLICY_RULES_ERROR"])
    );
}

#[test]
fn a_rule_reads_the_signed_intent_and_the_ttl() {
    let world = World::new();
    world.install(json!([
        {"id": "resource", "logic": {"in": ["vendor-api/", {"var": "intent.resource"}]}},
        {"id": "quantity", "logic": {"<": [{"var": "intent.input.quantity"}, 4]}},
        {"id": "ttl", "logic": {"<=": [{"var": "ttl_seconds"}, 60]}},
        {"id": "currency", "logic": {"in": [{"var": "money.currency"}, ["USD", "EUR"]]}},
        {"id": "total", "logic": {"===": [{"*": [{"var": "intent.input.quantity"}, 2]}, 6]}},
    ]));
    let permit = world.purchase("reads");
    assert_eq!(permit["authorization"]["decision"], "ALLOWED", "{permit}");
    assert_eq!(world.read(&permit)["status"], "VERIFIED");

    let mut longer = world.intent("longer");
    longer["idempotency_key"] = json!("longer");
    let permit = parse(
        &world
            .storage
            .request_action(&longer.to_string(), world.agent_key.to_str().unwrap(), 61)
            .unwrap(),
    );
    assert_eq!(
        permit["authorization"]["reason_codes"],
        json!(["POLICY_RULES_DENIED"])
    );
    assert_eq!(world.read(&permit)["status"], "VERIFIED");
}
