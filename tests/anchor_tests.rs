//! `tempus.anchor.v1` end to end: a real gate writes a checkpoint, a small fake log anchors
//! it, and the verifier answers from the documents alone. The fake log is a one-leaf Merkle
//! tree signed by a fixed P-256 key; real entries and real timestamp tokens are covered by
//! the unit tests in `src/rekor.rs` and `src/tsa.rs`, hostile tokens by `tests/test_anchor.py`.

use _tempus_ddb::{
    anchor_checkpoint_digest, generate_keypair, verify_anchor, verify_bundle,
    verify_bundle_anchored, SqliteStorage,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SIGSTORE_ROOT: &str = include_str!("vectors/anchor/sigstore_tsa_root.pem");

fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn public_key(path: &Path) -> String {
    parse(&std::fs::read_to_string(path).unwrap())["public_key"]
        .as_str()
        .unwrap()
        .to_string()
}

struct Gate {
    _temp: tempfile::TempDir,
    storage: SqliteStorage,
    gate_id: String,
    action_id: String,
}

fn keyfile(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    generate_keypair(path.to_str().unwrap()).unwrap();
    path
}

/// A gate with one authorized action in its ledger.
fn gate() -> Gate {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let gate_key = keyfile(dir, "gate.keys.json");
    let agent_key = keyfile(dir, "agent.keys.json");
    let (gate_id, agent_id) = (public_key(&gate_key), public_key(&agent_key));
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
    let requested_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let intent = json!({
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "acme",
        "agent_id": agent_id,
        "idempotency_key": "report-1",
        "action_type": "report.read",
        "resource": "reports/q3",
        "requested_at": requested_at,
        "input": {},
    });
    let permit = parse(
        &storage
            .request_action(&intent.to_string(), agent_key.to_str().unwrap(), 60)
            .unwrap(),
    );
    assert_eq!(permit["authorization"]["decision"], "ALLOWED");
    let action_id = permit["authorization"]["action_id"]
        .as_str()
        .unwrap()
        .to_string();
    Gate {
        _temp: temp,
        storage,
        gate_id,
        action_id,
    }
}

impl Gate {
    fn checkpoint(&self) -> Value {
        parse(&self.storage.create_checkpoint("acme").unwrap())
    }

    fn bundle(&self) -> Value {
        parse(&self.storage.export_bundle(&self.action_id, None).unwrap())
    }
}

/// A transparency log with one entry, as far as a verifier can tell.
struct FakeLog {
    key: p256::ecdsa::SigningKey,
}

impl FakeLog {
    fn new(seed: u8) -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap(),
        }
    }

    fn spki(&self) -> Vec<u8> {
        let mut spki = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
        spki.extend_from_slice(self.key.verifying_key().to_sec1_point(false).as_bytes());
        spki
    }

    fn roots(&self) -> String {
        json!({"rekor_public_keys": [STANDARD.encode(self.spki())]}).to_string()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        fn integer(value: &[u8]) -> Vec<u8> {
            let start = value.iter().position(|byte| *byte != 0).unwrap();
            let mut digits = value[start..].to_vec();
            if digits[0] & 0x80 != 0 {
                digits.insert(0, 0);
            }
            let mut out = vec![0x02, digits.len() as u8];
            out.extend_from_slice(&digits);
            out
        }
        let digest = Sha256::digest(message);
        let signature: p256::ecdsa::Signature = self.key.sign_prehash(&digest).unwrap();
        let fixed = signature.to_bytes();
        let (r, s) = fixed.split_at(32);
        let body = [integer(r), integer(s)].concat();
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    /// The proof a real log would hand back for `digest`, logged at `integrated_time`.
    fn proof(&self, digest: &str, integrated_time: u64) -> Value {
        let entry = json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {"data": {"hash": {"algorithm": "sha256", "value": digest}}},
        })
        .to_string();
        let body = STANDARD.encode(&entry);
        let log_id = hex::encode(Sha256::digest(self.spki()));
        // Keys in the canonical order Rekor signs them in.
        let set = format!(
            r#"{{"body":"{body}","integratedTime":{integrated_time},"logID":"{log_id}","logIndex":0}}"#
        );
        let mut leaf = vec![0u8];
        leaf.extend_from_slice(entry.as_bytes());
        let root = Sha256::digest(&leaf);
        let text = format!("fake.log\n1\n{}\n", STANDARD.encode(root));
        let mut note_signature = Sha256::digest(self.spki())[..4].to_vec();
        note_signature.extend_from_slice(&self.sign(text.as_bytes()));
        let note = format!(
            "{text}\n\u{2014} fake.log {}\n",
            STANDARD.encode(&note_signature)
        );
        json!({
            "backend": "rekor",
            "log_url": "https://log.example",
            "entry_uuid": "00",
            "body": body,
            "integrated_time": integrated_time,
            "log_id": log_id,
            "log_index": 0,
            "signed_entry_timestamp": STANDARD.encode(self.sign(set.as_bytes())),
            "inclusion_proof": {
                "log_index": 0,
                "tree_size": 1,
                "root_hash": hex::encode(root),
                "hashes": [],
                "checkpoint": note,
            },
        })
    }
}

fn anchor_for(checkpoint: &Value, proofs: Vec<Value>) -> Value {
    json!({
        "schema_version": "tempus.anchor.v1",
        "checkpoint_id": checkpoint["checkpoint_id"],
        "tenant_id": checkpoint["tenant_id"],
        "checkpoint_digest": anchor_checkpoint_digest(&checkpoint.to_string()).unwrap(),
        "proofs": proofs,
    })
}

fn digest_of(checkpoint: &Value) -> String {
    anchor_checkpoint_digest(&checkpoint.to_string()).unwrap()
}

fn verify(anchor: &Value, checkpoint: &Value, roots: &str) -> Value {
    parse(&verify_anchor(&anchor.to_string(), &checkpoint.to_string(), roots).unwrap())
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
fn a_pinned_log_makes_the_anchor_verified_with_its_time() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let log = FakeLog::new(7);
    let at = now_seconds() + 5;
    let anchor = anchor_for(&checkpoint, vec![log.proof(&digest_of(&checkpoint), at)]);
    let result = verify(&anchor, &checkpoint, &log.roots());
    assert_eq!(result["schema_version"], "tempus.anchor-verification.v1");
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["anchored_at"], at * 1_000_000);
    assert_eq!(result["checkpoint_id"], checkpoint["checkpoint_id"]);
    assert_eq!(result["checkpoint_digest"], digest_of(&checkpoint));
    assert_eq!(result["proofs"][0]["status"], "VERIFIED");
    assert_eq!(result["proofs"][0]["anchored_at"], at * 1_000_000);
    assert_eq!(errors(&result), Vec::<String>::new());
}

#[test]
fn without_a_pinned_root_it_never_says_verified() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let log = FakeLog::new(7);
    let anchor = anchor_for(
        &checkpoint,
        vec![log.proof(&digest_of(&checkpoint), now_seconds())],
    );
    for roots in ["", "{}", r#"{"rekor_public_keys":[]}"#] {
        let result = verify(&anchor, &checkpoint, roots);
        assert_eq!(result["status"], "NOT_CHECKED", "{result}");
        assert_eq!(result["anchored_at"], Value::Null);
        assert_eq!(result["proofs"][0]["status"], "NOT_CHECKED");
        assert!(result["not_checked"]
            .to_string()
            .contains("ANCHOR_NOT_PINNED"));
    }
}

#[test]
fn a_tsa_root_says_nothing_about_a_rekor_proof() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let log = FakeLog::new(7);
    let anchor = anchor_for(
        &checkpoint,
        vec![log.proof(&digest_of(&checkpoint), now_seconds())],
    );
    let roots = json!({"tsa_roots": [SIGSTORE_ROOT]}).to_string();
    assert_eq!(
        verify(&anchor, &checkpoint, &roots)["status"],
        "NOT_CHECKED"
    );
}

#[test]
fn another_checkpoint_of_the_same_tenant_is_a_mismatch_even_with_valid_proofs() {
    let gate = gate();
    let first = gate.checkpoint();
    let second = gate.checkpoint();
    assert_ne!(first["checkpoint_id"], second["checkpoint_id"]);
    let log = FakeLog::new(7);
    let anchor = anchor_for(&first, vec![log.proof(&digest_of(&first), now_seconds())]);
    let result = verify(&anchor, &second, &log.roots());
    assert_eq!(result["status"], "INVALID");
    assert!(
        errors(&result).contains(&"ANCHOR_CHECKPOINT_MISMATCH".to_string()),
        "{result}"
    );

    // Rewriting the wrapper to name the second checkpoint does not help: the entry is
    // still about the first.
    let mut rewritten = anchor_for(&second, vec![log.proof(&digest_of(&first), now_seconds())]);
    let result = verify(&rewritten, &second, &log.roots());
    assert_eq!(errors(&result), vec!["ANCHOR_REKOR_ENTRY_MISMATCH"]);

    // Nor does editing a single field of the checkpoint.
    rewritten = anchor_for(&first, vec![log.proof(&digest_of(&first), now_seconds())]);
    let mut altered = first.clone();
    altered["sequence"] = json!(999);
    let result = verify(&rewritten, &altered, &log.roots());
    assert_eq!(result["status"], "INVALID");
}

#[test]
fn a_time_before_the_checkpoint_is_refused_and_a_late_one_is_honest() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let log = FakeLog::new(7);
    let digest = digest_of(&checkpoint);
    let created = checkpoint["created_at"].as_u64().unwrap() / 1_000_000;

    let early = anchor_for(&checkpoint, vec![log.proof(&digest, created - 301)]);
    let result = verify(&early, &checkpoint, &log.roots());
    assert_eq!(errors(&result), vec!["ANCHOR_BEFORE_CHECKPOINT"]);
    assert_eq!(result["proofs"][0]["status"], "FAILED");
    assert_eq!(result["anchored_at"], Value::Null);

    // Within the allowed clock skew.
    let skewed = anchor_for(&checkpoint, vec![log.proof(&digest, created - 299)]);
    assert_eq!(
        verify(&skewed, &checkpoint, &log.roots())["status"],
        "VERIFIED"
    );

    let late = anchor_for(
        &checkpoint,
        vec![log.proof(&digest, created + 86_400 * 365)],
    );
    assert_eq!(
        verify(&late, &checkpoint, &log.roots())["status"],
        "VERIFIED"
    );
}

#[test]
fn the_earliest_verified_proof_sets_the_date_and_any_failure_is_invalid() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let log = FakeLog::new(7);
    let other = FakeLog::new(9);
    let digest = digest_of(&checkpoint);
    let now = now_seconds();
    let both = anchor_for(
        &checkpoint,
        vec![log.proof(&digest, now + 50), log.proof(&digest, now + 10)],
    );
    let result = verify(&both, &checkpoint, &log.roots());
    assert_eq!(result["anchored_at"], (now + 10) * 1_000_000);

    // A second log nobody pinned turns a good anchor bad: its key is simply unknown.
    let mixed = anchor_for(
        &checkpoint,
        vec![log.proof(&digest, now), other.proof(&digest, now)],
    );
    let result = verify(&mixed, &checkpoint, &log.roots());
    assert_eq!(result["status"], "INVALID");
    assert_eq!(errors(&result), vec!["ANCHOR_REKOR_LOG_UNKNOWN"]);
    assert_eq!(result["anchored_at"], Value::Null);
    assert_eq!(result["proofs"][0]["status"], "VERIFIED");
    assert_eq!(result["proofs"][1]["status"], "FAILED");
}

#[test]
fn the_document_is_closed_and_bounded() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let log = FakeLog::new(7);
    let good = log.proof(&digest_of(&checkpoint), now_seconds());
    let roots = log.roots();
    let invalid_with = |anchor: &Value, code: &str| {
        let result = verify(anchor, &checkpoint, &roots);
        assert_eq!(result["status"], "INVALID", "{code}: {result}");
        assert!(
            errors(&result).iter().any(|e| e == code),
            "{code}: {result}"
        );
    };

    let mut extra = anchor_for(&checkpoint, vec![good.clone()]);
    extra["note"] = json!("trust me");
    invalid_with(&extra, "UNKNOWN_FIELD (anchor.note)");

    invalid_with(
        &anchor_for(&checkpoint, vec![]),
        "ANCHOR_MALFORMED (anchor.proofs)",
    );
    invalid_with(
        &anchor_for(&checkpoint, vec![good.clone(); 9]),
        "ANCHOR_MALFORMED (anchor.proofs)",
    );
    let mut no_list = anchor_for(&checkpoint, vec![good.clone()]);
    no_list["proofs"] = json!("many");
    invalid_with(&no_list, "ANCHOR_MALFORMED (anchor.proofs)");
    invalid_with(
        &anchor_for(&checkpoint, vec![json!({"backend": "ethereum"})]),
        "ANCHOR_MALFORMED (anchor.proofs[0].backend)",
    );
    invalid_with(
        &anchor_for(&checkpoint, vec![json!("a string")]),
        "ANCHOR_MALFORMED (anchor.proofs[0].backend)",
    );

    // 100 proofs are refused without looking at any of them.
    invalid_with(
        &anchor_for(&checkpoint, vec![json!({}); 100]),
        "ANCHOR_MALFORMED (anchor.proofs)",
    );
}

#[test]
fn an_unknown_schema_is_an_error_and_a_repeated_key_is_a_verdict() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let text = checkpoint.to_string();
    let error = verify_anchor(r#"{"schema_version":"tempus.anchor.v9"}"#, &text, "").unwrap_err();
    assert!(error.contains("TEMPUS_ANCHOR_SCHEMA_UNKNOWN"), "{error}");
    assert!(verify_anchor("not json", &text, "").is_err());
    assert!(verify_anchor("[]", &text, "").is_err());

    let repeated = r#"{"schema_version":"tempus.anchor.v1","proofs":[],"proofs":[]}"#;
    let result = parse(&verify_anchor(repeated, &text, "").unwrap());
    assert_eq!(result["status"], "INVALID");
    assert_eq!(errors(&result), vec!["DUPLICATE_JSON_KEY"]);
}

#[test]
fn a_bundle_says_what_an_anchor_adds() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let bundle = gate.bundle();
    let text = bundle.to_string();
    let log = FakeLog::new(7);
    let at = now_seconds();
    let anchor = anchor_for(&checkpoint, vec![log.proof(&digest_of(&checkpoint), at)]).to_string();

    // No anchor at all.
    let plain = parse(&verify_bundle(&text, &gate.gate_id, &[]).unwrap());
    assert_eq!(plain["status"], "VERIFIED", "{plain}");
    assert_eq!(plain["checks"]["anchor"], "NOT_PRESENT");
    assert!(plain.get("anchor").is_none());
    assert!(plain["trust"]["not_checked"]
        .to_string()
        .contains("CHECKPOINT_TIME"));

    // An anchor and its root: the date is established.
    let verified =
        parse(&verify_bundle_anchored(&text, &gate.gate_id, &[], &anchor, &log.roots()).unwrap());
    assert_eq!(verified["status"], "VERIFIED", "{verified}");
    assert_eq!(verified["checks"]["anchor"], "VERIFIED");
    assert_eq!(verified["anchor"]["anchored_at"], at * 1_000_000);
    assert!(verified["anchor"].get("schema_version").is_none());
    assert!(!verified["trust"]["not_checked"]
        .to_string()
        .contains("CHECKPOINT_TIME"));

    // An anchor without a root: still valid evidence, no date claimed.
    let unpinned = parse(&verify_bundle_anchored(&text, &gate.gate_id, &[], &anchor, "").unwrap());
    assert_eq!(unpinned["status"], "VERIFIED", "{unpinned}");
    assert_eq!(unpinned["checks"]["anchor"], "NOT_CHECKED");
    let not_checked = unpinned["trust"]["not_checked"].to_string();
    assert!(not_checked.contains("CHECKPOINT_TIME"), "{not_checked}");
    assert!(not_checked.contains("ANCHOR_NOT_PINNED"), "{not_checked}");

    // A broken anchor sinks the whole verdict.
    let wrong = FakeLog::new(9);
    let broken =
        parse(&verify_bundle_anchored(&text, &gate.gate_id, &[], &anchor, &wrong.roots()).unwrap());
    assert_eq!(broken["status"], "INVALID");
    assert_eq!(broken["decision"], Value::Null);
    assert_eq!(broken["checks"]["anchor"], "FAILED");
    assert!(broken["errors"]
        .to_string()
        .contains("ANCHOR_REKOR_LOG_UNKNOWN"));
}

#[test]
fn an_anchor_for_a_bundle_with_no_checkpoint_has_nothing_to_anchor() {
    let gate = gate();
    let bundle = gate.bundle();
    assert!(bundle["checkpoint"].is_null());
    let result =
        parse(&verify_bundle_anchored(&bundle.to_string(), &gate.gate_id, &[], "{}", "").unwrap());
    assert_eq!(result["status"], "INVALID");
    assert_eq!(result["checks"]["anchor"], "FAILED");
    assert!(result["errors"]
        .to_string()
        .contains("ANCHOR_NO_CHECKPOINT"));
}

#[test]
fn unreadable_trust_roots_are_an_error_of_the_call() {
    let gate = gate();
    let checkpoint = gate.checkpoint();
    let log = FakeLog::new(7);
    let anchor = anchor_for(
        &checkpoint,
        vec![log.proof(&digest_of(&checkpoint), now_seconds())],
    )
    .to_string();
    assert!(verify_anchor(&anchor, &checkpoint.to_string(), "not json").is_err());
    let roots = r#"{"rekor_public_keys":["???"]}"#;
    assert!(verify_anchor(&anchor, &checkpoint.to_string(), roots).is_err());
    let bundle = gate.bundle().to_string();
    assert!(verify_bundle_anchored(&bundle, &gate.gate_id, &[], &anchor, roots).is_err());
}
