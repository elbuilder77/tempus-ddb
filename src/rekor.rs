//! Offline verification of a Rekor v1 proof: the logged entry names the checkpoint digest,
//! the log signed the entry and its time (signed entry timestamp), and the entry is in a
//! Merkle tree whose head the log also signed. Nothing here needs the network; `tempus
//! anchor create` asks the log for these documents and stores them.

use crate::anchor::ProofVerdict;
use crate::b2a::{canonicalize, unknown_fields};
use crate::sigverify::{self, HashAlg, PublicKey};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const PROOF_FIELDS: &[&str] = &[
    "backend",
    "log_url",
    "entry_uuid",
    "body",
    "integrated_time",
    "log_id",
    "log_index",
    "signed_entry_timestamp",
    "inclusion_proof",
];
const INCLUSION_FIELDS: &[&str] = &[
    "log_index",
    "tree_size",
    "root_hash",
    "hashes",
    "checkpoint",
];

const ENTRY_MISMATCH: &str = "ANCHOR_REKOR_ENTRY_MISMATCH";
const LOG_UNKNOWN: &str = "ANCHOR_REKOR_LOG_UNKNOWN";
const SET_INVALID: &str = "ANCHOR_REKOR_SET_INVALID";
const INCLUSION_INVALID: &str = "ANCHOR_REKOR_INCLUSION_INVALID";
const NOTE_INVALID: &str = "ANCHOR_REKOR_NOTE_INVALID";

/// Bounds on what is read: a tree of 2^64 leaves has at most 64 hashes on a path.
const MAX_BODY_BYTES: usize = 65_536;
const MAX_PATH_HASHES: usize = 64;
const MAX_NOTE_BYTES: usize = 8_192;

/// A log public key the verifier pinned, with the log id it implies.
#[derive(Debug, Clone)]
pub(crate) struct LogKey {
    key: PublicKey,
    id: Vec<u8>,
}

impl LogKey {
    pub(crate) fn from_spki(spki: &[u8]) -> Result<Self, sigverify::KeyError> {
        Ok(Self {
            key: sigverify::parse_spki(spki)?,
            id: HashAlg::Sha256.digest(spki),
        })
    }
}

fn hash32(text: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(text).ok()?;
    bytes.try_into().ok()
}

fn node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(entry);
    hasher.finalize().into()
}

/// The Merkle root an inclusion path implies (RFC 9162, section 2.1.3.2).
fn root_from_path(leaf: [u8; 32], index: u64, size: u64, path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    let (mut position, mut last) = (index, size - 1);
    let mut root = leaf;
    for sibling in path {
        if last == 0 {
            return None;
        }
        if position & 1 == 1 || position == last {
            root = node_hash(sibling, &root);
            if position & 1 == 0 {
                while position & 1 == 0 && position != 0 {
                    position >>= 1;
                    last >>= 1;
                }
            }
        } else {
            root = node_hash(&root, sibling);
        }
        position >>= 1;
        last >>= 1;
    }
    (last == 0).then_some(root)
}

/// A signed note: `origin\nsize\nbase64(root)\n[more lines]\n\n— name base64(hint||sig)\n`.
/// The signature covers everything before the blank line, final newline included.
fn note_is_valid(note: &str, size: u64, root: &[u8; 32], key: &LogKey) -> bool {
    if note.len() > MAX_NOTE_BYTES || note.contains('\r') {
        return false;
    }
    let Some(split) = note.find("\n\n") else {
        return false;
    };
    let (text, signatures) = (&note[..=split], &note[split + 2..]);
    let mut lines = text.lines();
    if lines.next().is_none_or(str::is_empty)
        || lines.next().and_then(|line| line.parse::<u64>().ok()) != Some(size)
        || lines
            .next()
            .and_then(|line| STANDARD.decode(line).ok())
            .as_deref()
            != Some(&root[..])
    {
        return false;
    }
    let digest = HashAlg::Sha256.digest(text.as_bytes());
    signatures.lines().any(|line| {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            return false;
        };
        let Some((_, encoded)) = rest.rsplit_once(' ') else {
            return false;
        };
        let Ok(raw) = STANDARD.decode(encoded) else {
            return false;
        };
        raw.len() > 4
            && raw[..4] == key.id[..4]
            && sigverify::verify_digest(&key.key, HashAlg::Sha256, &digest, &raw[4..])
    })
}

/// The body must be a `hashedrekord` over exactly this digest.
fn entry_names_digest(body: &[u8], digest_hex: &str) -> bool {
    let Some(entry) = std::str::from_utf8(body)
        .ok()
        .and_then(|text| crate::strict_json::parse(text).ok())
    else {
        return false;
    };
    entry.get("kind").and_then(Value::as_str) == Some("hashedrekord")
        && entry.get("apiVersion").and_then(Value::as_str) == Some("0.0.1")
        && entry
            .pointer("/spec/data/hash/algorithm")
            .and_then(Value::as_str)
            == Some("sha256")
        && entry
            .pointer("/spec/data/hash/value")
            .and_then(Value::as_str)
            == Some(digest_hex)
}

/// `Ok(Some(seconds))` when verified, `Ok(None)` when consistent but no key was pinned.
fn check(proof: &Value, digest_hex: &str, keys: &[LogKey]) -> Result<Option<u64>, String> {
    let malformed = |field: &str| format!("ANCHOR_MALFORMED (rekor.{field})");
    let text = |field: &str| {
        proof
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| malformed(field))
    };
    let number = |field: &str| {
        proof
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed(field))
    };

    let body_text = text("body")?;
    if body_text.len() > MAX_BODY_BYTES {
        return Err(malformed("body"));
    }
    let body = STANDARD.decode(body_text).map_err(|_| malformed("body"))?;
    if !entry_names_digest(&body, digest_hex) {
        return Err(ENTRY_MISMATCH.to_string());
    }
    let integrated_time = number("integrated_time")?;
    let log_id = text("log_id")?;
    let log_index = number("log_index")?;
    let set_text = text("signed_entry_timestamp")?;
    let set = STANDARD
        .decode(set_text)
        .map_err(|_| malformed("signed_entry_timestamp"))?;
    let inclusion = proof
        .get("inclusion_proof")
        .filter(|value| value.is_object())
        .ok_or_else(|| malformed("inclusion_proof"))?;
    let inner_number = |field: &str| {
        inclusion
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed(&format!("inclusion_proof.{field}")))
    };
    let leaf_index = inner_number("log_index")?;
    let tree_size = inner_number("tree_size")?;
    let root_text = inclusion
        .get("root_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("inclusion_proof.root_hash"))?;
    let root = hash32(root_text).ok_or_else(|| malformed("inclusion_proof.root_hash"))?;
    let path_values = inclusion
        .get("hashes")
        .and_then(Value::as_array)
        .filter(|hashes| hashes.len() <= MAX_PATH_HASHES)
        .ok_or_else(|| malformed("inclusion_proof.hashes"))?;
    let path = path_values
        .iter()
        .map(|value| value.as_str().and_then(hash32))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| malformed("inclusion_proof.hashes"))?;
    let note = inclusion
        .get("checkpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("inclusion_proof.checkpoint"))?;

    // The tree arithmetic needs no key, so a broken path fails even when nothing is pinned.
    if root_from_path(leaf_hash(&body), leaf_index, tree_size, &path) != Some(root) {
        return Err(INCLUSION_INVALID.to_string());
    }

    if keys.is_empty() {
        return Ok(None);
    }
    let wanted = hex::decode(log_id).map_err(|_| malformed("log_id"))?;
    let key = keys
        .iter()
        .find(|key| key.id == wanted)
        .ok_or_else(|| LOG_UNKNOWN.to_string())?;
    let payload = canonicalize(&json!({
        "body": body_text,
        "integratedTime": integrated_time,
        "logID": log_id,
        "logIndex": log_index,
    }))?;
    let digest = HashAlg::Sha256.digest(payload.as_bytes());
    if !sigverify::verify_digest(&key.key, HashAlg::Sha256, &digest, &set) {
        return Err(SET_INVALID.to_string());
    }
    if !note_is_valid(note, tree_size, &root, key) {
        return Err(NOTE_INVALID.to_string());
    }
    Ok(Some(integrated_time))
}

/// Verify one `rekor` proof of an anchor against the checkpoint digest.
pub(crate) fn verify_proof(
    proof: &Value,
    path: &str,
    digest_hex: &str,
    keys: &[LogKey],
) -> ProofVerdict {
    let mut errors = unknown_fields(proof, path, PROOF_FIELDS);
    if let Some(inclusion) = proof.get("inclusion_proof") {
        errors.extend(unknown_fields(
            inclusion,
            &format!("{path}.inclusion_proof"),
            INCLUSION_FIELDS,
        ));
    }
    // Informational and never trusted, but still what the contract says they are.
    for field in ["log_url", "entry_uuid"] {
        if proof.get(field).is_some_and(|value| !value.is_string()) {
            errors.push(format!("ANCHOR_MALFORMED ({path}.{field})"));
        }
    }
    let outcome = check(proof, digest_hex, keys);
    ProofVerdict::from_check("rekor", outcome, errors)
}

/// Native only: the `hashedrekord` to submit, signed by a key that exists for this call.
/// The log checks the signature on upload but it adds no trust: only the log's own
/// signature does. A throwaway key keeps entries unlinkable to each other and to the gate.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn entry_request(digest_hex: &str) -> Result<Value, String> {
    let digest = hex::decode(digest_hex)
        .ok()
        .filter(|digest| digest.len() == 32)
        .ok_or_else(|| "TEMPUS_ANCHOR_DIGEST_INVALID: expected 64 hex characters".to_string())?;
    let (spki, signature) = sigverify::sign_with_ephemeral_p256(&digest)?;
    let encoded = STANDARD.encode(&spki);
    let wrapped = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----\n");
    Ok(json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": digest_hex}},
            "signature": {
                "content": STANDARD.encode(&signature),
                "publicKey": {"content": STANDARD.encode(pem.as_bytes())},
            },
        },
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::anchor::ProofStatus;
    use crate::der;

    const KEY: &str = include_str!("../tests/vectors/anchor/rekor_public_key.pem");
    const ENTRY: &str = include_str!("../tests/vectors/anchor/rekor_hashedrekord.json");
    const DIGEST: &str = "27d3174180b6bdb9247ca2278869a33a31b12243c754cdaec0634533d47a913e";

    fn real_key() -> LogKey {
        let spki = der::pem_or_base64_blocks(KEY, "PUBLIC KEY")
            .unwrap()
            .remove(0);
        LogKey::from_spki(&spki).unwrap()
    }

    /// What `tempus anchor create` stores for an entry as the log's API returns it.
    pub(crate) fn real_proof() -> Value {
        let entry: Value = serde_json::from_str(ENTRY).unwrap();
        let inclusion = &entry["verification"]["inclusionProof"];
        json!({
            "backend": "rekor",
            "log_url": "https://rekor.sigstore.dev",
            "entry_uuid": entry["uuid"],
            "body": entry["body"],
            "integrated_time": entry["integratedTime"],
            "log_id": entry["logID"],
            "log_index": entry["logIndex"],
            "signed_entry_timestamp": entry["verification"]["signedEntryTimestamp"],
            "inclusion_proof": {
                "log_index": inclusion["logIndex"],
                "tree_size": inclusion["treeSize"],
                "root_hash": inclusion["rootHash"],
                "hashes": inclusion["hashes"],
                "checkpoint": inclusion["checkpoint"],
            },
        })
    }

    fn run(proof: &Value, digest: &str, keys: &[LogKey]) -> ProofVerdict {
        verify_proof(proof, "anchor.proofs[0]", digest, keys)
    }

    #[test]
    fn a_real_entry_verifies_with_the_real_key() {
        let verdict = run(&real_proof(), DIGEST, &[real_key()]);
        assert_eq!(verdict.errors, Vec::<String>::new());
        assert_eq!(verdict.status, ProofStatus::Verified);
        assert_eq!(verdict.time_seconds, Some(1_780_365_839));
    }

    #[test]
    fn without_a_pinned_key_it_is_not_checked_but_mismatches_still_fail() {
        let verdict = run(&real_proof(), DIGEST, &[]);
        assert_eq!(verdict.status, ProofStatus::NotChecked);
        assert_eq!(verdict.time_seconds, None);

        let other = "00".repeat(32);
        let verdict = run(&real_proof(), &other, &[]);
        assert_eq!(verdict.status, ProofStatus::Failed);
        assert_eq!(verdict.errors, vec![ENTRY_MISMATCH]);

        let mut broken = real_proof();
        broken["inclusion_proof"]["log_index"] = json!(1);
        let verdict = run(&broken, DIGEST, &[]);
        assert_eq!(verdict.errors, vec![INCLUSION_INVALID]);
    }

    #[test]
    fn a_key_from_another_log_is_refused() {
        let other = sigverify::sign_with_ephemeral_p256(&[7u8; 32]).unwrap().0;
        let verdict = run(&real_proof(), DIGEST, &[LogKey::from_spki(&other).unwrap()]);
        assert_eq!(verdict.errors, vec![LOG_UNKNOWN]);
    }

    #[test]
    fn every_signed_or_proved_field_matters() {
        let key = real_key();
        let tamper = |edit: &dyn Fn(&mut Value), code: &str| {
            let mut proof = real_proof();
            edit(&mut proof);
            let verdict = run(&proof, DIGEST, std::slice::from_ref(&key));
            assert_eq!(verdict.status, ProofStatus::Failed, "{code}");
            assert_eq!(verdict.errors, vec![code.to_string()]);
        };
        tamper(
            &|proof| proof["integrated_time"] = json!(1_500_000_000),
            SET_INVALID,
        );
        tamper(&|proof| proof["log_index"] = json!(5), SET_INVALID);
        tamper(
            &|proof| {
                let root = proof["inclusion_proof"]["root_hash"].as_str().unwrap();
                let flipped = format!("00{}", &root[2..]);
                proof["inclusion_proof"]["root_hash"] = json!(flipped);
            },
            INCLUSION_INVALID,
        );
        tamper(
            &|proof| {
                let hash = proof["inclusion_proof"]["hashes"][3].as_str().unwrap();
                let flipped = format!("00{}", &hash[2..]);
                proof["inclusion_proof"]["hashes"][3] = json!(flipped);
            },
            INCLUSION_INVALID,
        );
        tamper(
            &|proof| proof["inclusion_proof"]["tree_size"] = json!(1),
            INCLUSION_INVALID,
        );
        tamper(
            &|proof| {
                let note = proof["inclusion_proof"]["checkpoint"].as_str().unwrap();
                proof["inclusion_proof"]["checkpoint"] = json!(note.replacen("rekor", "rekoR", 1));
            },
            NOTE_INVALID,
        );
        tamper(
            &|proof| proof["inclusion_proof"]["checkpoint"] = json!("no blank line"),
            NOTE_INVALID,
        );
    }

    #[test]
    fn absurd_sizes_and_bad_types_are_refused_quickly() {
        let key = real_key();
        let mut many = real_proof();
        many["inclusion_proof"]["hashes"] = json!(vec!["00".repeat(32); 1000]);
        let verdict = run(&many, DIGEST, std::slice::from_ref(&key));
        assert_eq!(
            verdict.errors,
            vec!["ANCHOR_MALFORMED (rekor.inclusion_proof.hashes)"]
        );

        let mut huge = real_proof();
        huge["body"] = json!("A".repeat(MAX_BODY_BYTES + 4));
        assert_eq!(
            run(&huge, DIGEST, std::slice::from_ref(&key)).errors,
            vec!["ANCHOR_MALFORMED (rekor.body)"]
        );

        let mut size = real_proof();
        size["inclusion_proof"]["tree_size"] = json!(u64::MAX);
        size["inclusion_proof"]["log_index"] = json!(u64::MAX - 1);
        assert_eq!(
            run(&size, DIGEST, std::slice::from_ref(&key)).errors,
            vec![INCLUSION_INVALID]
        );

        for field in [
            "body",
            "log_id",
            "signed_entry_timestamp",
            "integrated_time",
        ] {
            let mut wrong = real_proof();
            wrong[field] = json!(["not", "a", "scalar"]);
            let verdict = run(&wrong, DIGEST, std::slice::from_ref(&key));
            assert_eq!(verdict.status, ProofStatus::Failed, "{field}");
        }
    }

    #[test]
    fn unknown_fields_are_reported() {
        let mut proof = real_proof();
        proof["trust_me"] = json!(true);
        proof["inclusion_proof"]["extra"] = json!(1);
        let verdict = run(&proof, DIGEST, &[real_key()]);
        assert_eq!(verdict.status, ProofStatus::Failed);
        assert_eq!(
            verdict.errors,
            vec![
                "UNKNOWN_FIELD (anchor.proofs[0].trust_me)",
                "UNKNOWN_FIELD (anchor.proofs[0].inclusion_proof.extra)",
            ]
        );
    }

    #[test]
    fn merkle_paths_match_small_trees() {
        // A tree of three leaves, built by hand: root = H(H(a, b), c).
        let (a, b, c) = (leaf_hash(b"a"), leaf_hash(b"b"), leaf_hash(b"c"));
        let left = node_hash(&a, &b);
        let root = node_hash(&left, &c);
        assert_eq!(root_from_path(a, 0, 3, &[b, c]), Some(root));
        assert_eq!(root_from_path(b, 1, 3, &[a, c]), Some(root));
        assert_eq!(root_from_path(c, 2, 3, &[left]), Some(root));
        assert_ne!(root_from_path(c, 1, 3, &[left]), Some(root));
        assert_eq!(root_from_path(a, 3, 3, &[]), None, "index outside the tree");
        assert_eq!(root_from_path(a, 0, 1, &[]), Some(a), "a one-leaf tree");
        assert_eq!(root_from_path(a, 0, 3, &[b]), None, "path too short");
        assert_eq!(root_from_path(a, 0, 3, &[b, c, c]), None, "path too long");
    }

    #[test]
    fn the_request_is_a_hashedrekord_a_log_can_check() {
        let digest = hex::encode([9u8; 32]);
        let request = entry_request(&digest).unwrap();
        assert_eq!(request["kind"], "hashedrekord");
        assert_eq!(request["apiVersion"], "0.0.1");
        assert_eq!(request["spec"]["data"]["hash"]["value"], digest.as_str());
        let signature = STANDARD
            .decode(request["spec"]["signature"]["content"].as_str().unwrap())
            .unwrap();
        let pem = String::from_utf8(
            STANDARD
                .decode(
                    request["spec"]["signature"]["publicKey"]["content"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        let spki = der::pem_or_base64_blocks(&pem, "PUBLIC KEY")
            .unwrap()
            .remove(0);
        let key = sigverify::parse_spki(&spki).unwrap();
        assert!(sigverify::verify_digest(
            &key,
            HashAlg::Sha256,
            &[9u8; 32],
            &signature
        ));
        assert!(entry_request("short").is_err());
    }
}
