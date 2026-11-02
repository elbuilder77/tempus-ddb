//! `tempus.anchor.v1`: proof that a checkpoint existed by a date, from an authority that is
//! neither the operator nor Tempus. The document lives outside the checkpoint (a new field
//! there would break its signature) and outside the bundle (its field list is closed).
//! Everything here is pure and shared with the browser verifier; getting the proofs is the
//! CLI's job (`python/tempus_ddb/anchor.py`).

use crate::b2a::{canonicalize, sha256_hex, unknown_fields};
use crate::der;
use crate::rekor::{self, LogKey};
use crate::tsa;
use serde_json::{json, Value};

pub(crate) const ANCHOR_SCHEMA: &str = "tempus.anchor.v1";
pub(crate) const ANCHOR_VERIFICATION_SCHEMA: &str = "tempus.anchor-verification.v1";

const ANCHOR_FIELDS: &[&str] = &[
    "schema_version",
    "checkpoint_id",
    "tenant_id",
    "checkpoint_digest",
    "proofs",
];
const ROOTS_FIELDS: &[&str] = &["rekor_public_keys", "tsa_roots"];
const MAX_PROOFS: usize = 8;
/// Clocks disagree a little; a checkpoint cannot be anchored long before it exists.
const MAX_CLOCK_SKEW_MICROS: u64 = 300 * 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofStatus {
    Verified,
    NotChecked,
    Failed,
}

impl ProofStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::NotChecked => "NOT_CHECKED",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProofVerdict {
    pub backend: &'static str,
    pub status: ProofStatus,
    pub time_seconds: Option<u64>,
    pub errors: Vec<String>,
}

impl ProofVerdict {
    /// `outcome` is `Ok(Some(seconds))` when verified, `Ok(None)` when consistent but nothing
    /// was pinned, `Err(code)` when the proof is wrong. `errors` holds what was found earlier.
    pub(crate) fn from_check(
        backend: &'static str,
        outcome: Result<Option<u64>, String>,
        mut errors: Vec<String>,
    ) -> Self {
        let time_seconds = match outcome {
            Ok(time) => time,
            Err(code) => {
                errors.push(code);
                None
            }
        };
        let (status, time_seconds) = match (errors.is_empty(), time_seconds) {
            (false, _) => (ProofStatus::Failed, None),
            (true, Some(seconds)) => (ProofStatus::Verified, Some(seconds)),
            (true, None) => (ProofStatus::NotChecked, None),
        };
        Self {
            backend,
            status,
            time_seconds,
            errors,
        }
    }
}

/// What the verifier chose to trust, never read from the document being verified.
#[derive(Debug, Default)]
pub(crate) struct TrustRoots {
    rekor_keys: Vec<LogKey>,
    tsa_roots: Vec<Vec<u8>>,
}

impl TrustRoots {
    /// `{"rekor_public_keys": [...], "tsa_roots": [...]}`, each entry PEM or bare base64.
    /// A root that cannot be read is an error of the call: silently dropping it would turn
    /// a typo into "nothing pinned".
    pub(crate) fn parse(roots_json: &str) -> Result<Self, String> {
        if roots_json.trim().is_empty() {
            return Ok(Self::default());
        }
        let parsed = crate::strict_json::parse(roots_json)
            .map_err(|error| format!("Anchor trust roots are not valid JSON: {error}"))?;
        let unknown = unknown_fields(&parsed, "roots", ROOTS_FIELDS);
        if !parsed.is_object() || !unknown.is_empty() {
            return Err(format!(
                "Anchor trust roots must be an object with rekor_public_keys and tsa_roots ({})",
                unknown.join(", ")
            ));
        }
        let list = |field: &str| -> Result<Vec<&str>, String> {
            match parsed.get(field) {
                None => Ok(Vec::new()),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .ok_or_else(|| format!("Anchor trust roots: {field} holds strings"))
                    })
                    .collect(),
                Some(_) => Err(format!("Anchor trust roots: {field} must be an array")),
            }
        };
        let mut roots = Self::default();
        for text in list("rekor_public_keys")? {
            for block in der::pem_or_base64_blocks(text, "PUBLIC KEY")
                .map_err(|_| "A Rekor public key is not PEM or base64".to_string())?
            {
                roots.rekor_keys.push(
                    LogKey::from_spki(&block)
                        .map_err(|_| "A Rekor public key is not a usable key".to_string())?,
                );
            }
        }
        for text in list("tsa_roots")? {
            for block in der::pem_or_base64_blocks(text, "CERTIFICATE")
                .map_err(|_| "A TSA root is not PEM or base64".to_string())?
            {
                if !tsa::is_certificate(&block) {
                    return Err("A TSA root is not an X.509 certificate".to_string());
                }
                roots.tsa_roots.push(block);
            }
        }
        Ok(roots)
    }
}

/// `sha256_hex(canonical(signed checkpoint, signature included))`: what gets anchored. It
/// commits to `stream_root_hash` and to the tenant, the sequence, the date and the signature.
pub(crate) fn checkpoint_digest_of_value(checkpoint: &Value) -> Result<String, String> {
    Ok(sha256_hex(canonicalize(checkpoint)?.as_bytes()))
}

/// [`checkpoint_digest_of_value`] for checkpoint JSON text (strict parse).
pub(crate) fn checkpoint_digest(checkpoint_json: &str) -> Result<String, String> {
    let checkpoint = crate::strict_json::parse_labeled(checkpoint_json, "Checkpoint")?;
    if !checkpoint.is_object() {
        return Err("Checkpoint must be a JSON object".to_string());
    }
    checkpoint_digest_of_value(&checkpoint)
}

/// The anchor's verdict before it is written out as JSON.
#[derive(Debug)]
pub(crate) struct AnchorReport {
    pub status: &'static str,
    pub checkpoint_id: Value,
    pub checkpoint_digest: Option<String>,
    pub anchored_at: Option<u64>,
    pub proofs: Vec<ProofVerdict>,
    pub errors: Vec<String>,
}

impl AnchorReport {
    pub(crate) fn invalid(code: &str) -> Self {
        Self {
            status: "INVALID",
            checkpoint_id: Value::Null,
            checkpoint_digest: None,
            anchored_at: None,
            proofs: Vec::new(),
            errors: vec![code.to_string()],
        }
    }

    /// The fields shared by `tempus.anchor-verification.v1` and a bundle result's `anchor`.
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "status": self.status,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_digest": self.checkpoint_digest,
            "anchored_at": self.anchored_at,
            "proofs": self.proofs.iter().map(|proof| json!({
                "backend": proof.backend,
                "status": proof.status.as_str(),
                "anchored_at": proof.time_seconds.map(|seconds| seconds.saturating_mul(1_000_000)),
                "errors": proof.errors,
            })).collect::<Vec<_>>(),
            "errors": self.errors,
        })
    }

    /// What this anchor leaves unestablished, as `trust.not_checked` entries.
    pub(crate) fn not_checked(&self) -> Vec<String> {
        let mut entries = Vec::new();
        for proof in &self.proofs {
            if proof.status == ProofStatus::NotChecked {
                let (what, how) = match proof.backend {
                    "rekor" => ("the Rekor proof", "--rekor-public-key"),
                    _ => ("the timestamp token", "--tsa-root"),
                };
                entries.push(format!(
                    "ANCHOR_NOT_PINNED ({what} was not checked: pin its trust root with {how})"
                ));
            }
        }
        if self
            .proofs
            .iter()
            .any(|proof| proof.backend == "rfc3161" && proof.status == ProofStatus::Verified)
        {
            entries.push(
                "TSA_REVOCATION (whether the timestamp certificates were revoked cannot be checked offline)"
                    .to_string(),
            );
        }
        entries
    }
}

/// Verify an anchor document against a checkpoint document. `VERIFIED` says this exact
/// checkpoint existed by `anchored_at`; whether the gate really signed it is the checkpoint
/// verification's job, which `verify_bundle` runs on the same document.
pub(crate) fn verify_value(anchor: &Value, checkpoint: &Value, roots: &TrustRoots) -> AnchorReport {
    if !anchor.is_object() {
        return AnchorReport::invalid("ANCHOR_MALFORMED (anchor)");
    }
    let mut errors = unknown_fields(anchor, "anchor", ANCHOR_FIELDS);
    let digest = match checkpoint_digest_of_value(checkpoint) {
        Ok(digest) => digest,
        Err(_) => return AnchorReport::invalid("ANCHOR_CHECKPOINT_MISMATCH"),
    };
    let same = |field: &str| {
        anchor.get(field).is_some_and(Value::is_string)
            && anchor.get(field) == checkpoint.get(field)
    };
    if anchor.get("checkpoint_digest").and_then(Value::as_str) != Some(digest.as_str())
        || !same("checkpoint_id")
        || !same("tenant_id")
    {
        errors.push("ANCHOR_CHECKPOINT_MISMATCH".to_string());
    }
    let created_at = checkpoint.get("created_at").and_then(Value::as_u64);
    if created_at.is_none() {
        errors.push("ANCHOR_CHECKPOINT_MISMATCH".to_string());
    }

    let mut proofs = Vec::new();
    match anchor.get("proofs").and_then(Value::as_array) {
        Some(items) if !items.is_empty() && items.len() <= MAX_PROOFS => {
            for (index, proof) in items.iter().enumerate() {
                let path = format!("anchor.proofs[{index}]");
                let mut verdict = match proof.get("backend").and_then(Value::as_str) {
                    Some("rekor") => rekor::verify_proof(proof, &path, &digest, &roots.rekor_keys),
                    Some("rfc3161") => tsa::verify_proof(proof, &path, &digest, &roots.tsa_roots),
                    _ => {
                        errors.push(format!("ANCHOR_MALFORMED ({path}.backend)"));
                        continue;
                    }
                };
                // A checkpoint cannot be anchored before it exists: its date would be false.
                if let (Some(seconds), Some(created_at)) = (verdict.time_seconds, created_at) {
                    let micros = seconds.saturating_mul(1_000_000);
                    if micros.saturating_add(MAX_CLOCK_SKEW_MICROS) < created_at {
                        verdict.errors.push("ANCHOR_BEFORE_CHECKPOINT".to_string());
                        verdict.status = ProofStatus::Failed;
                        verdict.time_seconds = None;
                    }
                }
                errors.extend(verdict.errors.iter().cloned());
                proofs.push(verdict);
            }
        }
        _ => errors.push("ANCHOR_MALFORMED (anchor.proofs)".to_string()),
    }

    let earliest = proofs
        .iter()
        .filter(|proof| proof.status == ProofStatus::Verified)
        .filter_map(|proof| proof.time_seconds)
        .min();
    let status = if !errors.is_empty() {
        "INVALID"
    } else if earliest.is_some() {
        "VERIFIED"
    } else {
        "NOT_CHECKED"
    };
    AnchorReport {
        status,
        checkpoint_id: checkpoint
            .get("checkpoint_id")
            .cloned()
            .unwrap_or(Value::Null),
        checkpoint_digest: Some(digest),
        anchored_at: if status == "VERIFIED" {
            earliest.map(|seconds| seconds.saturating_mul(1_000_000))
        } else {
            None
        },
        proofs,
        errors,
    }
}

/// Parse an anchor's text and verify it. An unknown schema is an error of the call, as for
/// every other document; repeated keys are a verdict, so a reader sees them reported.
pub(crate) fn verify_text(
    anchor_json: &str,
    checkpoint: &Value,
    roots: &TrustRoots,
) -> Result<AnchorReport, String> {
    let anchor = match crate::strict_json::parse(anchor_json) {
        Ok(anchor) => anchor,
        Err(error) if crate::strict_json::is_duplicate_key(&error) => {
            return Ok(AnchorReport::invalid(
                crate::strict_json::DUPLICATE_KEY_CODE,
            ));
        }
        Err(error) => return Err(format!("Anchor is not valid JSON: {error}")),
    };
    if anchor.get("schema_version").and_then(Value::as_str) != Some(ANCHOR_SCHEMA) {
        return Err(format!(
            "TEMPUS_ANCHOR_SCHEMA_UNKNOWN: expected {ANCHOR_SCHEMA}"
        ));
    }
    Ok(verify_value(&anchor, checkpoint, roots))
}

/// `verify_anchor`: an anchor and its checkpoint, returning `tempus.anchor-verification.v1`.
pub(crate) fn verify_anchor(
    anchor_json: &str,
    checkpoint_json: &str,
    roots_json: &str,
) -> Result<String, String> {
    let roots = TrustRoots::parse(roots_json)?;
    let checkpoint = crate::strict_json::parse_labeled(checkpoint_json, "Checkpoint")?;
    let report = verify_text(anchor_json, &checkpoint, &roots)?;
    let mut result = report.to_json();
    result["schema_version"] = json!(ANCHOR_VERIFICATION_SCHEMA);
    result["not_checked"] = json!(report.not_checked());
    canonicalize(&result)
}

/// Native only: the Rekor entry to submit for a digest, as JSON text.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn rekor_entry_request(digest_hex: &str) -> Result<String, String> {
    canonicalize(&rekor::entry_request(digest_hex)?)
}

/// Native only: `{"request": base64 TimeStampReq, "nonce": hex}` for a digest. The nonce is
/// a positive DER integer of exactly eight bytes, so it reads back the way it was written.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn tsa_request(digest_hex: &str) -> Result<String, String> {
    use base64::Engine;
    use rand::RngCore;

    let digest = hex::decode(digest_hex)
        .ok()
        .filter(|digest| digest.len() == 32)
        .ok_or_else(|| "TEMPUS_ANCHOR_DIGEST_INVALID: expected 64 hex characters".to_string())?;
    let mut nonce = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce[0] = (nonce[0] & 0x3F) | 0x40;
    let request = tsa::build_request(&digest, &nonce);
    canonicalize(&json!({
        "request": base64::engine::general_purpose::STANDARD.encode(request),
        "nonce": hex::encode(nonce),
    }))
}

/// Native only: the base64 token inside a base64 `TimeStampResp`, nonce checked.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn tsa_token(response_base64: &str, nonce_hex: &str) -> Result<String, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let response = STANDARD
        .decode(response_base64)
        .map_err(|_| "the TSA response is not base64".to_string())?;
    let nonce = hex::decode(nonce_hex).map_err(|_| "the nonce is not hex".to_string())?;
    Ok(STANDARD.encode(tsa::token_from_response(&response, &nonce)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REKOR_KEY: &str = include_str!("../tests/vectors/anchor/rekor_public_key.pem");
    const SIGSTORE_ROOT: &str = include_str!("../tests/vectors/anchor/sigstore_tsa_root.pem");

    #[test]
    fn roots_accept_pem_variants() {
        let spki = der::pem_or_base64_blocks(REKOR_KEY, "PUBLIC KEY")
            .unwrap()
            .remove(0);
        use base64::Engine;
        let bare = base64::engine::general_purpose::STANDARD.encode(&spki);
        let crlf = REKOR_KEY.replace('\n', "\r\n");
        let double = format!("{SIGSTORE_ROOT}\n\n{SIGSTORE_ROOT}");
        let roots = TrustRoots::parse(
            &json!({
                "rekor_public_keys": [REKOR_KEY, crlf, bare],
                "tsa_roots": [double, SIGSTORE_ROOT],
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(roots.rekor_keys.len(), 3);
        assert_eq!(roots.tsa_roots.len(), 3);
        assert!(TrustRoots::parse("").unwrap().rekor_keys.is_empty());
        assert!(TrustRoots::parse("  ").unwrap().tsa_roots.is_empty());
    }

    #[test]
    fn an_unreadable_root_is_an_error_not_an_empty_pin() {
        for bad in [
            json!({"rekor_public_keys": ["not base64!"]}),
            json!({"rekor_public_keys": ["AQID"]}),
            json!({"tsa_roots": ["AQID"]}),
            json!({"tsa_roots": [SIGSTORE_ROOT.replace("CERTIFICATE", "OTHER")]}),
            json!({"tsa_roots": "not a list"}),
            json!({"tsa_roots": [1]}),
            json!({"something_else": []}),
            json!([]),
        ] {
            assert!(TrustRoots::parse(&bad.to_string()).is_err(), "{bad}");
        }
        assert!(TrustRoots::parse("{").is_err());
    }
}
