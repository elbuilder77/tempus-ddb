#![cfg_attr(
    target_arch = "wasm32",
    allow(dead_code, unused_imports, unused_variables, irrefutable_let_patterns)
)]
//! Signed policy bundles, their deterministic evaluation, and the signer boundary.
//! Policy storage needs the gate database and is compiled out on wasm32; evaluation and
//! verification are pure and shared with the browser verifier.

use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
#[cfg(not(target_arch = "wasm32"))]
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const SIGNER_CONFIG_SCHEMA: &str = "tempus.signer-config.v1";
pub(crate) const POLICY_BUNDLE_SCHEMA: &str = "tempus.policy-bundle.v1";
/// Allow-all policy that gates before 0.5.4 seeded automatically. It is never created or
/// resolved any more: a database that still carries it is treated as having no policy.
pub(crate) const LEGACY_BASELINE_POLICY_VERSION: &str = "tempus.baseline.v1";
/// Prefix of the explicit, opt-in allow-all policy (`install_allow_all_dev_policy`).
pub(crate) const DEV_ALLOW_ALL_POLICY_PREFIX: &str = "tempus.dev-allow-all.v1";
/// Sentinel `policy_version` of a BLOCKED receipt issued while no policy was installed.
pub(crate) const NO_POLICY_VERSION: &str = "tempus.policy-not-installed.v1";
pub(crate) const POLICY_NOT_INSTALLED_CODE: &str = "POLICY_NOT_INSTALLED";
pub(crate) const POLICY_NOT_INSTALLED_ERROR: &str = "TEMPUS_POLICY_NOT_INSTALLED";
pub(crate) const SIGNATURE_ALGORITHM: &str = "Ed25519";
pub(crate) const IDENTITY_EVENT_SCHEMA: &str = "tempus.identity-lifecycle-event.v1";

/// The decimals of a currency a policy does not mention.
const DEFAULT_CURRENCY_EXPONENT: u64 = 2;
const MAX_CURRENCY_EXPONENT: u64 = 8;
/// ISO 4217 currencies whose minor unit is not a hundredth, by decimals.
const ISO_4217_NOT_TWO_DECIMALS: &[(u64, &[&str])] = &[
    (
        0,
        &[
            "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI",
            "VND", "VUV", "XAF", "XOF", "XPF",
        ],
    ),
    (3, &["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"]),
    (4, &["CLF", "UYW"]),
];

const POLICY_FIELDS: &[&str] = &[
    "allowed_action_types",
    "allowed_resources",
    "allowed_executors",
    "max_ttl_seconds",
    "max_input_bytes",
    "allowed_currencies",
    "currency_exponents",
    "max_money_amount_minor",
    "allowed_beneficiaries",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignerIdentity {
    pub signer_uri: String,
    pub key_version: String,
    pub algorithm: String,
    pub public_key: String,
}

impl SignerIdentity {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "signer_uri": self.signer_uri,
            "key_version": self.key_version,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
        })
    }
}

/// Provider-neutral signing boundary used by the gate and mediated executor.
/// Implementations return a lowercase hexadecimal signature over the exact bytes.
pub(crate) trait SignerBackend {
    fn identity(&self) -> &SignerIdentity;
    fn sign(&self, message: &[u8]) -> Result<String, String>;
}

/// Verification keys are resolved independently from the signing provider. Unknown
/// algorithms, signer URIs, or key versions must return no key and therefore fail closed.
pub(crate) trait VerificationKeyResolver {
    fn resolve(
        &self,
        signer_uri: &str,
        key_version: &str,
        algorithm: &str,
        at_micros: u64,
    ) -> Result<Option<String>, String>;
}

pub(crate) struct EmbeddedKeyResolver {
    identity: SignerIdentity,
}

impl EmbeddedKeyResolver {
    pub(crate) fn new(identity: SignerIdentity) -> Self {
        Self { identity }
    }
}

impl VerificationKeyResolver for EmbeddedKeyResolver {
    fn resolve(
        &self,
        signer_uri: &str,
        key_version: &str,
        algorithm: &str,
        _at_micros: u64,
    ) -> Result<Option<String>, String> {
        if signer_uri == self.identity.signer_uri
            && key_version == self.identity.key_version
            && algorithm == self.identity.algorithm
            && algorithm == SIGNATURE_ALGORITHM
        {
            Ok(Some(self.identity.public_key.clone()))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub(crate) struct PolicyDecision {
    pub decision: &'static str,
    pub reason_codes: Vec<String>,
    pub evidence_digest: String,
    pub executor_constraints: Value,
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn initialize_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS policy_bundles (
            policy_version TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            policy_digest TEXT NOT NULL UNIQUE,
            issued_at INTEGER NOT NULL,
            retired_at INTEGER,
            bundle_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_policy_bundles_active
            ON policy_bundles (tenant_id, retired_at, issued_at DESC);

        CREATE TABLE IF NOT EXISTS identity_lifecycle_events (
            event_id TEXT PRIMARY KEY,
            identity_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            event_type TEXT NOT NULL,
            effective_at INTEGER NOT NULL,
            event_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_identity_events_identity
            ON identity_lifecycle_events (identity_id, effective_at ASC);

        CREATE TABLE IF NOT EXISTS revoked_authorizations (
            authorization_id TEXT PRIMARY KEY,
            revoked_at INTEGER NOT NULL,
            reason TEXT NOT NULL,
            identity_event_id TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS active_policy_attestations (
            tenant_id TEXT PRIMARY KEY,
            policy_version TEXT NOT NULL,
            policy_digest TEXT NOT NULL,
            activated_at INTEGER NOT NULL,
            signer_public_key TEXT NOT NULL,
            signature TEXT NOT NULL,
            attestation_json TEXT NOT NULL
        );",
    )
    .map_err(|e| format!("Failed to initialize Phase 3 schema: {e}"))?;

    for statement in [
        "ALTER TABLE agents ADD COLUMN identity_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE agents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '*'",
        "ALTER TABLE agents ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE agents ADD COLUMN signer_uri TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE agents ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'Ed25519'",
        "ALTER TABLE agents ADD COLUMN valid_from INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE agents ADD COLUMN valid_until INTEGER",
        "ALTER TABLE agents ADD COLUMN revoked_at INTEGER",
    ] {
        if let Err(error) = conn.execute(statement, []) {
            if !error.to_string().contains("duplicate column name") {
                return Err(format!(
                    "Failed to migrate Phase 3 identity schema: {error}"
                ));
            }
        }
    }
    conn.execute(
        "UPDATE agents SET
            identity_id = CASE WHEN identity_id = '' THEN public_key ELSE identity_id END,
            signer_uri = CASE WHEN signer_uri = '' THEN 'local-ed25519://' || public_key ELSE signer_uri END,
            valid_from = CASE WHEN valid_from = 0 THEN registered_at ELSE valid_from END",
        [],
    )
    .map_err(|e| format!("Failed to backfill Phase 3 identity metadata: {e}"))?;
    Ok(())
}

const STALE_DEV_CURRENCY_GUIDANCE: &str = "The stored dev allow-all policy lists currencies that \
     are not exact codes. It is not allowed. Reinstall with `tempus install-policy --allow-all-dev` \
     or TempusDDB.install_allow_all_dev_policy().";

/// A pre-0.5.4 dev allow-all bundle may store a currency list that is not exact codes.
/// Exact codes are still valid; a missing list is the current shape. Anything else must
/// not be used as-is.
fn stale_dev_allow_all(bundle: &Value) -> bool {
    let version = bundle
        .get("policy_version")
        .and_then(Value::as_str)
        .unwrap_or("");
    let tenant = bundle
        .get("tenant_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if tenant != "*" || !version.starts_with(DEV_ALLOW_ALL_POLICY_PREFIX) {
        return false;
    }
    match bundle
        .get("constraints")
        .and_then(|constraints| constraints.get("allowed_currencies"))
    {
        None => false,
        Some(currencies) => exact_currency_list(currencies).is_err(),
    }
}

fn stale_dev_currency_error(detail: &str) -> String {
    format!("TEMPUS_POLICY_INVALID: {detail} {STALE_DEV_CURRENCY_GUIDANCE}")
}

/// Explicit development opt-in: install a signed wildcard policy that allows every
/// action, resource and executor for every tenant without its own policy. Currency is
/// not listed: `allowed_currencies` accepts only exact codes, so omitting it leaves
/// currency unconstrained. Idempotent while a current dev policy is active. This call
/// is the only path that replaces a stored dev policy whose currency list is not exact
/// codes; loading that policy never rewrites it. Refuses to replace a different active
/// `*` policy.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn install_allow_all_dev_policy(
    conn: &Connection,
    signer: &ConfiguredSigner,
    issued_at: u64,
) -> Result<Value, String> {
    let active: Option<(String, String)> = conn
        .query_row(
            "SELECT policy_version, bundle_json FROM policy_bundles
             WHERE tenant_id = '*' AND retired_at IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("Failed to inspect active wildcard policy: {e}"))?;
    let mut replacing_stale = false;
    if let Some((version, bundle_json)) = active {
        if version.starts_with(DEV_ALLOW_ALL_POLICY_PREFIX) {
            let bundle: Value = serde_json::from_str(&bundle_json).map_err(|error| {
                stale_dev_currency_error(&format!(
                    "stored dev allow-all policy is invalid JSON ({error})."
                ))
            })?;
            if !stale_dev_allow_all(&bundle) {
                return Ok(bundle);
            }
            replacing_stale = true;
        } else if version != LEGACY_BASELINE_POLICY_VERSION {
            return Err(format!(
                "TEMPUS_DEV_ALLOW_ALL_REFUSED: an explicit wildcard policy '{version}' is active"
            ));
        }
    }
    let mut issued_at = issued_at;
    for _ in 0..4 {
        let spec = json!({
            "schema_version": POLICY_BUNDLE_SCHEMA,
            "policy_version": format!("{DEV_ALLOW_ALL_POLICY_PREFIX}.{issued_at}"),
            "tenant_id": "*",
            "constraints": {
                "allowed_action_types": ["*"],
                "allowed_resources": ["*"],
                "allowed_executors": ["*"],
                "max_ttl_seconds": 86400,
                "max_input_bytes": 65536
            }
        });
        match install_policy(conn, signer, &spec, issued_at) {
            Ok(bundle) => return Ok(bundle),
            Err(error) if replacing_stale && error.contains("TEMPUS_POLICY_VERSION_CONFLICT") => {
                issued_at = issued_at.saturating_add(1);
            }
            Err(error) if replacing_stale => {
                return Err(format!("{error} {STALE_DEV_CURRENCY_GUIDANCE}"));
            }
            Err(error) => return Err(error),
        }
    }
    Err(stale_dev_currency_error(
        "could not replace the stored dev allow-all policy.",
    ))
}

/// Decision recorded when no policy applies: always BLOCKED with a closed reason code.
pub(crate) fn no_policy_decision(
    intent: &Value,
    ttl_seconds: u64,
) -> Result<PolicyDecision, String> {
    Ok(PolicyDecision {
        decision: "BLOCKED",
        reason_codes: vec![POLICY_NOT_INSTALLED_CODE.to_string()],
        evidence_digest: digest_json(&json!({
            "schema_version": "tempus.policy-evidence.v1",
            "policy_version": NO_POLICY_VERSION,
            "intent": intent,
            "ttl_seconds": ttl_seconds,
        }))?,
        executor_constraints: json!({ "allowed_executors": [] }),
    })
}

/// Digest bound into receipts issued while no policy was installed.
pub(crate) fn no_policy_digest() -> String {
    crate::b2a::sha256_hex(NO_POLICY_VERSION.as_bytes())
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn install_policy(
    conn: &Connection,
    signer: &ConfiguredSigner,
    spec: &Value,
    issued_at: u64,
) -> Result<Value, String> {
    validate_policy_spec(spec)?;
    refuse_unstated_decimals(spec)?;
    let policy_version = required_policy_string(spec, "policy_version")?;
    let tenant_id = required_policy_string(spec, "tenant_id")?;
    let mut body = json!({
        "schema_version": POLICY_BUNDLE_SCHEMA,
        "policy_version": policy_version,
        "tenant_id": tenant_id,
        "constraints": spec.get("constraints").cloned().unwrap_or_else(|| json!({})),
        "issued_at": issued_at,
        "signer": signer.identity().to_json(),
    });
    // Absent stays absent, so a policy without rules keeps the bytes and digests it had.
    if let Some(rules) = spec.get("rules") {
        body["rules"] = rules.clone();
    }
    let policy_digest = digest_json(&body)?;
    let signature = signer
        .sign(&hex::decode(&policy_digest).map_err(|e| format!("Invalid policy digest: {e}"))?)?;
    let mut bundle = body;
    bundle["policy_digest"] = json!(policy_digest);
    bundle["signature"] = json!(signature);
    verify_policy_bundle(&bundle, Some(&signer.identity().public_key))?;
    let bundle_json = crate::b2a::canonicalize(&bundle)?;

    if let Some(existing) = policy_by_version(conn, &policy_version)? {
        if existing.get("policy_digest") == bundle.get("policy_digest") {
            return Ok(existing);
        }
        return Err(format!(
            "TEMPUS_POLICY_VERSION_CONFLICT: '{policy_version}' already identifies different bytes"
        ));
    }

    let attestation_body = json!({
        "schema_version": "tempus.active-policy-attestation.v1",
        "tenant_id": tenant_id,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "activated_at": issued_at,
        "signer": signer.identity().to_json(),
    });
    let canonical_attestation = crate::b2a::canonicalize(&attestation_body)?;
    let attestation_id = crate::b2a::sha256_hex(canonical_attestation.as_bytes());
    let attestation_sig = signer.sign(
        &hex::decode(&attestation_id).map_err(|e| format!("Invalid attestation digest: {e}"))?,
    )?;

    let manage_tx = conn.is_autocommit();
    if manage_tx {
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| format!("Failed to begin policy installation transaction: {e}"))?;
    }

    let install_result = (|| -> Result<(), String> {
        conn.execute(
            "UPDATE policy_bundles SET retired_at = ?1
             WHERE tenant_id = ?2 AND retired_at IS NULL",
            params![issued_at, tenant_id],
        )
        .map_err(|e| format!("Failed to retire previous policy: {e}"))?;

        conn.execute(
            "INSERT INTO policy_bundles
             (policy_version, tenant_id, policy_digest, issued_at, bundle_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                policy_version,
                tenant_id,
                policy_digest,
                issued_at,
                bundle_json
            ],
        )
        .map_err(|e| format!("Failed to install policy: {e}"))?;

        conn.execute(
            "INSERT OR REPLACE INTO active_policy_attestations
             (tenant_id, policy_version, policy_digest, activated_at, signer_public_key, signature, attestation_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                tenant_id,
                policy_version,
                policy_digest,
                issued_at,
                signer.identity().public_key,
                attestation_sig,
                canonical_attestation,
            ],
        )
        .map_err(|e| format!("Failed to record active policy attestation: {e}"))?;

        crate::events::record_event(
            conn,
            &tenant_id,
            "policy.published",
            &policy_digest,
            &bundle_json,
            issued_at,
        )?;

        Ok(())
    })();

    match install_result {
        Ok(()) => {
            if manage_tx {
                conn.execute_batch("COMMIT")
                    .map_err(|e| format!("Failed to commit policy installation: {e}"))?;
            }
        }
        Err(err) => {
            if manage_tx {
                let _ = conn.execute_batch("ROLLBACK");
            }
            return Err(err);
        }
    }

    Ok(bundle)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn active_policy(
    conn: &Connection,
    signer: &ConfiguredSigner,
    tenant_id: &str,
) -> Result<Value, String> {
    // 1. Check for signed active policy attestation for this specific tenant
    let row = conn
        .query_row(
            "SELECT a.policy_version, a.policy_digest, a.signature, a.attestation_json, b.bundle_json
             FROM active_policy_attestations a
             JOIN policy_bundles b ON b.policy_version = a.policy_version
             WHERE a.tenant_id = ?1 AND b.retired_at IS NULL",
            [tenant_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| format!("Failed to resolve active policy: {e}"))?;

    let row = row.filter(|(version, ..)| version != LEGACY_BASELINE_POLICY_VERSION);
    if let Some((version, digest, signature, attestation_json, bundle_json)) = row {
        let (_attestation_val, canonical_att) =
            crate::b2a::parse_canonical(&attestation_json, "active policy attestation")?;
        let attestation_id = crate::b2a::sha256_hex(canonical_att.as_bytes());
        if !verify_signature(
            &signer.identity().public_key,
            &hex::decode(&attestation_id).map_err(|e| format!("Invalid attestation id: {e}"))?,
            &signature,
        ) {
            return Err(
                "TEMPUS_POLICY_INVALID: active policy attestation signature invalid".to_string(),
            );
        }
        return accept_stored_bundle(
            signer,
            &version,
            &digest,
            &bundle_json,
            "TEMPUS_POLICY_INVALID: active policy digest mismatch",
        );
    }

    // If specific tenant not found:
    if tenant_id != "*" {
        // Fail-closed if this tenant previously had a policy installed that was retired
        let had_policy: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM policy_bundles WHERE tenant_id = ?1)",
                [tenant_id],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if had_policy {
            return Err(format!(
                "TEMPUS_POLICY_NOT_FOUND: no active policy applies to tenant '{tenant_id}' (previous policy was retired)"
            ));
        }
    }

    // 2. Query fallback active_policy_attestations for tenant '*'
    let row_star = conn
        .query_row(
            "SELECT a.policy_version, a.policy_digest, a.signature, a.attestation_json, b.bundle_json
             FROM active_policy_attestations a
             JOIN policy_bundles b ON b.policy_version = a.policy_version
             WHERE a.tenant_id = '*' AND b.retired_at IS NULL",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| format!("Failed to resolve fallback policy: {e}"))?;

    // A baseline seeded by an older gate is ignored: it is not an explicit policy.
    let row_star = row_star.filter(|(version, ..)| version != LEGACY_BASELINE_POLICY_VERSION);
    if let Some((version, digest, signature, attestation_json, bundle_json)) = row_star {
        let (_attestation_val, canonical_att) =
            crate::b2a::parse_canonical(&attestation_json, "active policy attestation")?;
        let attestation_id = crate::b2a::sha256_hex(canonical_att.as_bytes());
        if !verify_signature(
            &signer.identity().public_key,
            &hex::decode(&attestation_id).map_err(|e| format!("Invalid attestation id: {e}"))?,
            &signature,
        ) {
            return Err(
                "TEMPUS_POLICY_INVALID: fallback policy attestation signature invalid".to_string(),
            );
        }
        return accept_stored_bundle(
            signer,
            &version,
            &digest,
            &bundle_json,
            "TEMPUS_POLICY_INVALID: fallback policy digest mismatch",
        );
    }

    Err(format!(
        "{POLICY_NOT_INSTALLED_ERROR}: no policy is installed for tenant '{tenant_id}'; \
         install one with `tempus install-policy --policy FILE` (development only: \
         `tempus install-policy --allow-all-dev`)"
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn list_policies(conn: &Connection) -> Result<String, String> {
    let mut statement = conn
        .prepare("SELECT bundle_json, retired_at FROM policy_bundles ORDER BY issued_at ASC")
        .map_err(|e| format!("Failed to prepare policy list: {e}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<u64>>(1)?))
        })
        .map_err(|e| format!("Failed to list policies: {e}"))?;
    let mut policies = Vec::new();
    for row in rows {
        let (raw, retired_at) = row.map_err(|e| format!("Failed to read policy: {e}"))?;
        let mut value: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("Stored policy bundle is invalid JSON: {e}"))?;
        value["status"] = json!(if retired_at.is_some() {
            "RETIRED"
        } else {
            "ACTIVE"
        });
        if let Some(retired_at) = retired_at {
            value["retired_at"] = json!(retired_at);
        }
        policies.push(value);
    }
    crate::b2a::canonicalize(&Value::Array(policies))
}

pub(crate) fn signer_conformance(signer: &dyn SignerBackend) -> Result<String, String> {
    let challenge = b"tempus.signer-conformance.v1\0exact-bytes";
    let signature = signer.sign(challenge)?;
    let verified = verify_signature(&signer.identity().public_key, challenge, &signature);
    if !verified {
        return Err("TEMPUS_SIGNER_CONFORMANCE_FAILED: signature verification failed".to_string());
    }
    crate::b2a::canonicalize(&json!({
        "schema_version": "tempus.signer-conformance-result.v1",
        "status": "PASS",
        "signer": signer.identity().to_json(),
        "checks": {
            "exact_bytes": "PASS",
            "ed25519_verification": "PASS",
            "credential_material_returned": false,
        }
    }))
}

#[cfg(not(target_arch = "wasm32"))]
fn policy_by_version(conn: &Connection, version: &str) -> Result<Option<Value>, String> {
    conn.query_row(
        "SELECT bundle_json FROM policy_bundles WHERE policy_version = ?1",
        [version],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|e| format!("Failed to read policy: {e}"))?
    .map(|raw| {
        serde_json::from_str(&raw).map_err(|e| format!("Stored policy bundle is invalid JSON: {e}"))
    })
    .transpose()
}

/// Signature and digest only. A stored dev policy can be authentic and still fail
/// `validate_policy_spec` when its currency list is not exact codes.
fn authenticate_policy_bundle(
    bundle: &Value,
    expected_public_key: Option<&str>,
) -> Result<Value, String> {
    if bundle.get("schema_version").and_then(Value::as_str) != Some(POLICY_BUNDLE_SCHEMA) {
        return Err("TEMPUS_POLICY_SCHEMA_UNKNOWN".to_string());
    }
    let policy_digest = required_policy_string(bundle, "policy_digest")?;
    let signature = required_policy_string(bundle, "signature")?;
    let signer = bundle
        .get("signer")
        .ok_or_else(|| "TEMPUS_POLICY_SIGNER_MISSING".to_string())?;
    let identity = SignerIdentity {
        signer_uri: required_policy_string(signer, "signer_uri")?,
        key_version: required_policy_string(signer, "key_version")?,
        algorithm: required_policy_string(signer, "algorithm")?,
        public_key: required_policy_string(signer, "public_key")?,
    };
    if let Some(expected) = expected_public_key {
        if identity.public_key != expected {
            return Err("TEMPUS_POLICY_SIGNER_UNTRUSTED".to_string());
        }
    }
    let resolver = EmbeddedKeyResolver::new(identity.clone());
    let resolved = resolver
        .resolve(
            &identity.signer_uri,
            &identity.key_version,
            &identity.algorithm,
            bundle.get("issued_at").and_then(Value::as_u64).unwrap_or(0),
        )?
        .ok_or_else(|| "TEMPUS_POLICY_SIGNER_UNKNOWN".to_string())?;
    let mut body = bundle.clone();
    body.as_object_mut()
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: bundle must be an object".to_string())?
        .retain(|key, _| {
            key != "policy_digest" && key != "signature" && key != "status" && key != "retired_at"
        });
    if digest_json(&body)? != policy_digest {
        return Err("TEMPUS_POLICY_DIGEST_MISMATCH".to_string());
    }
    let digest =
        hex::decode(&policy_digest).map_err(|_| "TEMPUS_POLICY_DIGEST_INVALID".to_string())?;
    if !verify_signature(&resolved, &digest, &signature) {
        return Err("TEMPUS_POLICY_SIGNATURE_INVALID".to_string());
    }
    Ok(body)
}

pub(crate) fn verify_policy_bundle(
    bundle: &Value,
    expected_public_key: Option<&str>,
) -> Result<(), String> {
    let body = authenticate_policy_bundle(bundle, expected_public_key)?;
    validate_policy_spec(&body)
}

/// Load a stored bundle without rewriting it. A dev allow-all policy whose currency
/// list is not exact codes is refused and left as stored. The operator replaces it
/// by calling `install_allow_all_dev_policy`.
fn accept_stored_bundle(
    signer: &ConfiguredSigner,
    version: &str,
    digest: &str,
    bundle_json: &str,
    digest_mismatch: &str,
) -> Result<Value, String> {
    let bundle: Value = match serde_json::from_str(bundle_json) {
        Ok(bundle) => bundle,
        Err(error) if version.starts_with(DEV_ALLOW_ALL_POLICY_PREFIX) => {
            return Err(stale_dev_currency_error(&format!(
                "stored dev allow-all policy is invalid JSON ({error})."
            )));
        }
        Err(error) => return Err(format!("Stored policy bundle is invalid JSON: {error}")),
    };
    if stale_dev_allow_all(&bundle) {
        return Err(stale_dev_currency_error(
            "stored dev allow-all policy cannot be used.",
        ));
    }
    verify_policy_bundle(&bundle, Some(&signer.identity().public_key))?;
    if bundle.get("policy_digest").and_then(Value::as_str) != Some(digest) {
        return Err(digest_mismatch.to_string());
    }
    Ok(bundle)
}

pub(crate) fn evaluate_policy(
    bundle: &Value,
    intent: &Value,
    ttl_seconds: u64,
) -> Result<PolicyDecision, String> {
    verify_policy_bundle(bundle, None)?;
    let constraints = bundle
        .get("constraints")
        .and_then(Value::as_object)
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: constraints must be an object".to_string())?;
    let mut reasons = Vec::new();
    let tenant_id = required_policy_string(intent, "tenant_id")?;
    let policy_tenant = required_policy_string(bundle, "tenant_id")?;
    if policy_tenant != "*" && policy_tenant != tenant_id {
        reasons.push("POLICY_TENANT_DENIED".to_string());
    }
    let action_type = required_policy_string(intent, "action_type")?;
    if !matches_patterns(constraints.get("allowed_action_types"), &action_type)? {
        reasons.push("POLICY_ACTION_DENIED".to_string());
    }
    let resource = required_policy_string(intent, "resource")?;
    if !matches_patterns(constraints.get("allowed_resources"), &resource)? {
        reasons.push("POLICY_RESOURCE_DENIED".to_string());
    }
    let max_ttl = constraints
        .get("max_ttl_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: max_ttl_seconds is required".to_string())?;
    if ttl_seconds > max_ttl {
        reasons.push("POLICY_TTL_DENIED".to_string());
    }
    let input = intent.get("input").cloned().unwrap_or_else(|| json!({}));
    if contains_non_integer_number(&input) {
        reasons.push("POLICY_NON_DETERMINISTIC_INPUT".to_string());
    }
    let input_bytes = crate::b2a::canonicalize(&input)?.len() as u64;
    let max_input_bytes = constraints
        .get("max_input_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: max_input_bytes is required".to_string())?;
    if input_bytes > max_input_bytes {
        reasons.push("POLICY_INPUT_TOO_LARGE".to_string());
    }
    // Invalid money is an error, the same one `validate_intent` returns, so a permit
    // and its later re-evaluation agree.
    reject_payment_without_money(&action_type, intent)?;
    if let Some(money) = intent.get("money").filter(|value| !value.is_null()) {
        if !money_allowed(constraints, money)? {
            reasons.push("POLICY_MONEY_DENIED".to_string());
        }
    }
    if let Some(rules) = bundle.get("rules") {
        let mut context = json!({"intent": intent, "ttl_seconds": ttl_seconds});
        // Absent when there is none: `missing` only sees an absent key, and a null is not one.
        if let Some(money) = intent.get("money").filter(|value| !value.is_null()) {
            let (amount_minor, currency) =
                validate_money(money, constraints.get("currency_exponents"))?;
            context["money"] = json!({"amount_minor": amount_minor, "currency": currency});
        }
        reasons.extend(
            crate::rules::evaluate(rules, &context)
                .into_iter()
                .map(str::to_string),
        );
    }
    if reasons.is_empty() {
        reasons.push("POLICY_ALLOWED".to_string());
    }
    let policy_digest = required_policy_string(bundle, "policy_digest")?;
    let evidence = json!({
        "schema_version": "tempus.policy-evidence.v1",
        "policy_digest": policy_digest,
        "intent": intent,
        "ttl_seconds": ttl_seconds,
    });
    let allowed = reasons.len() == 1 && reasons[0] == "POLICY_ALLOWED";
    Ok(PolicyDecision {
        decision: if allowed { "ALLOWED" } else { "BLOCKED" },
        reason_codes: reasons,
        evidence_digest: digest_json(&evidence)?,
        executor_constraints: json!({
            "allowed_executors": constraints.get("allowed_executors").cloned().unwrap_or_else(|| json!([])),
        }),
    })
}

pub(crate) fn executor_allowed(bundle: &Value, executor_id: &str) -> Result<bool, String> {
    verify_policy_bundle(bundle, None)?;
    let constraints = bundle
        .get("constraints")
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: constraints are missing".to_string())?;
    matches_patterns(constraints.get("allowed_executors"), executor_id)
}

fn validate_policy_spec(spec: &Value) -> Result<(), String> {
    if spec.get("schema_version").and_then(Value::as_str) != Some(POLICY_BUNDLE_SCHEMA) {
        return Err("TEMPUS_POLICY_SCHEMA_UNKNOWN".to_string());
    }
    required_policy_string(spec, "policy_version")?;
    required_policy_string(spec, "tenant_id")?;
    let constraints = spec
        .get("constraints")
        .and_then(Value::as_object)
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: constraints must be an object".to_string())?;
    for field in constraints.keys() {
        if !POLICY_FIELDS.contains(&field.as_str()) {
            return Err(format!("TEMPUS_POLICY_CONSTRAINT_UNKNOWN: '{field}'"));
        }
    }
    for field in [
        "allowed_action_types",
        "allowed_resources",
        "allowed_executors",
    ] {
        pattern_list(constraints.get(field), field)?;
    }
    let max_ttl = constraints
        .get("max_ttl_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: max_ttl_seconds is required".to_string())?;
    if !(1..=86400).contains(&max_ttl) {
        return Err("TEMPUS_POLICY_INVALID: max_ttl_seconds must be 1..86400".to_string());
    }
    let max_input = constraints
        .get("max_input_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: max_input_bytes is required".to_string())?;
    if max_input == 0 || max_input > 10_000_000 {
        return Err("TEMPUS_POLICY_INVALID: max_input_bytes must be 1..10000000".to_string());
    }
    if let Some(currencies) = constraints.get("allowed_currencies") {
        exact_currency_list(currencies)?;
    }
    if let Some(exponents) = constraints.get("currency_exponents") {
        validate_currency_exponents(exponents)?;
    }
    if let Some(beneficiaries) = constraints.get("allowed_beneficiaries") {
        pattern_list(Some(beneficiaries), "allowed_beneficiaries")?;
    }
    if let Some(amount) = constraints.get("max_money_amount_minor") {
        if amount.as_u64().is_none() {
            return Err(
                "TEMPUS_POLICY_INVALID: max_money_amount_minor must be an unsigned integer"
                    .to_string(),
            );
        }
    }
    if let Some(rules) = spec.get("rules") {
        crate::rules::validate(rules)?;
    }
    Ok(())
}

/// One piece of a pattern or a candidate, split on `.` and `/`.
///
/// A `*` is a wildcard only when it is the whole piece. Any other `*` makes
/// the pattern match nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Piece<'a> {
    Text(&'a str),
    Sep(u8),
    Wild,
}

/// Split `input` on `.` and `/`. With `wildcards`, a piece that is exactly `*`
/// becomes [`Piece::Wild`]; a piece that merely contains `*` is rejected.
fn component_pieces<'a>(input: &'a str, wildcards: bool) -> Option<Vec<Piece<'a>>> {
    let mut pieces = Vec::new();
    let mut start = 0usize;
    for (index, byte) in input.bytes().enumerate() {
        if byte == b'.' || byte == b'/' {
            if start < index && !push_piece(&mut pieces, &input[start..index], wildcards) {
                return None;
            }
            pieces.push(Piece::Sep(byte));
            start = index + 1;
        }
    }
    if start < input.len() && !push_piece(&mut pieces, &input[start..], wildcards) {
        return None;
    }
    Some(pieces)
}

fn push_piece<'a>(pieces: &mut Vec<Piece<'a>>, text: &'a str, wildcards: bool) -> bool {
    if wildcards && text.contains('*') {
        if text != "*" {
            return false;
        }
        pieces.push(Piece::Wild);
    } else {
        pieces.push(Piece::Text(text));
    }
    true
}

fn pieces_match(pattern: &[Piece<'_>], candidate: &[Piece<'_>]) -> bool {
    match pattern {
        [] => candidate.is_empty(),
        [Piece::Wild, rest @ ..] => wildcard_matches(rest, candidate),
        [Piece::Sep(separator), rest @ ..] => match candidate {
            [Piece::Sep(candidate_separator), tail @ ..] if candidate_separator == separator => {
                pieces_match(rest, tail)
            }
            _ => false,
        },
        [Piece::Text(text), rest @ ..] => match candidate {
            [Piece::Text(candidate_text), tail @ ..] if candidate_text == text => {
                pieces_match(rest, tail)
            }
            _ => false,
        },
    }
}

/// A whole-component `*` consumes one or more pieces.
///
/// When more of the pattern follows, the extra pieces stay inside the wildcard
/// only while they are joined by the separator that comes right after the `*`
/// (`*.example.com` can span more than one label but cannot cross a `/`). A
/// trailing `*` consumes the non-empty remainder. It does not match the text
/// before the star by itself, and it does not match a different component.
fn wildcard_matches(rest: &[Piece<'_>], candidate: &[Piece<'_>]) -> bool {
    if rest.is_empty() {
        return !candidate.is_empty();
    }
    let bound = match rest {
        [Piece::Sep(separator), ..] => Some(*separator),
        _ => None,
    };
    let mut index = 0usize;
    let mut texts = 0usize;
    while index < candidate.len() {
        match candidate[index] {
            Piece::Text(_) => {
                texts += 1;
                index += 1;
                if pieces_match(rest, &candidate[index..]) {
                    return true;
                }
            }
            Piece::Sep(separator) => {
                if texts == 0 || bound != Some(separator) {
                    return false;
                }
                index += 1;
            }
            Piece::Wild => return false,
        }
    }
    false
}

/// `true` when `pattern` matches `candidate` on component boundaries.
///
/// `*` alone matches everything. Any other `*` matches only as a whole
/// component between `.` or `/`. A pattern whose `*` is not a whole component
/// matches nothing.
fn pattern_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" || pattern == candidate {
        return true;
    }
    let Some(pattern_pieces) = component_pieces(pattern, true) else {
        return false;
    };
    let Some(candidate_pieces) = component_pieces(candidate, false) else {
        return false;
    };
    pieces_match(&pattern_pieces, &candidate_pieces)
}

/// ISO-style currency code: three ASCII uppercase letters.
fn is_exact_currency_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 3 && bytes.iter().all(|byte| byte.is_ascii_uppercase())
}

/// `allowed_currencies` is an exact allowlist. Patterns are rejected when the bundle
/// is loaded and again when it is evaluated.
fn exact_currency_list(value: &Value) -> Result<Vec<&str>, String> {
    let codes = pattern_list(Some(value), "allowed_currencies")?;
    for code in &codes {
        if !is_exact_currency_code(code) {
            return Err(format!(
                "TEMPUS_POLICY_INVALID: allowed_currencies entries must be exact currency codes, not patterns ({code})"
            ));
        }
    }
    Ok(codes)
}

/// `currency_exponents`: how many decimals a currency has in this policy, for a currency
/// whose minor unit is not a hundredth.
fn validate_currency_exponents(value: &Value) -> Result<(), String> {
    let exponents = value
        .as_object()
        .ok_or_else(|| "TEMPUS_POLICY_INVALID: currency_exponents must be an object".to_string())?;
    for (code, exponent) in exponents {
        if !is_exact_currency_code(code) {
            return Err(format!(
                "TEMPUS_POLICY_INVALID: currency_exponents keys must be exact currency codes ({code})"
            ));
        }
        if !exponent
            .as_u64()
            .is_some_and(|value| value <= MAX_CURRENCY_EXPONENT)
        {
            return Err(format!(
                "TEMPUS_POLICY_INVALID: currency_exponents.{code} must be an integer from 0 to {MAX_CURRENCY_EXPONENT}"
            ));
        }
    }
    Ok(())
}

/// Installing a policy that lists one of these currencies without stating its decimals is
/// refused: read in hundredths, `"500"` yen would meet a limit as 50000. A policy already
/// stored or signed stays what it says, so this is never applied when a bundle is read.
fn refuse_unstated_decimals(spec: &Value) -> Result<(), String> {
    let constraints = spec.get("constraints");
    let Some(currencies) = constraints.and_then(|value| value.get("allowed_currencies")) else {
        return Ok(());
    };
    let stated = constraints.and_then(|value| value.get("currency_exponents"));
    for code in exact_currency_list(currencies)? {
        if stated.is_some_and(|exponents| exponents.get(code).is_some()) {
            continue;
        }
        if let Some((decimals, _)) = ISO_4217_NOT_TWO_DECIMALS
            .iter()
            .find(|(_, codes)| codes.contains(&code))
        {
            return Err(format!(
                "TEMPUS_POLICY_INVALID: allowed_currencies names {code}, which has {decimals} \
                 decimals in ISO 4217: state it with \"currency_exponents\": {{\"{code}\": {decimals}}}, \
                 or {{\"{code}\": 2}} to keep reading it in hundredths"
            ));
        }
    }
    Ok(())
}

/// Payment action types the gate and the payment executor both recognize.
pub(crate) fn is_payment_action(action_type: &str) -> bool {
    matches!(
        action_type,
        "finance.disburse" | "finance.transfer" | "payment.charge"
    )
}

/// A payment action has no effect without a money object whose amount is greater than zero.
pub(crate) fn reject_payment_without_money(
    action_type: &str,
    intent: &Value,
) -> Result<(), String> {
    if !is_payment_action(action_type) {
        return Ok(());
    }
    match intent.get("money") {
        Some(money) if money.is_object() => {
            validate_money_shape(money)?;
            // Zero is zero in any currency, so this holds before the policy is known.
            let zero_text = money
                .get("amount")
                .and_then(Value::as_str)
                .is_some_and(|text| text.bytes().all(|byte| matches!(byte, b'0' | b'.')));
            let zero_minor = money.get("amount_minor").and_then(Value::as_u64) == Some(0);
            if zero_text || zero_minor {
                Err(
                    "TEMPUS_INVALID_CONTRACT: a payment action requires a non-zero amount"
                        .to_string(),
                )
            } else {
                Ok(())
            }
        }
        _ => Err("TEMPUS_INVALID_CONTRACT: a payment action requires a money object".to_string()),
    }
}

fn matches_patterns(value: Option<&Value>, candidate: &str) -> Result<bool, String> {
    Ok(pattern_list(value, "pattern list")?
        .iter()
        .any(|pattern| pattern_matches(pattern, candidate)))
}

fn pattern_list<'a>(value: Option<&'a Value>, field: &str) -> Result<Vec<&'a str>, String> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("TEMPUS_POLICY_INVALID: {field} must be an array"))?;
    if values.is_empty() {
        return Err(format!("TEMPUS_POLICY_INVALID: {field} must not be empty"));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("TEMPUS_POLICY_INVALID: {field} entries must be strings"))
        })
        .collect()
}

/// The names in an intent's `money`: its one currency, and a beneficiary of the right type.
fn money_currency(money: &Value) -> Result<String, String> {
    let name = |field: &str| -> Result<Option<&str>, String> {
        match money.get(field) {
            None => Ok(None),
            Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.as_str())),
            Some(_) => Err(format!(
                "TEMPUS_INVALID_CONTRACT: money.{field} must be a non-empty string"
            )),
        }
    };
    let currency_name = name("currency")?;
    let asset_name = name("asset")?;
    for (field, value) in [("currency", currency_name), ("asset", asset_name)] {
        if let Some(value) = value {
            if !is_exact_currency_code(value) {
                return Err(format!(
                    "TEMPUS_INVALID_CONTRACT: money.{field} must be an exact 3-letter currency code"
                ));
            }
        }
    }
    let currency = match (currency_name, asset_name) {
        (Some(currency), Some(asset)) if currency != asset => {
            return Err(
                "TEMPUS_INVALID_CONTRACT: money.currency and money.asset must be the same value"
                    .to_string(),
            )
        }
        (Some(value), _) | (None, Some(value)) => value.to_string(),
        (None, None) => return Err("TEMPUS_INVALID_CONTRACT: money.asset is required".to_string()),
    };
    // The executor pays this value as written: when present it must be a real string.
    // (It is only *required* here when `allowed_beneficiaries` constrains it.)
    if let Some(beneficiary) = money.get("beneficiary") {
        if !matches!(beneficiary, Value::String(text) if !text.is_empty()) {
            return Err(
                "TEMPUS_INVALID_CONTRACT: money.beneficiary must be a non-empty string".to_string(),
            );
        }
    }
    Ok(currency)
}

fn money_amount_text(money: &Value) -> Result<Option<&str>, String> {
    match money.get("amount") {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => {
            Err("TEMPUS_INVALID_CONTRACT: money.amount must be a decimal string".to_string())
        }
    }
}

fn money_amount_minor(money: &Value) -> Result<Option<u64>, String> {
    money
        .get("amount_minor")
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                "TEMPUS_INVALID_CONTRACT: money.amount_minor must be an unsigned integer"
                    .to_string()
            })
        })
        .transpose()
}

/// What an intent's `money` must be whatever policy reads it. How many decimals its currency
/// has is the policy's to say, so an amount is only read in `validate_money`.
pub(crate) fn validate_money_shape(money: &Value) -> Result<(), String> {
    money_currency(money)?;
    let text = money_amount_text(money)?;
    let minor = money_amount_minor(money)?;
    match text {
        Some(text) if !is_decimal(text, MAX_CURRENCY_EXPONENT) => {
            Err(amount_error(MAX_CURRENCY_EXPONENT))
        }
        None if minor.is_none() => {
            Err("TEMPUS_INVALID_CONTRACT: money.amount must be a decimal string".to_string())
        }
        _ => Ok(()),
    }
}

/// The decimals of a currency in this policy: what `currency_exponents` says, or two.
fn currency_exponent(exponents: Option<&Value>, currency: &str) -> Result<u64, String> {
    let Some(exponent) = exponents.and_then(|value| value.get(currency)) else {
        return Ok(DEFAULT_CURRENCY_EXPONENT);
    };
    exponent
        .as_u64()
        .filter(|value| *value <= MAX_CURRENCY_EXPONENT)
        .ok_or_else(|| {
            format!(
                "TEMPUS_POLICY_INVALID: currency_exponents.{currency} must be an integer from 0 to {MAX_CURRENCY_EXPONENT}"
            )
        })
}

/// The one reading of an intent's `money` that the policy evaluates and the executors use.
///
/// Amounts are minor units: `exponents` (the policy's `currency_exponents`) says how many
/// decimals a currency has, and any other currency has two. `amount` (decimal string) and
/// `amount_minor` (unsigned integer) are two spellings of one value, and `currency` and
/// `asset` are two names for one field: if both spellings are present they must agree, and a
/// field of the wrong type is an error rather than being skipped.
pub(crate) fn validate_money(
    money: &Value,
    exponents: Option<&Value>,
) -> Result<(u64, String), String> {
    let currency = money_currency(money)?;
    let exponent = currency_exponent(exponents, &currency)?;
    let from_text = money_amount_text(money)?
        .map(|text| parse_minor_units(text, exponent))
        .transpose()?;
    let from_minor = money_amount_minor(money)?;
    let amount = match (from_text, from_minor) {
        (Some(text), Some(minor)) if text != minor => {
            return Err(format!(
                "TEMPUS_INVALID_CONTRACT: money.amount ({text} minor units) and \
                 money.amount_minor ({minor}) disagree"
            ))
        }
        (Some(value), _) | (None, Some(value)) => value,
        (None, None) => {
            return Err(
                "TEMPUS_INVALID_CONTRACT: money.amount must be a decimal string".to_string(),
            )
        }
    };
    Ok((amount, currency))
}

fn money_allowed(
    constraints: &serde_json::Map<String, Value>,
    money: &Value,
) -> Result<bool, String> {
    let (amount, currency) = validate_money(money, constraints.get("currency_exponents"))?;
    let currency = currency.as_str();
    if let Some(currencies) = constraints.get("allowed_currencies") {
        // Exact codes only.
        let codes = exact_currency_list(currencies)?;
        if !codes.contains(&currency) {
            return Ok(false);
        }
    }
    if let Some(beneficiaries) = constraints.get("allowed_beneficiaries") {
        let beneficiary = money
            .get("beneficiary")
            .and_then(Value::as_str)
            .ok_or_else(|| "TEMPUS_INVALID_CONTRACT: money.beneficiary is required when allowed_beneficiaries is constrained".to_string())?;
        if !matches_patterns(Some(beneficiaries), beneficiary)? {
            return Ok(false);
        }
    }
    Ok(constraints
        .get("max_money_amount_minor")
        .and_then(Value::as_u64)
        .is_none_or(|maximum| amount <= maximum))
}

/// ASCII digits, and a `.` followed by at least one digit ("5." is not "5"): executors read
/// this same grammar, and a gate that accepted more would burn permits they refuse.
fn is_decimal(value: &str, max_fractional_digits: u64) -> bool {
    let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
    !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && !(value.contains('.') && fractional.is_empty())
        && fractional.len() as u64 <= max_fractional_digits
        && fractional.bytes().all(|byte| byte.is_ascii_digit())
}

fn amount_error(max_fractional_digits: u64) -> String {
    const WORDS: [&str; 9] = [
        "no", "one", "two", "three", "four", "five", "six", "seven", "eight",
    ];
    let digits = match max_fractional_digits {
        0 => "no".to_string(),
        count => format!("at most {}", WORDS[count as usize]),
    };
    format!(
        "TEMPUS_INVALID_CONTRACT: money.amount must be an unsigned decimal with {digits} fractional digits"
    )
}

fn parse_minor_units(value: &str, exponent: u64) -> Result<u64, String> {
    if !is_decimal(value, exponent) {
        return Err(amount_error(exponent));
    }
    let too_large = || "TEMPUS_INVALID_CONTRACT: money.amount is too large".to_string();
    let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
    let whole = whole.parse::<u64>().map_err(|_| too_large())?;
    // At most eight digits, so neither the digits nor the scale can overflow.
    let exponent = exponent as u32;
    let fraction =
        fractional.parse::<u64>().unwrap_or(0) * 10u64.pow(exponent - fractional.len() as u32);
    whole
        .checked_mul(10u64.pow(exponent))
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(too_large)
}

fn contains_non_integer_number(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_i64().is_none() && number.as_u64().is_none(),
        Value::Array(values) => values.iter().any(contains_non_integer_number),
        Value::Object(values) => values.values().any(contains_non_integer_number),
        _ => false,
    }
}

fn required_policy_string(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("TEMPUS_POLICY_INVALID: '{field}' is required"))
}

fn digest_json(value: &Value) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(
        crate::b2a::canonicalize(value)?.as_bytes(),
    )))
}

#[derive(Clone)]
pub(crate) enum ConfiguredSigner {
    Local {
        identity: SignerIdentity,
        key: SigningKey,
    },
    VaultTransitCli {
        identity: SignerIdentity,
        vault_binary: String,
        signing_path: String,
        timeout_ms: u64,
        max_attempts: u32,
    },
}

impl ConfiguredSigner {
    pub(crate) fn from_path(path: &str) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read signer configuration '{path}': {e}"))?;
        let value: Value = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse signer configuration '{path}': {e}"))?;

        if let Some(private_key) = value.get("private_key").and_then(Value::as_str) {
            let bytes = hex::decode(private_key)
                .map_err(|e| format!("Invalid private key hex in '{path}': {e}"))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "Private key must be exactly 32 bytes".to_string())?;
            let key = SigningKey::from_bytes(&bytes);
            let public_key = hex::encode(key.verifying_key().to_bytes());
            if let Some(configured_public_key) = value.get("public_key").and_then(Value::as_str) {
                if configured_public_key != public_key {
                    return Err(
                        "TEMPUS_SIGNER_KEY_MISMATCH: public_key does not match private_key"
                            .to_string(),
                    );
                }
            }
            return Ok(Self::Local {
                identity: SignerIdentity {
                    signer_uri: value
                        .get("signer_uri")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("local-ed25519://{public_key}")),
                    key_version: value
                        .get("key_version")
                        .and_then(Value::as_str)
                        .unwrap_or("1")
                        .to_string(),
                    algorithm: SIGNATURE_ALGORITHM.to_string(),
                    public_key,
                },
                key,
            });
        }

        if value.get("schema_version").and_then(Value::as_str) != Some(SIGNER_CONFIG_SCHEMA) {
            return Err(format!(
                "TEMPUS_SIGNER_CONFIG_INVALID: expected {SIGNER_CONFIG_SCHEMA}"
            ));
        }
        let provider = required_string(&value, "provider")?;
        if provider != "vault-transit-cli" {
            return Err(format!(
                "TEMPUS_SIGNER_PROVIDER_UNKNOWN: unsupported provider '{provider}'"
            ));
        }
        let algorithm = required_string(&value, "algorithm")?;
        if algorithm != SIGNATURE_ALGORITHM {
            return Err(format!(
                "TEMPUS_SIGNER_ALGORITHM_UNKNOWN: unsupported algorithm '{algorithm}'"
            ));
        }
        let signer_uri = required_string(&value, "signer_uri")?;
        let signing_path = vault_signing_path(&signer_uri)?;
        let public_key = required_string(&value, "public_key")?;
        decode_verifying_key(&public_key)?;
        let key_version = required_string(&value, "key_version")?;
        let timeout_ms = value
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(5_000);
        if !(100..=60_000).contains(&timeout_ms) {
            return Err("TEMPUS_SIGNER_CONFIG_INVALID: timeout_ms must be 100..60000".to_string());
        }
        let max_attempts = value
            .get("max_attempts")
            .and_then(Value::as_u64)
            .unwrap_or(2);
        if !(1..=3).contains(&max_attempts) {
            return Err("TEMPUS_SIGNER_CONFIG_INVALID: max_attempts must be 1..3".to_string());
        }
        Ok(Self::VaultTransitCli {
            identity: SignerIdentity {
                signer_uri,
                key_version,
                algorithm,
                public_key,
            },
            vault_binary: value
                .get("vault_binary")
                .and_then(Value::as_str)
                .unwrap_or("vault")
                .to_string(),
            signing_path,
            timeout_ms,
            max_attempts: max_attempts as u32,
        })
    }

    fn sign_vault(
        &self,
        vault_binary: &str,
        signing_path: &str,
        timeout_ms: u64,
        max_attempts: u32,
        message: &[u8],
    ) -> Result<String, String> {
        let encoded = base64_encode(message);
        let mut last_error = "Vault Transit signer did not run".to_string();
        for attempt in 1..=max_attempts {
            match run_with_timeout(
                vault_binary,
                &[
                    "write",
                    "-field=signature",
                    signing_path,
                    &format!("input={encoded}"),
                ],
                timeout_ms,
            ) {
                Ok(output) => {
                    let parts: Vec<&str> = output.trim().split(':').collect();
                    let expected_version = format!("v{}", self.identity().key_version);
                    if parts.len() != 3 || parts[0] != "vault" || parts[1] != expected_version {
                        return Err(format!(
                            "TEMPUS_SIGNER_RESPONSE_INVALID: expected vault:{expected_version}:..."
                        ));
                    }
                    let encoded_signature = parts[2];
                    let signature = base64_decode(encoded_signature)?;
                    if signature.len() != 64 {
                        return Err(
                            "TEMPUS_SIGNER_RESPONSE_INVALID: Ed25519 signature must be 64 bytes"
                                .to_string(),
                        );
                    }
                    let signature_hex = hex::encode(signature);
                    if !verify_signature(&self.identity().public_key, message, &signature_hex) {
                        return Err(
                            "TEMPUS_SIGNER_RESPONSE_INVALID: signature does not match configured public key"
                                .to_string(),
                        );
                    }
                    return Ok(signature_hex);
                }
                Err(error) => last_error = format!("attempt {attempt}/{max_attempts}: {error}"),
            }
        }
        Err(format!("TEMPUS_SIGNER_UNAVAILABLE: {last_error}"))
    }
}

impl SignerBackend for ConfiguredSigner {
    fn identity(&self) -> &SignerIdentity {
        match self {
            Self::Local { identity, .. } | Self::VaultTransitCli { identity, .. } => identity,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<String, String> {
        match self {
            Self::Local { key, .. } => Ok(hex::encode(key.sign(message).to_bytes())),
            Self::VaultTransitCli {
                vault_binary,
                signing_path,
                timeout_ms,
                max_attempts,
                ..
            } => self.sign_vault(
                vault_binary,
                signing_path,
                *timeout_ms,
                *max_attempts,
                message,
            ),
        }
    }
}

pub(crate) fn verify_signature(public_key: &str, message: &[u8], signature: &str) -> bool {
    let Ok(key) = decode_verifying_key(public_key) else {
        return false;
    };
    let Ok(bytes) = hex::decode(signature) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(bytes) else {
        return false;
    };
    key.verify(message, &Signature::from_bytes(&bytes)).is_ok()
}

fn decode_verifying_key(public_key: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(public_key).map_err(|e| format!("Invalid public key hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("Invalid Ed25519 public key: {e}"))
}

fn required_string(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("TEMPUS_SIGNER_CONFIG_INVALID: '{field}' is required"))
}

fn vault_signing_path(signer_uri: &str) -> Result<String, String> {
    let suffix = signer_uri.strip_prefix("vault-transit://").ok_or_else(|| {
        "TEMPUS_SIGNER_URI_UNKNOWN: expected vault-transit://mount/key".to_string()
    })?;
    let (mount, key) = suffix.split_once('/').ok_or_else(|| {
        "TEMPUS_SIGNER_URI_INVALID: expected vault-transit://mount/key".to_string()
    })?;
    if mount.is_empty()
        || key.is_empty()
        || !mount.chars().all(safe_uri_char)
        || !key.chars().all(safe_uri_char)
    {
        return Err(
            "TEMPUS_SIGNER_URI_INVALID: mount and key contain unsafe characters".to_string(),
        );
    }
    Ok(format!("{mount}/sign/{key}"))
}

fn safe_uri_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '-' | '_' | '.')
}

fn run_with_timeout(binary: &str, args: &[&str], timeout_ms: u64) -> Result<String, String> {
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start '{binary}': {e}"))?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if child
            .try_wait()
            .map_err(|e| format!("failed while waiting for signer: {e}"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|e| format!("failed to read signer output: {e}"))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!(
                    "signer exited with {}: {}",
                    output.status,
                    stderr.trim()
                ));
            }
            return String::from_utf8(output.stdout)
                .map_err(|_| "signer returned non-UTF-8 output".to_string());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("signer timed out after {timeout_ms}ms"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (first << 16) | (second << 8) | third;
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(4) {
        return Err("TEMPUS_SIGNER_RESPONSE_INVALID: invalid base64 signature".to_string());
    }
    let mut output = Vec::with_capacity(cleaned.len() / 4 * 3);
    let (chunks, _) = cleaned.as_chunks::<4>();
    for chunk in chunks {
        let mut values = [0u8; 4];
        let mut padding = 0;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                padding += 1;
                values[index] = 0;
            } else {
                values[index] = base64_value(*byte).ok_or_else(|| {
                    "TEMPUS_SIGNER_RESPONSE_INVALID: invalid base64 signature".to_string()
                })?;
            }
        }
        let value = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | values[3] as u32;
        output.push((value >> 16) as u8);
        if padding < 2 {
            output.push((value >> 8) as u8);
        }
        if padding == 0 {
            output.push(value as u8);
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn money_has_one_reading_for_policy_and_executors() {
        let ok = |money: Value| validate_money(&money, None).unwrap();
        assert_eq!(
            ok(json!({"amount": "25.5", "asset": "USD"})),
            (2550, "USD".into())
        );
        assert_eq!(
            ok(json!({"amount_minor": 2550, "currency": "USD"})),
            (2550, "USD".into())
        );
        assert_eq!(
            ok(json!({"amount": "1.00", "asset": "USD", "beneficiary": "alice"})),
            (100, "USD".into())
        );
        assert_eq!(
            ok(json!({"amount": "25.50", "amount_minor": 2550, "currency": "USD", "asset": "USD"})),
            (2550, "USD".into())
        );
        for money in [
            json!({"amount": "1.00", "asset": "USD", "beneficiary": null}),
            json!({"amount": "1.00", "asset": "USD", "beneficiary": ""}),
            json!({"amount": "1.00", "asset": "USD", "beneficiary": 7}),
            json!({"amount": "1.00", "asset": "USD", "beneficiary": ["a"]}),
            json!({"amount": "5.", "asset": "USD"}),
            json!({"amount": "0.", "asset": "USD"}),
            json!({"amount": ".5", "asset": "USD"}),
            json!({"amount": "5.5.", "asset": "USD"}),
            json!({"amount": "99999.00", "amount_minor": 1, "asset": "USD"}),
            json!({"amount": "1.00", "currency": "USD", "asset": "EUR"}),
            json!({"amount": "1.00", "currency": "USD", "asset": "usd"}),
            json!({"amount": "1.00", "amount_minor": "100", "asset": "USD"}),
            json!({"amount": "1.00", "amount_minor": -100, "asset": "USD"}),
            json!({"amount": 1, "amount_minor": 100, "asset": "USD"}),
            json!({"amount": "1.00", "currency": 1, "asset": "USD"}),
            json!({"amount": "1.00", "asset": ""}),
            json!({"asset": "USD"}),
            json!({"amount": "1.00"}),
        ] {
            let error = validate_money(&money, None).unwrap_err();
            assert!(
                error.starts_with("TEMPUS_INVALID_CONTRACT"),
                "{money}: {error}"
            );
        }
    }

    #[test]
    fn currency_codes_must_be_exact() {
        for asset in ["usd", "USD ", "USD\u{200b}", "ＵＳＤ", "US*", "*"] {
            let error =
                validate_money(&json!({"amount": "1.00", "asset": asset}), None).unwrap_err();
            assert!(
                error.contains("exact 3-letter currency code"),
                "{asset:?}: {error}"
            );
        }
        let spec = |currencies: Value| {
            json!({
                "schema_version": POLICY_BUNDLE_SCHEMA,
                "policy_version": "v1",
                "tenant_id": "acme",
                "constraints": {
                    "allowed_action_types": ["payment.charge"],
                    "allowed_resources": ["*"],
                    "allowed_executors": ["*"],
                    "max_ttl_seconds": 60,
                    "max_input_bytes": 1024,
                    "allowed_currencies": currencies
                }
            })
        };
        assert!(validate_policy_spec(&spec(json!(["USD", "EUR"]))).is_ok());
        for currencies in [
            json!(["US*"]),
            json!(["*"]),
            json!(["usd"]),
            json!(["USD "]),
        ] {
            let error = validate_policy_spec(&spec(currencies)).unwrap_err();
            assert!(
                error.contains("TEMPUS_POLICY_INVALID") && error.contains("exact currency codes"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_stored_dev_allow_all_with_a_non_exact_currency_list_is_stale() {
        let dev = |currencies: Option<Value>| {
            let mut constraints = serde_json::Map::new();
            if let Some(currencies) = currencies {
                constraints.insert("allowed_currencies".to_string(), currencies);
            }
            json!({
                "policy_version": "tempus.dev-allow-all.v1.1",
                "tenant_id": "*",
                "constraints": constraints
            })
        };
        assert!(stale_dev_allow_all(&dev(Some(json!(["*"])))));
        assert!(stale_dev_allow_all(&dev(Some(json!(["US*"])))));
        assert!(stale_dev_allow_all(&dev(Some(json!(["usd"])))));
        assert!(!stale_dev_allow_all(&dev(Some(json!(["USD"])))));
        assert!(!stale_dev_allow_all(&dev(None)));
        assert!(!stale_dev_allow_all(&json!({
            "policy_version": "acme-v1",
            "tenant_id": "acme",
            "constraints": {"allowed_currencies": ["*"]}
        })));
    }

    #[test]
    fn payment_actions_require_a_positive_amount() {
        let paid =
            json!({"action_type": "payment.charge", "money": {"amount": "1.00", "asset": "USD"}});
        assert!(reject_payment_without_money("payment.charge", &paid).is_ok());
        assert!(reject_payment_without_money("github.create_issue", &json!({})).is_ok());
        for action in ["finance.disburse", "finance.transfer", "payment.charge"] {
            for intent in [
                json!({}),
                json!({"money": null}),
                json!({"money": {"amount": "0", "asset": "USD"}}),
                json!({"money": {"amount": "0.00", "asset": "USD"}}),
                json!({"money": {"amount": "000", "asset": "USD"}}),
            ] {
                let error = reject_payment_without_money(action, &intent).unwrap_err();
                assert!(
                    error.starts_with("TEMPUS_INVALID_CONTRACT"),
                    "{action} {intent}: {error}"
                );
            }
        }
    }

    #[test]
    fn amount_strings_and_the_minor_unit_boundary() {
        for amount in [
            "1e3",
            "-1.00",
            "+1.00",
            "1,00",
            " 1.00",
            "1.000",
            "5.",
            ".5",
            "１.００",
            "184467440737095516.16",
        ] {
            let error =
                validate_money(&json!({"amount": amount, "asset": "USD"}), None).unwrap_err();
            assert!(
                error.starts_with("TEMPUS_INVALID_CONTRACT"),
                "{amount}: {error}"
            );
        }
        for minor in [json!(-1), json!("100"), json!(true), json!(1.5)] {
            let money = json!({"amount_minor": minor, "asset": "USD"});
            let error = validate_money(&money, None).unwrap_err();
            assert!(error.contains("amount_minor"), "{money}: {error}");
        }
        let constraints = json!({
            "allowed_currencies": ["USD"],
            "max_money_amount_minor": 5000
        });
        let constraints = constraints.as_object().unwrap();
        assert!(money_allowed(constraints, &json!({"amount": "50.00", "asset": "USD"})).unwrap());
        assert!(!money_allowed(constraints, &json!({"amount": "50.01", "asset": "USD"})).unwrap());
        assert!(
            money_allowed(constraints, &json!({"amount": "00050.00", "asset": "USD"})).unwrap()
        );
        assert_eq!(
            validate_money(&json!({"amount": "00050.00", "asset": "USD"}), None)
                .unwrap()
                .0,
            5000
        );
    }

    #[test]
    fn an_amount_is_read_in_the_decimals_of_its_currency() {
        let exponents = json!({"JPY": 0, "KWD": 3, "XTS": 8});
        let read = |amount: &str, asset: &str| {
            validate_money(&json!({"amount": amount, "asset": asset}), Some(&exponents))
        };
        for (amount, asset, minor) in [
            ("5", "JPY", 5),
            ("500", "JPY", 500),
            ("18446744073709551615", "JPY", u64::MAX),
            ("1.234", "KWD", 1234),
            ("1.2", "KWD", 1200),
            ("1", "KWD", 1000),
            ("18446744073709551.615", "KWD", u64::MAX),
            ("25.5", "USD", 2550),
            ("25", "USD", 2500),
            ("0.00000001", "XTS", 1),
            ("1.5", "XTS", 150_000_000),
        ] {
            assert_eq!(read(amount, asset).unwrap().0, minor, "{amount} {asset}");
        }
        for (amount, asset, why) in [
            ("5.5", "JPY", "with no fractional digits"),
            ("5.00", "JPY", "with no fractional digits"),
            ("1.2345", "KWD", "at most three fractional"),
            ("1.234", "USD", "at most two fractional"),
            ("1.123456789", "XTS", "at most eight fractional"),
            ("18446744073709551616", "JPY", "too large"),
            ("18446744073709551.616", "KWD", "too large"),
        ] {
            let error = read(amount, asset).unwrap_err();
            assert!(error.contains(why), "{amount} {asset}: {error}");
        }
        let two = |amount: &str, minor: u64| {
            validate_money(
                &json!({"amount": amount, "amount_minor": minor, "asset": "JPY"}),
                Some(&exponents),
            )
        };
        assert_eq!(two("500", 500).unwrap().0, 500);
        assert!(two("500", 50_000).unwrap_err().contains("disagree"));
    }

    #[test]
    fn without_a_stated_exponent_every_currency_has_two_decimals() {
        let yen = json!({"amount": "500", "asset": "JPY"});
        assert_eq!(validate_money(&yen, None).unwrap().0, 50_000);
        let others = json!({"KWD": 3});
        assert_eq!(validate_money(&yen, Some(&others)).unwrap().0, 50_000);
        let stated = json!({"JPY": 2});
        assert_eq!(validate_money(&yen, Some(&stated)).unwrap().0, 50_000);
        let error = validate_money(&json!({"amount": "1.234", "asset": "KWD"}), None).unwrap_err();
        assert!(error.contains("at most two fractional"), "{error}");
    }

    #[test]
    fn an_exponent_out_of_range_is_an_error_when_a_bundle_is_read_too() {
        // A reader evaluates a bundle it has already refused: this must not reach `pow`.
        for exponent in [json!(9), json!(4_000_000_000u64), json!(-1), json!("2")] {
            let exponents = json!({"JPY": exponent});
            let money = json!({"amount": "5", "asset": "JPY"});
            let error = validate_money(&money, Some(&exponents)).unwrap_err();
            assert!(error.contains("currency_exponents.JPY"), "{error}");
        }
    }

    #[test]
    fn the_shape_of_money_does_not_depend_on_the_policy() {
        for money in [
            json!({"amount": "1.234", "asset": "KWD"}),
            json!({"amount": "1.12345678", "asset": "XTS"}),
            json!({"amount": "99999999999999999999999", "asset": "JPY"}),
            json!({"amount_minor": 5, "currency": "JPY"}),
            json!({"amount": "500", "amount_minor": 50_000, "asset": "JPY"}),
        ] {
            assert!(validate_money_shape(&money).is_ok(), "{money}");
        }
        for money in [
            json!({"amount": "1.123456789", "asset": "XTS"}),
            json!({"amount": "5.", "asset": "USD"}),
            json!({"amount": ".5", "asset": "USD"}),
            json!({"amount": "", "asset": "USD"}),
            json!({"amount": "abc", "asset": "USD"}),
            json!({"amount": 5, "asset": "USD"}),
            json!({"amount_minor": "5", "asset": "USD"}),
            json!({"asset": "USD"}),
            json!({"amount": "5"}),
            json!({"amount": "5", "asset": "usd"}),
            json!({"amount": "5", "asset": "USD", "currency": "EUR"}),
            json!({"amount": "5", "asset": "USD", "beneficiary": 1}),
        ] {
            let error = validate_money_shape(&money).unwrap_err();
            assert!(
                error.starts_with("TEMPUS_INVALID_CONTRACT"),
                "{money}: {error}"
            );
        }
    }

    #[test]
    fn a_payment_of_zero_is_refused_in_any_currency() {
        let charge =
            |money: Value| reject_payment_without_money("payment.charge", &json!({"money": money}));
        for money in [
            json!({"amount": "0", "asset": "JPY"}),
            json!({"amount": "000", "asset": "JPY"}),
            json!({"amount": "0.000", "asset": "KWD"}),
            json!({"amount": "0.00000000", "asset": "XTS"}),
            json!({"amount_minor": 0, "asset": "JPY"}),
        ] {
            let error = charge(money.clone()).unwrap_err();
            assert!(error.contains("non-zero"), "{money}: {error}");
        }
        assert!(charge(json!({"amount": "0.001", "asset": "KWD"})).is_ok());
        assert!(charge(json!({"amount_minor": 1, "asset": "JPY"})).is_ok());
    }

    #[test]
    fn currency_exponents_are_closed() {
        for good in [json!({}), json!({"JPY": 0, "KWD": 3, "XTS": 8})] {
            assert!(validate_currency_exponents(&good).is_ok(), "{good}");
        }
        for bad in [
            json!("JPY"),
            json!(["JPY"]),
            json!({"jpy": 0}),
            json!({"JPYX": 0}),
            json!({"J*": 0}),
            json!({"JPY": 9}),
            json!({"JPY": -1}),
            json!({"JPY": "0"}),
            json!({"JPY": true}),
            json!({"JPY": null}),
            json!({"JPY": 1.5}),
        ] {
            let error = validate_currency_exponents(&bad).unwrap_err();
            assert!(error.contains("currency_exponents"), "{bad}: {error}");
        }
    }

    #[test]
    fn installing_a_currency_without_stating_its_decimals_is_refused() {
        let spec = |currencies: Value, exponents: Option<Value>| {
            let mut constraints = json!({"allowed_currencies": currencies});
            if let Some(exponents) = exponents {
                constraints["currency_exponents"] = exponents;
            }
            json!({"constraints": constraints})
        };
        for (decimals, codes) in ISO_4217_NOT_TWO_DECIMALS {
            for code in *codes {
                let error = refuse_unstated_decimals(&spec(json!([code]), None)).unwrap_err();
                assert!(
                    error.contains(code) && error.contains(&format!("has {decimals} decimals")),
                    "{error}"
                );
                let stated = spec(json!(["USD", code]), Some(json!({*code: decimals})));
                assert!(refuse_unstated_decimals(&stated).is_ok(), "{code}");
                // Operator opt-in to the old reading.
                let hundredths = spec(json!([code]), Some(json!({*code: 2})));
                assert!(refuse_unstated_decimals(&hundredths).is_ok(), "{code}");
            }
        }
        assert_eq!(
            ISO_4217_NOT_TWO_DECIMALS
                .iter()
                .map(|(_, codes)| codes.len())
                .sum::<usize>(),
            26
        );
        assert!(refuse_unstated_decimals(&spec(json!(["USD", "EUR"]), None)).is_ok());
        assert!(refuse_unstated_decimals(&json!({"constraints": {}})).is_ok());
        let another = spec(json!(["JPY"]), Some(json!({"KWD": 3})));
        assert!(refuse_unstated_decimals(&another).is_err());
    }

    #[test]
    fn a_stored_policy_that_names_yen_stays_what_it_says() {
        // Refused for a new install, but a bundle already signed is read as it always was.
        let spec = json!({
            "schema_version": POLICY_BUNDLE_SCHEMA,
            "policy_version": "stored-v1",
            "tenant_id": "acme",
            "constraints": {
                "allowed_action_types": ["*"],
                "allowed_resources": ["*"],
                "allowed_executors": ["*"],
                "max_ttl_seconds": 60,
                "max_input_bytes": 1024,
                "allowed_currencies": ["JPY"],
                "max_money_amount_minor": 1000
            }
        });
        assert!(validate_policy_spec(&spec).is_ok());
        let constraints = spec["constraints"].as_object().unwrap();
        let yen = |amount: &str| json!({"amount": amount, "asset": "JPY"});
        assert!(!money_allowed(constraints, &yen("500")).unwrap());
        assert!(money_allowed(constraints, &yen("10")).unwrap());
    }

    struct TestRemoteSigner {
        identity: SignerIdentity,
        key: SigningKey,
    }

    impl SignerBackend for TestRemoteSigner {
        fn identity(&self) -> &SignerIdentity {
            &self.identity
        }

        fn sign(&self, message: &[u8]) -> Result<String, String> {
            Ok(hex::encode(self.key.sign(message).to_bytes()))
        }
    }

    #[test]
    fn local_signer_and_resolver_contract_is_exact_byte_ed25519() {
        let key = SigningKey::generate(&mut OsRng);
        let signer = ConfiguredSigner::Local {
            identity: SignerIdentity {
                signer_uri: "test://local".to_string(),
                key_version: "1".to_string(),
                algorithm: SIGNATURE_ALGORITHM.to_string(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
            },
            key,
        };
        let signature = signer.sign(b"provider-conformance-fixture").unwrap();
        assert!(verify_signature(
            &signer.identity().public_key,
            b"provider-conformance-fixture",
            &signature
        ));
        assert!(!verify_signature(
            &signer.identity().public_key,
            b"different",
            &signature
        ));
    }

    #[test]
    fn test_remote_signer_passes_the_same_conformance_suite() {
        let key = SigningKey::generate(&mut OsRng);
        let signer = TestRemoteSigner {
            identity: SignerIdentity {
                signer_uri: "test-remote://provider/key".to_string(),
                key_version: "7".to_string(),
                algorithm: SIGNATURE_ALGORITHM.to_string(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
            },
            key,
        };
        let result: Value = serde_json::from_str(&signer_conformance(&signer).unwrap()).unwrap();
        assert_eq!(result["status"], "PASS");
        assert_eq!(result["signer"]["signer_uri"], "test-remote://provider/key");
    }

    #[test]
    fn unknown_provider_and_algorithm_fail_closed() {
        let unknown = json!({
            "schema_version": SIGNER_CONFIG_SCHEMA,
            "provider": "unknown",
            "signer_uri": "unknown://key",
            "key_version": "1",
            "algorithm": SIGNATURE_ALGORITHM,
            "public_key": "00".repeat(32),
        });
        let path =
            std::env::temp_dir().join(format!("tempus-signer-unknown-{}.json", std::process::id()));
        std::fs::write(&path, unknown.to_string()).unwrap();
        let error = ConfiguredSigner::from_path(path.to_str().unwrap())
            .err()
            .unwrap();
        let _ = std::fs::remove_file(path);
        assert!(error.contains("TEMPUS_SIGNER_PROVIDER_UNKNOWN"));
    }

    #[test]
    fn patterns_match_whole_components_and_reject_glued_stars() {
        let cases = [
            ("*", "anything", true),
            ("*", "https://api.example.com.evil.com/x", true),
            ("acme/repo", "acme/repo", true),
            ("acme/repo", "acme/other", false),
            ("acme/*", "acme/repo", true),
            ("acme/*", "acme/repo/extra", true),
            ("vendor-api/*", "vendor-api/credits", true),
            ("vendor-api/*", "vendor-apifoo", false),
            (
                "https://api.example.com/*",
                "https://api.example.com/v1/users",
                true,
            ),
            (
                "https://api.example.com/*",
                "https://api.example.com/v1/users/1",
                true,
            ),
            (
                "https://api.example.com/*",
                "https://api.example.com.evil.com/v1",
                false,
            ),
            (
                "https://api.example.com*",
                "https://api.example.com.evil.com/x",
                false,
            ),
            (
                "https://api.example.com*",
                "https://api.example.com/x",
                false,
            ),
            ("https://api.example.com*", "https://api.example.com", false),
            ("https://*.example.com/*", "https://a.example.com/v1", true),
            (
                "https://*.example.com/*",
                "https://a.b.example.com/v1/x",
                true,
            ),
            (
                "https://*.example.com/*",
                "https://evilexample.com/v1",
                false,
            ),
            (
                "https://*.example.com/*",
                "https://example.com.evil.com/v1",
                false,
            ),
            ("host*", "host.evil.com", false),
            ("host*", "host", false),
            ("host*", "hostile", false),
            ("*.example.com", "a.example.com", true),
            ("*.example.com", "a.b.example.com", true),
            ("*.example.com", "evilexample.com", false),
            ("*.example.com", "example.com.evil.com", false),
            ("*.example.com", "example.com", false),
            ("/api*", "/apifoo", false),
            ("/api*", "/api/foo", false),
            ("/api/*", "/apifoo", false),
            ("/api/*", "/api/foo", true),
            ("/api/*", "/api/foo/bar", true),
            ("/api/*", "/api", false),
            ("http.post", "http.post", true),
            ("http.*", "http.post", true),
            ("http*", "http.post", false),
            ("vendor-*", "vendor-42", false),
            ("USD", "USD", true),
            ("USD*", "USDC", false),
        ];
        for (pattern, candidate, expected) in cases {
            let value = json!([pattern]);
            let matched = matches_patterns(Some(&value), candidate).unwrap();
            assert_eq!(matched, expected, "{pattern} vs {candidate}");
        }
        // A pattern that does not match does not change another pattern in the list.
        let both = json!(["https://api.example.com*", "https://api.example.com/*"]);
        assert!(matches_patterns(Some(&both), "https://api.example.com/v1").unwrap());
        assert!(!matches_patterns(Some(&both), "https://api.example.com.evil.com/v1").unwrap());
    }
}
