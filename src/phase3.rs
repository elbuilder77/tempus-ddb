use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const SIGNER_CONFIG_SCHEMA: &str = "tempus.signer-config.v1";
pub(crate) const POLICY_BUNDLE_SCHEMA: &str = "tempus.policy-bundle.v1";
pub(crate) const DEFAULT_POLICY_VERSION: &str = "tempus.baseline.v1";
pub(crate) const SIGNATURE_ALGORITHM: &str = "Ed25519";
pub(crate) const IDENTITY_EVENT_SCHEMA: &str = "tempus.identity-lifecycle-event.v1";

const POLICY_FIELDS: &[&str] = &[
    "allowed_action_types",
    "allowed_resources",
    "allowed_executors",
    "max_ttl_seconds",
    "max_input_bytes",
    "allowed_currencies",
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

pub(crate) fn ensure_default_policy(
    conn: &Connection,
    signer: &ConfiguredSigner,
    issued_at: u64,
) -> Result<Value, String> {
    if let Some(existing) = policy_by_version(conn, DEFAULT_POLICY_VERSION)? {
        let is_attested: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM active_policy_attestations WHERE tenant_id = '*' AND policy_version = ?1)",
                [DEFAULT_POLICY_VERSION],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !is_attested {
            let policy_digest = required_policy_string(&existing, "policy_digest")?;
            let attestation_body = json!({
                "schema_version": "tempus.active-policy-attestation.v1",
                "tenant_id": "*",
                "policy_version": DEFAULT_POLICY_VERSION,
                "policy_digest": policy_digest,
                "activated_at": issued_at,
                "signer": signer.identity().to_json(),
            });
            let canonical_attestation = crate::b2a::canonicalize(&attestation_body)?;
            let attestation_id = crate::b2a::sha256_hex(canonical_attestation.as_bytes());
            let attestation_sig = signer.sign(
                &hex::decode(&attestation_id)
                    .map_err(|e| format!("Invalid attestation digest: {e}"))?,
            )?;
            let _ = conn.execute(
                "INSERT OR REPLACE INTO active_policy_attestations
                 (tenant_id, policy_version, policy_digest, activated_at, signer_public_key, signature, attestation_json)
                 VALUES ('*', ?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    DEFAULT_POLICY_VERSION,
                    policy_digest,
                    issued_at,
                    signer.identity().public_key,
                    attestation_sig,
                    canonical_attestation,
                ],
            );
        }
        return verify_policy_bundle(&existing, None).map(|_| existing);
    }
    let spec = json!({
        "schema_version": POLICY_BUNDLE_SCHEMA,
        "policy_version": DEFAULT_POLICY_VERSION,
        "tenant_id": "*",
        "constraints": {
            "allowed_action_types": ["*"],
            "allowed_resources": ["*"],
            "allowed_executors": ["*"],
            "max_ttl_seconds": 86400,
            "max_input_bytes": 65536,
            "allowed_currencies": ["*"],
        }
    });
    install_policy(conn, signer, &spec, issued_at)
}

pub(crate) fn install_policy(
    conn: &Connection,
    signer: &ConfiguredSigner,
    spec: &Value,
    issued_at: u64,
) -> Result<Value, String> {
    validate_policy_spec(spec)?;
    let policy_version = required_policy_string(spec, "policy_version")?;
    let tenant_id = required_policy_string(spec, "tenant_id")?;
    let body = json!({
        "schema_version": POLICY_BUNDLE_SCHEMA,
        "policy_version": policy_version,
        "tenant_id": tenant_id,
        "constraints": spec.get("constraints").cloned().unwrap_or_else(|| json!({})),
        "issued_at": issued_at,
        "signer": signer.identity().to_json(),
    });
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

pub(crate) fn active_policy(
    conn: &Connection,
    signer: &ConfiguredSigner,
    tenant_id: &str,
    now: u64,
) -> Result<Value, String> {
    ensure_default_policy(conn, signer, now)?;

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

    if let Some((_version, digest, signature, attestation_json, bundle_json)) = row {
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
        let bundle: Value = serde_json::from_str(&bundle_json)
            .map_err(|e| format!("Stored policy bundle is invalid JSON: {e}"))?;
        verify_policy_bundle(&bundle, Some(&signer.identity().public_key))?;
        if bundle.get("policy_digest").and_then(Value::as_str) != Some(&digest) {
            return Err("TEMPUS_POLICY_INVALID: active policy digest mismatch".to_string());
        }
        return Ok(bundle);
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

    if let Some((_version, digest, signature, attestation_json, bundle_json)) = row_star {
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
        let bundle: Value = serde_json::from_str(&bundle_json)
            .map_err(|e| format!("Stored policy bundle is invalid JSON: {e}"))?;
        verify_policy_bundle(&bundle, Some(&signer.identity().public_key))?;
        if bundle.get("policy_digest").and_then(Value::as_str) != Some(&digest) {
            return Err("TEMPUS_POLICY_INVALID: fallback policy digest mismatch".to_string());
        }
        return Ok(bundle);
    }

    Err("TEMPUS_POLICY_NOT_FOUND: no active policy applies".to_string())
}

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

pub(crate) fn verify_policy_bundle(
    bundle: &Value,
    expected_public_key: Option<&str>,
) -> Result<(), String> {
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
    validate_policy_spec(&body)
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
    if let Some(money) = intent.get("money").filter(|value| !value.is_null()) {
        if !money_allowed(constraints, money)? {
            reasons.push("POLICY_MONEY_DENIED".to_string());
        }
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
        pattern_list(Some(currencies), "allowed_currencies")?;
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
    Ok(())
}

fn matches_patterns(value: Option<&Value>, candidate: &str) -> Result<bool, String> {
    Ok(pattern_list(value, "pattern list")?.iter().any(|pattern| {
        *pattern == "*"
            || *pattern == candidate
            || pattern
                .strip_suffix('*')
                .is_some_and(|prefix| candidate.starts_with(prefix))
    }))
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

fn money_allowed(
    constraints: &serde_json::Map<String, Value>,
    money: &Value,
) -> Result<bool, String> {
    let currency = money
        .get("currency")
        .or_else(|| money.get("asset"))
        .and_then(Value::as_str)
        .ok_or_else(|| "TEMPUS_INVALID_CONTRACT: money.asset is required".to_string())?;
    let amount = if let Some(amount) = money.get("amount_minor").and_then(Value::as_u64) {
        amount
    } else {
        parse_minor_units(money.get("amount").and_then(Value::as_str).ok_or_else(|| {
            "TEMPUS_INVALID_CONTRACT: money.amount must be a decimal string".to_string()
        })?)?
    };
    if let Some(currencies) = constraints.get("allowed_currencies") {
        if !matches_patterns(Some(currencies), currency)? {
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

fn parse_minor_units(value: &str) -> Result<u64, String> {
    let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > 2
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(
            "TEMPUS_INVALID_CONTRACT: money.amount must be an unsigned decimal with at most two fractional digits"
                .to_string(),
        );
    }
    let whole = whole
        .parse::<u64>()
        .map_err(|_| "TEMPUS_INVALID_CONTRACT: money.amount is too large".to_string())?;
    let fraction = match fractional.len() {
        0 => 0,
        1 => fractional.parse::<u64>().unwrap_or(0) * 10,
        _ => fractional.parse::<u64>().unwrap_or(0),
    };
    whole
        .checked_mul(100)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| "TEMPUS_INVALID_CONTRACT: money.amount is too large".to_string())
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
}
