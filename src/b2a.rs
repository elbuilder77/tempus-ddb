use crate::phase3::{ConfiguredSigner, SignerBackend};
use crate::SqliteStorage;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ACTION_INTENT_SCHEMA: &str = "tempus.action-intent.v1";
const ACTION_OUTCOME_SCHEMA: &str = "tempus.action-outcome.v1";
const AUTHORIZATION_RESULT_SCHEMA: &str = "tempus.authorization-result.v1";
const AUTHORIZATION_RECEIPT_SCHEMA: &str = "tempus.authorization-receipt.v1";
const EXECUTION_RESULT_SCHEMA: &str = "tempus.execution-result.v1";
const EXECUTION_RECEIPT_SCHEMA: &str = "tempus.execution-receipt.v1";
const TRACE_SCHEMA: &str = "tempus.action-trace.v1";
const TRACE_VERIFICATION_SCHEMA: &str = "tempus.trace-verification.v1";
const AGENT_REGISTRATION_SCHEMA: &str = "tempus.agent-registration.v1";
const LEGACY_POLICY_VERSION: &str = "tempus.identity-gate.v1";

#[derive(Debug)]
struct AgentState {
    active: bool,
    can_delegate: bool,
    tenant_id: String,
    identity_id: String,
    metadata: String,
}

#[derive(Debug)]
struct IntentFields {
    tenant_id: String,
    agent_id: String,
    idempotency_key: String,
    requested_at: u64,
}

pub(crate) fn initialize_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS agents (
            public_key TEXT PRIMARY KEY,
            alias TEXT NOT NULL,
            registered_at INTEGER NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'active',
            can_delegate INTEGER NOT NULL DEFAULT 0,
            registered_by TEXT NOT NULL DEFAULT '',
            registration_event_id TEXT NOT NULL DEFAULT '',
            registration_event TEXT NOT NULL DEFAULT '{}',
            registration_signature TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_agents_alias ON agents (alias);

        CREATE TABLE IF NOT EXISTS action_authorizations (
            authorization_id TEXT PRIMARY KEY,
            action_id TEXT NOT NULL UNIQUE,
            tenant_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            intent_hash TEXT NOT NULL,
            decision TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            authorization_json TEXT NOT NULL,
            UNIQUE (tenant_id, agent_id, idempotency_key)
        );
        CREATE INDEX IF NOT EXISTS idx_action_authorizations_agent
            ON action_authorizations (tenant_id, agent_id, issued_at DESC);

        CREATE TABLE IF NOT EXISTS action_outcomes (
            receipt_id TEXT PRIMARY KEY,
            authorization_id TEXT NOT NULL UNIQUE,
            action_id TEXT NOT NULL UNIQUE,
            executor_id TEXT NOT NULL,
            outcome_hash TEXT NOT NULL,
            completed_at INTEGER NOT NULL,
            execution_json TEXT NOT NULL,
            FOREIGN KEY (authorization_id) REFERENCES action_authorizations(authorization_id)
        );
        CREATE INDEX IF NOT EXISTS idx_action_outcomes_executor
            ON action_outcomes (executor_id, completed_at DESC);

        CREATE TABLE IF NOT EXISTS trusted_roots (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            public_key TEXT NOT NULL UNIQUE,
            established_at INTEGER NOT NULL
        );",
    )
    .map_err(|e| format!("Failed to initialize B2A schema: {e}"))?;

    // Forward-only migration for ledgers created by v0.2.1 before the
    // registration receipt became an authorization primitive.
    for statement in [
        "ALTER TABLE agents ADD COLUMN status TEXT NOT NULL DEFAULT 'legacy'",
        "ALTER TABLE agents ADD COLUMN can_delegate INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE agents ADD COLUMN registered_by TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE agents ADD COLUMN registration_event_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE agents ADD COLUMN registration_event TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE agents ADD COLUMN registration_signature TEXT NOT NULL DEFAULT ''",
    ] {
        if let Err(error) = conn.execute(statement, []) {
            if !error.to_string().contains("duplicate column name") {
                return Err(format!("Failed to migrate B2A agent schema: {error}"));
            }
        }
    }

    // Backfill trusted root from earliest self-signed agent if not yet present
    let _ = conn.execute(
        "INSERT OR IGNORE INTO trusted_roots (id, public_key, established_at)
         SELECT 1, public_key, registered_at FROM agents
         WHERE registered_by = public_key ORDER BY registered_at ASC LIMIT 1",
        [],
    );

    crate::phase3::initialize_schema(conn)?;
    crate::events::initialize_schema(conn)?;

    Ok(())
}

pub(crate) fn now_micros() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_micros() as u64)
        .map_err(|e| format!("System time error: {e}"))
}

fn write_canonical(value: &Value, output: &mut String) -> Result<(), String> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|e| format!("Failed to canonicalize JSON string: {e}"))?,
        ),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|e| format!("Failed to canonicalize JSON key: {e}"))?,
                );
                output.push(':');
                write_canonical(&values[*key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

pub(crate) fn canonicalize(value: &Value) -> Result<String, String> {
    let mut output = String::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

pub(crate) fn parse_canonical(raw: &str, label: &str) -> Result<(Value, String), String> {
    let value: Value =
        serde_json::from_str(raw).map_err(|e| format!("{label} must be valid JSON: {e}"))?;
    let canonical = canonicalize(&value)?;
    Ok((value, canonical))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn decode_public_key(public_key: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(public_key).map_err(|e| format!("Invalid public key hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("Invalid Ed25519 public key: {e}"))
}

pub(crate) fn decode_signature(signature: &str) -> Result<Signature, String> {
    let bytes = hex::decode(signature).map_err(|e| format!("Invalid signature hex: {e}"))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&bytes))
}

pub(crate) fn verify_message_signature(public_key: &str, message: &[u8], signature: &str) -> bool {
    let Ok(verifying_key) = decode_public_key(public_key) else {
        return false;
    };
    let Ok(signature) = decode_signature(signature) else {
        return false;
    };
    verifying_key.verify(message, &signature).is_ok()
}

pub(crate) fn sign_digest(signer: &ConfiguredSigner, digest: &str) -> Result<String, String> {
    let bytes = hex::decode(digest).map_err(|e| format!("Invalid digest hex: {e}"))?;
    signer.sign(&bytes)
}

pub(crate) fn verify_digest_signature(public_key: &str, digest: &str, signature: &str) -> bool {
    let Ok(bytes) = hex::decode(digest) else {
        return false;
    };
    verify_message_signature(public_key, &bytes, signature)
}

fn load_signing_key(path: &str) -> Result<SigningKey, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read key file '{path}': {e}"))?;
    let value: Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse key file '{path}': {e}"))?;
    let private_key = value
        .get("private_key")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Key file '{path}' does not contain private_key"))?;
    let bytes = hex::decode(private_key).map_err(|e| format!("Invalid private key hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Private key must be exactly 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn string_field(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("TEMPUS_INVALID_CONTRACT: '{field}' must be a non-empty string"))
}

fn integer_field(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("TEMPUS_INVALID_CONTRACT: '{field}' must be an unsigned integer"))
}

fn validate_intent(value: &Value, expected_agent: &str) -> Result<IntentFields, String> {
    if !value.is_object() {
        return Err("TEMPUS_INVALID_CONTRACT: action intent must be a JSON object".to_string());
    }
    if string_field(value, "schema_version")? != ACTION_INTENT_SCHEMA {
        return Err(format!(
            "TEMPUS_INVALID_CONTRACT: schema_version must be '{ACTION_INTENT_SCHEMA}'"
        ));
    }
    let tenant_id = string_field(value, "tenant_id")?;
    let agent_id = string_field(value, "agent_id")?;
    if agent_id != expected_agent {
        return Err(
            "TEMPUS_AGENT_ID_MISMATCH: intent agent_id does not match the signing key".to_string(),
        );
    }
    let idempotency_key = string_field(value, "idempotency_key")?;
    string_field(value, "action_type")?;
    string_field(value, "resource")?;
    let requested_at = integer_field(value, "requested_at")?;
    if let Some(money) = value.get("money") {
        if !money.is_null() && !money.is_object() {
            return Err("TEMPUS_INVALID_CONTRACT: money must be an object or null".to_string());
        }
    }
    Ok(IntentFields {
        tenant_id,
        agent_id,
        idempotency_key,
        requested_at,
    })
}

fn validate_outcome(
    value: &Value,
    authorization_id: &str,
    action_id: &str,
) -> Result<String, String> {
    if !value.is_object() {
        return Err("TEMPUS_INVALID_CONTRACT: action outcome must be a JSON object".to_string());
    }
    if string_field(value, "schema_version")? != ACTION_OUTCOME_SCHEMA {
        return Err(format!(
            "TEMPUS_INVALID_CONTRACT: schema_version must be '{ACTION_OUTCOME_SCHEMA}'"
        ));
    }
    if string_field(value, "authorization_id")? != authorization_id {
        return Err(
            "TEMPUS_AUTHORIZATION_MISMATCH: outcome authorization_id does not match".to_string(),
        );
    }
    if string_field(value, "action_id")? != action_id {
        return Err("TEMPUS_ACTION_ID_MISMATCH: outcome action_id does not match".to_string());
    }
    let status = string_field(value, "status")?;
    if !matches!(status.as_str(), "SUCCEEDED" | "FAILED") {
        return Err(
            "TEMPUS_INVALID_CONTRACT: outcome status must be SUCCEEDED or FAILED".to_string(),
        );
    }
    Ok(status)
}

fn action_id_for(fields: &IntentFields) -> String {
    sha256_hex(
        format!(
            "tempus.action.v1\0{}\0{}\0{}",
            fields.tenant_id, fields.agent_id, fields.idempotency_key
        )
        .as_bytes(),
    )
}

fn gate_identity(storage: &SqliteStorage) -> Result<(ConfiguredSigner, String), String> {
    let signer = storage.load_signer()?;
    let gate_id = signer.identity().public_key.clone();
    let state = verify_agent_state(&storage.conn, &gate_id)?.ok_or_else(|| {
        "TEMPUS_GATE_NOT_BOOTSTRAPPED: register the gate key as the root agent".to_string()
    })?;
    if !state.active || !state.can_delegate {
        return Err(
            "TEMPUS_GATE_NOT_AUTHORIZED: gate identity is not an active delegation root"
                .to_string(),
        );
    }
    Ok((signer, gate_id))
}

fn lifecycle_end_for_key(
    conn: &Connection,
    identity_id: &str,
    public_key: &str,
) -> Result<Option<(u64, String)>, String> {
    let mut statement = conn
        .prepare(
            "SELECT event_json FROM identity_lifecycle_events
             WHERE identity_id = ?1 ORDER BY effective_at ASC",
        )
        .map_err(|e| format!("Failed to prepare identity lifecycle verification: {e}"))?;
    let rows = statement
        .query_map([identity_id], |row| row.get::<_, String>(0))
        .map_err(|e| format!("Failed to query identity lifecycle: {e}"))?;
    let mut end = None;
    for row in rows {
        let raw = row.map_err(|e| format!("Failed to read identity lifecycle event: {e}"))?;
        let wrapper: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("Stored identity lifecycle event is invalid JSON: {e}"))?;
        let event = wrapper
            .get("event")
            .ok_or_else(|| "TEMPUS_IDENTITY_EVENT_INVALID: event is missing".to_string())?;
        if event.get("schema_version").and_then(Value::as_str)
            != Some(crate::phase3::IDENTITY_EVENT_SCHEMA)
            || event.get("identity_id").and_then(Value::as_str) != Some(identity_id)
        {
            return Err("TEMPUS_IDENTITY_EVENT_INVALID: schema or identity mismatch".to_string());
        }
        let event_id = string_field(&wrapper, "event_id")?;
        let signature = string_field(&wrapper, "signature")?;
        if sha256_hex(canonicalize(event)?.as_bytes()) != event_id {
            return Err("TEMPUS_IDENTITY_EVENT_INVALID: digest mismatch".to_string());
        }
        let authorized_by = string_field(event, "authorized_by")?;
        if !verify_digest_signature(&authorized_by, &event_id, &signature) {
            return Err("TEMPUS_IDENTITY_EVENT_INVALID: signature mismatch".to_string());
        }
        if event
            .get("signer")
            .and_then(|value| value.get("public_key"))
            .and_then(Value::as_str)
            != Some(authorized_by.as_str())
        {
            return Err("TEMPUS_IDENTITY_EVENT_INVALID: signer metadata mismatch".to_string());
        }
        let effective_at = integer_field(event, "effective_at")?;
        let authority = verify_agent_state_at(conn, &authorized_by, effective_at)?
            .filter(|state| state.active && state.can_delegate)
            .ok_or_else(|| {
                "TEMPUS_IDENTITY_EVENT_INVALID: signing authority was not valid".to_string()
            })?;
        let event_tenant = string_field(event, "tenant_id")?;
        if authority.tenant_id != "*" && authority.tenant_id != event_tenant {
            return Err("TEMPUS_IDENTITY_EVENT_INVALID: tenant delegation mismatch".to_string());
        }
        let event_type = string_field(event, "event_type")?;
        let affects_key = match event_type.as_str() {
            "ROTATE" => {
                event.get("previous_public_key").and_then(Value::as_str) == Some(public_key)
            }
            "REVOKE" => event.get("public_key").and_then(Value::as_str) == Some(public_key),
            _ => return Err("TEMPUS_IDENTITY_EVENT_INVALID: unknown event type".to_string()),
        };
        if affects_key {
            end.get_or_insert((effective_at, event_type));
        }
    }
    Ok(end)
}

fn verify_agent_state_at(
    conn: &Connection,
    public_key: &str,
    at_micros: u64,
) -> Result<Option<AgentState>, String> {
    let mut visited = std::collections::HashSet::new();
    verify_agent_state_at_inner(conn, public_key, at_micros, &mut visited)
}

fn verify_agent_state_at_inner(
    conn: &Connection,
    public_key: &str,
    at_micros: u64,
    visited: &mut std::collections::HashSet<String>,
) -> Result<Option<AgentState>, String> {
    if visited.len() > 16 || !visited.insert(public_key.to_string()) {
        return Ok(None);
    }
    let row = conn
        .query_row(
            "SELECT alias, registered_at, metadata, status, can_delegate, registered_by,
                    registration_event_id, registration_event, registration_signature,
                    identity_id, tenant_id, valid_from, valid_until, revoked_at,
                    key_version, signer_uri, algorithm
             FROM agents WHERE public_key = ?1",
            [public_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, u64>(11)?,
                    row.get::<_, Option<u64>>(12)?,
                    row.get::<_, Option<u64>>(13)?,
                    row.get::<_, u64>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                ))
            },
        )
        .optional()
        .map_err(|e| format!("Failed to read agent registration: {e}"))?;

    let Some((
        alias,
        registered_at,
        metadata,
        status,
        can_delegate,
        registered_by,
        event_id,
        event,
        signature,
        identity_id,
        tenant_id,
        valid_from,
        valid_until,
        revoked_at,
        key_version,
        signer_uri,
        algorithm,
    )) = row
    else {
        return Ok(None);
    };
    if event_id.is_empty() || signature.is_empty() || registered_by.is_empty() {
        return Ok(None);
    }
    let (event_value, canonical_event) = parse_canonical(&event, "registration_event")?;
    if sha256_hex(canonical_event.as_bytes()) != event_id
        || !verify_digest_signature(&registered_by, &event_id, &signature)
    {
        return Ok(None);
    }
    let metadata_value: Value = serde_json::from_str(&metadata).unwrap_or_else(|_| json!({}));
    let event_signer = event_value.get("signer");
    let matches_columns = string_field(&event_value, "schema_version").ok().as_deref()
        == Some(AGENT_REGISTRATION_SCHEMA)
        && string_field(&event_value, "agent_id").ok().as_deref() == Some(public_key)
        && string_field(&event_value, "alias").ok().as_deref() == Some(alias.as_str())
        && string_field(&event_value, "registered_by").ok().as_deref()
            == Some(registered_by.as_str())
        && integer_field(&event_value, "registered_at").ok() == Some(registered_at)
        && event_value.get("metadata") == Some(&metadata_value)
        && event_value.get("can_delegate").and_then(Value::as_bool) == Some(can_delegate)
        && event_value
            .get("identity_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value == identity_id)
        && event_value
            .get("tenant_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value == tenant_id)
        && event_value
            .get("key_version")
            .and_then(Value::as_u64)
            .is_none_or(|value| value == key_version)
        && event_signer.is_none_or(|signer| {
            signer.get("signer_uri").and_then(Value::as_str) == Some(signer_uri.as_str())
                && signer.get("algorithm").and_then(Value::as_str) == Some(algorithm.as_str())
                && signer.get("public_key").and_then(Value::as_str) == Some(public_key)
        });
    if !matches_columns {
        return Ok(None);
    }
    let lifecycle_end = lifecycle_end_for_key(conn, &identity_id, public_key)?;
    match lifecycle_end.as_ref() {
        Some((effective_at, event_type)) => {
            let expected_status = if event_type == "ROTATE" {
                "rotated"
            } else {
                "revoked"
            };
            if valid_until != Some(*effective_at)
                || status != expected_status
                || (event_type == "REVOKE" && revoked_at != Some(*effective_at))
            {
                return Ok(None);
            }
        }
        None if status != "active" || valid_until.is_some() || revoked_at.is_some() => {
            return Ok(None);
        }
        None => {}
    }
    let effective_until = lifecycle_end.as_ref().map(|(value, _)| *value);
    let valid_at_time = valid_from <= at_micros
        && effective_until.is_none_or(|value| at_micros < value)
        && revoked_at.is_none_or(|value| at_micros < value);

    let is_trusted_root: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM trusted_roots WHERE public_key = ?1)",
            [public_key],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if registered_by == public_key {
        if !is_trusted_root {
            return Ok(None);
        }
    } else {
        let registrar = verify_agent_state_at_inner(conn, &registered_by, registered_at, visited)?;
        let Some(registrar_state) = registrar else {
            return Ok(None);
        };
        if !registrar_state.active || !registrar_state.can_delegate {
            return Ok(None);
        }
        if registrar_state.tenant_id != "*" && registrar_state.tenant_id != tenant_id {
            return Ok(None);
        }
    }

    Ok(Some(AgentState {
        active: valid_at_time,
        can_delegate,
        tenant_id,
        identity_id,
        metadata,
    }))
}

fn verify_agent_state(conn: &Connection, public_key: &str) -> Result<Option<AgentState>, String> {
    verify_agent_state_at(conn, public_key, now_micros()?)
}

pub(crate) fn register_agent(
    storage: &SqliteStorage,
    public_key: &str,
    alias: &str,
    metadata: &str,
) -> Result<String, String> {
    decode_public_key(public_key)?;
    if alias.trim().is_empty() {
        return Err("TEMPUS_INVALID_AGENT: alias must not be empty".to_string());
    }
    let (metadata_value, canonical_metadata) = parse_canonical(metadata, "metadata")?;
    if !metadata_value.is_object() {
        return Err("TEMPUS_INVALID_AGENT: metadata must be a JSON object".to_string());
    }

    let registrar_key = storage.load_signer()?;
    let registrar_id = registrar_key.identity().public_key.clone();
    let agent_count: u64 = storage
        .conn
        .query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))
        .map_err(|e| format!("Failed to count agents: {e}"))?;
    let (signer_uri, key_version, algorithm) = if public_key == registrar_id {
        (
            registrar_key.identity().signer_uri.clone(),
            registrar_key
                .identity()
                .key_version
                .parse::<u64>()
                .map_err(|_| "TEMPUS_INVALID_AGENT: signer key_version must be numeric")?,
            registrar_key.identity().algorithm.clone(),
        )
    } else {
        let signer_uri = metadata_value
            .get("signer_uri")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("local-ed25519://{public_key}"));
        let key_version = metadata_value
            .get("key_version")
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|raw| raw.parse().ok()))
            })
            .unwrap_or(1);
        let algorithm = metadata_value
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or("Ed25519")
            .to_string();
        (signer_uri, key_version, algorithm)
    };
    if signer_uri.trim().is_empty() || key_version == 0 || algorithm != "Ed25519" {
        return Err(
            "TEMPUS_INVALID_AGENT: signer_uri, positive key_version, and Ed25519 are required"
                .to_string(),
        );
    }

    let can_delegate = if agent_count == 0 {
        if public_key != registrar_id {
            return Err(
                "TEMPUS_ROOT_MISMATCH: the first registration must bootstrap the gate key itself"
                    .to_string(),
            );
        }
        true
    } else {
        let registrar = verify_agent_state(&storage.conn, &registrar_id)?.ok_or_else(|| {
            "TEMPUS_REGISTRAR_NOT_AUTHORIZED: registrar has no valid signed registration"
                .to_string()
        })?;
        if !registrar.active || !registrar.can_delegate {
            return Err(
                "TEMPUS_REGISTRAR_NOT_AUTHORIZED: registrar cannot delegate agent authority"
                    .to_string(),
            );
        }
        metadata_value
            .get("can_delegate")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let tenant_id = metadata_value
        .get("tenant_id")
        .and_then(Value::as_str)
        .unwrap_or("*");
    if tenant_id.trim().is_empty() {
        return Err("TEMPUS_INVALID_AGENT: metadata.tenant_id must not be empty".to_string());
    }
    if agent_count > 0 {
        let registrar = verify_agent_state(&storage.conn, &registrar_id)?
            .ok_or_else(|| "TEMPUS_REGISTRAR_NOT_AUTHORIZED".to_string())?;
        if registrar.tenant_id != "*" && registrar.tenant_id != tenant_id {
            return Err(
                "TEMPUS_DELEGATION_SCOPE_DENIED: registrar cannot delegate across tenants"
                    .to_string(),
            );
        }
    }

    if storage
        .conn
        .query_row(
            "SELECT 1 FROM agents WHERE public_key = ?1",
            [public_key],
            |_| Ok(()),
        )
        .optional()
        .map_err(|e| format!("Failed to check agent registration: {e}"))?
        .is_some()
    {
        return Err("TEMPUS_AGENT_ALREADY_REGISTERED: registrations are immutable".to_string());
    }

    let registered_at = now_micros()?;
    let event = json!({
        "schema_version": AGENT_REGISTRATION_SCHEMA,
        "agent_id": public_key,
        "alias": alias,
        "metadata": metadata_value,
        "status": "active",
        "can_delegate": can_delegate,
        "registered_at": registered_at,
        "registered_by": registrar_id,
        "identity_id": public_key,
        "tenant_id": tenant_id,
        "key_version": key_version,
        "signer": {
            "signer_uri": signer_uri,
            "key_version": key_version.to_string(),
            "algorithm": algorithm,
            "public_key": public_key,
        },
    });
    let canonical_event = canonicalize(&event)?;
    let event_id = sha256_hex(canonical_event.as_bytes());
    let signature = sign_digest(&registrar_key, &event_id)?;

    storage
        .conn
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("Failed to begin registration transaction: {e}"))?;
    let reg_result: Result<(), String> = (|| {
        storage
            .conn
            .execute(
                "INSERT INTO agents
                 (public_key, alias, registered_at, metadata, status, can_delegate, registered_by,
                   registration_event_id, registration_event, registration_signature,
                   identity_id, tenant_id, key_version, signer_uri, algorithm, valid_from)
                  VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8, ?9,
                          ?1, ?10, ?11, ?12, ?13, ?3)",
                params![
                    public_key,
                    alias,
                    registered_at,
                    canonical_metadata,
                    can_delegate,
                    registrar_id,
                    event_id,
                    canonical_event,
                    signature,
                    tenant_id,
                    key_version,
                    signer_uri,
                    algorithm,
                ],
            )
            .map_err(|e| format!("Failed to insert agent: {e}"))?;

        if agent_count == 0 {
            storage
                .conn
                .execute(
                    "INSERT OR REPLACE INTO trusted_roots (id, public_key, established_at) VALUES (1, ?1, ?2)",
                    params![public_key, registered_at],
                )
                .map_err(|e| format!("Failed to establish trusted root: {e}"))?;
            crate::phase3::ensure_default_policy(&storage.conn, &registrar_key, registered_at)?;
        }

        crate::events::record_event(
            &storage.conn,
            tenant_id,
            "agent.registered",
            &event_id,
            &canonical_event,
            registered_at,
        )?;
        Ok(())
    })();

    match reg_result {
        Ok(()) => {
            storage
                .conn
                .execute_batch("COMMIT")
                .map_err(|e| format!("Failed to commit registration: {e}"))?;
        }
        Err(err) => {
            let _ = storage.conn.execute_batch("ROLLBACK");
            return Err(format!("Failed to register agent: {err}"));
        }
    }

    canonicalize(&json!({
        "schema_version": AGENT_REGISTRATION_SCHEMA,
        "event_id": event_id,
        "registration": event,
        "signature": signature,
    }))
}

pub(crate) fn verify_agent(storage: &SqliteStorage, public_key: &str) -> Result<bool, String> {
    Ok(verify_agent_state(&storage.conn, public_key)?
        .map(|state| state.active)
        .unwrap_or(false))
}

pub(crate) fn list_agents(storage: &SqliteStorage) -> Result<String, String> {
    let mut statement = storage
        .conn
        .prepare(
            "SELECT public_key, alias, registered_at, metadata, status, can_delegate,
                    registered_by, registration_event_id, identity_id, tenant_id,
                    key_version, signer_uri, algorithm, valid_from, valid_until, revoked_at
             FROM agents ORDER BY registered_at ASC",
        )
        .map_err(|e| format!("Failed to prepare agents query: {e}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, bool>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, u64>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, u64>(13)?,
                row.get::<_, Option<u64>>(14)?,
                row.get::<_, Option<u64>>(15)?,
            ))
        })
        .map_err(|e| format!("Failed to query agents: {e}"))?;

    let mut agents = Vec::new();
    for row in rows {
        let (
            public_key,
            alias,
            registered_at,
            metadata,
            status,
            can_delegate,
            registered_by,
            event_id,
            identity_id,
            tenant_id,
            key_version,
            signer_uri,
            algorithm,
            valid_from,
            valid_until,
            revoked_at,
        ) = row.map_err(|e| format!("Error reading agent: {e}"))?;
        let trusted = verify_agent_state(&storage.conn, &public_key)?.is_some();
        agents.push(json!({
            "public_key": public_key,
            "alias": alias,
            "registered_at": registered_at,
            "metadata": serde_json::from_str::<Value>(&metadata).unwrap_or_else(|_| json!({})),
            "status": status,
            "can_delegate": can_delegate,
            "registered_by": registered_by,
            "registration_event_id": event_id,
            "identity_id": identity_id,
            "tenant_id": tenant_id,
            "key_version": key_version,
            "signer_uri": signer_uri,
            "algorithm": algorithm,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "revoked_at": revoked_at,
            "trusted": trusted,
        }));
    }
    canonicalize(&Value::Array(agents))
}

pub(crate) fn get_agent(storage: &SqliteStorage, public_key: &str) -> Result<String, String> {
    let agents: Value = serde_json::from_str(&list_agents(storage)?)
        .map_err(|e| format!("Failed to parse agent list: {e}"))?;
    agents
        .as_array()
        .and_then(|agents| {
            agents
                .iter()
                .find(|agent| agent.get("public_key").and_then(Value::as_str) == Some(public_key))
        })
        .map(canonicalize)
        .transpose()?
        .ok_or_else(|| "TEMPUS_AGENT_NOT_FOUND".to_string())
}

pub(crate) fn rotate_agent(
    storage: &SqliteStorage,
    current_public_key: &str,
    new_public_key: &str,
) -> Result<String, String> {
    decode_public_key(new_public_key)?;
    if current_public_key == new_public_key {
        return Err("TEMPUS_ROTATION_INVALID: new key must differ from current key".to_string());
    }
    let current = verify_agent_state(&storage.conn, current_public_key)?
        .filter(|state| state.active)
        .ok_or_else(|| "TEMPUS_ROTATION_INVALID: current identity is not active".to_string())?;
    let (gate_signer, registrar_id) = gate_identity(storage)?;
    if current_public_key == registrar_id {
        return Err(
            "TEMPUS_ROTATION_INVALID: gate signer rotation requires an offline root ceremony"
                .to_string(),
        );
    }
    let registrar = verify_agent_state(&storage.conn, &registrar_id)?
        .ok_or_else(|| "TEMPUS_REGISTRAR_NOT_AUTHORIZED".to_string())?;
    if registrar.tenant_id != "*" && registrar.tenant_id != current.tenant_id {
        return Err("TEMPUS_DELEGATION_SCOPE_DENIED".to_string());
    }
    if storage
        .conn
        .query_row(
            "SELECT 1 FROM agents WHERE public_key = ?1",
            [new_public_key],
            |_| Ok(()),
        )
        .optional()
        .map_err(|e| format!("Failed to check rotation key: {e}"))?
        .is_some()
    {
        return Err("TEMPUS_AGENT_ALREADY_REGISTERED".to_string());
    }
    let (alias, metadata, can_delegate, key_version): (String, String, bool, u64) = storage
        .conn
        .query_row(
            "SELECT alias, metadata, can_delegate, key_version FROM agents WHERE public_key = ?1",
            [current_public_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|e| format!("Failed to read identity for rotation: {e}"))?;
    let metadata_value: Value = serde_json::from_str(&metadata)
        .map_err(|e| format!("Stored agent metadata is invalid: {e}"))?;
    let effective_at = now_micros()?;
    let next_version = key_version
        .checked_add(1)
        .ok_or_else(|| "TEMPUS_ROTATION_INVALID: key version overflow".to_string())?;
    let lifecycle = json!({
        "schema_version": crate::phase3::IDENTITY_EVENT_SCHEMA,
        "event_type": "ROTATE",
        "identity_id": current.identity_id,
        "tenant_id": current.tenant_id,
        "previous_public_key": current_public_key,
        "public_key": new_public_key,
        "previous_key_version": key_version,
        "key_version": next_version,
        "effective_at": effective_at,
        "authorized_by": registrar_id,
        "signer": gate_signer.identity().to_json(),
    });
    let lifecycle_canonical = canonicalize(&lifecycle)?;
    let lifecycle_id = sha256_hex(lifecycle_canonical.as_bytes());
    let lifecycle_signature = sign_digest(&gate_signer, &lifecycle_id)?;
    let lifecycle_result = json!({
        "event": lifecycle,
        "event_id": lifecycle_id,
        "signature": lifecycle_signature,
    });
    let lifecycle_json = canonicalize(&lifecycle_result)?;

    let registration = json!({
        "schema_version": AGENT_REGISTRATION_SCHEMA,
        "agent_id": new_public_key,
        "alias": alias,
        "metadata": metadata_value,
        "status": "active",
        "can_delegate": can_delegate,
        "registered_at": effective_at,
        "registered_by": registrar_id,
        "identity_id": current.identity_id,
        "tenant_id": current.tenant_id,
        "key_version": next_version,
        "signer": {
            "signer_uri": format!("local-ed25519://{new_public_key}"),
            "key_version": next_version.to_string(),
            "algorithm": "Ed25519",
            "public_key": new_public_key,
        },
        "rotation_event_id": lifecycle_id,
    });
    let registration_canonical = canonicalize(&registration)?;
    let registration_id = sha256_hex(registration_canonical.as_bytes());
    let registration_signature = sign_digest(&gate_signer, &registration_id)?;

    storage
        .conn
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("Failed to begin identity rotation: {e}"))?;
    let result = (|| -> Result<(), String> {
        storage
            .conn
            .execute(
                "UPDATE agents SET status = 'rotated', valid_until = ?1
                 WHERE public_key = ?2 AND status = 'active'",
                params![effective_at, current_public_key],
            )
            .map_err(|e| format!("Failed to retire previous key: {e}"))?;
        storage
            .conn
            .execute(
                "INSERT INTO agents
                 (public_key, alias, registered_at, metadata, status, can_delegate, registered_by,
                  registration_event_id, registration_event, registration_signature,
                  identity_id, tenant_id, key_version, signer_uri, algorithm, valid_from)
                 VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8, ?9,
                         ?10, ?11, ?12, ?13, 'Ed25519', ?3)",
                params![
                    new_public_key,
                    alias,
                    effective_at,
                    metadata,
                    can_delegate,
                    registrar_id,
                    registration_id,
                    registration_canonical,
                    registration_signature,
                    current.identity_id,
                    current.tenant_id,
                    next_version,
                    format!("local-ed25519://{new_public_key}"),
                ],
            )
            .map_err(|e| format!("Failed to install rotated key: {e}"))?;
        storage
            .conn
            .execute(
                "INSERT INTO identity_lifecycle_events
                 (event_id, identity_id, public_key, event_type, effective_at, event_json)
                 VALUES (?1, ?2, ?3, 'ROTATE', ?4, ?5)",
                params![
                    lifecycle_id,
                    current.identity_id,
                    new_public_key,
                    effective_at,
                    lifecycle_json,
                ],
            )
            .map_err(|e| format!("Failed to persist rotation event: {e}"))?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = storage.conn.execute_batch("ROLLBACK");
        return Err(error);
    }
    storage
        .conn
        .execute_batch("COMMIT")
        .map_err(|e| format!("Failed to commit identity rotation: {e}"))?;
    Ok(lifecycle_json)
}

pub(crate) fn revoke_agent(
    storage: &SqliteStorage,
    public_key: &str,
    reason: &str,
) -> Result<String, String> {
    if reason.trim().is_empty() {
        return Err("TEMPUS_REVOCATION_INVALID: reason must not be empty".to_string());
    }
    let state = verify_agent_state(&storage.conn, public_key)?
        .filter(|state| state.active)
        .ok_or_else(|| "TEMPUS_REVOCATION_INVALID: identity key is not active".to_string())?;
    let (gate_signer, registrar_id) = gate_identity(storage)?;
    if public_key == registrar_id {
        return Err(
            "TEMPUS_REVOCATION_INVALID: rotate the active gate signer before revoking it"
                .to_string(),
        );
    }
    let effective_at = now_micros()?;
    let event = json!({
        "schema_version": crate::phase3::IDENTITY_EVENT_SCHEMA,
        "event_type": "REVOKE",
        "identity_id": state.identity_id,
        "tenant_id": state.tenant_id,
        "public_key": public_key,
        "effective_at": effective_at,
        "reason": reason,
        "authorized_by": registrar_id,
        "signer": gate_signer.identity().to_json(),
    });
    let canonical_event = canonicalize(&event)?;
    let event_id = sha256_hex(canonical_event.as_bytes());
    let signature = sign_digest(&gate_signer, &event_id)?;
    let mut event_result = json!({
        "event": event,
        "event_id": event_id,
        "signature": signature,
    });

    storage
        .conn
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("Failed to begin identity revocation: {e}"))?;
    let result = (|| -> Result<u64, String> {
        storage
            .conn
            .execute(
                "UPDATE agents SET status = 'revoked', valid_until = ?1, revoked_at = ?1
                 WHERE public_key = ?2 AND status = 'active'",
                params![effective_at, public_key],
            )
            .map_err(|e| format!("Failed to revoke identity: {e}"))?;
        storage
            .conn
            .execute(
                "INSERT INTO identity_lifecycle_events
                 (event_id, identity_id, public_key, event_type, effective_at, event_json)
                 VALUES (?1, ?2, ?3, 'REVOKE', ?4, ?5)",
                params![
                    event_id,
                    state.identity_id,
                    public_key,
                    effective_at,
                    canonicalize(&event_result)?,
                ],
            )
            .map_err(|e| format!("Failed to persist revocation event: {e}"))?;
        let revoked = storage
            .conn
            .execute(
                "INSERT OR IGNORE INTO revoked_authorizations
                 (authorization_id, revoked_at, reason, identity_event_id)
                 SELECT a.authorization_id, ?1, ?2, ?3
                 FROM action_authorizations a
                 LEFT JOIN action_outcomes o ON o.authorization_id = a.authorization_id
                 WHERE a.agent_id = ?4 AND a.decision = 'ALLOWED'
                   AND a.expires_at > ?1 AND o.authorization_id IS NULL",
                params![effective_at, reason, event_id, public_key],
            )
            .map_err(|e| format!("Failed to revoke unconsumed permits: {e}"))?;
        Ok(revoked as u64)
    })();
    let revoked_permits = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = storage.conn.execute_batch("ROLLBACK");
            return Err(error);
        }
    };
    storage
        .conn
        .execute_batch("COMMIT")
        .map_err(|e| format!("Failed to commit identity revocation: {e}"))?;
    event_result["revoked_unconsumed_permits"] = json!(revoked_permits);
    canonicalize(&event_result)
}

pub(crate) fn list_identity_events(storage: &SqliteStorage) -> Result<String, String> {
    let mut statement = storage
        .conn
        .prepare("SELECT event_json FROM identity_lifecycle_events ORDER BY effective_at ASC")
        .map_err(|e| format!("Failed to prepare identity event list: {e}"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| format!("Failed to list identity events: {e}"))?;
    let mut events = Vec::new();
    for row in rows {
        let raw = row.map_err(|e| format!("Failed to read identity event: {e}"))?;
        events.push(
            serde_json::from_str::<Value>(&raw)
                .map_err(|e| format!("Stored identity event is invalid JSON: {e}"))?,
        );
    }
    canonicalize(&Value::Array(events))
}

pub(crate) fn request_action(
    storage: &SqliteStorage,
    intent: &str,
    agent_keyfile: &str,
    ttl_seconds: u64,
) -> Result<String, String> {
    let agent_key = load_signing_key(agent_keyfile)?;
    let agent_id = hex::encode(agent_key.verifying_key().to_bytes());
    let (intent_value, canonical_intent) = parse_canonical(intent, "intent")?;
    validate_intent(&intent_value, &agent_id)?;
    let agent_signature = hex::encode(agent_key.sign(canonical_intent.as_bytes()).to_bytes());
    request_action_signed(
        storage,
        &canonical_intent,
        &agent_id,
        &agent_signature,
        ttl_seconds,
    )
}

pub(crate) fn request_action_signed(
    storage: &SqliteStorage,
    intent: &str,
    agent_id: &str,
    agent_signature: &str,
    ttl_seconds: u64,
) -> Result<String, String> {
    if !(1..=86_400).contains(&ttl_seconds) {
        return Err("TEMPUS_INVALID_TTL: ttl_seconds must be between 1 and 86400".to_string());
    }
    let (intent_value, canonical_intent) = parse_canonical(intent, "intent")?;
    let fields = validate_intent(&intent_value, agent_id)?;
    let intent_hash = sha256_hex(canonical_intent.as_bytes());
    let action_id = action_id_for(&fields);

    let existing = storage
        .conn
        .query_row(
            "SELECT intent_hash, authorization_json FROM action_authorizations WHERE action_id = ?1",
            [&action_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| format!("Failed to check action idempotency: {e}"))?;
    if let Some((existing_hash, authorization_json)) = existing {
        if existing_hash == intent_hash {
            let existing_value: Value = serde_json::from_str(&authorization_json)
                .map_err(|e| format!("TEMPUS_STORED_AUTHORIZATION_INVALID: {e}"))?;
            let errors = verify_authorization(storage, &existing_value);
            if !errors.is_empty() {
                return Err(format!(
                    "TEMPUS_STORED_AUTHORIZATION_INVALID: {}",
                    errors.join(",")
                ));
            }
            return Ok(authorization_json);
        }
        return Err(
            "TEMPUS_IDEMPOTENCY_CONFLICT: idempotency key was already used for a different intent"
                .to_string(),
        );
    }

    let (gate_key, gate_id) = gate_identity(storage)?;
    let issued_at = now_micros()?;
    let policy_bundle =
        crate::phase3::active_policy(&storage.conn, &gate_key, &fields.tenant_id, issued_at)?;
    let policy_decision =
        crate::phase3::evaluate_policy(&policy_bundle, &intent_value, ttl_seconds)?;
    let signature_valid =
        verify_message_signature(agent_id, canonical_intent.as_bytes(), agent_signature);
    let agent_state = verify_agent_state(&storage.conn, agent_id)?;
    let agent_authorized = agent_state.as_ref().is_some_and(|state| state.active);
    let agent_tenant_authorized = agent_state
        .as_ref()
        .is_some_and(|state| state.tenant_id == "*" || state.tenant_id == fields.tenant_id);
    let request_too_old = issued_at.saturating_sub(fields.requested_at) > 300_000_000;
    let request_from_future = fields.requested_at.saturating_sub(issued_at) > 60_000_000;
    let (decision, reason_codes): (&str, Vec<String>) = if !signature_valid {
        ("BLOCKED", vec!["INVALID_AGENT_SIGNATURE".to_string()])
    } else if !agent_authorized {
        ("BLOCKED", vec!["AGENT_NOT_REGISTERED".to_string()])
    } else if !agent_tenant_authorized {
        ("BLOCKED", vec!["AGENT_TENANT_SCOPE_DENIED".to_string()])
    } else if request_too_old {
        ("BLOCKED", vec!["REQUEST_STALE".to_string()])
    } else if request_from_future {
        ("BLOCKED", vec!["REQUEST_FROM_FUTURE".to_string()])
    } else if policy_decision.decision == "BLOCKED" {
        ("BLOCKED", policy_decision.reason_codes.clone())
    } else {
        (
            "ALLOWED",
            vec![
                "IDENTITY_VERIFIED".to_string(),
                "POLICY_ALLOWED".to_string(),
            ],
        )
    };

    let expires_at = issued_at
        .checked_add(ttl_seconds.saturating_mul(1_000_000))
        .ok_or_else(|| "TEMPUS_INVALID_TTL: expiration overflow".to_string())?;
    let body = json!({
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA,
        "action_id": action_id,
        "tenant_id": fields.tenant_id,
        "agent_id": fields.agent_id,
        "intent_hash": intent_hash,
        "decision": decision,
        "reason_codes": reason_codes,
        "policy_version": string_field(&policy_bundle, "policy_version")?,
        "policy_digest": string_field(&policy_bundle, "policy_digest")?,
        "evidence_digest": policy_decision.evidence_digest,
        "executor_constraints": policy_decision.executor_constraints,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "gate_id": gate_id,
        "gate_signer": gate_key.identity().to_json(),
    });
    let authorization_id = sha256_hex(canonicalize(&body)?.as_bytes());
    let gate_signature = sign_digest(&gate_key, &authorization_id)?;
    let mut authorization = body;
    authorization
        .as_object_mut()
        .expect("authorization body is an object")
        .insert(
            "authorization_id".to_string(),
            Value::String(authorization_id.clone()),
        );
    authorization
        .as_object_mut()
        .expect("authorization body is an object")
        .insert("gate_signature".to_string(), Value::String(gate_signature));
    let result = json!({
        "schema_version": AUTHORIZATION_RESULT_SCHEMA,
        "authorization": authorization,
        "intent": intent_value,
        "agent_signature": agent_signature,
        "policy_bundle": policy_bundle,
    });
    let authorization_json = canonicalize(&result)?;

    storage
        .conn
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("Failed to begin authorization transaction: {e}"))?;

    let auth_result: Result<(), String> = (|| {
        storage
            .conn
            .execute(
                "INSERT INTO action_authorizations
                 (authorization_id, action_id, tenant_id, agent_id, idempotency_key, intent_hash,
                  decision, issued_at, expires_at, authorization_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    authorization_id,
                    action_id,
                    fields.tenant_id,
                    fields.agent_id,
                    fields.idempotency_key,
                    intent_hash,
                    decision,
                    issued_at,
                    expires_at,
                    authorization_json,
                ],
            )
            .map_err(|e| format!("Failed to persist authorization receipt: {e}"))?;

        crate::events::record_event(
            &storage.conn,
            &fields.tenant_id,
            "action.authorized",
            &authorization_id,
            &authorization_json,
            issued_at,
        )?;
        Ok(())
    })();

    match auth_result {
        Ok(()) => {
            storage
                .conn
                .execute_batch("COMMIT")
                .map_err(|e| format!("Failed to commit authorization transaction: {e}"))?;
        }
        Err(err) => {
            let _ = storage.conn.execute_batch("ROLLBACK");
            return Err(err);
        }
    }

    Ok(authorization_json)
}

fn verify_authorization(storage: &SqliteStorage, result: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if result.get("schema_version").and_then(Value::as_str) != Some(AUTHORIZATION_RESULT_SCHEMA) {
        errors.push("AUTHORIZATION_RESULT_SCHEMA_MISMATCH".to_string());
    }
    let Some(mut authorization) = result.get("authorization").cloned() else {
        errors.push("AUTHORIZATION_RECEIPT_MISSING".to_string());
        return errors;
    };
    let Some(object) = authorization.as_object_mut() else {
        errors.push("AUTHORIZATION_RECEIPT_INVALID".to_string());
        return errors;
    };
    let authorization_id = object
        .remove("authorization_id")
        .and_then(|value| value.as_str().map(str::to_string));
    let gate_signature = object
        .remove("gate_signature")
        .and_then(|value| value.as_str().map(str::to_string));
    let Some(authorization_id) = authorization_id else {
        errors.push("AUTHORIZATION_ID_MISSING".to_string());
        return errors;
    };
    let Some(gate_signature) = gate_signature else {
        errors.push("GATE_SIGNATURE_MISSING".to_string());
        return errors;
    };
    let canonical_body = match canonicalize(&authorization) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return errors;
        }
    };
    if sha256_hex(canonical_body.as_bytes()) != authorization_id {
        errors.push("AUTHORIZATION_ID_MISMATCH".to_string());
    }
    if authorization.get("schema_version").and_then(Value::as_str)
        != Some(AUTHORIZATION_RECEIPT_SCHEMA)
    {
        errors.push("AUTHORIZATION_RECEIPT_SCHEMA_MISMATCH".to_string());
    }
    let gate_id = authorization
        .get("gate_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !verify_digest_signature(gate_id, &authorization_id, &gate_signature) {
        errors.push("GATE_SIGNATURE_INVALID".to_string());
    }
    let authorization_issued_at = authorization
        .get("issued_at")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    match verify_agent_state_at(&storage.conn, gate_id, authorization_issued_at) {
        Ok(Some(state)) if state.active && state.can_delegate => {}
        Ok(_) => errors.push("GATE_IDENTITY_NOT_TRUSTED".to_string()),
        Err(error) => errors.push(error),
    }

    let policy_bundle = result.get("policy_bundle");
    match policy_bundle {
        Some(bundle) => {
            if let Err(error) = crate::phase3::verify_policy_bundle(bundle, Some(gate_id)) {
                errors.push(error);
            }
            if authorization.get("policy_version") != bundle.get("policy_version") {
                errors.push("AUTHORIZATION_POLICY_VERSION_MISMATCH".to_string());
            }
            if authorization.get("policy_digest") != bundle.get("policy_digest") {
                errors.push("AUTHORIZATION_POLICY_DIGEST_MISMATCH".to_string());
            }
            if authorization.get("gate_signer") != bundle.get("signer") {
                errors.push("AUTHORIZATION_SIGNER_METADATA_MISMATCH".to_string());
            }
        }
        None => {
            if authorization.get("policy_version").and_then(Value::as_str)
                != Some(LEGACY_POLICY_VERSION)
            {
                errors.push("AUTHORIZATION_POLICY_BUNDLE_MISSING".to_string());
            }
        }
    }

    let Some(intent) = result.get("intent") else {
        errors.push("INTENT_MISSING".to_string());
        return errors;
    };
    let canonical_intent = match canonicalize(intent) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return errors;
        }
    };
    let intent_hash = authorization
        .get("intent_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if sha256_hex(canonical_intent.as_bytes()) != intent_hash {
        errors.push("INTENT_HASH_MISMATCH".to_string());
    }
    if let Some(bundle) = policy_bundle {
        let issued_at = authorization
            .get("issued_at")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let expires_at = authorization
            .get("expires_at")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let ttl_seconds = expires_at.saturating_sub(issued_at) / 1_000_000;
        match crate::phase3::evaluate_policy(bundle, intent, ttl_seconds) {
            Ok(policy_decision) => {
                if authorization.get("evidence_digest").and_then(Value::as_str)
                    != Some(policy_decision.evidence_digest.as_str())
                {
                    errors.push("AUTHORIZATION_EVIDENCE_DIGEST_MISMATCH".to_string());
                }
                if authorization.get("executor_constraints")
                    != Some(&policy_decision.executor_constraints)
                {
                    errors.push("AUTHORIZATION_EXECUTOR_CONSTRAINTS_MISMATCH".to_string());
                }
                let reasons = authorization.get("reason_codes").and_then(Value::as_array);
                let identity_or_time_denial = reasons.is_some_and(|values| {
                    values.iter().any(|value| {
                        matches!(
                            value.as_str(),
                            Some(
                                "INVALID_AGENT_SIGNATURE"
                                    | "AGENT_NOT_REGISTERED"
                                    | "AGENT_TENANT_SCOPE_DENIED"
                                    | "REQUEST_STALE"
                                    | "REQUEST_FROM_FUTURE"
                            )
                        )
                    })
                });
                if !identity_or_time_denial
                    && authorization.get("decision").and_then(Value::as_str)
                        != Some(policy_decision.decision)
                {
                    errors.push("AUTHORIZATION_POLICY_DECISION_MISMATCH".to_string());
                }
            }
            Err(error) => errors.push(error),
        }
    }
    let agent_id = authorization
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let agent_signature = result
        .get("agent_signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !verify_message_signature(agent_id, canonical_intent.as_bytes(), agent_signature) {
        let is_expected_denial = authorization.get("decision").and_then(Value::as_str)
            == Some("BLOCKED")
            && authorization
                .get("reason_codes")
                .and_then(Value::as_array)
                .is_some_and(|reasons| {
                    reasons
                        .iter()
                        .any(|reason| reason.as_str() == Some("INVALID_AGENT_SIGNATURE"))
                });
        if !is_expected_denial {
            errors.push("AGENT_SIGNATURE_INVALID".to_string());
        }
    }
    match validate_intent(intent, agent_id) {
        Ok(fields) => {
            if authorization.get("action_id").and_then(Value::as_str)
                != Some(action_id_for(&fields).as_str())
            {
                errors.push("AUTHORIZATION_ACTION_ID_MISMATCH".to_string());
            }
            if authorization.get("tenant_id").and_then(Value::as_str)
                != Some(fields.tenant_id.as_str())
            {
                errors.push("AUTHORIZATION_TENANT_ID_MISMATCH".to_string());
            }
            if let Some(bundle) = policy_bundle {
                let ttl_seconds = authorization
                    .get("expires_at")
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
                    .saturating_sub(authorization_issued_at)
                    / 1_000_000;
                match (
                    verify_agent_state_at(&storage.conn, agent_id, authorization_issued_at),
                    crate::phase3::evaluate_policy(bundle, intent, ttl_seconds),
                ) {
                    (Ok(agent_state), Ok(policy)) => {
                        let signature_valid = verify_message_signature(
                            agent_id,
                            canonical_intent.as_bytes(),
                            agent_signature,
                        );
                        let active = agent_state.as_ref().is_some_and(|state| state.active);
                        let tenant_allowed = agent_state.as_ref().is_some_and(|state| {
                            state.tenant_id == "*" || state.tenant_id == fields.tenant_id
                        });
                        let too_old = authorization_issued_at.saturating_sub(fields.requested_at)
                            > 300_000_000;
                        let from_future =
                            fields.requested_at.saturating_sub(authorization_issued_at)
                                > 60_000_000;
                        let (expected_decision, expected_reasons): (&str, Vec<String>) =
                            if !signature_valid {
                                ("BLOCKED", vec!["INVALID_AGENT_SIGNATURE".to_string()])
                            } else if !active {
                                ("BLOCKED", vec!["AGENT_NOT_REGISTERED".to_string()])
                            } else if !tenant_allowed {
                                ("BLOCKED", vec!["AGENT_TENANT_SCOPE_DENIED".to_string()])
                            } else if too_old {
                                ("BLOCKED", vec!["REQUEST_STALE".to_string()])
                            } else if from_future {
                                ("BLOCKED", vec!["REQUEST_FROM_FUTURE".to_string()])
                            } else if policy.decision == "BLOCKED" {
                                ("BLOCKED", policy.reason_codes)
                            } else {
                                (
                                    "ALLOWED",
                                    vec![
                                        "IDENTITY_VERIFIED".to_string(),
                                        "POLICY_ALLOWED".to_string(),
                                    ],
                                )
                            };
                        if authorization.get("decision").and_then(Value::as_str)
                            != Some(expected_decision)
                        {
                            errors.push("AUTHORIZATION_DECISION_NOT_REPRODUCIBLE".to_string());
                        }
                        if authorization.get("reason_codes") != Some(&json!(expected_reasons)) {
                            errors.push("AUTHORIZATION_REASON_CODES_NOT_REPRODUCIBLE".to_string());
                        }
                    }
                    (Err(error), _) | (_, Err(error)) => errors.push(error),
                }
            }
        }
        Err(error) => errors.push(error),
    }
    errors
}

pub(crate) fn commit_outcome(
    storage: &SqliteStorage,
    authorization_id: &str,
    outcome: &str,
    executor_keyfile: &str,
) -> Result<String, String> {
    let executor_key = load_signing_key(executor_keyfile)?;
    let executor_id = hex::encode(executor_key.verifying_key().to_bytes());

    let mut outcome_value: Value =
        serde_json::from_str(outcome).map_err(|e| format!("outcome must be valid JSON: {e}"))?;
    if let Some(obj) = outcome_value.as_object_mut() {
        obj.insert(
            "executor_id".to_string(),
            Value::String(executor_id.clone()),
        );
    }
    let canonical_outcome_for_sign = canonicalize(&outcome_value)?;
    let executor_signature = hex::encode(
        executor_key
            .sign(canonical_outcome_for_sign.as_bytes())
            .to_bytes(),
    );

    if let Some(obj) = outcome_value.as_object_mut() {
        obj.insert(
            "executor_signature".to_string(),
            Value::String(executor_signature),
        );
    }
    let signed_outcome = canonicalize(&outcome_value)?;

    commit_outcome_signed(storage, authorization_id, &signed_outcome)
}

pub(crate) fn commit_outcome_signed(
    storage: &SqliteStorage,
    authorization_id: &str,
    outcome: &str,
) -> Result<String, String> {
    let authorization_json: String = storage
        .conn
        .query_row(
            "SELECT authorization_json FROM action_authorizations WHERE authorization_id = ?1",
            [authorization_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("Failed to read authorization: {e}"))?
        .ok_or_else(|| "TEMPUS_AUTHORIZATION_NOT_FOUND".to_string())?;
    let authorization_value: Value = serde_json::from_str(&authorization_json)
        .map_err(|e| format!("Stored authorization is invalid JSON: {e}"))?;
    let authorization_errors = verify_authorization(storage, &authorization_value);
    if !authorization_errors.is_empty() {
        return Err(format!(
            "TEMPUS_AUTHORIZATION_INVALID: {}",
            authorization_errors.join(",")
        ));
    }
    let authorization = authorization_value
        .get("authorization")
        .ok_or_else(|| "TEMPUS_AUTHORIZATION_INVALID".to_string())?;
    if authorization.get("decision").and_then(Value::as_str) != Some("ALLOWED") {
        return Err("TEMPUS_ACTION_BLOCKED: denied authorizations cannot be consumed".to_string());
    }
    let revoked: bool = storage
        .conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_authorizations WHERE authorization_id = ?1)",
            [authorization_id],
            |row| row.get(0),
        )
        .map_err(|e| format!("Failed to check permit revocation: {e}"))?;
    if revoked {
        return Err(
            "TEMPUS_PERMIT_REVOKED: identity revocation invalidated this unconsumed permit"
                .to_string(),
        );
    }
    let expires_at = integer_field(authorization, "expires_at")?;
    if now_micros()? > expires_at {
        return Err("TEMPUS_PERMIT_EXPIRED".to_string());
    }
    let action_id = string_field(authorization, "action_id")?;

    let (outcome_value, _) = parse_canonical(outcome, "outcome")?;
    let executor_signature = outcome_value
        .get("executor_signature")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "TEMPUS_OUTCOME_MISSING_SIGNATURE: outcome must have an executor_signature".to_string()
        })?
        .to_string();

    let mut outcome_for_hash = outcome_value.clone();
    if let Some(obj) = outcome_for_hash.as_object_mut() {
        obj.remove("executor_signature");
    }
    let canonical_outcome = canonicalize(&outcome_for_hash)?;

    let outcome_status = validate_outcome(&outcome_for_hash, authorization_id, &action_id)?;
    let outcome_hash = sha256_hex(canonical_outcome.as_bytes());

    let existing = storage
        .conn
        .query_row(
            "SELECT outcome_hash, execution_json FROM action_outcomes WHERE authorization_id = ?1",
            [authorization_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| format!("Failed to check permit consumption: {e}"))?;
    if let Some((existing_hash, execution_json)) = existing {
        if existing_hash == outcome_hash {
            let execution_value: Value = serde_json::from_str(&execution_json)
                .map_err(|e| format!("TEMPUS_STORED_EXECUTION_INVALID: {e}"))?;
            let errors = verify_execution(storage, &authorization_value, &execution_value);
            if !errors.is_empty() {
                return Err(format!(
                    "TEMPUS_STORED_EXECUTION_INVALID: {}",
                    errors.join(",")
                ));
            }
            return Ok(execution_json);
        }
        return Err(
            "TEMPUS_PERMIT_ALREADY_CONSUMED: a permit can produce only one outcome".to_string(),
        );
    }

    let executor_id = string_field(&outcome_for_hash, "executor_id")?;
    let agent_id = string_field(authorization, "agent_id")?;
    if executor_id == agent_id {
        return Err(
            "TEMPUS_EXECUTOR_INVALID: proposer agent cannot execute its own permit".to_string(),
        );
    }
    let policy_bundle = authorization_value
        .get("policy_bundle")
        .ok_or_else(|| "TEMPUS_POLICY_BUNDLE_MISSING".to_string())?;
    if !crate::phase3::executor_allowed(policy_bundle, &executor_id)? {
        return Err("TEMPUS_EXECUTOR_POLICY_DENIED".to_string());
    }
    let executor = verify_agent_state(&storage.conn, &executor_id)?
        .ok_or_else(|| "TEMPUS_EXECUTOR_NOT_REGISTERED".to_string())?;
    if !executor.active {
        return Err("TEMPUS_EXECUTOR_NOT_ACTIVE".to_string());
    }
    let tenant_id = string_field(authorization, "tenant_id")?;
    if executor.tenant_id != "*" && executor.tenant_id != tenant_id {
        return Err(
            "TEMPUS_EXECUTOR_TENANT_SCOPE_DENIED: executor cannot operate outside assigned tenant"
                .to_string(),
        );
    }
    if let Ok(meta_val) = serde_json::from_str::<Value>(&executor.metadata) {
        if meta_val.get("role").and_then(Value::as_str) == Some("proposer") {
            return Err(
                "TEMPUS_EXECUTOR_INVALID: executor agent cannot have proposer role".to_string(),
            );
        }
    }

    if !verify_message_signature(
        &executor_id,
        canonical_outcome.as_bytes(),
        &executor_signature,
    ) {
        return Err("TEMPUS_EXECUTOR_SIGNATURE_INVALID".to_string());
    }

    let (gate_key, gate_id) = gate_identity(storage)?;
    let completed_at = now_micros()?;
    let body = json!({
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "authorization_id": authorization_id,
        "action_id": action_id,
        "intent_hash": string_field(authorization, "intent_hash")?,
        "outcome_hash": outcome_hash,
        "executor_id": executor_id,
        "status": outcome_status,
        "completed_at": completed_at,
        "gate_id": gate_id,
    });
    let receipt_id = sha256_hex(canonicalize(&body)?.as_bytes());
    let gate_signature = sign_digest(&gate_key, &receipt_id)?;
    let mut receipt = body;
    receipt
        .as_object_mut()
        .expect("execution receipt body is an object")
        .insert("receipt_id".to_string(), Value::String(receipt_id.clone()));
    receipt
        .as_object_mut()
        .expect("execution receipt body is an object")
        .insert("gate_signature".to_string(), Value::String(gate_signature));
    let result = json!({
        "schema_version": EXECUTION_RESULT_SCHEMA,
        "receipt": receipt,
        "outcome": outcome_value,
    });
    let execution_json = canonicalize(&result)?;

    storage
        .conn
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("Failed to begin outcome commit transaction: {e}"))?;

    let outcome_result: Result<(), String> = (|| {
        storage
            .conn
            .execute(
                "INSERT INTO action_outcomes
                 (receipt_id, authorization_id, action_id, executor_id, outcome_hash,
                  completed_at, execution_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    receipt_id,
                    authorization_id,
                    action_id,
                    executor_id,
                    outcome_hash,
                    completed_at,
                    execution_json,
                ],
            )
            .map_err(|e| format!("Failed to persist execution receipt: {e}"))?;

        let event_tenant =
            string_field(authorization, "tenant_id").unwrap_or_else(|_| "*".to_string());
        let event_type = if outcome_status == "SUCCEEDED" {
            "action.executed"
        } else {
            "action.failed"
        };
        crate::events::record_event(
            &storage.conn,
            &event_tenant,
            event_type,
            &receipt_id,
            &execution_json,
            completed_at,
        )?;
        Ok(())
    })();

    match outcome_result {
        Ok(()) => {
            storage
                .conn
                .execute_batch("COMMIT")
                .map_err(|e| format!("Failed to commit outcome transaction: {e}"))?;
        }
        Err(err) => {
            let _ = storage.conn.execute_batch("ROLLBACK");
            return Err(err);
        }
    }

    Ok(execution_json)
}

fn verify_execution(
    storage: &SqliteStorage,
    authorization: &Value,
    execution: &Value,
) -> Vec<String> {
    let mut errors = Vec::new();
    if execution.get("schema_version").and_then(Value::as_str) != Some(EXECUTION_RESULT_SCHEMA) {
        errors.push("EXECUTION_RESULT_SCHEMA_MISMATCH".to_string());
    }
    let Some(mut receipt) = execution.get("receipt").cloned() else {
        errors.push("EXECUTION_RECEIPT_MISSING".to_string());
        return errors;
    };
    let Some(receipt_object) = receipt.as_object_mut() else {
        errors.push("EXECUTION_RECEIPT_INVALID".to_string());
        return errors;
    };
    let receipt_id = receipt_object
        .remove("receipt_id")
        .and_then(|value| value.as_str().map(str::to_string));
    let gate_signature = receipt_object
        .remove("gate_signature")
        .and_then(|value| value.as_str().map(str::to_string));
    let Some(receipt_id) = receipt_id else {
        errors.push("EXECUTION_RECEIPT_ID_MISSING".to_string());
        return errors;
    };
    let Some(gate_signature) = gate_signature else {
        errors.push("EXECUTION_GATE_SIGNATURE_MISSING".to_string());
        return errors;
    };
    let canonical_receipt = match canonicalize(&receipt) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return errors;
        }
    };
    if sha256_hex(canonical_receipt.as_bytes()) != receipt_id {
        errors.push("EXECUTION_RECEIPT_ID_MISMATCH".to_string());
    }
    if receipt.get("schema_version").and_then(Value::as_str) != Some(EXECUTION_RECEIPT_SCHEMA) {
        errors.push("EXECUTION_RECEIPT_SCHEMA_MISMATCH".to_string());
    }
    let gate_id = receipt
        .get("gate_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !verify_digest_signature(gate_id, &receipt_id, &gate_signature) {
        errors.push("EXECUTION_GATE_SIGNATURE_INVALID".to_string());
    }
    let authorization_receipt = authorization.get("authorization").unwrap_or(&Value::Null);
    for field in ["authorization_id", "action_id", "intent_hash"] {
        if receipt.get(field) != authorization_receipt.get(field) {
            errors.push(format!("EXECUTION_{field}_MISMATCH").to_uppercase());
        }
    }
    if receipt.get("executor_id").is_some()
        && receipt.get("executor_id") == authorization_receipt.get("agent_id")
    {
        errors.push("EXECUTOR_AGENT_COLLUSION".to_string());
    }
    let Some(outcome) = execution.get("outcome") else {
        errors.push("OUTCOME_MISSING".to_string());
        return errors;
    };

    let mut outcome_for_hash = outcome.clone();
    let executor_signature = if let Some(obj) = outcome_for_hash.as_object_mut() {
        obj.remove("executor_signature")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let canonical_outcome_for_hash = match canonicalize(&outcome_for_hash) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return errors;
        }
    };

    if sha256_hex(canonical_outcome_for_hash.as_bytes())
        != receipt
            .get("outcome_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
    {
        errors.push("OUTCOME_HASH_MISMATCH".to_string());
    }

    let executor_id = receipt
        .get("executor_id")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if !verify_message_signature(
        executor_id,
        canonical_outcome_for_hash.as_bytes(),
        &executor_signature,
    ) {
        errors.push("EXECUTOR_SIGNATURE_INVALID".to_string());
    }
    let completed_at = receipt
        .get("completed_at")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    match verify_agent_state_at(&storage.conn, executor_id, completed_at) {
        Ok(Some(state)) if state.active => {
            let auth_tenant = authorization_receipt
                .get("tenant_id")
                .and_then(Value::as_str)
                .unwrap_or("*");
            if state.tenant_id != "*" && auth_tenant != "*" && state.tenant_id != auth_tenant {
                errors.push("EXECUTOR_TENANT_SCOPE_MISMATCH".to_string());
            }
            if let Ok(meta_val) = serde_json::from_str::<Value>(&state.metadata) {
                if meta_val.get("role").and_then(Value::as_str) == Some("proposer") {
                    errors.push("EXECUTOR_ROLE_INVALID".to_string());
                }
            }
        }
        Ok(_) => errors.push("EXECUTOR_IDENTITY_NOT_TRUSTED".to_string()),
        Err(error) => errors.push(error),
    }
    let authorization_id = authorization_receipt
        .get("authorization_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let action_id = authorization_receipt
        .get("action_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if let Err(error) = validate_outcome(outcome, authorization_id, action_id) {
        errors.push(error);
    }
    if receipt.get("status") != outcome.get("status") {
        errors.push("EXECUTION_STATUS_MISMATCH".to_string());
    }
    errors
}

pub(crate) fn get_trace(storage: &SqliteStorage, action_id: &str) -> Result<String, String> {
    let authorization_json: String = storage
        .conn
        .query_row(
            "SELECT authorization_json FROM action_authorizations WHERE action_id = ?1",
            [action_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("Failed to read action trace: {e}"))?
        .ok_or_else(|| "TEMPUS_ACTION_NOT_FOUND".to_string())?;
    let authorization: Value = serde_json::from_str(&authorization_json)
        .map_err(|e| format!("Stored authorization is invalid JSON: {e}"))?;
    let execution_json = storage
        .conn
        .query_row(
            "SELECT execution_json FROM action_outcomes WHERE action_id = ?1",
            [action_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| format!("Failed to read execution receipt: {e}"))?;
    let execution = execution_json
        .map(|value| {
            serde_json::from_str::<Value>(&value)
                .map_err(|e| format!("Stored execution receipt is invalid JSON: {e}"))
        })
        .transpose()?;
    canonicalize(&json!({
        "schema_version": TRACE_SCHEMA,
        "action_id": action_id,
        "authorization": authorization,
        "execution": execution,
    }))
}

pub(crate) fn verify_trace(storage: &SqliteStorage, action_id: &str) -> Result<String, String> {
    let trace: Value = serde_json::from_str(&get_trace(storage, action_id)?)
        .map_err(|e| format!("Stored trace is invalid JSON: {e}"))?;
    let authorization = trace
        .get("authorization")
        .ok_or_else(|| "TEMPUS_AUTHORIZATION_NOT_FOUND".to_string())?;
    let mut errors = verify_authorization(storage, authorization);
    let execution = trace.get("execution").filter(|value| !value.is_null());
    if let Some(execution) = execution {
        errors.extend(verify_execution(storage, authorization, execution));
    }
    let receipt = authorization.get("authorization").unwrap_or(&Value::Null);
    let decision = receipt
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    let expires_at = receipt
        .get("expires_at")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let phase = if decision == "BLOCKED" {
        "BLOCKED"
    } else if execution.is_some() {
        "COMPLETED"
    } else if now_micros()? > expires_at {
        "EXPIRED"
    } else {
        "AUTHORIZED"
    };
    let status = if errors.is_empty() {
        "VERIFIED"
    } else {
        "INVALID"
    };
    canonicalize(&json!({
        "schema_version": TRACE_VERIFICATION_SCHEMA,
        "status": status,
        "action_id": action_id,
        "phase": phase,
        "checks": {
            "authorization": if errors.iter().any(|error| error.contains("AUTHORIZATION") || error.contains("INTENT") || error.contains("AGENT") || error.contains("GATE")) { "FAILED" } else { "VERIFIED" },
            "execution": if execution.is_none() { "NOT_PRESENT" } else if errors.iter().any(|error| error.contains("EXECUTION") || error.contains("OUTCOME") || error.contains("EXECUTOR")) { "FAILED" } else { "VERIFIED" },
        },
        "errors": errors,
    }))
}
