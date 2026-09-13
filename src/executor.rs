use crate::phase3::{ConfiguredSigner, SignerBackend};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

pub trait ExecutorStorage {
    fn initialize(&self) -> Result<(), String>;
    fn start_consumption(
        &self,
        authorization_id: &str,
        action_id: &str,
        observation: &str,
    ) -> Result<(), String>;
    fn complete_consumption(
        &self,
        authorization_id: &str,
        status: &str,
        outcome: &str,
        observation: &str,
    ) -> Result<(), String>;
    fn mark_unknown(&self, authorization_id: &str, observation: &str) -> Result<(), String>;
    fn get_state(&self, authorization_id: &str) -> Result<Option<ExecutionState>, String>;
    fn list_started_before(&self, cutoff: u64) -> Result<Vec<ExecutionState>, String>;
}

#[derive(Debug, Clone)]
pub struct ExecutionState {
    pub authorization_id: String,
    pub action_id: String,
    pub status: String,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub outcome: Option<String>,
    pub observation: String,
}

#[derive(Clone)]
pub struct SqliteExecutorStorage {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteExecutorStorage {
    pub fn with_pool_size(db_path: &str, max_size: u32) -> Result<Self, String> {
        if max_size == 0 {
            return Err("Executor SQLite pool size must be greater than zero".to_string());
        }

        let manager = SqliteConnectionManager::file(db_path).with_init(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA busy_timeout = 5000;",
            )
        });
        let pool = Pool::builder()
            .max_size(max_size)
            .connection_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
            .build(manager)
            .map_err(|error| format!("Failed to initialize executor SQLite pool: {error}"))?;

        Ok(Self { pool })
    }

    fn get_connection(&self) -> Result<PooledConnection<SqliteConnectionManager>, String> {
        self.pool
            .get()
            .map_err(|error| format!("Failed to acquire executor SQLite connection: {error}"))
    }
}

impl ExecutorStorage for SqliteExecutorStorage {
    fn initialize(&self) -> Result<(), String> {
        let conn = self.get_connection()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS consumed_permits (
                authorization_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                completed_at INTEGER,
                outcome TEXT,
                observation_json TEXT NOT NULL DEFAULT '{}'
             );",
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_consumed_permits_recovery
             ON consumed_permits (status, started_at);",
            [],
        )
        .map_err(|e| e.to_string())?;
        if let Err(error) = conn.execute(
            "ALTER TABLE consumed_permits ADD COLUMN observation_json TEXT NOT NULL DEFAULT '{}'",
            [],
        ) {
            if !error.to_string().contains("duplicate column name") {
                return Err(error.to_string());
            }
        }
        Ok(())
    }

    fn start_consumption(
        &self,
        authorization_id: &str,
        action_id: &str,
        observation: &str,
    ) -> Result<(), String> {
        let mut conn = self.get_connection()?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let now = now_micros()?;

        tx.execute(
            "INSERT INTO consumed_permits
             (authorization_id, action_id, status, started_at, observation_json)
             VALUES (?1, ?2, 'STARTED', ?3, ?4)",
            params![authorization_id, action_id, now, observation],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                "Permit already consumed or action ID re-used".to_string()
            } else {
                e.to_string()
            }
        })?;

        tx.commit().map_err(|e| e.to_string())
    }

    fn complete_consumption(
        &self,
        authorization_id: &str,
        status: &str,
        outcome: &str,
        observation: &str,
    ) -> Result<(), String> {
        let mut conn = self.get_connection()?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let now = now_micros()?;

        let rows = tx
            .execute(
                "UPDATE consumed_permits
                 SET status = ?1, completed_at = ?2, outcome = ?3, observation_json = ?4
                 WHERE authorization_id = ?5 AND status = 'STARTED'",
                params![status, now, outcome, observation, authorization_id],
            )
            .map_err(|e| e.to_string())?;

        if rows == 0 {
            return Err("Consumption not found or already completed".to_string());
        }

        tx.commit().map_err(|e| e.to_string())
    }

    fn mark_unknown(&self, authorization_id: &str, observation: &str) -> Result<(), String> {
        let conn = self.get_connection()?;
        let rows = conn
            .execute(
                "UPDATE consumed_permits
                 SET status = 'UNKNOWN', completed_at = ?1, observation_json = ?2
                 WHERE authorization_id = ?3 AND status = 'STARTED'",
                params![now_micros()?, observation, authorization_id],
            )
            .map_err(|e| e.to_string())?;
        if rows == 0 {
            return Err("Execution is not in STARTED state".to_string());
        }
        Ok(())
    }

    fn get_state(&self, authorization_id: &str) -> Result<Option<ExecutionState>, String> {
        let conn = self.get_connection()?;
        conn.query_row(
            "SELECT authorization_id, action_id, status, started_at, completed_at,
                    outcome, observation_json
             FROM consumed_permits WHERE authorization_id = ?1",
            [authorization_id],
            |row| {
                Ok(ExecutionState {
                    authorization_id: row.get(0)?,
                    action_id: row.get(1)?,
                    status: row.get(2)?,
                    started_at: row.get(3)?,
                    completed_at: row.get(4)?,
                    outcome: row.get(5)?,
                    observation: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    fn list_started_before(&self, cutoff: u64) -> Result<Vec<ExecutionState>, String> {
        let conn = self.get_connection()?;
        let mut statement = conn
            .prepare(
                "SELECT authorization_id, action_id, status, started_at, completed_at,
                        outcome, observation_json
                 FROM consumed_permits
                 WHERE status = 'STARTED' AND started_at <= ?1
                 ORDER BY started_at",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([cutoff], |row| {
                Ok(ExecutionState {
                    authorization_id: row.get(0)?,
                    action_id: row.get(1)?,
                    status: row.get(2)?,
                    started_at: row.get(3)?,
                    completed_at: row.get(4)?,
                    outcome: row.get(5)?,
                    observation: row.get(6)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

fn now_micros() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros() as u64)
        .map_err(|e| format!("System time error: {e}"))
}

pub struct MediatedExecutor {
    storage: Box<dyn ExecutorStorage + Send>,
    signer: ConfiguredSigner,
    trusted_gate_id: String,
    trusted_tenant_id: String,
    gate_db: Option<String>,
}

impl MediatedExecutor {
    pub fn new(
        storage: Box<dyn ExecutorStorage + Send>,
        keyfile: &str,
        trusted_gate_id: &str,
        trusted_tenant_id: &str,
    ) -> Result<Self, String> {
        let signer = ConfiguredSigner::from_path(keyfile)?;
        storage.initialize()?;
        let gate_db = std::env::var("TEMPUS_GATE_DB").ok();
        Ok(Self {
            storage,
            signer,
            trusted_gate_id: trusted_gate_id.to_string(),
            trusted_tenant_id: trusted_tenant_id.to_string(),
            gate_db,
        })
    }

    pub fn with_gate_db(mut self, gate_db: Option<String>) -> Self {
        self.gate_db = gate_db;
        self
    }

    fn executor_id(&self) -> String {
        self.signer.identity().public_key.clone()
    }

    fn sign_observation(
        &self,
        authorization_id: &str,
        action_id: &str,
        status: &str,
        details: Value,
    ) -> Result<String, String> {
        let mut observation = json!({
            "schema_version": "tempus.executor-observation.v1",
            "authorization_id": authorization_id,
            "action_id": action_id,
            "executor_id": self.executor_id(),
            "status": status,
            "observed_at": now_micros()?,
            "details": details,
        });
        let canonical = crate::b2a::canonicalize(&observation)?;
        observation["executor_signature"] = json!(self.signer.sign(canonical.as_bytes())?);
        crate::b2a::canonicalize(&observation)
    }

    pub fn verify_and_consume_permit(&self, permit_json: &str) -> Result<Value, String> {
        let permit: Value = serde_json::from_str(permit_json).map_err(|e| e.to_string())?;

        let schema = permit.get("schema_version").and_then(|v| v.as_str());
        if schema != Some("tempus.authorization-result.v1") {
            return Err("Invalid permit schema".to_string());
        }

        let authorization = permit.get("authorization").ok_or("Missing authorization")?;
        let intent = permit.get("intent").ok_or("Missing intent")?;
        let permit_tenant_id = intent
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing tenant_id in intent")?;
        if permit_tenant_id != self.trusted_tenant_id {
            return Err("Cross-tenant permit rejected".to_string());
        }

        let gate_signature_hex = authorization
            .get("gate_signature")
            .and_then(|v| v.as_str())
            .ok_or("Missing gate_signature")?;
        let gate_id_hex = authorization
            .get("gate_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing gate_id")?;
        if gate_id_hex != self.trusted_gate_id {
            return Err("Untrusted gate ID".to_string());
        }

        let mut pk_bytes = [0u8; 32];
        hex::decode_to_slice(gate_id_hex, &mut pk_bytes).map_err(|e| e.to_string())?;
        let gate_vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| "Invalid gate pk")?;
        let mut sig_bytes = [0u8; 64];
        hex::decode_to_slice(gate_signature_hex, &mut sig_bytes).map_err(|e| e.to_string())?;
        let signature = Signature::from_bytes(&sig_bytes);

        let authorization_id = authorization
            .get("authorization_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing authorization_id")?;
        let mut auth_clone = authorization.clone();
        let auth_object = auth_clone
            .as_object_mut()
            .ok_or("Invalid authorization object")?;
        auth_object.remove("authorization_id");
        auth_object.remove("gate_signature");
        let canonical_auth = crate::b2a::canonicalize(&auth_clone)?;
        let digest_bytes = Sha256::digest(canonical_auth.as_bytes());
        if hex::encode(digest_bytes) != authorization_id {
            return Err("Authorization ID mismatch".to_string());
        }
        let digest = hex::decode(authorization_id).map_err(|e| e.to_string())?;
        gate_vk
            .verify(&digest, &signature)
            .map_err(|_| "Invalid gate signature")?;

        if authorization.get("decision").and_then(|v| v.as_str()) != Some("ALLOWED") {
            return Err("Permit is not ALLOWED".to_string());
        }
        let policy_bundle = permit
            .get("policy_bundle")
            .ok_or("Missing signed policy bundle")?;
        crate::phase3::verify_policy_bundle(policy_bundle, Some(gate_id_hex))
            .map_err(|error| format!("Invalid policy bundle: {error}"))?;
        if authorization.get("policy_version") != policy_bundle.get("policy_version")
            || authorization.get("policy_digest") != policy_bundle.get("policy_digest")
        {
            return Err("Authorization policy binding mismatch".to_string());
        }
        if !crate::phase3::executor_allowed(policy_bundle, &self.executor_id())? {
            return Err("Executor is denied by policy".to_string());
        }

        let canonical_intent = crate::b2a::canonicalize(intent)?;
        let expected_intent_hash = hex::encode(Sha256::digest(canonical_intent.as_bytes()));
        let permit_intent_hash = authorization
            .get("intent_hash")
            .and_then(|v| v.as_str())
            .ok_or("Missing intent_hash in permit")?;
        if expected_intent_hash != permit_intent_hash {
            return Err("Intent hash mismatch".to_string());
        }

        let expires_at = authorization
            .get("expires_at")
            .and_then(|v| v.as_u64())
            .ok_or("Missing expires_at")?;
        if now_micros()? > expires_at {
            return Err("Permit has expired".to_string());
        }
        let issued_at = authorization
            .get("issued_at")
            .and_then(|value| value.as_u64())
            .ok_or("Missing issued_at")?;
        let ttl_seconds = expires_at.saturating_sub(issued_at) / 1_000_000;
        let policy_decision = crate::phase3::evaluate_policy(policy_bundle, intent, ttl_seconds)?;
        if policy_decision.decision != "ALLOWED"
            || authorization.get("evidence_digest").and_then(Value::as_str)
                != Some(policy_decision.evidence_digest.as_str())
            || authorization.get("executor_constraints")
                != Some(&policy_decision.executor_constraints)
        {
            return Err("Policy evidence is not reproducible".to_string());
        }

        if let Some(ref gate_db_path) = self.gate_db {
            let gate_conn = rusqlite::Connection::open_with_flags(
                gate_db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| format!("Failed to open gate DB for revocation check: {e}"))?;

            let is_revoked: bool = gate_conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM revoked_authorizations WHERE authorization_id = ?1)",
                    [authorization_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("Failed to query revoked_authorizations: {e}"))?;
            if is_revoked {
                return Err("TEMPUS_PERMIT_REVOKED: permit has been revoked at gate".to_string());
            }

            let agent_id = authorization
                .get("agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let agent_revoked: bool = gate_conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM identity_lifecycle_events WHERE public_key = ?1 AND event_type = 'REVOKE')",
                    [agent_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("Failed to query identity revocation: {e}"))?;
            if agent_revoked {
                return Err("TEMPUS_PERMIT_REVOKED: agent identity has been revoked".to_string());
            }

            let already_consumed: bool = gate_conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM action_outcomes WHERE authorization_id = ?1)",
                    [authorization_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("Failed to query action_outcomes: {e}"))?;
            if already_consumed {
                return Err("TEMPUS_PERMIT_ALREADY_CONSUMED: permit already has an outcome committed to gate".to_string());
            }
        }

        let action_id = authorization
            .get("action_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing action_id")?;
        let started = self.sign_observation(
            authorization_id,
            action_id,
            "STARTED",
            json!({
                "policy_version": authorization.get("policy_version"),
                "policy_digest": authorization.get("policy_digest"),
            }),
        )?;
        self.storage
            .start_consumption(authorization_id, action_id, &started)?;

        Ok(authorization.clone())
    }

    pub fn complete_execution(
        &self,
        authorization_id: &str,
        action_id: &str,
        status: &str,
        output: Value,
    ) -> Result<String, String> {
        if !matches!(status, "SUCCEEDED" | "FAILED") {
            return Err("Execution status must be SUCCEEDED or FAILED".to_string());
        }
        let state = self
            .storage
            .get_state(authorization_id)?
            .ok_or_else(|| "Consumption not found".to_string())?;
        if state.action_id != action_id || state.status != "STARTED" {
            return Err("Consumption does not match a STARTED action".to_string());
        }

        let mut outcome = json!({
            "schema_version": "tempus.action-outcome.v1",
            "authorization_id": authorization_id,
            "action_id": action_id,
            "status": status,
            "executor_id": self.executor_id(),
            "output": output
        });
        let canonical_outcome = crate::b2a::canonicalize(&outcome)
            .map_err(|e| format!("Failed to canonicalize outcome: {e}"))?;
        outcome["executor_signature"] = json!(self.signer.sign(canonical_outcome.as_bytes())?);

        let final_outcome = crate::b2a::canonicalize(&outcome)
            .map_err(|e| format!("Failed to serialize final outcome: {e}"))?;
        let observation = self.sign_observation(
            authorization_id,
            action_id,
            status,
            json!({"outcome_hash": hex::encode(Sha256::digest(final_outcome.as_bytes()))}),
        )?;
        self.storage.complete_consumption(
            authorization_id,
            status,
            &final_outcome,
            &observation,
        )?;

        Ok(final_outcome)
    }

    pub fn mark_unknown(&self, authorization_id: &str, reason: &str) -> Result<String, String> {
        let state = self
            .storage
            .get_state(authorization_id)?
            .ok_or_else(|| "Consumption not found".to_string())?;
        if state.status != "STARTED" {
            return Err("Execution is not in STARTED state".to_string());
        }
        let observation = self.sign_observation(
            authorization_id,
            &state.action_id,
            "UNKNOWN",
            json!({"reason": reason}),
        )?;
        self.storage.mark_unknown(authorization_id, &observation)?;
        Ok(observation)
    }

    pub fn recover_incomplete(&self, older_than_seconds: u64) -> Result<String, String> {
        let cutoff = now_micros()?.saturating_sub(older_than_seconds.saturating_mul(1_000_000));
        let started = self.storage.list_started_before(cutoff)?;
        let mut recovered = Vec::with_capacity(started.len());
        for state in started {
            let observation = self.sign_observation(
                &state.authorization_id,
                &state.action_id,
                "UNKNOWN",
                json!({"reason": "EXECUTOR_RECOVERY_TIMEOUT"}),
            )?;
            self.storage
                .mark_unknown(&state.authorization_id, &observation)?;
            recovered.push(serde_json::from_str::<Value>(&observation).map_err(|e| e.to_string())?);
        }
        crate::b2a::canonicalize(&Value::Array(recovered))
    }

    pub fn get_execution_state(&self, authorization_id: &str) -> Result<String, String> {
        let state = self
            .storage
            .get_state(authorization_id)?
            .ok_or_else(|| "Consumption not found".to_string())?;
        let observation =
            serde_json::from_str::<Value>(&state.observation).unwrap_or_else(|_| json!({}));
        let outcome = state
            .outcome
            .as_deref()
            .and_then(|value| serde_json::from_str::<Value>(value).ok());
        crate::b2a::canonicalize(&json!({
            "authorization_id": state.authorization_id,
            "action_id": state.action_id,
            "status": state.status,
            "started_at": state.started_at,
            "completed_at": state.completed_at,
            "outcome": outcome,
            "observation": observation,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn executor_pool_allows_exactly_one_concurrent_permit_consumption() {
        const CONTENDERS: usize = 16;

        let temp = tempdir().unwrap();
        let storage = Arc::new(
            SqliteExecutorStorage::with_pool_size(
                temp.path().join("executor.db").to_str().unwrap(),
                4,
            )
            .unwrap(),
        );
        storage.initialize().unwrap();
        let barrier = Arc::new(Barrier::new(CONTENDERS));

        let handles = (0..CONTENDERS)
            .map(|_| {
                let storage = Arc::clone(&storage);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    storage.start_consumption(
                        "shared-authorization",
                        "shared-action",
                        r#"{"status":"STARTED"}"#,
                    )
                })
            })
            .collect::<Vec<_>>();

        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| error == "Permit already consumed or action ID re-used"));

        let state = storage.get_state("shared-authorization").unwrap().unwrap();
        assert_eq!(state.status, "STARTED");
        assert_eq!(state.action_id, "shared-action");
    }

    #[test]
    fn executor_rejects_a_gate_signed_permit_without_policy_bundle() {
        let temp = tempdir().unwrap();
        let executor_key = SigningKey::generate(&mut OsRng);
        let executor_keyfile = temp.path().join("executor.keys.json");
        fs::write(
            &executor_keyfile,
            json!({
                "private_key": hex::encode(executor_key.to_bytes()),
                "public_key": hex::encode(executor_key.verifying_key().to_bytes()),
            })
            .to_string(),
        )
        .unwrap();

        let gate_key = SigningKey::generate(&mut OsRng);
        let gate_id = hex::encode(gate_key.verifying_key().to_bytes());
        let intent = json!({
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "test-tenant",
            "agent_id": "test-agent",
            "idempotency_key": "unknown-policy-001",
            "action_type": "github.create_issue",
            "resource": "acme/widget",
            "requested_at": now_micros().unwrap(),
            "input": {"title": "test"},
        });
        let intent_hash = hex::encode(Sha256::digest(
            crate::b2a::canonicalize(&intent).unwrap().as_bytes(),
        ));
        let mut authorization = json!({
            "schema_version": "tempus.authorization-receipt.v1",
            "action_id": "test-action",
            "tenant_id": "test-tenant",
            "agent_id": "test-agent",
            "intent_hash": intent_hash,
            "decision": "ALLOWED",
            "reason_codes": ["POLICY_ALLOWED"],
            "policy_version": "tempus.unknown-policy.v999",
            "issued_at": now_micros().unwrap(),
            "expires_at": now_micros().unwrap() + 60_000_000,
            "gate_id": gate_id,
        });
        let authorization_id = hex::encode(Sha256::digest(
            crate::b2a::canonicalize(&authorization).unwrap().as_bytes(),
        ));
        let signature = gate_key.sign(&hex::decode(&authorization_id).unwrap());
        authorization["authorization_id"] = json!(authorization_id);
        authorization["gate_signature"] = json!(hex::encode(signature.to_bytes()));
        let permit = crate::b2a::canonicalize(&json!({
            "schema_version": "tempus.authorization-result.v1",
            "authorization": authorization,
            "intent": intent,
            "agent_signature": "",
        }))
        .unwrap();

        let executor = MediatedExecutor::new(
            Box::new(
                SqliteExecutorStorage::with_pool_size(
                    temp.path().join("executor.db").to_str().unwrap(),
                    8,
                )
                .unwrap(),
            ),
            executor_keyfile.to_str().unwrap(),
            &gate_id,
            "test-tenant",
        )
        .unwrap();
        assert_eq!(
            executor.verify_and_consume_permit(&permit).unwrap_err(),
            "Missing signed policy bundle"
        );
    }

    #[test]
    fn executor_checks_gate_db_revocations_and_replays() {
        let temp = tempdir().unwrap();
        let executor_key = SigningKey::generate(&mut OsRng);
        let executor_keyfile = temp.path().join("executor.keys.json");
        fs::write(
            &executor_keyfile,
            json!({
                "private_key": hex::encode(executor_key.to_bytes()),
                "public_key": hex::encode(executor_key.verifying_key().to_bytes()),
            })
            .to_string(),
        )
        .unwrap();

        let gate_key = SigningKey::generate(&mut OsRng);
        let gate_id = hex::encode(gate_key.verifying_key().to_bytes());
        let gate_db_path = temp.path().join("gate.db");

        // Set up gate DB tables
        let gate_conn = rusqlite::Connection::open(&gate_db_path).unwrap();
        gate_conn
            .execute_batch(
                "CREATE TABLE revoked_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    revoked_at INTEGER NOT NULL,
                    reason TEXT,
                    identity_event_id TEXT
                 );
                 CREATE TABLE identity_lifecycle_events (
                    event_id TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    effective_at INTEGER NOT NULL,
                    event_json TEXT NOT NULL
                 );
                 CREATE TABLE action_outcomes (
                    receipt_id TEXT PRIMARY KEY,
                    authorization_id TEXT NOT NULL UNIQUE,
                    action_id TEXT NOT NULL UNIQUE,
                    executor_id TEXT NOT NULL,
                    outcome_hash TEXT NOT NULL,
                    completed_at INTEGER NOT NULL,
                    execution_json TEXT NOT NULL
                 );",
            )
            .unwrap();

        let issued_at = now_micros().unwrap();
        let expires_at = issued_at + 60_000_000;

        // Valid signed policy bundle
        let mut policy_body = json!({
            "schema_version": "tempus.policy-bundle.v1",
            "policy_version": "tempus.identity-gate.v1",
            "tenant_id": "test-tenant",
            "constraints": {
                "allowed_action_types": ["github.create_issue"],
                "allowed_resources": ["*"],
                "allowed_executors": ["*"],
                "max_ttl_seconds": 86400,
                "max_input_bytes": 65536,
                "allowed_currencies": ["*"],
            },
            "issued_at": issued_at,
            "signer": {
                "signer_uri": format!("local-ed25519://{gate_id}"),
                "key_version": "v1",
                "algorithm": "Ed25519",
                "public_key": gate_id,
            }
        });
        let policy_digest = hex::encode(Sha256::digest(
            crate::b2a::canonicalize(&policy_body).unwrap().as_bytes(),
        ));
        let policy_sig = gate_key.sign(&hex::decode(&policy_digest).unwrap());
        policy_body["policy_digest"] = json!(policy_digest);
        policy_body["signature"] = json!(hex::encode(policy_sig.to_bytes()));
        let policy_bundle = policy_body;

        let intent = json!({
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "test-tenant",
            "agent_id": "test-agent",
            "idempotency_key": "revocation-test-001",
            "action_type": "github.create_issue",
            "resource": "acme/widget",
            "requested_at": now_micros().unwrap(),
            "input": {"title": "test issue"},
        });
        let intent_hash = hex::encode(Sha256::digest(
            crate::b2a::canonicalize(&intent).unwrap().as_bytes(),
        ));
        let policy_decision = crate::phase3::evaluate_policy(&policy_bundle, &intent, 60).unwrap();
        let mut authorization = json!({
            "schema_version": "tempus.authorization-receipt.v1",
            "action_id": "test-action-rev",
            "tenant_id": "test-tenant",
            "agent_id": "test-agent",
            "intent_hash": intent_hash,
            "decision": "ALLOWED",
            "reason_codes": ["POLICY_ALLOWED"],
            "policy_version": "tempus.identity-gate.v1",
            "policy_digest": policy_bundle["policy_digest"].as_str().unwrap(),
            "evidence_digest": policy_decision.evidence_digest,
            "executor_constraints": policy_decision.executor_constraints,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "gate_id": gate_id,
        });
        let authorization_id = hex::encode(Sha256::digest(
            crate::b2a::canonicalize(&authorization).unwrap().as_bytes(),
        ));
        let signature = gate_key.sign(&hex::decode(&authorization_id).unwrap());
        authorization["authorization_id"] = json!(authorization_id);
        authorization["gate_signature"] = json!(hex::encode(signature.to_bytes()));

        let permit = crate::b2a::canonicalize(&json!({
            "schema_version": "tempus.authorization-result.v1",
            "authorization": authorization,
            "intent": intent,
            "agent_signature": "",
            "policy_bundle": policy_bundle,
        }))
        .unwrap();

        // Insert into revoked_authorizations
        gate_conn
            .execute(
                "INSERT INTO revoked_authorizations (authorization_id, revoked_at, reason, identity_event_id)
                 VALUES (?1, ?2, 'test revoked', 'evt-1')",
                rusqlite::params![authorization_id, issued_at],
            )
            .unwrap();

        let executor = MediatedExecutor::new(
            Box::new(
                SqliteExecutorStorage::with_pool_size(
                    temp.path().join("executor.db").to_str().unwrap(),
                    8,
                )
                .unwrap(),
            ),
            executor_keyfile.to_str().unwrap(),
            &gate_id,
            "test-tenant",
        )
        .unwrap()
        .with_gate_db(Some(gate_db_path.to_str().unwrap().to_string()));

        let err = executor.verify_and_consume_permit(&permit).unwrap_err();
        assert!(
            err.contains("TEMPUS_PERMIT_REVOKED"),
            "Expected TEMPUS_PERMIT_REVOKED, got: {err}"
        );

        // Test agent identity revocation
        gate_conn
            .execute("DELETE FROM revoked_authorizations", [])
            .unwrap();
        gate_conn
            .execute(
                "INSERT INTO identity_lifecycle_events (event_id, identity_id, public_key, event_type, effective_at, event_json)
                 VALUES ('evt-1', 'test-agent', 'test-agent', 'REVOKE', ?1, '{}')",
                rusqlite::params![issued_at],
            )
            .unwrap();
        let err_agent = executor.verify_and_consume_permit(&permit).unwrap_err();
        assert!(
            err_agent.contains("agent identity has been revoked"),
            "Expected agent revoked error, got: {err_agent}"
        );

        // Test already consumed replay guard
        gate_conn
            .execute("DELETE FROM identity_lifecycle_events", [])
            .unwrap();
        gate_conn
            .execute(
                "INSERT INTO action_outcomes (receipt_id, authorization_id, action_id, executor_id, outcome_hash, completed_at, execution_json)
                 VALUES ('rcpt-1', ?1, 'test-action-rev', 'exec-1', 'hash-1', ?2, '{}')",
                rusqlite::params![authorization_id, issued_at],
            )
            .unwrap();
        let err_consumed = executor.verify_and_consume_permit(&permit).unwrap_err();
        assert!(
            err_consumed.contains("TEMPUS_PERMIT_ALREADY_CONSUMED"),
            "Expected already consumed error, got: {err_consumed}"
        );
    }
}
