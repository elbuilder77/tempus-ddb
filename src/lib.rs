#![allow(clippy::useless_conversion)] // PyO3 macro expansion on Rust 1.96.

#[cfg(not(target_arch = "wasm32"))]
use pyo3::exceptions::{PyPermissionError, PyRuntimeError};
#[cfg(not(target_arch = "wasm32"))]
use pyo3::prelude::*;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(not(target_arch = "wasm32"))]
mod b2a;

#[cfg(not(target_arch = "wasm32"))]
mod phase3;
#[cfg(not(target_arch = "wasm32"))]
use phase3::SignerBackend;

#[cfg(not(target_arch = "wasm32"))]
mod events;

// --- 1. PATRÓN STORAGE LAYER (TRAIT) ---
pub trait StorageLayer {
    fn insert_decision(&mut self, payload: &str, rules: &str, genesis: bool) -> Result<(), String>;
    fn insert_decision_batch(
        &mut self,
        decisions: Vec<(&str, &str)>,
        genesis: bool,
    ) -> Result<(), String>;
    fn get_latest_hash(&self) -> Result<String, String>;
    fn export_ledger(&self) -> Result<String, String>;
    fn list_decisions(&self, limit: u32, offset: u32) -> Result<String, String>;
    fn count_decisions(&self) -> Result<u64, String>;
}

// Experimental WASM support: in-memory stub storage only, not persistent ledger storage.
#[cfg(target_arch = "wasm32")]
pub struct MemoryStorage {
    records: Vec<String>,
    latest_hash: String,
}

#[cfg(target_arch = "wasm32")]
impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            latest_hash: "GENESIS_HASH_MEM".to_string(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl StorageLayer for MemoryStorage {
    fn insert_decision(
        &mut self,
        payload: &str,
        _rules: &str,
        genesis: bool,
    ) -> Result<(), String> {
        self.records.push(payload.to_string());
        if genesis {
            self.latest_hash = "GENESIS_HASH_MEM".to_string();
        } else {
            self.latest_hash = "NEW_HASH_MEM".to_string(); // Simulación de nuevo hash
        }
        Ok(())
    }

    fn insert_decision_batch(
        &mut self,
        decisions: Vec<(&str, &str)>,
        genesis: bool,
    ) -> Result<(), String> {
        let mut is_first = true;
        for (payload, rules) in decisions {
            self.insert_decision(payload, rules, genesis && is_first)?;
            is_first = false;
        }
        Ok(())
    }

    fn get_latest_hash(&self) -> Result<String, String> {
        Ok(self.latest_hash.clone())
    }

    fn export_ledger(&self) -> Result<String, String> {
        // En una implementación real, serializaríamos a JSON usando serde_json
        Ok(format!("[{}]", self.records.join(",")))
    }

    fn list_decisions(&self, limit: u32, offset: u32) -> Result<String, String> {
        let start = offset as usize;
        let end = std::cmp::min(start + limit as usize, self.records.len());
        if start >= self.records.len() {
            return Ok("[]".to_string());
        }
        Ok(format!("[{}]", self.records[start..end].join(",")))
    }

    fn count_decisions(&self) -> Result<u64, String> {
        Ok(self.records.len() as u64)
    }
}

// Implementación SQLite (Para Python / Nativo)
#[cfg(not(target_arch = "wasm32"))]
use rusqlite::Connection;

#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use sha2::{Digest, Sha256};

#[cfg(not(target_arch = "wasm32"))]
use ed25519_dalek::Signer;

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Decision {
    id: String,
    parent_id: String,
    causal_depth: u64,
    actor_id: String,
    timestamp: u64,
    payload: String,
    rules_evaluated: String,
    signature: String,
}

#[cfg(not(target_arch = "wasm32"))]
pub struct SqliteStorage {
    conn: Connection,
    keyfile: String,
    cached_signing_key: std::cell::RefCell<Option<ed25519_dalek::SigningKey>>,
    cached_signer: std::cell::RefCell<Option<phase3::ConfiguredSigner>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl SqliteStorage {
    pub fn new(db_path: String, keyfile: String) -> Result<Self, String> {
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("Failed to open SQLite database '{}': {}", db_path, e))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| e.to_string())?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                parent_id TEXT NOT NULL,
                causal_depth INTEGER NOT NULL,
                actor_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                payload TEXT NOT NULL,
                rules_evaluated TEXT NOT NULL,
                signature TEXT NOT NULL
            );",
            [],
        )
        .map_err(|e| format!("Failed to create decisions table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_parent_id ON decisions (parent_id);",
            [],
        )
        .map_err(|e| format!("Failed to create parent index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_causal_depth ON decisions (causal_depth);",
            [],
        )
        .map_err(|e| format!("Failed to create causal depth index: {}", e))?;

        b2a::initialize_schema(&conn)?;

        Ok(Self {
            conn,
            keyfile,
            cached_signing_key: std::cell::RefCell::new(None),
            cached_signer: std::cell::RefCell::new(None),
        })
    }

    /// Load an Ed25519 signing key from a file path.
    fn load_signing_key_from_path(keyfile: &str) -> Result<ed25519_dalek::SigningKey, String> {
        #[derive(Deserialize)]
        struct KeyPairConfig {
            #[allow(dead_code)]
            public_key: String,
            private_key: String,
        }

        let content = std::fs::read_to_string(keyfile)
            .map_err(|e| format!("Failed to read key file '{}': {}", keyfile, e))?;
        let config: KeyPairConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse key file JSON: {}", e))?;

        let private_key_bytes = hex::decode(&config.private_key)
            .map_err(|e| format!("Invalid private key hex: {}", e))?;
        let private_key_array: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| "Private key must be exactly 32 bytes".to_string())?;

        Ok(ed25519_dalek::SigningKey::from_bytes(&private_key_array))
    }

    /// Return the signing key, loading from disk on first use and caching.
    pub(crate) fn load_signing_key(&self) -> Result<ed25519_dalek::SigningKey, String> {
        if let Some(ref key) = *self.cached_signing_key.borrow() {
            return Ok(key.clone());
        }
        let key = Self::load_signing_key_from_path(&self.keyfile)?;
        *self.cached_signing_key.borrow_mut() = Some(key.clone());
        Ok(key)
    }

    /// Load the configured signing backend. Local key files remain compatible, while
    /// production deployments may point at a non-secret Vault Transit signer config.
    pub(crate) fn load_signer(&self) -> Result<phase3::ConfiguredSigner, String> {
        if let Some(ref signer) = *self.cached_signer.borrow() {
            return Ok(signer.clone());
        }
        let signer = phase3::ConfiguredSigner::from_path(&self.keyfile)?;
        *self.cached_signer.borrow_mut() = Some(signer.clone());
        Ok(signer)
    }

    /// Compute the canonical SHA-256 hash for a decision (matches main.rs logic).
    pub fn calculate_canonical_hash(
        parent_id: &str,
        actor_id: &str,
        timestamp: u64,
        payload: &str,
        rules_evaluated: &str,
    ) -> Result<[u8; 32], String> {
        #[derive(Serialize)]
        struct CanonicalPayload<'a> {
            parent_id: &'a str,
            actor_id: &'a str,
            timestamp: u64,
            payload: serde_json::Value,
            rules_evaluated: serde_json::Value,
        }

        let payload_val: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid payload JSON: {}", e))?;
        let rules_val: serde_json::Value = serde_json::from_str(rules_evaluated)
            .map_err(|e| format!("Invalid rules JSON: {}", e))?;

        let canonical = CanonicalPayload {
            parent_id,
            actor_id,
            timestamp,
            payload: payload_val,
            rules_evaluated: rules_val,
        };

        let canonical_bytes = serde_json::to_vec(&canonical).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        Ok(hasher.finalize().into())
    }

    fn get_last_decision_conn(conn: &rusqlite::Connection) -> Result<Option<Decision>, String> {
        let mut stmt = conn.prepare(
            "SELECT id, parent_id, causal_depth, actor_id, timestamp, payload, rules_evaluated, signature
             FROM decisions
             ORDER BY causal_depth DESC, timestamp DESC
             LIMIT 1"
        ).map_err(|e| format!("Failed to prepare select statement: {}", e))?;

        let mut rows = stmt
            .query([])
            .map_err(|e| format!("Failed to query database: {}", e))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| format!("Error advancing row: {}", e))?
        {
            Ok(Some(Decision {
                id: row.get(0).map_err(|e| e.to_string())?,
                parent_id: row.get(1).map_err(|e| e.to_string())?,
                causal_depth: row.get(2).map_err(|e| e.to_string())?,
                actor_id: row.get(3).map_err(|e| e.to_string())?,
                timestamp: row.get(4).map_err(|e| e.to_string())?,
                payload: row.get(5).map_err(|e| e.to_string())?,
                rules_evaluated: row.get(6).map_err(|e| e.to_string())?,
                signature: row.get(7).map_err(|e| e.to_string())?,
            }))
        } else {
            Ok(None)
        }
    }

    #[allow(dead_code)]
    fn get_last_decision(&self) -> Result<Option<Decision>, String> {
        Self::get_last_decision_conn(&self.conn)
    }

    pub fn validate_ledger(&self) -> Result<String, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, causal_depth, actor_id, timestamp, payload, rules_evaluated, signature
             FROM decisions
             ORDER BY causal_depth ASC, timestamp ASC"
        ).map_err(|e| format!("Failed to prepare select statement: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Decision {
                    id: row.get(0)?,
                    parent_id: row.get(1)?,
                    causal_depth: row.get(2)?,
                    actor_id: row.get(3)?,
                    timestamp: row.get(4)?,
                    payload: row.get(5)?,
                    rules_evaluated: row.get(6)?,
                    signature: row.get(7)?,
                })
            })
            .map_err(|e| format!("Failed to execute query: {}", e))?;

        let mut decisions = Vec::new();
        for r in rows {
            match r {
                Ok(d) => decisions.push(d),
                Err(e) => return Err(format!("Error reading record: {}", e)),
            }
        }

        if decisions.is_empty() {
            return Ok(serde_json::to_string(&serde_json::json!({
                "status": "valid",
                "message": "Database is empty.",
                "total_records": 0
            }))
            .unwrap());
        }

        use std::collections::HashMap;
        let mut decision_map = HashMap::new();
        let mut genesis_count = 0;
        for d in &decisions {
            decision_map.insert(d.id.clone(), d.clone());
            if d.parent_id == "genesis" {
                genesis_count += 1;
            }
        }

        let mut errors = Vec::new();

        if !decisions.is_empty() && genesis_count == 0 {
            errors.push("No genesis decision found in the ledger.".to_string());
        } else if genesis_count > 1 {
            errors.push(format!(
                "Multiple genesis decisions found ({}). Only one is allowed.",
                genesis_count
            ));
        }

        for d in &decisions {
            let computed_hash = match Self::calculate_canonical_hash(
                &d.parent_id,
                &d.actor_id,
                d.timestamp,
                &d.payload,
                &d.rules_evaluated,
            ) {
                Ok(h) => h,
                Err(e) => {
                    errors.push(format!("Decision '{}' hash calculation error: {}", d.id, e));
                    continue;
                }
            };
            let computed_id = hex::encode(computed_hash);
            if computed_id != d.id {
                errors.push(format!(
                    "Decision '{}' has invalid hash. Computed: '{}', Recorded: '{}'",
                    d.id, computed_id, d.id
                ));
                continue;
            }

            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let pub_bytes = match hex::decode(&d.actor_id) {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!("Invalid actor_id: {}", e));
                    continue;
                }
            };
            let pub_array: [u8; 32] = match pub_bytes.try_into() {
                Ok(a) => a,
                Err(_) => {
                    errors.push("Invalid public key size".to_string());
                    continue;
                }
            };
            let verifying_key = match VerifyingKey::from_bytes(&pub_array) {
                Ok(k) => k,
                Err(e) => {
                    errors.push(format!("Invalid public key: {}", e));
                    continue;
                }
            };

            let sig_bytes = match hex::decode(&d.signature) {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!("Invalid signature hex: {}", e));
                    continue;
                }
            };
            let sig_array: [u8; 64] = match sig_bytes.try_into() {
                Ok(a) => a,
                Err(_) => {
                    errors.push("Invalid signature size".to_string());
                    continue;
                }
            };
            let signature = Signature::from_bytes(&sig_array);

            let id_bytes = match hex::decode(&d.id) {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!("Invalid id hex: {}", e));
                    continue;
                }
            };

            if let Err(e) = verifying_key.verify(&id_bytes, &signature) {
                errors.push(format!(
                    "Decision '{}' signature verification failed: {}",
                    d.id, e
                ));
                continue;
            }

            if d.parent_id != "genesis" {
                match decision_map.get(&d.parent_id) {
                    Some(parent) => {
                        if d.causal_depth != parent.causal_depth + 1 {
                            errors.push(format!(
                                "Decision '{}' causal depth mismatch. Expected '{}', found '{}'",
                                d.id,
                                parent.causal_depth + 1,
                                d.causal_depth
                            ));
                        }
                        if d.timestamp < parent.timestamp {
                            errors.push(format!(
                                "Decision '{}' temporal anomaly. Precedes parent '{}'",
                                d.id, d.parent_id
                            ));
                        }
                    }
                    None => {
                        errors.push(format!(
                            "Decision '{}' orphan node. Parent '{}' missing",
                            d.id, d.parent_id
                        ));
                    }
                }
            } else {
                if d.causal_depth != 0 {
                    errors.push(format!(
                        "Genesis decision '{}' must have causal_depth 0",
                        d.id
                    ));
                }
            }
        }

        // Check for unregistered actors (warnings, not errors)
        let mut warnings = Vec::new();
        let mut unique_actors: std::collections::HashSet<String> = std::collections::HashSet::new();
        for d in &decisions {
            unique_actors.insert(d.actor_id.clone());
        }
        for actor in &unique_actors {
            let registered: bool = self
                .conn
                .prepare("SELECT 1 FROM agents WHERE public_key = ?1 LIMIT 1")
                .and_then(|mut s| s.exists([actor]))
                .unwrap_or(false);
            if !registered {
                warnings.push(format!(
                    "Actor '{}' is not registered in the agents table.",
                    actor
                ));
            }
        }

        if errors.is_empty() {
            let mut result = serde_json::json!({
                "status": "valid",
                "message": "All decisions verified successfully.",
                "total_records": decisions.len(),
                "unique_actors": unique_actors.len()
            });
            if !warnings.is_empty() {
                result["warnings"] = serde_json::json!(warnings);
            }
            Ok(serde_json::to_string(&result).unwrap())
        } else {
            let mut result = serde_json::json!({
                "status": "invalid",
                "errors": errors,
                "total_records": decisions.len()
            });
            if !warnings.is_empty() {
                result["warnings"] = serde_json::json!(warnings);
            }
            Err(serde_json::to_string(&result).unwrap())
        }
    }

    /// Register an agent through a signed, immutable delegation event.
    ///
    /// The first registration bootstraps the gate key itself. Every later
    /// registration must be signed by an active agent with delegation rights.
    pub fn register_agent(
        &self,
        public_key: &str,
        alias: &str,
        metadata: &str,
    ) -> Result<String, String> {
        b2a::register_agent(self, public_key, alias, metadata)
    }

    /// Verify that an agent has a valid signed registration and is active.
    pub fn verify_agent(&self, public_key: &str) -> Result<bool, String> {
        b2a::verify_agent(self, public_key)
    }

    /// List registered agents and the validity of their registration receipts.
    pub fn list_agents(&self) -> Result<String, String> {
        b2a::list_agents(self)
    }

    /// Get a single registered agent.
    pub fn get_agent(&self, public_key: &str) -> Result<String, String> {
        b2a::get_agent(self, public_key)
    }

    /// Rotate an identity to a new Ed25519 verification key while retaining its stable ID.
    pub fn rotate_agent(
        &self,
        current_public_key: &str,
        new_public_key: &str,
    ) -> Result<String, String> {
        b2a::rotate_agent(self, current_public_key, new_public_key)
    }

    /// Revoke an active identity key and invalidate its unconsumed permits.
    pub fn revoke_agent(&self, public_key: &str, reason: &str) -> Result<String, String> {
        b2a::revoke_agent(self, public_key, reason)
    }

    /// List signed rotation and revocation events.
    pub fn list_identity_events(&self) -> Result<String, String> {
        b2a::list_identity_events(self)
    }

    /// Ask the Tempus gate for a single-use authorization receipt.
    pub fn request_action(
        &self,
        intent: &str,
        agent_keyfile: &str,
        ttl_seconds: u64,
    ) -> Result<String, String> {
        b2a::request_action(self, intent, agent_keyfile, ttl_seconds)
    }

    /// Lower-level transport-neutral authorization API for signed requests.
    pub fn request_action_signed(
        &self,
        intent: &str,
        agent_id: &str,
        agent_signature: &str,
        ttl_seconds: u64,
    ) -> Result<String, String> {
        b2a::request_action_signed(self, intent, agent_id, agent_signature, ttl_seconds)
    }

    /// Consume an allowed permit exactly once and append the executor outcome.
    pub fn commit_outcome(
        &self,
        authorization_id: &str,
        outcome: &str,
        executor_keyfile: &str,
    ) -> Result<String, String> {
        b2a::commit_outcome(self, authorization_id, outcome, executor_keyfile)
    }

    /// Consume an allowed permit exactly once with an already signed outcome.
    pub fn commit_outcome_signed(
        &self,
        authorization_id: &str,
        outcome: &str,
    ) -> Result<String, String> {
        b2a::commit_outcome_signed(self, authorization_id, outcome)
    }

    /// Return the authorization and optional execution receipt for an action.
    pub fn get_trace(&self, action_id: &str) -> Result<String, String> {
        b2a::get_trace(self, action_id)
    }

    /// Cryptographically verify an action trace end to end.
    pub fn verify_trace(&self, action_id: &str) -> Result<String, String> {
        b2a::verify_trace(self, action_id)
    }

    /// Install and activate a deterministic policy bundle signed by the gate.
    pub fn install_policy(&self, policy_spec: &str) -> Result<String, String> {
        let spec: serde_json::Value = serde_json::from_str(policy_spec)
            .map_err(|e| format!("Policy spec must be valid JSON: {e}"))?;
        let signer = self.load_signer()?;
        let bundle = phase3::install_policy(&self.conn, &signer, &spec, b2a::now_micros()?)?;
        b2a::canonicalize(&bundle)
    }

    /// List active and retired policy bundles.
    pub fn list_policies(&self) -> Result<String, String> {
        phase3::list_policies(&self.conn)
    }

    /// Exercise the configured local or remote signer with an offline-verifiable fixture.
    pub fn signer_conformance(&self) -> Result<String, String> {
        phase3::signer_conformance(&self.load_signer()?)
    }

    pub fn create_checkpoint(&self, tenant_id: &str) -> Result<String, String> {
        let signer = self.load_signer()?;
        let created_at = b2a::now_micros()?;
        events::create_checkpoint(&self.conn, &signer, tenant_id, created_at)
    }

    pub fn export_event_stream(
        &self,
        tenant_id: &str,
        from_sequence: u64,
        limit: u32,
    ) -> Result<String, String> {
        events::export_event_stream(&self.conn, tenant_id, from_sequence, limit)
    }

    pub fn verify_checkpoint_stream(
        &self,
        checkpoint_json: &str,
        stream_json: &str,
        expected_public_key: Option<&str>,
    ) -> Result<String, String> {
        let expected = match expected_public_key {
            Some(pk) => Some(pk.to_string()),
            None => self
                .load_signer()
                .ok()
                .map(|s| s.identity().public_key.clone())
                .or_else(|| {
                    self.conn
                        .query_row(
                            "SELECT public_key FROM trusted_roots WHERE id = 1",
                            [],
                            |r| r.get(0),
                        )
                        .ok()
                }),
        };
        events::verify_checkpoint_stream(checkpoint_json, stream_json, expected.as_deref())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl StorageLayer for SqliteStorage {
    fn insert_decision(&mut self, payload: &str, rules: &str, genesis: bool) -> Result<(), String> {
        // Validate payload and rules are valid JSON
        serde_json::from_str::<serde_json::Value>(payload)
            .map_err(|e| format!("Payload is not valid JSON: {}", e))?;
        serde_json::from_str::<serde_json::Value>(rules)
            .map_err(|e| format!("Rules is not valid JSON: {}", e))?;

        // Load signing key from keyfile
        let signing_key = self.load_signing_key()?;
        let verifying_key = signing_key.verifying_key();
        let actor_id = hex::encode(verifying_key.to_bytes());

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        // Resolve parent_id and causal_depth
        let (parent_id, causal_depth) = match Self::get_last_decision_conn(&tx)? {
            Some(last_d) => {
                if genesis {
                    // Even if there are existing decisions, --genesis forces a new root
                    ("genesis".to_string(), 0u64)
                } else {
                    (last_d.id, last_d.causal_depth + 1)
                }
            }
            None => {
                if genesis {
                    ("genesis".to_string(), 0u64)
                } else {
                    return Err(
                        "Database is empty. Use genesis=true to record the first decision."
                            .to_string(),
                    );
                }
            }
        };

        if parent_id == "genesis" {
            let mut stmt = tx
                .prepare("SELECT 1 FROM decisions WHERE parent_id = 'genesis' LIMIT 1")
                .map_err(|e| format!("Prepare error: {}", e))?;
            let exists = stmt.exists([]).map_err(|e| format!("Query error: {}", e))?;
            if exists {
                return Err("A genesis decision already exists in the database.".to_string());
            }
        }

        // Timestamp in microseconds
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|e| format!("System time error: {}", e))?
            .as_micros() as u64;

        // Compute the deterministic SHA-256 hash
        let hash_bytes =
            Self::calculate_canonical_hash(&parent_id, &actor_id, timestamp, payload, rules)?;
        let id = hex::encode(hash_bytes);

        // Ed25519 signature of the hash
        let signature_struct = signing_key.sign(&hash_bytes);
        let signature = hex::encode(signature_struct.to_bytes());

        // Insert into SQLite
        tx.execute(
            "INSERT INTO decisions (id, parent_id, causal_depth, actor_id, timestamp, payload, rules_evaluated, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                &id,
                &parent_id,
                causal_depth,
                &actor_id,
                timestamp,
                payload,
                rules,
                &signature,
            ),
        ).map_err(|e| format!("Failed to insert decision into SQLite: {}", e))?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        Ok(())
    }

    fn insert_decision_batch(
        &mut self,
        decisions: Vec<(&str, &str)>,
        genesis: bool,
    ) -> Result<(), String> {
        if decisions.is_empty() {
            return Ok(());
        }

        let signing_key = self.load_signing_key()?;
        let verifying_key = signing_key.verifying_key();
        let actor_id = hex::encode(verifying_key.to_bytes());

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        let mut current_parent_id;
        let mut current_causal_depth;

        match Self::get_last_decision_conn(&tx)? {
            Some(last_d) => {
                if genesis {
                    current_parent_id = "genesis".to_string();
                    current_causal_depth = 0u64;
                } else {
                    current_parent_id = last_d.id;
                    current_causal_depth = last_d.causal_depth + 1;
                }
            }
            None => {
                if genesis {
                    current_parent_id = "genesis".to_string();
                    current_causal_depth = 0u64;
                } else {
                    return Err(
                        "Database is empty. Use genesis=true to record the first decision."
                            .to_string(),
                    );
                }
            }
        };

        if current_parent_id == "genesis" {
            let mut stmt = tx
                .prepare("SELECT 1 FROM decisions WHERE parent_id = 'genesis' LIMIT 1")
                .map_err(|e| format!("Prepare error: {}", e))?;
            let exists = stmt.exists([]).map_err(|e| format!("Query error: {}", e))?;
            if exists {
                return Err("A genesis decision already exists in the database.".to_string());
            }
        }

        for (payload, rules) in decisions {
            serde_json::from_str::<serde_json::Value>(payload)
                .map_err(|e| format!("Payload is not valid JSON: {}", e))?;
            serde_json::from_str::<serde_json::Value>(rules)
                .map_err(|e| format!("Rules is not valid JSON: {}", e))?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map_err(|e| format!("System time error: {}", e))?
                .as_micros() as u64;

            let hash_bytes = Self::calculate_canonical_hash(
                &current_parent_id,
                &actor_id,
                timestamp,
                payload,
                rules,
            )?;
            let id = hex::encode(hash_bytes);

            let signature_struct = signing_key.sign(&hash_bytes);
            let signature = hex::encode(signature_struct.to_bytes());

            tx.execute(
                "INSERT INTO decisions (id, parent_id, causal_depth, actor_id, timestamp, payload, rules_evaluated, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    &id,
                    &current_parent_id,
                    current_causal_depth,
                    &actor_id,
                    timestamp,
                    payload,
                    rules,
                    &signature,
                ),
            ).map_err(|e| format!("Failed to insert decision into SQLite: {}", e))?;

            current_parent_id = id;
            current_causal_depth += 1;
        }

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        Ok(())
    }

    fn get_latest_hash(&self) -> Result<String, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM decisions ORDER BY causal_depth DESC, timestamp DESC LIMIT 1")
            .map_err(|e| format!("Failed to prepare select statement: {}", e))?;

        let mut rows = stmt
            .query([])
            .map_err(|e| format!("Failed to query database: {}", e))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| format!("Error advancing row: {}", e))?
        {
            let id: String = row.get(0).unwrap();
            Ok(id)
        } else {
            Ok("GENESIS".to_string())
        }
    }

    fn export_ledger(&self) -> Result<String, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, causal_depth, actor_id, timestamp, payload, rules_evaluated, signature
             FROM decisions
             ORDER BY causal_depth ASC, timestamp ASC"
        ).map_err(|e| format!("Failed to prepare select statement: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Decision {
                    id: row.get(0)?,
                    parent_id: row.get(1)?,
                    causal_depth: row.get(2)?,
                    actor_id: row.get(3)?,
                    timestamp: row.get(4)?,
                    payload: row.get(5)?,
                    rules_evaluated: row.get(6)?,
                    signature: row.get(7)?,
                })
            })
            .map_err(|e| format!("Failed to execute query: {}", e))?;

        let mut decisions = Vec::new();
        for r in rows {
            match r {
                Ok(d) => decisions.push(d),
                Err(e) => return Err(format!("Error reading record: {}", e)),
            }
        }

        serde_json::to_string(&decisions)
            .map_err(|e| format!("Failed to serialize ledger to JSON: {}", e))
    }

    fn list_decisions(&self, limit: u32, offset: u32) -> Result<String, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, causal_depth, actor_id, timestamp, payload, rules_evaluated, signature
             FROM decisions
             ORDER BY causal_depth DESC, timestamp DESC
             LIMIT ?1 OFFSET ?2"
        ).map_err(|e| format!("Failed to prepare select statement: {}", e))?;

        let rows = stmt
            .query_map([limit, offset], |row| {
                Ok(Decision {
                    id: row.get(0)?,
                    parent_id: row.get(1)?,
                    causal_depth: row.get(2)?,
                    actor_id: row.get(3)?,
                    timestamp: row.get(4)?,
                    payload: row.get(5)?,
                    rules_evaluated: row.get(6)?,
                    signature: row.get(7)?,
                })
            })
            .map_err(|e| format!("Failed to execute query: {}", e))?;

        let mut decisions = Vec::new();
        for r in rows {
            match r {
                Ok(d) => decisions.push(d),
                Err(e) => return Err(format!("Error reading record: {}", e)),
            }
        }

        serde_json::to_string(&decisions)
            .map_err(|e| format!("Failed to serialize decisions to JSON: {}", e))
    }

    fn count_decisions(&self) -> Result<u64, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM decisions")
            .map_err(|e| format!("Failed to prepare count statement: {}", e))?;
        let count: u64 = stmt
            .query_row([], |row| row.get(0))
            .map_err(|e| format!("Failed to count decisions: {}", e))?;
        Ok(count)
    }
}
// --- 3. BINDINGS PARA PYTHON (PYO3) ---
#[cfg(not(target_arch = "wasm32"))]
#[pyclass(unsendable)]
pub struct TempusDDB {
    storage: SqliteStorage,
    #[allow(dead_code)]
    keyfile: String,
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::useless_conversion)]
#[pymethods]
impl TempusDDB {
    #[new]
    fn new(db_path: String, keyfile: String) -> PyResult<Self> {
        let storage =
            SqliteStorage::new(db_path, keyfile.clone()).map_err(PyPermissionError::new_err)?;

        if std::path::Path::new(&keyfile).exists() {
            storage.load_signer().map_err(PyPermissionError::new_err)?;
        }

        Ok(TempusDDB { storage, keyfile })
    }

    #[allow(unused_variables)]
    #[pyo3(signature = (payload, rules, genesis=false))]
    fn record(&mut self, payload: &str, rules: &str, genesis: bool) -> PyResult<String> {
        self.storage
            .insert_decision(payload, rules, genesis)
            .map_err(PyPermissionError::new_err)?;

        let result_json = format!(
            r#"{{"status": "success", "action": "recorded", "latest_hash": "{}"}}"#,
            self.storage.get_latest_hash().unwrap_or_default()
        );
        Ok(result_json)
    }

    #[allow(unused_variables)]
    #[pyo3(signature = (decisions, genesis=false))]
    fn record_batch(
        &mut self,
        decisions: Vec<(String, String)>,
        genesis: bool,
    ) -> PyResult<String> {
        let refs: Vec<(&str, &str)> = decisions
            .iter()
            .map(|(p, r)| (p.as_str(), r.as_str()))
            .collect();
        self.storage
            .insert_decision_batch(refs, genesis)
            .map_err(PyPermissionError::new_err)?;

        let result_json = format!(
            r#"{{"status": "success", "action": "recorded_batch", "latest_hash": "{}"}}"#,
            self.storage.get_latest_hash().unwrap_or_default()
        );
        Ok(result_json)
    }

    #[pyo3(signature = ())]
    fn validate(&self) -> PyResult<String> {
        self.storage
            .validate_ledger()
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = ())]
    fn export(&self) -> PyResult<String> {
        self.storage
            .export_ledger()
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (limit=10, offset=0))]
    fn list(&self, limit: u32, offset: u32) -> PyResult<String> {
        self.storage
            .list_decisions(limit, offset)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = ())]
    fn count(&self) -> PyResult<u64> {
        self.storage
            .count_decisions()
            .map_err(PyRuntimeError::new_err)
    }

    // --- Multi-Signer: Agent management ---

    #[pyo3(signature = (public_key, alias, metadata="{}".to_string()))]
    fn register_agent(&self, public_key: &str, alias: &str, metadata: String) -> PyResult<String> {
        self.storage
            .register_agent(public_key, alias, &metadata)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = ())]
    fn list_agents(&self) -> PyResult<String> {
        self.storage.list_agents().map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (public_key,))]
    fn get_agent(&self, public_key: &str) -> PyResult<String> {
        self.storage
            .get_agent(public_key)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (current_public_key, new_public_key))]
    fn rotate_agent(&self, current_public_key: &str, new_public_key: &str) -> PyResult<String> {
        self.storage
            .rotate_agent(current_public_key, new_public_key)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (public_key, reason))]
    fn revoke_agent(&self, public_key: &str, reason: &str) -> PyResult<String> {
        self.storage
            .revoke_agent(public_key, reason)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = ())]
    fn list_identity_events(&self) -> PyResult<String> {
        self.storage
            .list_identity_events()
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (public_key,))]
    fn verify_agent(&self, public_key: &str) -> PyResult<bool> {
        self.storage
            .verify_agent(public_key)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (intent, agent_keyfile, ttl_seconds=60))]
    fn request_action(
        &self,
        intent: &str,
        agent_keyfile: &str,
        ttl_seconds: u64,
    ) -> PyResult<String> {
        self.storage
            .request_action(intent, agent_keyfile, ttl_seconds)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (intent, agent_id, agent_signature, ttl_seconds=60))]
    fn request_action_signed(
        &self,
        intent: &str,
        agent_id: &str,
        agent_signature: &str,
        ttl_seconds: u64,
    ) -> PyResult<String> {
        self.storage
            .request_action_signed(intent, agent_id, agent_signature, ttl_seconds)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (authorization_id, outcome, executor_keyfile))]
    fn commit_outcome(
        &self,
        authorization_id: &str,
        outcome: &str,
        executor_keyfile: &str,
    ) -> PyResult<String> {
        self.storage
            .commit_outcome(authorization_id, outcome, executor_keyfile)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (authorization_id, outcome))]
    fn commit_outcome_signed(&self, authorization_id: &str, outcome: &str) -> PyResult<String> {
        self.storage
            .commit_outcome_signed(authorization_id, outcome)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (action_id,))]
    fn get_trace(&self, action_id: &str) -> PyResult<String> {
        self.storage
            .get_trace(action_id)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (action_id,))]
    fn verify_trace(&self, action_id: &str) -> PyResult<String> {
        self.storage
            .verify_trace(action_id)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (policy_spec,))]
    fn install_policy(&self, policy_spec: &str) -> PyResult<String> {
        self.storage
            .install_policy(policy_spec)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = ())]
    fn list_policies(&self) -> PyResult<String> {
        self.storage
            .list_policies()
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = ())]
    fn signer_conformance(&self) -> PyResult<String> {
        self.storage
            .signer_conformance()
            .map_err(PyRuntimeError::new_err)
    }

    /// Return the public key of the current keyfile ("who am I?").
    #[pyo3(signature = ())]
    fn whoami(&self) -> PyResult<String> {
        let signer = self
            .storage
            .load_signer()
            .map_err(PyRuntimeError::new_err)?;
        use crate::phase3::SignerBackend;
        let identity = signer.identity();
        let public_key = identity.public_key.clone();

        // Try to find the agent alias
        let alias = match self.storage.get_agent(&public_key) {
            Ok(json_str) => serde_json::from_str::<serde_json::Value>(&json_str)
                .ok()
                .and_then(|v| v["alias"].as_str().map(|s| s.to_string()))
                .unwrap_or_default(),
            Err(_) => String::new(),
        };

        Ok(serde_json::to_string(&serde_json::json!({
            "public_key": public_key,
            "alias": alias,
            "keyfile": self.keyfile,
            "signer_uri": identity.signer_uri,
            "key_version": identity.key_version,
            "algorithm": identity.algorithm,
        }))
        .unwrap())
    }

    #[pyo3(signature = (tenant_id="*".to_string()))]
    fn create_checkpoint(&self, tenant_id: String) -> PyResult<String> {
        self.storage
            .create_checkpoint(&tenant_id)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (tenant_id="*".to_string(), from_sequence=1, limit=1000))]
    fn export_event_stream(
        &self,
        tenant_id: String,
        from_sequence: u64,
        limit: u32,
    ) -> PyResult<String> {
        self.storage
            .export_event_stream(&tenant_id, from_sequence, limit)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (checkpoint_json, stream_json, expected_public_key=None))]
    fn verify_checkpoint_stream(
        &self,
        checkpoint_json: &str,
        stream_json: &str,
        expected_public_key: Option<&str>,
    ) -> PyResult<String> {
        self.storage
            .verify_checkpoint_stream(checkpoint_json, stream_json, expected_public_key)
            .map_err(PyRuntimeError::new_err)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_keypair(output: &str) -> Result<String, String> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::fs::File;
    use std::io::Write;

    #[derive(Serialize)]
    struct KeyPairConfig {
        public_key: String,
        private_key: String,
    }

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let config = KeyPairConfig {
        public_key: hex::encode(verifying_key.to_bytes()),
        private_key: hex::encode(signing_key.to_bytes()),
    };

    let json_str =
        serde_json::to_string_pretty(&config).map_err(|e| format!("Serialization error: {}", e))?;

    let mut file =
        File::create(output).map_err(|e| format!("Error creating key file {}: {}", output, e))?;

    file.write_all(json_str.as_bytes())
        .map_err(|e| format!("Error writing key file {}: {}", output, e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(output, perms) {
            eprintln!("Warning: Could not set key file permissions: {}", e);
        }
    }

    Ok(json_str)
}

#[cfg(not(target_arch = "wasm32"))]
#[pyfunction]
#[allow(clippy::useless_conversion)]
pub fn gen_keys(output: String) -> PyResult<String> {
    generate_keypair(&output).map_err(PyRuntimeError::new_err)
}

#[cfg(not(target_arch = "wasm32"))]
#[pymodule]
fn _tempus_ddb(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TempusDDB>()?;
    m.add_class::<TempusExecutor>()?;
    m.add_function(wrap_pyfunction!(gen_keys, m)?)?;
    Ok(())
}

// --- 4. BINDINGS PARA JAVASCRIPT (WASM-BINDGEN) ---
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct TempusDDBWasm {
    storage: MemoryStorage,
    keyfile: String,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl TempusDDBWasm {
    #[wasm_bindgen(constructor)]
    pub fn new(keyfile: String) -> Result<TempusDDBWasm, JsValue> {
        let storage = MemoryStorage::new();
        Ok(TempusDDBWasm { storage, keyfile })
    }

    #[wasm_bindgen]
    pub fn record(&mut self, payload: &str, rules: &str, genesis: bool) -> Result<String, JsValue> {
        self.storage
            .insert_decision(payload, rules, genesis)
            .map_err(|e| JsValue::from_str(&e))?;

        let result_json = format!(
            r#"{{"status": "success", "action": "recorded", "latest_hash": "{}"}}"#,
            self.storage.get_latest_hash().unwrap_or_default()
        );
        Ok(result_json)
    }

    #[wasm_bindgen]
    pub fn get_ledger(&self) -> Result<String, JsValue> {
        self.storage
            .export_ledger()
            .map_err(|e| JsValue::from_str(&e))
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod executor;

#[cfg(not(target_arch = "wasm32"))]
use executor::{MediatedExecutor, SqliteExecutorStorage};

#[cfg(not(target_arch = "wasm32"))]
#[pyclass(unsendable)]
pub struct TempusExecutor {
    inner: MediatedExecutor,
}

#[cfg(not(target_arch = "wasm32"))]
#[pymethods]
impl TempusExecutor {
    #[new]
    #[pyo3(signature = (db_path, keyfile, trusted_gate_id, trusted_tenant_id, pool_size=8, gate_db=None))]
    pub fn new(
        db_path: String,
        keyfile: String,
        trusted_gate_id: String,
        trusted_tenant_id: String,
        pool_size: u32,
        gate_db: Option<String>,
    ) -> PyResult<Self> {
        let storage = SqliteExecutorStorage::with_pool_size(&db_path, pool_size)
            .map_err(PyRuntimeError::new_err)?;
        let gate_db_final = gate_db.or_else(|| std::env::var("TEMPUS_GATE_DB").ok());
        let mut inner = MediatedExecutor::new(
            Box::new(storage),
            &keyfile,
            &trusted_gate_id,
            &trusted_tenant_id,
        )
        .map_err(PyRuntimeError::new_err)?;
        inner = inner.with_gate_db(gate_db_final);
        Ok(Self { inner })
    }

    pub fn verify_and_consume_permit(&self, permit_json: String) -> PyResult<String> {
        let auth = self
            .inner
            .verify_and_consume_permit(&permit_json)
            .map_err(PyPermissionError::new_err)?;
        Ok(serde_json::to_string(&auth).unwrap())
    }

    pub fn complete_execution(
        &self,
        authorization_id: String,
        action_id: String,
        status: String,
        output_json: String,
    ) -> PyResult<String> {
        let output: serde_json::Value = serde_json::from_str(&output_json)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid output JSON: {}", e)))?;

        let outcome = self
            .inner
            .complete_execution(&authorization_id, &action_id, &status, output)
            .map_err(PyRuntimeError::new_err)?;

        Ok(outcome)
    }

    pub fn mark_unknown(&self, authorization_id: String, reason: String) -> PyResult<String> {
        self.inner
            .mark_unknown(&authorization_id, &reason)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (older_than_seconds=0))]
    pub fn recover_incomplete(&self, older_than_seconds: u64) -> PyResult<String> {
        self.inner
            .recover_incomplete(older_than_seconds)
            .map_err(PyRuntimeError::new_err)
    }

    pub fn get_execution_state(&self, authorization_id: String) -> PyResult<String> {
        self.inner
            .get_execution_state(&authorization_id)
            .map_err(PyRuntimeError::new_err)
    }
}
