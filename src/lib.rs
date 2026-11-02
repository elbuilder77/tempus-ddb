//! Tempus DDB: a fail-closed authorization gate for autonomous agent actions.
//!
//! An agent signs an *intent*; the gate evaluates a signed tenant policy and issues a
//! single-use, expiring *permit* (`ALLOWED` or `BLOCKED`); a credential-isolated
//! *executor* consumes the permit exactly once and signs the *outcome*; the gate links
//! everything into a dual-signed *receipt* that anyone holding the gate public key can
//! verify offline. Unknown schemas, policies, identities and execution states are
//! refused or denied, never allowed, and with no installed policy every action is denied.
//!
//! This crate is published mainly as the native extension behind the
//! [`tempus-ddb` Python package](https://pypi.org/project/tempus-ddb/) (`tempus_ddb._tempus_ddb`,
//! built with PyO3 and maturin). The Rust API that is useful on its own:
//!
//! - [`verify_receipt`], [`verify_bundle`] and [`verify_checkpoint`]: independent
//!   verification of exported evidence against a pinned gate public key, with no database.
//! - [`generate_keypair`]: Ed25519 key generation in the key-file format the CLI reads.
//! - [`SqliteStorage`]: the gate itself (identities, signed policies, permits, receipts,
//!   event stream and checkpoints) on SQLite.
//!
//! On `wasm32` the crate compiles only the verifier and exposes it to JavaScript
//! (`verify_bundle`, `verify_receipt`, `verify_checkpoint`, `bundle_digest`); that build
//! is the public browser verifier at <https://tempus-protocol.github.io/tempus-ddb/verify.html>.
//!
//! Signed JSON documents are parsed strictly: duplicate object keys are refused, and
//! numbers must be exact (no floats, no integers beyond `i64`/`u64`).
//!
//! Documentation: <https://tempus-protocol.github.io/tempus-ddb/docs.html>. Threat model,
//! compatibility rules and changelog live in the repository:
//! <https://github.com/tempus-protocol/tempus-ddb>.
#![allow(clippy::useless_conversion)] // PyO3 macro expansion on Rust 1.96.

#[cfg(not(target_arch = "wasm32"))]
use pyo3::exceptions::{PyPermissionError, PyRuntimeError};
#[cfg(not(target_arch = "wasm32"))]
use pyo3::prelude::*;

mod b2a;
mod events;
mod phase3;
mod strict_json;

#[cfg(not(target_arch = "wasm32"))]
use phase3::SignerBackend;

// Implementación SQLite (Para Python / Nativo)
#[cfg(not(target_arch = "wasm32"))]
use rusqlite::Connection;

#[cfg(not(target_arch = "wasm32"))]
use serde::Serialize;

#[cfg(not(target_arch = "wasm32"))]
pub struct SqliteStorage {
    conn: Connection,
    keyfile: String,
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

        b2a::initialize_schema(&conn)?;

        Ok(Self {
            conn,
            keyfile,
            cached_signer: std::cell::RefCell::new(None),
        })
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

    /// Verify an action trace against a gate public key pinned by the verifier
    /// (and optionally pinned executor keys). Does not trust the database's
    /// own trusted root.
    pub fn verify_trace_pinned(
        &self,
        action_id: &str,
        gate_public_key: &str,
        executor_public_keys: &[String],
    ) -> Result<String, String> {
        b2a::verify_trace_pinned(self, action_id, gate_public_key, executor_public_keys)
    }

    /// Export a self-contained evidence bundle for one action (see
    /// `tempus.evidence-bundle.v1`). Contains no private key material.
    pub fn export_bundle(
        &self,
        action_id: &str,
        max_stream_events: Option<u64>,
    ) -> Result<String, String> {
        b2a::export_bundle(self, action_id, max_stream_events)
    }

    /// Install and activate a deterministic policy bundle signed by the gate.
    pub fn install_policy(&self, policy_spec: &str) -> Result<String, String> {
        let spec = strict_json::parse_labeled(policy_spec, "policy")?;
        strict_json::reject_inexact_numbers(&spec, "policy")?;
        let signer = self.load_signer()?;
        let bundle = phase3::install_policy(&self.conn, &signer, &spec, b2a::now_micros()?)?;
        b2a::canonicalize(&bundle)
    }

    /// DEVELOPMENT ONLY. Explicitly install a signed policy that allows every action,
    /// resource and executor for every tenant without its own policy. Nothing installs
    /// this implicitly: without it (or a real policy) the gate answers BLOCKED with
    /// `POLICY_NOT_INSTALLED`. Idempotent while a current dev policy is active. A stored
    /// dev policy whose `allowed_currencies` is not a list of exact codes is left in
    /// place and refused on load (`TEMPUS_POLICY_INVALID`); only this call replaces it.
    pub fn install_allow_all_dev_policy(&self) -> Result<String, String> {
        let signer = self.load_signer()?;
        let bundle = phase3::install_allow_all_dev_policy(&self.conn, &signer, b2a::now_micros()?)?;
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

    /// Verify an action trace. With `gate_public_key` the gate key is pinned by
    /// the caller and the database's own trusted root is not used; without it the
    /// result is marked `"independent": false`.
    #[pyo3(signature = (action_id, gate_public_key=None, executor_public_keys=None))]
    fn verify_trace(
        &self,
        action_id: &str,
        gate_public_key: Option<&str>,
        executor_public_keys: Option<Vec<String>>,
    ) -> PyResult<String> {
        match gate_public_key {
            Some(gate) => self.storage.verify_trace_pinned(
                action_id,
                gate,
                &executor_public_keys.unwrap_or_default(),
            ),
            None if executor_public_keys.is_some() => {
                Err("executor_public_keys requires gate_public_key".to_string())
            }
            None => self.storage.verify_trace(action_id),
        }
        .map_err(PyRuntimeError::new_err)
    }

    /// Export one action as a self-contained evidence bundle (JSON string).
    #[pyo3(signature = (action_id, max_stream_events=None))]
    fn export_bundle(&self, action_id: &str, max_stream_events: Option<u64>) -> PyResult<String> {
        self.storage
            .export_bundle(action_id, max_stream_events)
            .map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (policy_spec,))]
    fn install_policy(&self, policy_spec: &str) -> PyResult<String> {
        self.storage
            .install_policy(policy_spec)
            .map_err(PyRuntimeError::new_err)
    }

    /// DEVELOPMENT ONLY: explicitly install an allow-all policy (emits a UserWarning).
    #[pyo3(signature = ())]
    fn install_allow_all_dev_policy(&self, py: Python<'_>) -> PyResult<String> {
        let bundle = self
            .storage
            .install_allow_all_dev_policy()
            .map_err(PyRuntimeError::new_err)?;
        PyErr::warn(
            py,
            &py.get_type::<pyo3::exceptions::PyUserWarning>(),
            c"tempus: allow-all development policy installed; every action is ALLOWED. \
              Do not use in production: install a real policy with install_policy().",
            1,
        )?;
        Ok(bundle)
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

/// Verify a standalone receipt (trace, permit or outcome JSON) with no database,
/// against a gate public key pinned by the verifier.
pub fn verify_receipt(
    receipt_json: &str,
    gate_public_key: &str,
    executor_public_keys: &[String],
) -> Result<String, String> {
    b2a::verify_receipt_pinned(receipt_json, gate_public_key, executor_public_keys)
}

/// Verify an evidence bundle with no database, against a pinned gate public key.
pub fn verify_bundle(
    bundle_json: &str,
    gate_public_key: &str,
    executor_public_keys: &[String],
) -> Result<String, String> {
    b2a::verify_bundle_pinned(bundle_json, gate_public_key, executor_public_keys)
}

/// Verify a checkpoint and its event stream with no database. The signer must
/// equal `expected_public_key`, which the verifier supplies out of band.
pub fn verify_checkpoint(
    checkpoint_json: &str,
    stream_json: &str,
    expected_public_key: &str,
) -> Result<String, String> {
    let expected = expected_public_key.trim().to_ascii_lowercase();
    b2a::decode_public_key(&expected).map_err(|e| format!("gate public key: {e}"))?;
    events::verify_checkpoint_stream(checkpoint_json, stream_json, Some(&expected))
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

/// Verify a standalone receipt (trace, permit or outcome JSON) without a database.
#[cfg(not(target_arch = "wasm32"))]
#[pyfunction]
#[pyo3(name = "verify_receipt", signature = (receipt_json, gate_public_key, executor_public_keys=None))]
#[allow(clippy::useless_conversion)]
pub fn py_verify_receipt(
    receipt_json: &str,
    gate_public_key: &str,
    executor_public_keys: Option<Vec<String>>,
) -> PyResult<String> {
    verify_receipt(
        receipt_json,
        gate_public_key,
        &executor_public_keys.unwrap_or_default(),
    )
    .map_err(PyRuntimeError::new_err)
}

/// Verify an evidence bundle without a database, against a pinned gate key.
#[cfg(not(target_arch = "wasm32"))]
#[pyfunction]
#[pyo3(name = "verify_bundle", signature = (bundle_json, gate_public_key, executor_public_keys=None))]
#[allow(clippy::useless_conversion)]
pub fn py_verify_bundle(
    bundle_json: &str,
    gate_public_key: &str,
    executor_public_keys: Option<Vec<String>>,
) -> PyResult<String> {
    verify_bundle(
        bundle_json,
        gate_public_key,
        &executor_public_keys.unwrap_or_default(),
    )
    .map_err(PyRuntimeError::new_err)
}

/// Verify a checkpoint and event stream without a database, against a pinned key.
#[cfg(not(target_arch = "wasm32"))]
#[pyfunction]
#[pyo3(name = "verify_checkpoint", signature = (checkpoint_json, stream_json, expected_public_key))]
#[allow(clippy::useless_conversion)]
pub fn py_verify_checkpoint(
    checkpoint_json: &str,
    stream_json: &str,
    expected_public_key: &str,
) -> PyResult<String> {
    verify_checkpoint(checkpoint_json, stream_json, expected_public_key)
        .map_err(PyRuntimeError::new_err)
}

/// SHA-256 of the canonical bundle without `verify_url`: the digest a verify link carries.
#[cfg(not(target_arch = "wasm32"))]
#[pyfunction]
#[pyo3(name = "bundle_digest")]
#[allow(clippy::useless_conversion)]
pub fn py_bundle_digest(bundle_json: &str) -> PyResult<String> {
    bundle_digest(bundle_json).map_err(PyRuntimeError::new_err)
}

#[cfg(not(target_arch = "wasm32"))]
#[pymodule]
fn _tempus_ddb(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_verify_receipt, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_bundle, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_checkpoint, m)?)?;
    m.add_function(wrap_pyfunction!(py_bundle_digest, m)?)?;
    m.add_class::<TempusDDB>()?;
    m.add_class::<TempusExecutor>()?;
    m.add_function(wrap_pyfunction!(gen_keys, m)?)?;
    Ok(())
}

/// Digest that identifies an evidence bundle: SHA-256 of its canonical JSON without the
/// unsigned `verify_url` field. It is what `verify_url` carries after `#bundle=`.
pub fn bundle_digest(bundle_json: &str) -> Result<String, String> {
    b2a::bundle_digest_of_json(bundle_json)
}

/// The verifier is what the browser build exposes: no database, no private keys, no
/// network. Every function takes JSON text and returns the verification result as JSON
/// text (`tempus.trace-verification.v1` or `tempus.checkpoint-verification.v1`).
#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    fn executor_keys(executor_public_keys: &str) -> Result<Vec<String>, JsValue> {
        let trimmed = executor_public_keys.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        if trimmed.starts_with('[') {
            return serde_json::from_str::<Vec<String>>(trimmed).map_err(|e| {
                JsValue::from_str(&format!(
                    "executor public keys must be a JSON array of strings: {e}"
                ))
            });
        }
        Ok(trimmed
            .split([',', '\n', ' '])
            .filter(|key| !key.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// Verify a `tempus.evidence-bundle.v1` against the pinned gate public key.
    /// `executor_public_keys` is empty, a JSON array, or a comma-separated list.
    #[wasm_bindgen]
    pub fn verify_bundle(
        bundle_json: &str,
        gate_public_key: &str,
        executor_public_keys: &str,
    ) -> Result<String, JsValue> {
        let executors = executor_keys(executor_public_keys)?;
        crate::verify_bundle(bundle_json, gate_public_key, &executors)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Verify a trace, permit or outcome document against the pinned gate public key.
    #[wasm_bindgen]
    pub fn verify_receipt(
        receipt_json: &str,
        gate_public_key: &str,
        executor_public_keys: &str,
    ) -> Result<String, JsValue> {
        let executors = executor_keys(executor_public_keys)?;
        crate::verify_receipt(receipt_json, gate_public_key, &executors)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Verify a checkpoint and its event stream against the pinned gate public key.
    #[wasm_bindgen]
    pub fn verify_checkpoint(
        checkpoint_json: &str,
        stream_json: &str,
        gate_public_key: &str,
    ) -> Result<String, JsValue> {
        crate::verify_checkpoint(checkpoint_json, stream_json, gate_public_key)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// SHA-256 of the canonical bundle without `verify_url` (what a verify link carries).
    #[wasm_bindgen]
    pub fn bundle_digest(bundle_json: &str) -> Result<String, JsValue> {
        crate::bundle_digest(bundle_json).map_err(|e| JsValue::from_str(&e))
    }

    /// Crate version, so a page can show which verifier it runs.
    #[wasm_bindgen]
    pub fn version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
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
