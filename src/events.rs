use crate::b2a::sha256_hex;
use crate::phase3::{ConfiguredSigner, SignerBackend};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    crate::b2a::canonicalize(value).map(|s| s.into_bytes())
}

pub(crate) const EVENT_STREAM_EVENT_SCHEMA: &str = "tempus.event-stream-event.v1";
pub(crate) const CHECKPOINT_SCHEMA: &str = "tempus.checkpoint.v1";
pub(crate) const CHECKPOINT_VERIFICATION_SCHEMA: &str = "tempus.checkpoint-verification.v1";
pub(crate) const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) fn initialize_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS event_stream (
            sequence_number INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            prev_event_hash TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            event_digest TEXT NOT NULL,
            event_json TEXT NOT NULL,
            PRIMARY KEY (tenant_id, sequence_number),
            UNIQUE (tenant_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_event_stream_seq
            ON event_stream (tenant_id, sequence_number ASC);

        CREATE TABLE IF NOT EXISTS checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            checkpoint_sequence INTEGER NOT NULL,
            first_sequence INTEGER NOT NULL,
            last_sequence INTEGER NOT NULL,
            stream_root_hash TEXT NOT NULL,
            total_events INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            checkpoint_json TEXT NOT NULL,
            UNIQUE (tenant_id, checkpoint_sequence)
        );
        CREATE INDEX IF NOT EXISTS idx_checkpoints_tenant
            ON checkpoints (tenant_id, checkpoint_sequence DESC);",
    )
    .map_err(|e| format!("Failed to initialize EventStream schema: {e}"))
}

/// Monotonically appends an event to the tenant's hash-linked event stream.
pub(crate) fn record_event(
    conn: &Connection,
    tenant_id: &str,
    event_type: &str,
    event_id: &str,
    payload_json: &str,
    timestamp: u64,
) -> Result<Value, String> {
    // 1. Get latest sequence number and event digest for this tenant
    let latest: Option<(u64, String)> = conn
        .query_row(
            "SELECT sequence_number, event_digest FROM event_stream
             WHERE tenant_id = ?1 ORDER BY sequence_number DESC LIMIT 1",
            params![tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("Failed to query latest event stream state: {e}"))?;

    let (next_seq, prev_hash) = match latest {
        Some((seq, digest)) => (seq + 1, digest),
        None => (1, GENESIS_PREV_HASH.to_string()),
    };

    let payload_hash = sha256_hex(payload_json.as_bytes());

    let mut event_body = json!({
        "schema_version": EVENT_STREAM_EVENT_SCHEMA,
        "tenant_id": tenant_id,
        "sequence_number": next_seq,
        "event_id": event_id,
        "event_type": event_type,
        "payload_hash": payload_hash,
        "prev_event_hash": prev_hash,
        "timestamp": timestamp,
    });

    let canonical_bytes = canonical_json_bytes(&event_body)?;
    let event_digest = sha256_hex(&canonical_bytes);

    event_body["event_digest"] = json!(event_digest);
    let event_json_str = event_body.to_string();

    conn.execute(
        "INSERT INTO event_stream (
            sequence_number, tenant_id, event_id, event_type,
            payload_hash, prev_event_hash, timestamp, event_digest, event_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            next_seq,
            tenant_id,
            event_id,
            event_type,
            payload_hash,
            prev_hash,
            timestamp,
            event_digest,
            event_json_str
        ],
    )
    .map_err(|e| format!("Failed to insert event into stream: {e}"))?;

    Ok(event_body)
}

/// Creates and signs a monotonic checkpoint over the tenant's current event stream state.
pub(crate) fn create_checkpoint(
    conn: &Connection,
    signer: &ConfiguredSigner,
    tenant_id: &str,
    created_at: u64,
) -> Result<String, String> {
    // 1. Get current checkpoint sequence
    let latest_chk_seq: Option<u64> = conn
        .query_row(
            "SELECT checkpoint_sequence FROM checkpoints
             WHERE tenant_id = ?1 ORDER BY checkpoint_sequence DESC LIMIT 1",
            params![tenant_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("Failed to query latest checkpoint sequence: {e}"))?;

    let next_chk_seq = latest_chk_seq.unwrap_or(0) + 1;

    // 2. Fetch all events for tenant ordered by sequence
    let mut stmt = conn
        .prepare(
            "SELECT sequence_number, event_digest FROM event_stream
             WHERE tenant_id = ?1 ORDER BY sequence_number ASC",
        )
        .map_err(|e| format!("Failed to prepare event stream query: {e}"))?;

    let event_rows = stmt
        .query_map(params![tenant_id], |row| {
            Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| format!("Failed to query event stream: {e}"))?;

    let mut first_seq = None;
    let mut last_seq = 0;
    let mut total_events = 0;
    let mut cumulative_hasher = Sha256::new();

    for item in event_rows {
        let (seq, digest) = item.map_err(|e| format!("Failed reading event row: {e}"))?;
        if first_seq.is_none() {
            first_seq = Some(seq);
        }
        last_seq = seq;
        total_events += 1;
        cumulative_hasher.update(digest.as_bytes());
    }

    if total_events == 0 {
        return Err(format!(
            "Cannot create checkpoint: No events recorded for tenant '{tenant_id}'"
        ));
    }

    let stream_root_hash = hex::encode(cumulative_hasher.finalize());
    let first_sequence = first_seq.unwrap_or(1);
    let checkpoint_id = format!("chk_{}_{}_{}", tenant_id, next_chk_seq, created_at);

    let checkpoint_envelope = json!({
        "schema_version": CHECKPOINT_SCHEMA,
        "checkpoint_id": checkpoint_id,
        "tenant_id": tenant_id,
        "checkpoint_sequence": next_chk_seq,
        "first_sequence": first_sequence,
        "last_sequence": last_seq,
        "stream_root_hash": stream_root_hash,
        "total_events": total_events,
        "created_at": created_at,
        "signer": signer.identity().to_json(),
    });

    let canonical_bytes = canonical_json_bytes(&checkpoint_envelope)?;
    let signature = signer.sign(&canonical_bytes)?;

    let mut signed_checkpoint = checkpoint_envelope;
    signed_checkpoint["signature"] = json!(signature);

    let checkpoint_json_str = signed_checkpoint.to_string();

    conn.execute(
        "INSERT INTO checkpoints (
            checkpoint_id, tenant_id, checkpoint_sequence,
            first_sequence, last_sequence, stream_root_hash,
            total_events, created_at, checkpoint_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            checkpoint_id,
            tenant_id,
            next_chk_seq,
            first_sequence,
            last_seq,
            stream_root_hash,
            total_events,
            created_at,
            checkpoint_json_str
        ],
    )
    .map_err(|e| format!("Failed to record checkpoint: {e}"))?;

    Ok(checkpoint_json_str)
}

/// Exports an incremental slice of the event stream for a tenant.
pub(crate) fn export_event_stream(
    conn: &Connection,
    tenant_id: &str,
    from_sequence: u64,
    limit: u32,
) -> Result<String, String> {
    let mut stmt = conn
        .prepare(
            "SELECT event_json FROM event_stream
             WHERE tenant_id = ?1 AND sequence_number >= ?2
             ORDER BY sequence_number ASC LIMIT ?3",
        )
        .map_err(|e| format!("Failed to prepare export stream query: {e}"))?;

    let rows = stmt
        .query_map(params![tenant_id, from_sequence, limit], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|e| format!("Failed to query export events: {e}"))?;

    let mut events = Vec::new();
    for row in rows {
        let json_str = row.map_err(|e| format!("Failed reading event json: {e}"))?;
        let parsed: Value = serde_json::from_str(&json_str)
            .map_err(|e| format!("Corrupt event JSON in database: {e}"))?;
        events.push(parsed);
    }

    serde_json::to_string(&events).map_err(|e| format!("Failed to serialize stream: {e}"))
}

/// Verifies a checkpoint against an event stream payload.
pub(crate) fn verify_checkpoint_stream(
    checkpoint_json: &str,
    stream_json: &str,
    expected_public_key: Option<&str>,
) -> Result<String, String> {
    let checkpoint: Value = serde_json::from_str(checkpoint_json)
        .map_err(|e| format!("Invalid checkpoint JSON: {e}"))?;

    let stream: Value =
        serde_json::from_str(stream_json).map_err(|e| format!("Invalid stream JSON: {e}"))?;

    let events = match stream.as_array() {
        Some(arr) => arr,
        None => return Err("Event stream must be a JSON array of events".to_string()),
    };

    let checkpoint_id = checkpoint
        .get("checkpoint_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let tenant_id = match checkpoint.get("tenant_id").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return Err("Checkpoint missing tenant_id".to_string()),
    };

    let chk_seq = checkpoint
        .get("checkpoint_sequence")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let first_seq = checkpoint
        .get("first_sequence")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let last_seq = checkpoint
        .get("last_sequence")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let expected_root_hash = match checkpoint.get("stream_root_hash").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return Err("Checkpoint missing stream_root_hash".to_string()),
    };

    let sig_hex = match checkpoint.get("signature").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Err("Checkpoint missing signature".to_string()),
    };

    // 1. Verify Checkpoint Signature
    let mut unsigned_chk = checkpoint.clone();
    if let Some(obj) = unsigned_chk.as_object_mut() {
        obj.remove("signature");
    }
    let canonical_chk_bytes = canonical_json_bytes(&unsigned_chk)?;

    let signer_obj = checkpoint
        .get("signer")
        .ok_or("Checkpoint missing signer")?;
    let pubkey_hex = signer_obj
        .get("public_key")
        .and_then(|v| v.as_str())
        .ok_or("Checkpoint signer missing public_key")?;

    let Some(expected_pk) = expected_public_key else {
        return Ok(json!({
            "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
            "status": "INVALID",
            "checkpoint_id": checkpoint_id,
            "events_verified": 0,
            "reason_code": "ERR_UNTRUSTED_SIGNER",
            "message": "Expected trusted signer public key must be provided to verify checkpoint"
        })
        .to_string());
    };

    if pubkey_hex != expected_pk {
        return Ok(json!({
            "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
            "status": "INVALID",
            "checkpoint_id": checkpoint_id,
            "events_verified": 0,
            "reason_code": "ERR_UNTRUSTED_SIGNER",
            "message": format!("Checkpoint signer {pubkey_hex} does not match expected trusted key {expected_pk}")
        })
        .to_string());
    }

    let pubkey_bytes =
        hex::decode(pubkey_hex).map_err(|e| format!("Invalid signer public key hex: {e}"))?;
    let verifying_key = VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid public key length")?,
    )
    .map_err(|e| format!("Failed parsing verifying key: {e}"))?;

    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("Invalid signature hex: {e}"))?;
    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length")?,
    );

    if verifying_key
        .verify(&canonical_chk_bytes, &signature)
        .is_err()
    {
        return Ok(json!({
            "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
            "status": "INVALID",
            "checkpoint_id": checkpoint_id,
            "events_verified": 0,
            "reason_code": "ERR_SIGNATURE_INVALID",
            "message": "Checkpoint Gate signature is mathematically invalid"
        })
        .to_string());
    }

    // 2. Validate Event Stream Hash Chain and Contiguity
    if events.is_empty() {
        return Ok(json!({
            "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
            "status": "INVALID",
            "checkpoint_id": checkpoint_id,
            "events_verified": 0,
            "reason_code": "ERR_EMPTY_STREAM",
            "message": "Event stream is empty but checkpoint declares events"
        })
        .to_string());
    }

    let mut expected_seq = first_seq;
    let mut prev_expected_hash = if first_seq == 1 {
        GENESIS_PREV_HASH.to_string()
    } else {
        events[0]
            .get("prev_event_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    let mut cumulative_hasher = Sha256::new();
    let mut verified_count = 0;

    for (idx, event) in events.iter().enumerate() {
        let seq = event
            .get("sequence_number")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let ev_tenant = event
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let prev_hash = event
            .get("prev_event_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let digest = event
            .get("event_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Multi-tenant isolation check
        if ev_tenant != tenant_id {
            return Ok(json!({
                "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
                "status": "INVALID",
                "checkpoint_id": checkpoint_id,
                "events_verified": verified_count,
                "reason_code": "ERR_TENANT_MISMATCH",
                "message": format!("Event at index {idx} belongs to tenant '{ev_tenant}', expected '{tenant_id}'")
            }).to_string());
        }

        // Sequence contiguity check
        if seq != expected_seq {
            return Ok(json!({
                "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
                "status": "INVALID",
                "checkpoint_id": checkpoint_id,
                "events_verified": verified_count,
                "reason_code": "ERR_SEQUENCE_GAP",
                "message": format!("Sequence gap detected at index {idx}: expected {expected_seq}, got {seq}")
            }).to_string());
        }

        // Hash chain linkage check
        if prev_hash != prev_expected_hash {
            return Ok(json!({
                "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
                "status": "INVALID",
                "checkpoint_id": checkpoint_id,
                "events_verified": verified_count,
                "reason_code": "ERR_CHAIN_LINKAGE_BROKEN",
                "message": format!("Hash chain broken at sequence {seq}")
            })
            .to_string());
        }

        // Recompute event digest
        let mut unsigned_ev = event.clone();
        if let Some(obj) = unsigned_ev.as_object_mut() {
            obj.remove("event_digest");
        }
        let canonical_ev_bytes = canonical_json_bytes(&unsigned_ev)?;
        let recomputed_digest = sha256_hex(&canonical_ev_bytes);

        if recomputed_digest != digest {
            return Ok(json!({
                "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
                "status": "INVALID",
                "checkpoint_id": checkpoint_id,
                "events_verified": verified_count,
                "reason_code": "ERR_EVENT_TAMPERED",
                "message": format!("Event payload tampered at sequence {seq}")
            })
            .to_string());
        }

        cumulative_hasher.update(digest.as_bytes());
        prev_expected_hash = digest.to_string();
        expected_seq += 1;
        verified_count += 1;
    }

    if (expected_seq - 1) != last_seq {
        return Ok(json!({
            "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
            "status": "INVALID",
            "checkpoint_id": checkpoint_id,
            "events_verified": verified_count,
            "reason_code": "ERR_ROLLBACK_DETECTED",
            "message": format!("Stream ended at sequence {}, but checkpoint requires {}", expected_seq - 1, last_seq)
        }).to_string());
    }

    let calculated_root_hash = hex::encode(cumulative_hasher.finalize());
    if calculated_root_hash != expected_root_hash {
        return Ok(json!({
            "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
            "status": "INVALID",
            "checkpoint_id": checkpoint_id,
            "events_verified": verified_count,
            "reason_code": "ERR_STREAM_HASH_MISMATCH",
            "message": "Calculated stream root hash does not match checkpoint root hash"
        })
        .to_string());
    }

    Ok(json!({
        "schema_version": CHECKPOINT_VERIFICATION_SCHEMA,
        "status": "VERIFIED",
        "checkpoint_id": checkpoint_id,
        "checkpoint_sequence": chk_seq,
        "tenant_id": tenant_id,
        "events_verified": verified_count,
        "first_sequence": first_seq,
        "last_sequence": last_seq,
        "stream_root_hash": calculated_root_hash,
        "reason_code": "CHECKPOINT_VALID",
        "message": "Event stream and checkpoint root hash verified mathematically"
    })
    .to_string())
}
