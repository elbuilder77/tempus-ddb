# Tempus DDB Backup, Restore, and Disaster Recovery Guide

> **Target Release Line:** `v0.5.0` (Durable Local Operations)  
> **Status:** Operational Specification & Architecture Guide

This document defines standard operating procedures for backing up, restoring, reconciling, and auditing Tempus DDB deployments, with explicit focus on **detecting rollback or deletion** using external signed checkpoints and append-only receipt streams.

---

## 1. Threat Model Context & Invariants

In single-instance SQLite deployments:
- **SQLite is mutable storage:** An attacker with root/filesystem access could delete `tempus.db` or roll back the database file to an earlier timestamp.
- **The Core Invariant:**
  > No valid Tempus permit, no external effect; every external effect produces a verifiable receipt.
- **The v0.5 Durability Invariant:**
  > Any rollback or deletion of past execution receipts must be deterministically detectable by comparing local ledger state against independently stored, signed checkpoint receipts.

---

## 2. Stable Contracts for Durability

### A. Append-Only Event Stream Event (`tempus.event-stream-event.v1`)

```json
{
  "schema_version": "tempus.event-stream-event.v1",
  "tenant_id": "acme",
  "sequence_number": 1,
  "event_id": "act_cli_chk_1",
  "event_type": "ACTION_AUTHORIZED",
  "payload_hash": "a1b2...c3d",
  "prev_event_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp": 1787040012000000,
  "event_digest": "fa08...44e"
}
```

### B. Signed Monotonic Checkpoint (`tempus.checkpoint.v1`)

```json
{
  "schema_version": "tempus.checkpoint.v1",
  "checkpoint_id": "chk_acme_1_1787040060000000",
  "tenant_id": "acme",
  "checkpoint_sequence": 1,
  "first_sequence": 1,
  "last_sequence": 1042,
  "stream_root_hash": "99ee...00f",
  "total_events": 1042,
  "created_at": 1787040060000000,
  "signer": {
    "public_key": "ed25519-gate-public-key-hex",
    "signer_uri": "vault://tempus-gate-key",
    "key_version": 1,
    "algorithm": "Ed25519"
  },
  "signature": "signature-hex"
}
```

---

## 3. Operational Backup Procedure

### Step 1: Safe Hot Backup via SQLite Online Backup API

Never use raw `cp` while the database is actively receiving write transactions. Use SQLite's online backup or `.backup` command to produce a point-in-time snapshot with write-ahead logging (WAL) consistency:

```bash
sqlite3 tempus.db ".backup 'tempus.backup-$(date +%Y%m%d%H%M%S).db'"
```

Or programmatically in Python:
```python
import sqlite3
import time

def backup_database(source_db_path: str, target_db_path: str):
    with sqlite3.connect(source_db_path) as src, sqlite3.connect(target_db_path) as dst:
        src.backup(dst, pages=100, sleep=0.01)
```

### Step 2: Generate Signed Checkpoint & Export Event Stream

Generate a cryptographically signed monotonic checkpoint and export the hash-linked event stream:

```bash
# 1. Create a signed checkpoint for the tenant
tempus checkpoint create --tenant-id acme --out /tmp/checkpoint-acme-latest.json

# 2. Export the incremental event stream
tempus checkpoint export --tenant-id acme --from-seq 1 --out /tmp/event-stream-acme.json

# 3. Publish to WORM / cold storage
aws s3 cp /tmp/checkpoint-acme-latest.json s3://acme-tempus-audit-checkpoints/$(date +%Y%m%d)/
aws s3 cp /tmp/event-stream-acme.json s3://acme-tempus-audit-checkpoints/$(date +%Y%m%d)/
```

---

## 4. Restore & Reconciliation Procedure

When restoring a database following hardware failure or disaster recovery:

1. **Restore base snapshot:**
   ```bash
   cp /backups/tempus.backup-latest.db ./tempus.db
   ```

2. **Verify Cryptographic Integrity:**
   Ensure no records have been corrupted:
   ```bash
   tempus doctor --json
   tempus conformance --signer
   ```

3. **Reconcile Against Independent Checkpoints (`tempus checkpoint verify`):**
   Cryptographically verify the restored database event stream against the external checkpoint retrieved from WORM storage:
   ```bash
   tempus checkpoint verify \
     --checkpoint /path/to/checkpoint-acme-latest.json \
     --stream /path/to/event-stream-acme.json
   ```
   The verifier enforces:
   - **Gate Signature Authenticity:** Validates Ed25519 signature of the checkpoint root hash.
   - **Monotonic Sequence Continuity:** Verifies sequence numbers are strictly incrementing without gaps (`ERR_SEQUENCE_GAP`).
   - **Hash Chain Linkage:** Verifies `prev_event_hash` linkage across all stream items (`ERR_CHAIN_LINKAGE_BROKEN`).
   - **Rollback Prevention:** Detects truncated or truncated stream (`ERR_ROLLBACK_DETECTED`).
   - **Root Hash Conformance:** Detects any payload tampering (`ERR_EVENT_TAMPERED` / `ERR_ROOT_HASH_MISMATCH`).

4. **Verify Active Actor Registrations & Unconsumed Permits:**
   ```bash
   tempus list-agents
   tempus list-policies
   ```

---

## 5. Multi-Process Contention & Recovery Guarantees

1. **Single-Use Permit Consumption:**
   - The executor database and gate use SQLite WAL mode with `busy_timeout = 5000` ms.
   - All state transitions (`STARTED` -> `SUCCEEDED` / `FAILED` / `UNKNOWN`) execute inside immediate transactions.
2. **Ambiguous Crash Recovery:**
   - If an executor crashes while executing an external call, its observation remains in `STARTED` or `UNKNOWN`.
   - On restart recovery, Tempus marks the state `UNKNOWN` and **never automatically retries** an external effect.

