# Tempus DDB Backup, Restore, and Disaster Recovery Guide

> **Target Release Line:** `v0.5.0` (Durable Local Operations)  
> **Status:** Operational Specification & Architecture Guide

This document defines standard operating procedures for backing up, restoring, reconciling, and auditing Tempus DDB deployments, with explicit focus on **detecting rollback or deletion** using external signed checkpoints and append-only receipt streams.

---

## 1. Threat Model Context & Invariants

In single-instance SQLite deployments:
- **SQLite is mutable storage:** An attacker with root/filesystem access could delete `tempus.db` or roll back the database file to an earlier timestamp.
- **The execution boundary:**
  > An executor must durably consume a valid permit before starting an external effect. A crash can leave the result UNKNOWN; absence of a Gate receipt does not prove absence of an effect.
- **The v0.5 Durability Invariant:**
  > Export the restored Gate's event stream and compare it with the latest independently retained, trusted checkpoint. This establishes coverage through that checkpoint's boundary, not freshness beyond it or completeness of the executor's consumption database.

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

### Step 1: Establish a coordinated recovery boundary

Pause new Gate authorizations, delivery of permits and executor dispatch. Drain
in-flight operations and commit available signed outcomes. If an operation cannot
be resolved, retain its durable STARTED/UNKNOWN observation and list it as an
unresolved item. Keep this barrier in place until the backup set is complete.

An online SQLite backup is consistent for **one database**. Independently backing
up a running Gate and executor does not create a consistent cross-process cut.
For this procedure, quiesce all participating writers. A deployment that cannot
do so needs a separately validated coordination/reconciliation mechanism.

### Step 2: Create checkpoints, then snapshot Gate and every executor

For each tenant, create a checkpoint at the frozen boundary:

```bash
tempus --db /live/tempus.db --keyfile /secure/gate.keys.json checkpoint create \
  --tenant-id acme --out /backup-set/checkpoint-acme.json
```

Record the checkpoint ID, sequence, first/last event sequence, total event count
and trusted signer identity. Repeat for each tenant in the recovery inventory;
`--tenant-id '*'` names the literal global stream, not all tenant streams.

Snapshot both stores using SQLite's online backup API (or `.backup`). Never copy
only an active `.db` file or assemble `.db`, `-wal` and `-shm` files from different
times. The backup API includes committed data visible through WAL:

```python
from pathlib import Path
import sqlite3

def backup_database(source, destination):
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve()
    if destination.exists():
        raise FileExistsError(destination)
    with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as src:
        with sqlite3.connect(destination) as dst:
            src.backup(dst, pages=100, sleep=0.01)

backup_database("/live/tempus.db", "/backup-set/gate.db")
backup_database("/live/executor.db", "/backup-set/executor.db")
# Repeat for EVERY executor database in the deployment inventory.
```

The executor snapshot must include the complete `consumed_permits` table:
authorization/action IDs, STARTED/SUCCEEDED/FAILED/UNKNOWN state, timestamps,
signed observations and completed outcomes. Losing consumed rows can make an
already used permit appear unused. A Gate checkpoint does not protect this table.

### Step 3: Retain an independent, identifiable backup set

Store a protected manifest identifying the Gate and each executor snapshot,
cryptographic file hashes, backup time/cut, tenant/executor/trusted-Gate bindings,
checkpoint IDs/sequences and unresolved operations. Preserve separately protected
signing keys or signer configuration, key-version history and the means to restore
Vault access. Never place private keys in a public audit bundle.

Retain checkpoints and the manifest independently of the database host, with
enforced immutability/retention and an independently tracked latest sequence.
A normal object-storage upload alone does not establish WORM retention. Verify
the retention configuration and complete copies before releasing the barrier.

An archived event JSON may accompany the set as evidence. It is **not** the input
used to prove the restored database's state. Test the snapshots using the fresh
export procedure below; a checkpoint newer than a snapshot must not be silently
replaced with an older checkpoint to make that snapshot pass.

---

## 4. Restore & Reconciliation Procedure

### Step 1: Restore into an isolated recovery directory

Keep Gate issuance, permit delivery and all executor dispatch stopped; keep
downstream credentials unavailable to dispatching processes. Preserve failed
files and logs for investigation. Restore the matched Gate **and every executor**
snapshot into a new empty directory, with no old WAL/SHM sidecars. Verify snapshot
hashes against the independently protected manifest, restore signer access and
confirm tenant/Gate/executor identity bindings. Do not substitute an empty
executor database for a missing one.

Run SQLite `PRAGMA integrity_check` on each restored database. Then run local
configuration and signer checks against the intended Gate explicitly:

```bash
tempus --db /recovery/gate.db --keyfile /secure/gate.keys.json doctor --json
tempus --db /recovery/gate.db --keyfile /secure/gate.keys.json conformance --signer
```

These checks do not prove historical completeness, absence of rollback or the
state of external effects.

### Step 2: Export events FROM THE RESTORED GATE and compare them

Retrieve the latest required checkpoint from independent retained storage.
Confirm its tenant, checkpoint sequence and signer public key against an
independent trusted inventory/key history. The current verifier checks the
signature using the key embedded in the checkpoint; it does not independently
establish that this is your expected Gate or that this is the latest checkpoint.
Never create a replacement checkpoint on the restored database as evidence of
its freshness.

Read `first_sequence` and `total_events` from that trusted checkpoint and use
them for **a new export from `/recovery/gate.db`**:

```bash
tempus --db /recovery/gate.db --keyfile /secure/gate.keys.json checkpoint export \
  --tenant-id acme --from-seq FIRST_SEQUENCE --limit TOTAL_EVENTS \
  --out /recovery/events-exported-from-restored-acme.json

tempus --db /recovery/gate.db --keyfile /secure/gate.keys.json checkpoint verify \
  --checkpoint /independent/checkpoint-acme-latest.json \
  --stream /recovery/events-exported-from-restored-acme.json
```

Replace the uppercase range placeholders with the checkpoint's numeric values.
Do not rely on the export command's default limit of 1000. For large streams,
export consecutive pages and combine them into one ordered JSON array covering
the exact checkpoint range; never fill missing restored events from an archive.

Require VERIFIED, matching tenant/checkpoint ID/sequence, first/last sequence and
`events_verified == total_events`. A missing suffix fails with
`ERR_ROLLBACK_DETECTED`; an empty stream, gaps, altered events or a different root
also fail. Keep the Gate disabled on any discrepancy and recover a sufficiently
current, trusted snapshot before retrying verification.

**`checkpoint verify` compares its two JSON inputs. Supplying `--db` does not make
it compare those inputs to that database. Two compatible external files can pass
while the restored database is stale. The fresh export above is mandatory.**

Passing establishes the restored event stream's coverage **through that
checkpoint**, not that it contains every event up to the failure. If the restored
database has newer events, this range verifies only the covered prefix; retain
and reconcile the tail separately. Passing also does not cross-check all domain
tables against event payload hashes. Inspect affected action traces, policies
and identity history separately. Repeat for every tenant/global stream required
by the recovery inventory.

### Step 3: Reconcile the executor's durable consumption state

Reconcile **every** restored executor against its independent backup manifest,
the Gate's authorizations/receipts, retained signed observations and downstream
records. The Gate's event-stream checkpoint says nothing about the completeness
of executor consumption rows.

| Executor/Gate state | Recovery action |
|---|---|
| Executor SUCCEEDED/FAILED; Gate lacks receipt | Validate the completed signed outcome and commit it to the Gate without calling the external adapter again. |
| Both have completed records | Compare authorization/action/executor IDs and the signed result; retain the consumed row and verify the trace. |
| Executor STARTED after the old worker is fenced | Explicitly run `recover_incomplete` to mark it UNKNOWN, preserve the signed observation and reconcile the downstream effect. No replay. |
| Executor UNKNOWN | Keep the permit consumed. Investigate downstream state; do not invent a successful outcome or retry the action. |
| Gate has a receipt but executor lacks consumption | Treat the executor snapshot as incomplete/stale. Restore trusted consumption state before enabling it. |
| Gate has authorization but neither store has a completed result | Absence of consumption in a possibly stale snapshot is not evidence that the permit was unused. Reconcile retained observations and downstream records. |

Example for an isolated restored executor, after confirming the previous worker
cannot still execute (substitute the trusted IDs from the recovery inventory):

```python
import json
from tempus_ddb import TempusDDB, TempusExecutor

executor = TempusExecutor(
    "/recovery/executor.db", "/secure/executor.keys.json",
    "TRUSTED_GATE_PUBLIC_KEY", "acme",
)
print(executor.recover_incomplete(0))  # STARTED -> UNKNOWN; never invokes an adapter
state = json.loads(executor.get_execution_state("AUTHORIZATION_ID"))
if state["status"] in {"SUCCEEDED", "FAILED"}:
    gate = TempusDDB("/recovery/gate.db", "/secure/gate.keys.json")
    # Only when this matching signed outcome is absent from the Gate:
    receipt = gate.commit_outcome_signed(state["authorization_id"], json.dumps(state["outcome"]))
    print(gate.verify_trace(state["action_id"]))
```

`recover_incomplete` changes restored executor state, so preserve the untouched
snapshot and resulting observations. Recovery is an explicit API call, not an
automatic startup hook. `get_execution_state` needs an authorization ID; build
the reconciliation inventory from both databases and retained evidence, including
unresolved operations in the backup manifest. Do not reconcile only Gate receipts.

If executor state is lost or its completeness cannot be established, keep
execution disabled. This release has no independently checkpointed executor
consumption ledger and no supported automatic reconstruction from Gate events.
Do not delete consumed rows, mark UNKNOWN as unused or simply start with a fresh
executor database. A later controlled cutover must reconcile possible effects
and ensure all possibly outstanding permits are expired or invalidated in a way
enforced by every executor before enabling new work.

### Step 4: Release the recovery barrier only after both stores reconcile

Require successful fresh-export comparisons, expected signer/tenant identities,
verified relevant traces and an accounted-for consumption record for every
possibly dispatched permit. Document unresolved external results and keep them
blocked from replay. Check active policies and identity events against the
trusted inventory, take a new coordinated backup and publish a new checkpoint
only after reconciliation. Do not use that new checkpoint to erase an earlier
recovery discrepancy.

---

## 5. Multi-Process Contention & Recovery Guarantees

1. **Single-Use Permit Consumption:**
   - The executor database and gate use SQLite WAL mode with `busy_timeout = 5000` ms.
   - All state transitions (`STARTED` -> `SUCCEEDED` / `FAILED` / `UNKNOWN`) execute inside immediate transactions.
2. **Ambiguous Crash Recovery:**
   - If an executor crashes while executing an external call, its observation remains in `STARTED` or `UNKNOWN`.
   - After fencing the old worker, explicitly call `recover_incomplete` to mark stale STARTED entries UNKNOWN. Construction/startup alone does not invoke recovery.
   - Recovery preserves consumption and **never automatically retries** an external effect. These guarantees require retention of the executor database; restoring an older copy can remove the very rows that enforce single use.
