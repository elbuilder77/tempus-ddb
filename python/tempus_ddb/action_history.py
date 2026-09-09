"""Discover action IDs without treating recorded fields as verified evidence."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ._tempus_ddb import TempusDDB


def list_actions(db_path, keyfile, *, limit=20, agent=None, resource=None, since=None):
    if not 1 <= limit <= 100:
        raise ValueError("--limit must be between 1 and 100")
    path = Path(db_path).resolve()
    if not path.is_file():
        raise ValueError(
            "Database not found. Run tempus init or tempus quickstart first."
        )
    since_us = None
    if since:
        start = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        since_us = int(start.timestamp() * 1_000_000)
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute(
            "SELECT a.action_id, a.issued_at, a.authorization_json, o.execution_json "
            "FROM action_authorizations a LEFT JOIN action_outcomes o USING(action_id) "
            "WHERE (? IS NULL OR a.agent_id = ?) "
            "AND (? IS NULL OR json_extract(a.authorization_json, '$.intent.resource') = ?) "
            "AND (? IS NULL OR a.issued_at >= ?) "
            "ORDER BY a.issued_at DESC, a.action_id LIMIT ?",
            (agent, agent, resource, resource, since_us, since_us, limit),
        ).fetchall()
    gate = TempusDDB(str(path), keyfile)
    result = []
    for action_id, issued_at, authorization_json, execution_json in rows:
        authorization = json.loads(authorization_json)
        execution = json.loads(execution_json) if execution_json else None
        try:
            verification = json.loads(gate.verify_trace(action_id))
        except Exception:
            verification = {"status": "INVALID"}
        result.append(
            {
                "action_id": action_id,
                "issued_at": datetime.fromtimestamp(
                    issued_at / 1_000_000, timezone.utc
                ).isoformat(),
                "resource": authorization["intent"].get("resource"),
                "agent_id": authorization["intent"]["agent_id"],
                "recorded_decision": authorization["authorization"]["decision"],
                "recorded_outcome": execution["receipt"]["status"]
                if execution
                else "NO_RECEIPT",
                "integrity": verification["status"],
                "verification_phase": verification.get("phase"),
            }
        )
    return result


def run_actions(args):
    rows = list_actions(
        args.db,
        args.keyfile,
        limit=args.limit,
        agent=args.agent,
        resource=args.resource,
        since=args.since,
    )
    if args.json:
        print(
            json.dumps(
                {"schema_version": "tempus.action-history.v1", "actions": rows},
                indent=2,
            )
        )
        return
    if not rows:
        print(
            "No matching actions. Run tempus quickstart for a separate first-action trial."
        )
        return
    for row in rows:
        print(f"{row['action_id']}  {row['issued_at']}\n  {row['resource']}")
        print(
            f"  Recorded authorization: {row['recorded_decision']} | Recorded execution: {row['recorded_outcome']} | Integrity: {row['integrity']}"
        )
        if row["integrity"] == "INVALID":
            print(
                "  Evidence is untrusted. Investigate before relying on these fields."
            )
        elif row["recorded_outcome"] == "NO_RECEIPT":
            print(
                "  No committed receipt; this does not establish whether an external effect occurred. Reconcile executor state."
            )
    print(
        "Inspect an ID with tempus trace / verify-trace using the same --db and --keyfile."
    )
