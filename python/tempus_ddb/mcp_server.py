import asyncio
import json
import os

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from ._tempus_ddb import TempusDDB, gen_keys

load_dotenv()

# ── Global configuration ──────────────────────────────────────────────
SANDBOX_DIR = os.path.realpath(os.getcwd())
TEMPUS_MODE = os.environ.get("TEMPUS_MODE", "autonomous")
TEMPUS_GATE_KEYFILE = os.environ.get("TEMPUS_GATE_KEYFILE", "keys.json")
TEMPUS_ADMIN_TOOLS = os.environ.get("TEMPUS_ADMIN_TOOLS", "0") == "1"
TEMPUS_LEGACY_TOOLS = os.environ.get("TEMPUS_LEGACY_TOOLS", "0") == "1"
TEMPUS_DESTRUCTIVE_TOOLS = os.environ.get("TEMPUS_DESTRUCTIVE_TOOLS", "0") == "1"
# Development-only compatibility tools that receive private-key file paths from
# the MCP client. Production agents must sign locally and use the signed tools.
TEMPUS_LOCAL_KEYFILE_TOOLS = os.environ.get("TEMPUS_LOCAL_KEYFILE_TOOLS", "0") == "1"

ADMIN_TOOL_NAMES = {
    "tempus_init",
    "tempus_gen_keys",
    "tempus_register_agent",
    "tempus_whoami",
}
LEGACY_TOOL_NAMES = {
    "tempus_record",
    "tempus_record_decision",
    "tempus_validate",
    "tempus_list",
    "tempus_export",
    "tempus_count",
}
DESTRUCTIVE_TOOL_NAMES = {"tempus_cleanup"}
LOCAL_KEYFILE_TOOL_NAMES = {
    "tempus_request_action",
    "tempus_commit_outcome",
}


# ── Path-traversal guard ──────────────────────────────────────────────
def validate_path(path: str) -> str:
    """Resolve *path* and ensure it stays inside SANDBOX_DIR."""
    resolved = os.path.realpath(os.path.join(SANDBOX_DIR, path))
    if ".." in os.path.normpath(path).split(os.sep):
        raise ValueError(f"Path contains disallowed '..': {path}")
    if not resolved.startswith(SANDBOX_DIR + os.sep) and resolved != SANDBOX_DIR:
        raise ValueError(f"Path escapes sandbox: {path}")
    return resolved


# ── Input validation helpers ─────────────────────────────────────
def validate_json_string(value: str, field_name: str) -> None:
    """Ensure *value* is a valid JSON string."""
    try:
        json.loads(value)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"'{field_name}' must be a valid JSON string: {exc}")


# ── MCP server setup ──────────────────────────────────────────────────
app = Server("tempus-ddb-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    tools = [
        Tool(
            name="tempus_request_action_signed",
            description="Verify a locally signed intent and issue a signed, single-use permit.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db": {"type": "string", "description": "Tempus database path"},
                    "intent": {
                        "type": "string",
                        "description": "tempus.action-intent.v1 JSON",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Ed25519 public key of the requesting agent",
                    },
                    "agent_signature": {
                        "type": "string",
                        "description": "Ed25519 signature over the canonical intent",
                    },
                    "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 86400},
                },
                "required": ["db", "intent", "agent_id", "agent_signature"],
            },
        ),
        Tool(
            name="tempus_commit_outcome_signed",
            description="Consume an allowed permit with an executor-signed outcome.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db": {"type": "string", "description": "Tempus database path"},
                    "authorization_id": {"type": "string"},
                    "outcome": {
                        "type": "string",
                        "description": "tempus.action-outcome.v1 JSON including executor_id and executor_signature",
                    },
                },
                "required": ["db", "authorization_id", "outcome"],
            },
        ),
        Tool(
            name="tempus_get_trace",
            description="Return the authorization and execution receipts for an action.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db": {"type": "string"},
                    "action_id": {"type": "string"},
                },
                "required": ["db", "action_id"],
            },
        ),
        Tool(
            name="tempus_verify_trace",
            description="Cryptographically verify an action trace end to end.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db": {"type": "string"},
                    "action_id": {"type": "string"},
                },
                "required": ["db", "action_id"],
            },
        ),
        Tool(
            name="tempus_list_agents",
            description="Read the signed registry of agent identities.",
            inputSchema={
                "type": "object",
                "properties": {"db": {"type": "string"}},
                "required": ["db"],
            },
        ),
        Tool(
            name="tempus_list_policies",
            description="Read active and retired signed deterministic policies.",
            inputSchema={
                "type": "object",
                "properties": {"db": {"type": "string"}},
                "required": ["db"],
            },
        ),
        Tool(
            name="tempus_list_identity_events",
            description="Read signed identity rotation and revocation events.",
            inputSchema={
                "type": "object",
                "properties": {"db": {"type": "string"}},
                "required": ["db"],
            },
        ),
    ]
    if TEMPUS_LOCAL_KEYFILE_TOOLS:
        tools.extend(
            [
                Tool(
                    name="tempus_request_action",
                    description="Development-only: sign an intent from a local agent key file and request a permit.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "db": {
                                "type": "string",
                                "description": "Tempus database path",
                            },
                            "intent": {
                                "type": "string",
                                "description": "tempus.action-intent.v1 JSON",
                            },
                            "agent_keyfile": {
                                "type": "string",
                                "description": "Requesting agent key file",
                            },
                            "ttl_seconds": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 86400,
                            },
                        },
                        "required": ["db", "intent", "agent_keyfile"],
                    },
                ),
                Tool(
                    name="tempus_commit_outcome",
                    description="Development-only: sign an executor outcome from a local key file and append it.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "db": {
                                "type": "string",
                                "description": "Tempus database path",
                            },
                            "authorization_id": {"type": "string"},
                            "outcome": {
                                "type": "string",
                                "description": "tempus.action-outcome.v1 JSON",
                            },
                            "executor_keyfile": {
                                "type": "string",
                                "description": "Executor key file",
                            },
                        },
                        "required": [
                            "db",
                            "authorization_id",
                            "outcome",
                            "executor_keyfile",
                        ],
                    },
                ),
            ]
        )
    if TEMPUS_ADMIN_TOOLS:
        tools.extend(
            [
                Tool(
                    name="tempus_init",
                    description="Initialize the SQLite database schema for Tempus DDB.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "db": {
                                "type": "string",
                                "description": "Database file path",
                            }
                        },
                        "required": ["db"],
                    },
                ),
                Tool(
                    name="tempus_gen_keys",
                    description="Generate a new Ed25519 cryptographic keypair.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "output": {
                                "type": "string",
                                "description": "Key file output path",
                            }
                        },
                        "required": ["output"],
                    },
                ),
                Tool(
                    name="tempus_register_agent",
                    description="Register an agent through a gate-signed immutable delegation event.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "db": {
                                "type": "string",
                                "description": "Database file path",
                            },
                            "public_key": {
                                "type": "string",
                                "description": "Ed25519 public key (64 hex chars)",
                            },
                            "alias": {
                                "type": "string",
                                "description": "Human-readable alias for the agent",
                            },
                            "metadata": {
                                "type": "string",
                                "description": "Optional JSON metadata for the agent",
                            },
                        },
                        "required": ["db", "public_key", "alias"],
                    },
                ),
                Tool(
                    name="tempus_whoami",
                    description="Return the identity (public key and alias) of the current agent based on the keyfile.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "db": {
                                "type": "string",
                                "description": "Database file path",
                            },
                            "keyfile": {
                                "type": "string",
                                "description": "Path to the agent's key file",
                            },
                        },
                        "required": ["db", "keyfile"],
                    },
                ),
            ]
        )
    if TEMPUS_LEGACY_TOOLS:
        for name, description in [
            ("tempus_record_decision", "Legacy direct decision recorder."),
            ("tempus_record", "Legacy alias for direct decision recording."),
        ]:
            tools.append(
                Tool(
                    name=name,
                    description=description,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "db": {"type": "string"},
                            "payload": {"type": "string"},
                            "rules": {"type": "string"},
                            "keyfile": {"type": "string"},
                            "genesis": {"type": "boolean"},
                        },
                        "required": ["db", "payload", "rules", "keyfile"],
                    },
                )
            )
        for name, description in [
            ("tempus_validate", "Validate the legacy decision chain."),
            ("tempus_list", "List legacy decisions."),
            ("tempus_export", "Export legacy decisions."),
            ("tempus_count", "Count legacy decisions."),
        ]:
            tools.append(
                Tool(
                    name=name,
                    description=description,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "db": {"type": "string"},
                            "limit": {"type": "integer"},
                            "offset": {"type": "integer"},
                        },
                        "required": ["db"],
                    },
                )
            )
    if TEMPUS_DESTRUCTIVE_TOOLS:
        tools.append(
            Tool(
                name="tempus_cleanup",
                description="Delete demo database and keys. Disabled by default.",
                inputSchema={"type": "object", "properties": {}, "required": []},
            )
        )
    return tools


def _handle_record(arguments: dict) -> list[TextContent]:
    """Shared implementation for tempus_record and tempus_record_decision."""
    payload = arguments["payload"]
    rules = arguments["rules"]
    validate_json_string(payload, "payload")
    validate_json_string(rules, "rules")

    db = validate_path(arguments["db"])
    keyfile = validate_path(arguments["keyfile"])

    genesis = arguments.get("genesis", False)

    db_instance = TempusDDB(db, keyfile)
    output = db_instance.record(payload, rules, genesis)

    result = {
        "status": "success",
        "message": "Record successful.",
        "output": json.loads(output)
        if isinstance(output, str)
        and (output.strip().startswith("{") or output.strip().startswith("["))
        else output,
    }
    if TEMPUS_MODE == "demo":
        result["mode"] = TEMPUS_MODE
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


def _gate_keyfile() -> str:
    """Return the server-controlled gate key; clients cannot override it."""
    return validate_path(TEMPUS_GATE_KEYFILE)


def _gate_db(arguments: dict) -> TempusDDB:
    db_path = validate_path(arguments.get("db", "tempus.db"))
    return TempusDDB(db_path, _gate_keyfile())


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name in ADMIN_TOOL_NAMES and not TEMPUS_ADMIN_TOOLS:
            raise PermissionError("TEMPUS_ADMIN_TOOL_DISABLED")
        if name in LEGACY_TOOL_NAMES and not TEMPUS_LEGACY_TOOLS:
            raise PermissionError("TEMPUS_LEGACY_TOOL_DISABLED")
        if name in DESTRUCTIVE_TOOL_NAMES and not TEMPUS_DESTRUCTIVE_TOOLS:
            raise PermissionError("TEMPUS_DESTRUCTIVE_TOOL_DISABLED")
        if name in LOCAL_KEYFILE_TOOL_NAMES and not TEMPUS_LOCAL_KEYFILE_TOOLS:
            raise PermissionError("TEMPUS_LOCAL_KEYFILE_TOOL_DISABLED")

        if name == "tempus_request_action_signed":
            intent = arguments["intent"]
            validate_json_string(intent, "intent")
            output = _gate_db(arguments).request_action_signed(
                intent,
                arguments["agent_id"],
                arguments["agent_signature"],
                arguments.get("ttl_seconds", 60),
            )
            return [TextContent(type="text", text=output)]

        elif name == "tempus_commit_outcome_signed":
            outcome = arguments["outcome"]
            validate_json_string(outcome, "outcome")
            output = _gate_db(arguments).commit_outcome_signed(
                arguments["authorization_id"],
                outcome,
            )
            return [TextContent(type="text", text=output)]

        elif name == "tempus_request_action":
            intent = arguments["intent"]
            validate_json_string(intent, "intent")
            agent_keyfile = validate_path(arguments["agent_keyfile"])
            output = _gate_db(arguments).request_action(
                intent,
                agent_keyfile,
                arguments.get("ttl_seconds", 60),
            )
            return [TextContent(type="text", text=output)]

        elif name == "tempus_commit_outcome":
            outcome = arguments["outcome"]
            validate_json_string(outcome, "outcome")
            executor_keyfile = validate_path(arguments["executor_keyfile"])
            output = _gate_db(arguments).commit_outcome(
                arguments["authorization_id"],
                outcome,
                executor_keyfile,
            )
            return [TextContent(type="text", text=output)]

        elif name == "tempus_get_trace":
            output = _gate_db(arguments).get_trace(arguments["action_id"])
            return [TextContent(type="text", text=output)]

        elif name == "tempus_verify_trace":
            output = _gate_db(arguments).verify_trace(arguments["action_id"])
            return [TextContent(type="text", text=output)]

        if name == "tempus_init":
            db_path = validate_path(arguments.get("db", "tempus.db"))
            db = TempusDDB(db_path, _gate_keyfile())
            identity = json.loads(db.whoami())
            if not db.verify_agent(identity["public_key"]):
                db.register_agent(
                    identity["public_key"],
                    "tempus-gate",
                    json.dumps({"can_delegate": True, "role": "gate"}),
                )
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": f"Database initialized: {db_path}",
                            "db_path": db_path,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name == "tempus_gen_keys":
            output_file = validate_path(arguments.get("output", TEMPUS_GATE_KEYFILE))
            output = gen_keys(output_file)
            try:
                output_json = json.loads(output)
                if isinstance(output_json, dict) and "private_key" in output_json:
                    del output_json["private_key"]
            except Exception:
                output_json = output
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": f"Keys generated at {output_file}",
                            "key_file": output_file,
                            "output": output_json,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name in ("tempus_record", "tempus_record_decision"):
            return _handle_record(arguments)

        elif name == "tempus_validate":
            db_path = validate_path(arguments.get("db", "tempus.db"))
            db = TempusDDB(db_path, _gate_keyfile())
            try:
                output = db.validate()
                out_str = str(output).lower()
                if "invalid" in out_str or "mismatch" in out_str or "error" in out_str:
                    raise RuntimeError(f"TEMPUS_LEDGER_INTEGRITY_FAILURE: {output}")
            except Exception as e:
                if "TEMPUS_LEDGER_INTEGRITY_FAILURE" not in str(e):
                    raise RuntimeError(f"TEMPUS_LEDGER_INTEGRITY_FAILURE: {e!s}")
                raise

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": "Validation query completed.",
                            "db_path": db_path,
                            "result": output,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name == "tempus_list":
            db_path = validate_path(arguments.get("db", "tempus.db"))
            limit = arguments.get("limit", 10)
            offset = arguments.get("offset", 0)
            db = TempusDDB(db_path, _gate_keyfile())
            output = db.list(limit=limit, offset=offset)
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": f"Listed {limit} decisions (offset {offset}).",
                            "db_path": db_path,
                            "decisions": json.loads(output)
                            if isinstance(output, str)
                            else output,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name == "tempus_export":
            db_path = validate_path(arguments.get("db", "tempus.db"))
            db = TempusDDB(db_path, _gate_keyfile())
            output = db.export()
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": "Ledger exported successfully.",
                            "db_path": db_path,
                            "decisions": json.loads(output)
                            if isinstance(output, str)
                            else output,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name == "tempus_count":
            db_path = validate_path(arguments.get("db", "tempus.db"))
            db = TempusDDB(db_path, _gate_keyfile())
            count = db.count()
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": f"Total decisions: {count}",
                            "db_path": db_path,
                            "total_decisions": count,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name == "tempus_cleanup":
            db_path = os.path.join(SANDBOX_DIR, "tempus.db")
            keys_path = os.path.join(SANDBOX_DIR, "keys.json")
            removed = []
            for p in [db_path, keys_path]:
                if os.path.exists(p):
                    os.remove(p)
                    removed.append(p)
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": "Cleanup successful.",
                            "removed": removed,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name == "tempus_register_agent":
            db_path = validate_path(arguments.get("db", "tempus.db"))
            public_key = arguments["public_key"]
            alias = arguments["alias"]
            metadata = arguments.get("metadata", "{}")
            db = TempusDDB(db_path, _gate_keyfile())
            output = db.register_agent(public_key, alias, metadata)
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": f"Agent '{alias}' registered.",
                            "db_path": db_path,
                            "result": json.loads(output)
                            if isinstance(output, str)
                            else output,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name == "tempus_list_agents":
            db_path = validate_path(arguments.get("db", "tempus.db"))
            db = TempusDDB(db_path, _gate_keyfile())
            output = db.list_agents()
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": "Agents listed.",
                            "db_path": db_path,
                            "agents": json.loads(output)
                            if isinstance(output, str)
                            else output,
                        },
                        indent=2,
                    ),
                )
            ]

        elif name == "tempus_list_policies":
            output = _gate_db(arguments).list_policies()
            return [TextContent(type="text", text=output)]

        elif name == "tempus_list_identity_events":
            output = _gate_db(arguments).list_identity_events()
            return [TextContent(type="text", text=output)]

        elif name == "tempus_whoami":
            db_path = validate_path(arguments.get("db", "tempus.db"))
            keyfile = validate_path(arguments.get("keyfile", "keys.json"))
            db = TempusDDB(db_path, keyfile)
            output = db.whoami()
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "message": "Agent identity retrieved.",
                            "identity": json.loads(output)
                            if isinstance(output, str)
                            else output,
                        },
                        indent=2,
                    ),
                )
            ]

        else:
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "error",
                            "error": "TEMPUS_UNKNOWN_TOOL",
                            "message": f"Unknown tool: {name}",
                        },
                        indent=2,
                    ),
                )
            ]

    except Exception as e:
        err_msg = str(e)
        error_code = "TEMPUS_EXECUTION_ERROR"
        for token in err_msg.replace(":", " ").split():
            if token.startswith("TEMPUS_"):
                error_code = token
                break

        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "status": "error",
                        "error": error_code,
                        "tool": name,
                        "message": err_msg,
                    },
                    indent=2,
                ),
            )
        ]


async def main():
    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream, write_stream, app.create_initialization_options()
            )
    except KeyboardInterrupt:
        pass


def main_sync():
    """Entry point for the tempus-mcp console script."""
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
