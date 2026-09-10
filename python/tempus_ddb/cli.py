import argparse
import json
import os
import shutil
import stat
import sys
import time

from . import __version__
from ._tempus_ddb import TempusDDB, gen_keys
from .mcp_server import main_sync

# --- Default paths (used when global args are not provided) ---
DEFAULT_KEYFILE = "keys.json"
DEFAULT_DB = "tempus.db"


def _resolve_paths(args):
    """Extract db and keyfile paths from global args, falling back to defaults."""
    db = getattr(args, "db", None) or DEFAULT_DB
    keyfile = getattr(args, "keyfile", None) or DEFAULT_KEYFILE
    return db, keyfile


def _load_json_argument(value, label):
    """Load a JSON object from a literal string or a file path."""
    if os.path.isfile(value):
        with open(value, encoding="utf-8") as handle:
            value = handle.read().strip()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"--{label} must be valid JSON or a path to a JSON file: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"--{label} must contain a JSON object")
    return json.dumps(parsed, separators=(",", ":"), sort_keys=True)


def run_init(args):
    db_path, keyfile = _resolve_paths(args)

    if os.path.exists(keyfile):
        print(f"[{keyfile}] already exists — skipping key generation.")
    else:
        try:
            gen_keys(keyfile)
            print(f"✓ Generated new Ed25519 keys → {keyfile}")
        except Exception as e:
            print(f"✗ Failed to generate keys: {e}", file=sys.stderr)
            sys.exit(1)

    if os.path.exists(db_path):
        print(f"[{db_path}] already exists — verifying schema...")
    else:
        print(f"Initializing new ledger at {db_path}...")

    try:
        db = TempusDDB(db_path, keyfile)
        identity = json.loads(db.whoami())
        gate_id = identity["public_key"]
        if not db.verify_agent(gate_id):
            db.register_agent(
                gate_id,
                "tempus-gate",
                json.dumps({"can_delegate": True, "role": "gate"}),
            )
        print("✓ Tempus DDB ready.")
        print(f"  Keys:  {keyfile}")
        print(f"  DB:    {db_path}")
    except Exception as e:
        print(f"✗ Failed to initialize database: {e}", file=sys.stderr)
        sys.exit(1)


def run_keygen(args):
    """Generate a workload keypair for an agent, executor, or gate."""
    if os.path.exists(args.output):
        print(
            f"✗ Refusing to overwrite existing key file: {args.output}", file=sys.stderr
        )
        sys.exit(1)
    try:
        result = json.loads(gen_keys(args.output))
        result.pop("private_key", None)
        print(
            json.dumps(
                {
                    "schema_version": "tempus.identity-key.v1",
                    "keyfile": args.output,
                    "public_key": result["public_key"],
                },
                indent=2,
            )
        )
    except Exception as exc:
        print(f"✗ Key generation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_verify(args):
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(db_path):
        print("✗ No database found. Run 'tempus init' first.", file=sys.stderr)
        sys.exit(1)

    try:
        db = TempusDDB(db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE)
        result = db.validate()
        result_str = str(result).lower()
        if "invalid" in result_str or "error" in result_str or "mismatch" in result_str:
            print("✗ Ledger validation FAILED")
            print(result)
            sys.exit(1)
        else:
            print("✓ Ledger validation successful.")
            print(result)
    except Exception as e:
        print(f"✗ Validation failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_status(args):
    db_path, keyfile = _resolve_paths(args)

    print("Tempus DDB Status")
    print("=================")

    # Keys
    if os.path.exists(keyfile):
        try:
            size = os.path.getsize(keyfile)
            print(f"✓ Keys file: {keyfile} ({size} bytes)")
        except Exception:
            print(f"✓ Keys file: {keyfile}")
    else:
        print("✗ Keys file: not found (run 'tempus init')")

    # Database
    if os.path.exists(db_path):
        try:
            size = os.path.getsize(db_path)
            print(f"✓ Database: {db_path} ({size} bytes)")
        except Exception:
            print(f"✓ Database: {db_path}")

        try:
            db = TempusDDB(
                db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE
            )
            validation = db.validate()
            val_str = str(validation).lower()

            if "invalid" in val_str or "error" in val_str or "mismatch" in val_str:
                print("✗ Chain integrity: INVALID")
                print(f"  Details: {validation}")
            else:
                print("✓ Chain integrity: VALID")

            # Show record count
            try:
                count = db.count()
                print(f"  Total decisions: {count}")
            except Exception as exc:
                print(f"  Total decisions: unavailable ({exc})")

            # Try to show last hash if present in result
            try:
                if isinstance(validation, str):
                    data = json.loads(validation)
                else:
                    data = validation
                if isinstance(data, dict):
                    last_hash = data.get("latest_hash") or data.get("result", {}).get(
                        "latest_hash"
                    )
                    if last_hash:
                        print(f"  Latest hash: {last_hash}")
            except Exception as exc:
                print(f"  Latest hash: unavailable ({exc})")

        except Exception as e:
            print(f"✗ Could not validate database: {e}")
    else:
        print("✗ Database: not found (run 'tempus init' and record at least once)")

    print("\nNext steps if needed:")
    print("  tempus init     # to initialize")
    print("  tempus request-action  # obtain a signed execution permit")


def run_record(args):
    """Direct CLI recording (task D improvement)."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(keyfile):
        print("✗ No keys found. Run 'tempus init' first.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(db_path) and not args.genesis:
        # For non-genesis, db should exist
        print(
            "✗ Database not found. You must create the first (genesis) record first.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        # Load payload
        payload = args.payload
        if os.path.isfile(payload):
            with open(payload, encoding="utf-8") as f:
                payload = f.read().strip()
        try:
            json.loads(payload)
        except json.JSONDecodeError:
            print(
                "✗ --payload must be valid JSON (or path to JSON file)", file=sys.stderr
            )
            sys.exit(1)

        # Load rules
        rules = args.rules
        if os.path.isfile(rules):
            with open(rules, encoding="utf-8") as f:
                rules = f.read().strip()
        try:
            json.loads(rules)
        except json.JSONDecodeError:
            print(
                "✗ --rules must be valid JSON (or path to JSON file)", file=sys.stderr
            )
            sys.exit(1)

        db = TempusDDB(db_path, keyfile)

        # The core auto-links non-genesis records to the latest record.
        result = db.record(payload, rules, genesis=args.genesis)
        print("✓ Decision recorded successfully.")
        print(result)
    except Exception as e:
        err_msg = str(e)
        if "genesis" in err_msg.lower() or "empty" in err_msg.lower():
            print(f"✗ Chaining error: {err_msg}", file=sys.stderr)
            print(
                "  Tip: Use --genesis only for the first record. Later records auto-link to the latest record.",
                file=sys.stderr,
            )
        else:
            print(f"✗ Record failed: {err_msg}", file=sys.stderr)
        sys.exit(1)


def run_export(args):
    """Export the entire ledger as a JSON array."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(db_path):
        print("✗ No database found. Run 'tempus init' first.", file=sys.stderr)
        sys.exit(1)

    try:
        db = TempusDDB(db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE)
        result = db.export()
        print(result)
    except Exception as e:
        print(f"✗ Export failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_list(args):
    """List decisions with pagination."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(db_path):
        print("✗ No database found. Run 'tempus init' first.", file=sys.stderr)
        sys.exit(1)

    try:
        db = TempusDDB(db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE)
        result = db.list(limit=args.limit, offset=args.offset)
        # Pretty-print the JSON output
        try:
            parsed = json.loads(result)
            print(json.dumps(parsed, indent=2))
        except (json.JSONDecodeError, TypeError):
            print(result)
    except Exception as e:
        print(f"✗ List failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_count(args):
    """Count the total number of decisions in the ledger."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(db_path):
        print("✗ No database found. Run 'tempus init' first.", file=sys.stderr)
        sys.exit(1)

    try:
        db = TempusDDB(db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE)
        count = db.count()
        print(json.dumps({"total_decisions": count}))
    except Exception as e:
        print(f"✗ Count failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_register_agent(args):
    """Register an agent in the ledger's identity registry."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(db_path):
        print("✗ No database found. Run 'tempus init' first.", file=sys.stderr)
        sys.exit(1)

    try:
        # If no --public-key provided, extract from keyfile
        public_key = getattr(args, "public_key", None)
        if not public_key:
            agent_keyfile = getattr(args, "agent_keyfile", None) or keyfile
            if not os.path.exists(agent_keyfile):
                print(f"✗ Key file not found: {agent_keyfile}", file=sys.stderr)
                sys.exit(1)
            with open(agent_keyfile, encoding="utf-8") as f:
                key_data = json.load(f)
            public_key = key_data.get("public_key")
            if not public_key:
                print("✗ Key file does not contain 'public_key'.", file=sys.stderr)
                sys.exit(1)

        db = TempusDDB(db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE)
        metadata = getattr(args, "metadata", "{}") or "{}"
        result = db.register_agent(public_key, args.alias, metadata)
        parsed = json.loads(result)
        print(f"✓ Agent '{args.alias}' registered.")
        print(f"  Public key: {parsed.get('public_key', public_key)}")
    except Exception as e:
        print(f"✗ Registration failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_list_agents(args):
    """List all registered agents."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(db_path):
        print("✗ No database found. Run 'tempus init' first.", file=sys.stderr)
        sys.exit(1)

    try:
        db = TempusDDB(db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE)
        result = db.list_agents()
        agents = json.loads(result)
        if not agents:
            print("No agents registered yet. Use 'tempus register-agent' to add one.")
        else:
            print(json.dumps(agents, indent=2))
    except Exception as e:
        print(f"✗ List agents failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_whoami(args):
    """Show the identity of the current keyfile."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(keyfile):
        print(
            f"✗ Key file not found: {keyfile}. Run 'tempus init' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        db = TempusDDB(db_path if os.path.exists(db_path) else ":memory:", keyfile)
        result = db.whoami()
        parsed = json.loads(result)
        print(f"Public Key: {parsed.get('public_key')}")
        alias = parsed.get("alias", "")
        if alias:
            print(f"Alias:      {alias}")
        else:
            print("Alias:      (not registered — use 'tempus register-agent')")
        print(f"Key File:   {parsed.get('keyfile')}")
    except Exception as e:
        print(f"✗ Whoami failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_request_action(args):
    """Request a fail-closed, single-use authorization for an agent action."""
    db_path, gate_keyfile = _resolve_paths(args)
    try:
        intent = _load_json_argument(args.intent, "intent")
        db = TempusDDB(db_path, gate_keyfile)
        result = db.request_action(intent, args.agent_keyfile, args.ttl_seconds)
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"✗ Authorization request failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_commit_outcome(args):
    """Consume an authorization permit with a signed executor outcome."""
    db_path, gate_keyfile = _resolve_paths(args)
    try:
        outcome = _load_json_argument(args.outcome, "outcome")
        db = TempusDDB(db_path, gate_keyfile)
        result = db.commit_outcome(
            args.authorization_id,
            outcome,
            args.executor_keyfile,
        )
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"✗ Outcome commit failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_trace(args, *, verify=False):
    """Read or verify a B2A action trace."""
    db_path, gate_keyfile = _resolve_paths(args)
    try:
        db = TempusDDB(db_path, gate_keyfile)
        result = (
            db.verify_trace(args.action_id) if verify else db.get_trace(args.action_id)
        )
        parsed = json.loads(result)
        print(json.dumps(parsed, indent=2))
        if verify and parsed.get("status") == "INVALID":
            sys.exit(2)
    except Exception as exc:
        print(
            f"✗ Trace {'verification' if verify else 'lookup'} failed: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


def _gate(args):
    db_path, keyfile = _resolve_paths(args)
    return TempusDDB(db_path, keyfile)


def run_install_policy(args):
    """Install a signed deterministic policy and make it active for its tenant."""
    try:
        spec = _load_json_argument(args.policy, "policy")
        print(json.dumps(json.loads(_gate(args).install_policy(spec)), indent=2))
    except Exception as exc:
        print(f"✗ Policy installation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_list_policies(args):
    try:
        print(json.dumps(json.loads(_gate(args).list_policies()), indent=2))
    except Exception as exc:
        print(f"✗ Policy listing failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_rotate_agent(args):
    try:
        with open(args.new_keyfile, encoding="utf-8") as handle:
            new_public_key = json.load(handle)["public_key"]
        result = _gate(args).rotate_agent(args.current_public_key, new_public_key)
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"✗ Identity rotation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_revoke_agent(args):
    try:
        result = _gate(args).revoke_agent(args.public_key, args.reason)
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"✗ Identity revocation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_identity_events(args):
    try:
        result = _gate(args).list_identity_events()
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"✗ Identity event listing failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_conformance(args):
    """Emit the adapter contract and optionally exercise the configured signer."""
    manifest = {
        "schema_version": "tempus.adapter-conformance.v1",
        "status": "PASS",
        "contracts": {
            "permit": "tempus.authorization-result.v1",
            "outcome": "tempus.action-outcome.v1",
            "policy": "tempus.policy-bundle.v1",
            "single_consumption": True,
            "fail_closed_checks": [
                "schema",
                "gate_signature",
                "tenant",
                "intent_hash",
                "policy_digest",
                "evidence_digest",
                "executor_constraints",
                "expiry",
                "replay",
            ],
        },
    }
    if args.signer:
        try:
            manifest["signer"] = json.loads(_gate(args).signer_conformance())
        except Exception as exc:
            manifest["status"] = "FAIL"
            manifest["signer"] = {"status": "FAIL", "error": str(exc)}
    print(json.dumps(manifest, indent=2))
    if manifest["status"] != "PASS":
        sys.exit(1)


def run_checkpoint(args):
    """Manage checkpoints and event stream export/verification."""
    cmd = args.checkpoint_cmd
    if cmd == "create":
        try:
            gate = _gate(args)
            chk_str = gate.create_checkpoint(args.tenant_id)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(chk_str)
                print(f"✓ Checkpoint created → {args.out}")
            else:
                print(json.dumps(json.loads(chk_str), indent=2))
        except Exception as exc:
            print(f"✗ Checkpoint creation failed: {exc}", file=sys.stderr)
            sys.exit(1)
    elif cmd == "export":
        try:
            gate = _gate(args)
            stream_str = gate.export_event_stream(
                args.tenant_id, args.from_seq, args.limit
            )
            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(stream_str)
                print(f"✓ Event stream exported → {args.out}")
            else:
                print(json.dumps(json.loads(stream_str), indent=2))
        except Exception as exc:
            print(f"✗ Event stream export failed: {exc}", file=sys.stderr)
            sys.exit(1)
    elif cmd == "verify":
        try:
            chk_raw = args.checkpoint
            if os.path.isfile(chk_raw):
                with open(chk_raw, "r", encoding="utf-8") as f:
                    chk_raw = f.read().strip()

            stream_raw = args.stream
            if os.path.isfile(stream_raw):
                with open(stream_raw, "r", encoding="utf-8") as f:
                    stream_raw = f.read().strip()

            gate = _gate(args)
            res_str = gate.verify_checkpoint_stream(chk_raw, stream_raw)
            result = json.loads(res_str)
            print(json.dumps(result, indent=2))
            if result.get("status") != "VERIFIED":
                sys.exit(2)
        except Exception as exc:
            print(f"✗ Checkpoint verification failed: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Invalid checkpoint subcommand", file=sys.stderr)
        sys.exit(1)


def run_doctor(args):
    """Check whether the local gate is ready without exposing credential material."""
    db_path, keyfile = _resolve_paths(args)
    checks = []

    def add(name, status, detail):
        checks.append({"name": name, "status": status, "detail": detail})

    if os.path.isfile(keyfile) and os.access(keyfile, os.R_OK):
        add("signer_config", "PASS", f"readable: {keyfile}")
        if os.name != "nt":
            mode = stat.S_IMODE(os.stat(keyfile).st_mode)
            add(
                "signer_permissions",
                "PASS" if mode & 0o077 == 0 else "FAIL",
                oct(mode),
            )
        try:
            with open(keyfile, encoding="utf-8") as handle:
                signer_config = json.load(handle)
            if signer_config.get("provider") == "vault-transit-cli":
                vault_binary = signer_config.get("vault_binary", "vault")
                resolved = shutil.which(vault_binary)
                add(
                    "vault_cli",
                    "PASS" if resolved else "FAIL",
                    resolved or f"not found: {vault_binary}",
                )
        except (OSError, ValueError) as exc:
            add("signer_json", "FAIL", str(exc))
    else:
        add("signer_config", "FAIL", f"not readable: {keyfile}")

    now = time.time()
    add(
        "clock",
        "PASS" if now > 1_700_000_000 else "FAIL",
        f"unix_seconds={int(now)}",
    )
    if not os.path.isfile(db_path):
        add("database", "FAIL", f"not found: {db_path}")
    else:
        try:
            gate = TempusDDB(db_path, keyfile)
            identity = json.loads(gate.whoami())
            add("database", "PASS", f"open: {db_path}")
            trusted = gate.verify_agent(identity["public_key"])
            add(
                "gate_identity",
                "PASS" if trusted else "FAIL",
                identity["public_key"],
            )
            policies = json.loads(gate.list_policies())
            active = [policy for policy in policies if policy.get("status") == "ACTIVE"]
            add(
                "active_policy",
                "PASS" if active else "FAIL",
                f"active={len(active)}",
            )
        except Exception as exc:
            add("database", "FAIL", str(exc))
    if args.github:
        add(
            "github_executor_credentials",
            "PASS" if os.environ.get("GITHUB_TOKEN") else "FAIL",
            "GITHUB_TOKEN is set"
            if os.environ.get("GITHUB_TOKEN")
            else "GITHUB_TOKEN is missing",
        )

    overall = "FAIL" if any(check["status"] == "FAIL" for check in checks) else "PASS"
    report = {
        "schema_version": "tempus.doctor-result.v1",
        "status": overall,
        "version": __version__,
        "checks": checks,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Tempus doctor: {overall}")
        for check in checks:
            print(f"[{check['status']}] {check['name']}: {check['detail']}")
    if overall != "PASS":
        sys.exit(1)


def run_version():
    print(f"tempus {__version__}")


def main():
    parser = argparse.ArgumentParser(
        prog="tempus",
        description="Tempus DDB — The B2A security gate for autonomous agent actions",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    # Global arguments available to all subcommands
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        help=f"Path to the ledger database (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--keyfile",
        default=DEFAULT_KEYFILE,
        help=f"Path to the Ed25519 key file (default: {DEFAULT_KEYFILE})",
    )

    subparsers = parser.add_subparsers(dest="command", required=False)

    # init
    subparsers.add_parser("init", help="Initialize keys and database")

    keygen_p = subparsers.add_parser(
        "keygen", help="Generate a workload Ed25519 keypair"
    )
    keygen_p.add_argument("--output", required=True, help="New key file path")

    # mcp
    mcp_parser = subparsers.add_parser("mcp", help="MCP server commands")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_cmd", required=True)
    mcp_sub.add_parser("start", help="Start the MCP server for agents (stdio)")

    # verify
    subparsers.add_parser("verify", help="Cryptographically verify the entire ledger")

    # status
    subparsers.add_parser("status", help="Show current ledger and keys status")

    # record (new/improved for CLI users)
    record_p = subparsers.add_parser(
        "record", help="Record a decision directly from CLI"
    )
    record_p.add_argument(
        "--payload",
        required=True,
        help="JSON string or path to JSON file with the decision",
    )
    record_p.add_argument(
        "--rules",
        required=True,
        help="JSON string or path to JSON file with the rules applied",
    )
    record_p.add_argument(
        "--genesis",
        action="store_true",
        help="Mark this as the first decision in the chain",
    )
    # Note: Parent chaining for audit should be included inside the JSON payload.
    # The core ledger is append-only controlled by the `genesis` flag.

    # export
    subparsers.add_parser("export", help="Export the entire ledger as a JSON array")

    # list
    list_p = subparsers.add_parser("list", help="List decisions with pagination")
    list_p.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of records to return (default: 10)",
    )
    list_p.add_argument(
        "--offset", type=int, default=0, help="Number of records to skip (default: 0)"
    )

    # count
    subparsers.add_parser(
        "count", help="Count the total number of decisions in the ledger"
    )

    # register-agent
    reg_agent_p = subparsers.add_parser(
        "register-agent", help="Register an agent identity in the ledger"
    )
    reg_agent_p.add_argument(
        "--alias", required=True, help="Human-readable alias for the agent"
    )
    reg_agent_p.add_argument(
        "--public-key",
        dest="public_key",
        default=None,
        help="Ed25519 public key (hex). If omitted, extracted from --agent-keyfile or --keyfile",
    )
    reg_agent_p.add_argument(
        "--agent-keyfile",
        dest="agent_keyfile",
        default=None,
        help="Path to the agent's key file (used to extract public key)",
    )
    reg_agent_p.add_argument(
        "--metadata", default="{}", help="JSON metadata for the agent"
    )

    # list-agents
    subparsers.add_parser("list-agents", help="List all registered agents")

    # whoami
    subparsers.add_parser("whoami", help="Show the identity of the current keyfile")

    install_policy_p = subparsers.add_parser(
        "install-policy", help="Sign and activate a deterministic policy bundle"
    )
    install_policy_p.add_argument("--policy", required=True, help="Policy JSON or file")
    subparsers.add_parser(
        "list-policies", help="List active and retired signed policies"
    )

    rotate_p = subparsers.add_parser(
        "rotate-agent", help="Rotate an active identity key"
    )
    rotate_p.add_argument("--current-public-key", required=True)
    rotate_p.add_argument("--new-keyfile", required=True)
    revoke_p = subparsers.add_parser(
        "revoke-agent", help="Revoke an identity key and open permits"
    )
    revoke_p.add_argument("--public-key", required=True)
    revoke_p.add_argument("--reason", required=True)
    subparsers.add_parser(
        "identity-events", help="List signed rotation and revocation events"
    )

    conformance_p = subparsers.add_parser(
        "conformance", help="Emit machine-readable adapter conformance requirements"
    )
    conformance_p.add_argument(
        "--signer",
        action="store_true",
        help="Also exercise the configured signing provider",
    )
    doctor_p = subparsers.add_parser(
        "doctor", help="Check production configuration readiness"
    )
    doctor_p.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )
    doctor_p.add_argument(
        "--github", action="store_true", help="Also check GitHub executor credentials"
    )

    # B2A execution-gate workflow
    request_p = subparsers.add_parser(
        "request-action",
        help="Request a signed, single-use authorization before executing an action",
    )
    request_p.add_argument(
        "--intent", required=True, help="tempus.action-intent.v1 JSON or file"
    )
    request_p.add_argument(
        "--agent-keyfile", required=True, help="Requesting agent Ed25519 key file"
    )
    request_p.add_argument(
        "--ttl-seconds", type=int, default=60, help="Permit lifetime (1-86400 seconds)"
    )

    outcome_p = subparsers.add_parser(
        "commit-outcome",
        help="Consume an allowed permit and append the signed executor outcome",
    )
    outcome_p.add_argument("--authorization-id", required=True)
    outcome_p.add_argument(
        "--outcome", required=True, help="tempus.action-outcome.v1 JSON or file"
    )
    outcome_p.add_argument(
        "--executor-keyfile", required=True, help="Executor Ed25519 key file"
    )

    trace_p = subparsers.add_parser(
        "trace", help="Read an action authorization and outcome"
    )
    trace_p.add_argument("--action-id", required=True)
    verify_trace_p = subparsers.add_parser(
        "verify-trace", help="Verify an action trace end to end"
    )
    verify_trace_p.add_argument("--action-id", required=True)

    # checkpoint subcommands
    chk_parser = subparsers.add_parser(
        "checkpoint", help="Cryptographic checkpoint and event stream operations"
    )
    chk_sub = chk_parser.add_subparsers(dest="checkpoint_cmd", required=True)

    # checkpoint create
    chk_create = chk_sub.add_parser(
        "create", help="Generate and sign a new monotonic checkpoint for a tenant"
    )
    chk_create.add_argument("--tenant-id", default="*", help="Tenant ID (default: *)")
    chk_create.add_argument("--out", help="Output file path to save checkpoint JSON")

    # checkpoint export
    chk_export = chk_sub.add_parser(
        "export", help="Export event stream events for a tenant"
    )
    chk_export.add_argument("--tenant-id", default="*", help="Tenant ID (default: *)")
    chk_export.add_argument(
        "--from-seq", type=int, default=1, help="Starting sequence number (default: 1)"
    )
    chk_export.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum events to export (default: 1000)",
    )
    chk_export.add_argument("--out", help="Output file path to save stream JSON")

    # checkpoint verify
    chk_verify = chk_sub.add_parser(
        "verify", help="Cryptographically verify an event stream against a checkpoint"
    )
    chk_verify.add_argument(
        "--checkpoint", required=True, help="Checkpoint JSON string or file path"
    )
    chk_verify.add_argument(
        "--stream", required=True, help="Event stream JSON array string or file path"
    )

    args = parser.parse_args()

    if getattr(args, "version", False):
        run_version()
        return

    try:
        if args.command == "init":
            run_init(args)
        elif args.command == "keygen":
            run_keygen(args)
        elif args.command == "mcp" and getattr(args, "mcp_cmd", None) == "start":
            main_sync()
        elif args.command == "verify":
            run_verify(args)
        elif args.command == "status":
            run_status(args)
        elif args.command == "record":
            run_record(args)
        elif args.command == "export":
            run_export(args)
        elif args.command == "list":
            run_list(args)
        elif args.command == "count":
            run_count(args)
        elif args.command == "register-agent":
            run_register_agent(args)
        elif args.command == "list-agents":
            run_list_agents(args)
        elif args.command == "whoami":
            run_whoami(args)
        elif args.command == "install-policy":
            run_install_policy(args)
        elif args.command == "list-policies":
            run_list_policies(args)
        elif args.command == "rotate-agent":
            run_rotate_agent(args)
        elif args.command == "revoke-agent":
            run_revoke_agent(args)
        elif args.command == "identity-events":
            run_identity_events(args)
        elif args.command == "conformance":
            run_conformance(args)
        elif args.command == "doctor":
            run_doctor(args)
        elif args.command == "request-action":
            run_request_action(args)
        elif args.command == "commit-outcome":
            run_commit_outcome(args)
        elif args.command == "trace":
            run_trace(args)
        elif args.command == "verify-trace":
            run_trace(args, verify=True)
        elif args.command == "checkpoint":
            run_checkpoint(args)
        elif args.command is None:
            parser.print_help()
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
    except Exception as e:
        # Last resort - should not reach here for handled cases
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
