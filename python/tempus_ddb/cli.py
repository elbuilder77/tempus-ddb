import argparse
import hashlib
import json
import math
import os
import shutil
import stat
import sys
import time
import warnings

from . import __version__
from ._tempus_ddb import (
    TempusDDB,
    bundle_digest,
    gen_keys,
    verify_bundle,
    verify_checkpoint,
    verify_receipt,
)
from .mcp_server import main_sync

# --- Default paths (used when global args are not provided) ---
DEFAULT_KEYFILE = "keys.json"
DEFAULT_DB = "tempus.db"
DEFAULT_VERIFY_URL = "https://tempus-protocol.github.io/tempus-ddb/verify.html"


def _verify_url_base():
    """The verifier receipts and bundles link to (override: TEMPUS_VERIFY_URL)."""
    raw = os.environ.get("TEMPUS_VERIFY_URL", "").strip().rstrip("#")
    if raw.startswith(("https://", "http://")):
        return raw
    return DEFAULT_VERIFY_URL


def _resolve_paths(args):
    """Extract db and keyfile paths from global args, falling back to defaults."""
    db = getattr(args, "db", None) or DEFAULT_DB
    keyfile = getattr(args, "keyfile", None) or DEFAULT_KEYFILE
    return db, keyfile


def _non_exact(label, text):
    raise ValueError(
        f"NON_EXACT_NUMBER: --{label} holds the number {text}, which is not an integer in "
        "the i64/u64 range; send decimals and larger values as strings"
    )


def _parse_float(label, text):
    # Python reads 1e400 as inf and would later write it back as `Infinity`; a float is
    # refused by the gate anyway, so report it with the same code as every other one.
    if not math.isfinite(float(text)):
        _non_exact(label, text)
    return float(text)


def _parse_int(label, text):
    # `-0` is read as 0 and signed as 0; a spelling that changes on the way is rejected
    # instead of being silently rewritten.
    if text.startswith("-") and not text.lstrip("-0"):
        _non_exact(label, text)
    try:
        return int(text)
    except ValueError:  # beyond Python's integer digit limit
        _non_exact(label, text[:20] + "...")


def _parse_exact(value, label):
    """json.loads that reports NaN, Infinity, 1e400 and -0 as NON_EXACT_NUMBER."""
    return json.loads(
        value,
        parse_constant=lambda name: _non_exact(label, name),
        parse_float=lambda text: _parse_float(label, text),
        parse_int=lambda text: _parse_int(label, text),
    )


def _load_json_argument(value, label):
    """Load a JSON object from a literal string or a file path."""
    if os.path.isfile(value):
        with open(value, encoding="utf-8") as handle:
            value = handle.read().strip()
    elif not value.lstrip().startswith("{"):
        raise ValueError(
            f"--{label}: file not found: {value} "
            "(pass the path of an existing JSON file, or a JSON object)"
        )
    try:
        parsed = _parse_exact(value, label)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"--{label} must be valid JSON or a path to a JSON file: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"--{label} must contain a JSON object")
    return json.dumps(parsed, separators=(",", ":"), sort_keys=True)


ALLOW_ALL_DEV_WARNING = (
    "WARNING: --allow-all-dev installed a development policy that ALLOWS EVERY ACTION "
    "for every tenant without its own policy. Never use it in production; install a "
    "real policy with 'tempus install-policy --policy FILE'."
)
NON_PRODUCTION_POLICY_PREFIXES = ("tempus.dev-allow-all.v1", "tempus.baseline.v1")


def _install_allow_all_dev(db):
    """Explicit development opt-in; the gate never installs this by itself."""
    with warnings.catch_warnings():
        # The CLI prints its own visible warning below.
        warnings.simplefilter("ignore", UserWarning)
        bundle = db.install_allow_all_dev_policy()
    print(ALLOW_ALL_DEV_WARNING, file=sys.stderr)
    return bundle


def run_init(args):
    db_path, keyfile = _resolve_paths(args)

    if os.path.exists(keyfile):
        print(f"[{keyfile}] already exists - skipping key generation.")
    else:
        try:
            gen_keys(keyfile)
            print(f"[OK] Generated new Ed25519 keys -> {keyfile}")
        except Exception as e:
            print(f"[ERROR] Failed to generate keys: {e}", file=sys.stderr)
            sys.exit(1)

    if os.path.exists(db_path):
        print(f"[{db_path}] already exists - verifying schema...")
    else:
        print(f"Initializing new gate at {db_path}...")

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
        print("[OK] Tempus DDB ready.")
        print(f"  Keys:  {keyfile}")
        print(f"  DB:    {db_path}")
        if getattr(args, "allow_all_dev", False):
            _install_allow_all_dev(db)
            print("  Policy: allow-all DEVELOPMENT policy (explicit --allow-all-dev)")
        elif not any(
            policy.get("status") == "ACTIVE"
            and not policy.get("policy_version", "").startswith(
                NON_PRODUCTION_POLICY_PREFIXES
            )
            for policy in json.loads(db.list_policies())
        ):
            print(
                "  Policy: none installed - the gate DENIES every action "
                "(POLICY_NOT_INSTALLED) until you run:\n"
                "          tempus install-policy --policy FILE   "
                "(development only: tempus install-policy --allow-all-dev)"
            )
    except Exception as e:
        print(f"[ERROR] Failed to initialize database: {e}", file=sys.stderr)
        sys.exit(1)


def run_keygen(args):
    """Generate a workload keypair for an agent, executor, or gate."""
    if os.path.exists(args.output):
        print(
            f"[ERROR] Refusing to overwrite existing key file: {args.output}",
            file=sys.stderr,
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
        print(f"[ERROR] Key generation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_status(args):
    """Show the gate's keys, database, identities and policy, and where evidence is verified."""
    db_path, keyfile = _resolve_paths(args)

    print("Tempus status")
    print("=============")

    if os.path.exists(keyfile):
        print(f"[OK] Gate key file: {keyfile}")
        try:
            with open(keyfile, encoding="utf-8") as handle:
                public_key = json.load(handle).get("public_key")
            if public_key:
                print(f"  Gate public key: {public_key}")
        except Exception as exc:
            print(f"  Gate public key: unavailable ({exc})")
    else:
        print("[ERROR] Gate key file: not found (run 'tempus init')")

    if os.path.exists(db_path):
        print(f"[OK] Gate database: {db_path} ({os.path.getsize(db_path)} bytes)")
        try:
            db = TempusDDB(
                db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE
            )
            agents = json.loads(db.list_agents())
            print(f"  Registered identities: {len(agents)}")
            policies = json.loads(db.list_policies())
            active = [p for p in policies if p.get("status") == "ACTIVE"]
            if active:
                version = active[0].get("policy_version") or active[0].get("version")
                print(f"  Active policy: {version} (of {len(policies)} installed)")
            else:
                print("  Active policy: none (default deny: every request is BLOCKED)")
        except Exception as exc:
            print(f"[ERROR] Could not read the gate: {exc}")
    else:
        print("[ERROR] Gate database: not found (run 'tempus init')")

    print(f"  Evidence verifier: {_verify_url_base()}")
    print("\nNext steps if needed:")
    print("  tempus init            # create the gate key and database")
    print(
        "  tempus install-policy  # install a signed policy (the gate denies until then)"
    )
    print("  tempus request-action  # obtain a signed execution permit")
    print(
        "  tempus export-bundle   # one evidence file an auditor verifies with the gate public key"
    )


def run_register_agent(args):
    """Register an agent in the gate's identity registry."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(db_path):
        print("[ERROR] No database found. Run 'tempus init' first.", file=sys.stderr)
        sys.exit(1)

    try:
        # If no --public-key provided, extract from keyfile
        public_key = getattr(args, "public_key", None)
        if not public_key:
            agent_keyfile = getattr(args, "agent_keyfile", None) or keyfile
            if not os.path.exists(agent_keyfile):
                print(f"[ERROR] Key file not found: {agent_keyfile}", file=sys.stderr)
                sys.exit(1)
            with open(agent_keyfile, encoding="utf-8") as f:
                key_data = json.load(f)
            public_key = key_data.get("public_key")
            if not public_key:
                print(
                    "[ERROR] Key file does not contain 'public_key'.", file=sys.stderr
                )
                sys.exit(1)

        db = TempusDDB(db_path, keyfile if os.path.exists(keyfile) else DEFAULT_KEYFILE)
        metadata = getattr(args, "metadata", "{}") or "{}"
        try:
            _parse_exact(
                metadata, "metadata"
            )  # same NON_EXACT_NUMBER wording as --intent
        except json.JSONDecodeError:
            pass  # the gate reports a syntax error with its own message
        result = db.register_agent(public_key, args.alias, metadata)
        parsed = json.loads(result)
        print(f"[OK] Agent '{args.alias}' registered.")
        print(f"  Public key: {parsed.get('public_key', public_key)}")
    except Exception as e:
        print(f"[ERROR] Registration failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_list_agents(args):
    """List all registered agents."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(db_path):
        print("[ERROR] No database found. Run 'tempus init' first.", file=sys.stderr)
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
        print(f"[ERROR] List agents failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_whoami(args):
    """Show the identity of the current keyfile."""
    db_path, keyfile = _resolve_paths(args)

    if not os.path.exists(keyfile):
        print(
            f"[ERROR] Key file not found: {keyfile}. Run 'tempus init' first.",
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
            print("Alias:      (not registered - use 'tempus register-agent')")
        print(f"Key File:   {parsed.get('keyfile')}")
    except Exception as e:
        print(f"[ERROR] Whoami failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_request_action(args):
    """Request a signed, single-use authorization (ALLOWED or BLOCKED) for an agent action."""
    db_path, gate_keyfile = _resolve_paths(args)
    try:
        intent = _load_json_argument(args.intent, "intent")
        db = TempusDDB(db_path, gate_keyfile)
        result = db.request_action(intent, args.agent_keyfile, args.ttl_seconds)
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"[ERROR] Authorization request failed: {exc}", file=sys.stderr)
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
        print(f"[ERROR] Outcome commit failed: {exc}", file=sys.stderr)
        sys.exit(1)


NOT_INDEPENDENT_WARNING = (
    "WARNING: NOT INDEPENDENT - no --gate-public-key was given, so the trust root "
    "comes from the database being verified; a fully forged database verifies "
    "against itself. Pin the gate public key (published by the gate operator, see "
    "'tempus whoami') with --gate-public-key HEX|FILE."
)


KEY_FILE_FIELDS = ("public_key", "gate_public_key")


def _reject_duplicate_keys(pairs):
    seen = {}
    for key, item in pairs:
        if key in seen:
            raise ValueError(f"the key {key!r} appears more than once")
        seen[key] = item
    return seen


def _key_from_json_file(text, path, label):
    """The one public key a JSON key file names, or ValueError if it is not unambiguous.

    A key file is the verifier's trust root, so nothing is guessed: repeated keys, a
    candidate field that is empty or not a string, or two candidate fields holding different
    keys are all errors (the previous code let the last duplicate win and fell through from an
    empty `public_key` to `gate_public_key`).
    """
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as exc:  # includes JSONDecodeError and the duplicate-key error
        raise ValueError(f"{label}: {path} is not a valid key file: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{label}: {path} must hold a JSON object")
    candidates = {}
    for field in KEY_FILE_FIELDS:
        if field not in data:
            continue
        value = data[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label}: {field} in {path} must be a non-empty string")
        candidates[field] = value.strip().lower()
    if not candidates:
        raise ValueError(f"{label}: no public_key field in {path}")
    if len(set(candidates.values())) > 1:
        raise ValueError(
            f"{label}: {path} is ambiguous: public_key and gate_public_key differ"
        )
    return next(iter(candidates.values()))


def _load_public_key(value, label="--gate-public-key"):
    """Resolve a public key given as 64 hex chars or as a file path.

    A file may hold the bare hex key or a JSON object with a "public_key" field
    (a gate or identity key file also works: only the public part is read and
    private material is never used or printed).
    """
    raw = value.strip()
    if not raw:
        raise ValueError(
            f"{label} is empty: pass a 64-hex Ed25519 public key or a key file "
            "(is a shell variable unset?)"
        )
    if os.path.isfile(value):
        with open(value, encoding="utf-8") as handle:
            raw = handle.read().strip()
        if raw.startswith(("{", "[")):
            raw = _key_from_json_file(raw, value, label)
    key = raw.lower()
    if len(key) != 64 or any(ch not in "0123456789abcdef" for ch in key):
        raise ValueError(
            f"{label} must be 64 hex characters (Ed25519 public key) or a file "
            "containing one"
        )
    return key


def _pinned_keys(args):
    """Return (gate_key or None, [executor keys]) from CLI args, enforcing --strict."""
    gate_arg = getattr(args, "gate_public_key", None)
    # Only an omitted option means "not pinned"; an empty value is a usage error.
    gate_key = _load_public_key(gate_arg) if gate_arg is not None else None
    executors = [
        _load_public_key(value, "--executor-public-key")
        for value in (getattr(args, "executor_public_key", None) or [])
    ]
    if executors and gate_key is None:
        raise ValueError("--executor-public-key requires --gate-public-key")
    if gate_key is None and getattr(args, "strict", False):
        raise ValueError(
            "--strict requires --gate-public-key: independent verification must "
            "not trust the database's own root of trust"
        )
    return gate_key, executors


def _read_text_argument(value, label):
    """Read literal JSON, a file path, or '-' for stdin."""
    if value == "-":
        return sys.stdin.read()
    if os.path.isfile(value):
        with open(value, encoding="utf-8") as handle:
            return handle.read()
    if value.lstrip().startswith("{"):
        return value
    raise ValueError(f"--{label}: file not found: {value}")


REQUIREMENT_NOT_MET = "REQUIREMENT_NOT_MET"


def _apply_requirements(parsed, args):
    """Turn a VERIFIED result into INVALID when a --require-* condition is unmet.

    The signatures are checked first; these flags then say what the verified evidence
    must show (so an exit code of 0 can be read as "authorized and executed").
    """
    if parsed.get("status") != "VERIFIED":
        return parsed
    unmet = []
    require_decision = getattr(args, "require_decision", None)
    if require_decision and parsed.get("decision") != require_decision:
        unmet.append(
            f"decision (required {require_decision}, got {parsed.get('decision')})"
        )
    if getattr(args, "require_execution", False) and (
        parsed.get("execution_status") != "SUCCEEDED"
    ):
        unmet.append(
            f"execution (required SUCCEEDED, got {parsed.get('execution_status')})"
        )
    if getattr(args, "require_checkpoint", False) and (
        parsed.get("checks", {}).get("checkpoint") != "VERIFIED"
    ):
        unmet.append(
            f"checkpoint (required VERIFIED, got "
            f"{parsed.get('checks', {}).get('checkpoint', 'NOT_PRESENT')})"
        )
    if unmet:
        parsed["status"] = "INVALID"
        parsed.setdefault("errors", []).extend(
            f"{REQUIREMENT_NOT_MET} ({item})" for item in unmet
        )
    return parsed


def _print_verification(result_json, args=None):
    parsed = _apply_requirements(json.loads(result_json), args)
    print(json.dumps(parsed, indent=2))
    if parsed.get("output_degraded") is True:
        print(
            "NOTE: the executor recorded a degraded output (_tempus_output_degraded): the "
            "outcome status is signed but its output is a bounded summary, not the full "
            "result. The marker is written by the executor (anyone holding its key can "
            "write it).",
            file=sys.stderr,
        )
    if parsed.get("status") != "VERIFIED":
        sys.exit(2)


def run_trace(args, *, verify=False):
    """Read or verify a B2A action trace."""
    db_path, gate_keyfile = _resolve_paths(args)
    try:
        gate_key, executors = _pinned_keys(args) if verify else (None, [])
        db = TempusDDB(db_path, gate_keyfile)
        if verify and gate_key:
            result = db.verify_trace(args.action_id, gate_key, executors)
        elif verify:
            print(NOT_INDEPENDENT_WARNING, file=sys.stderr)
            result = db.verify_trace(args.action_id)
        else:
            result = db.get_trace(args.action_id)
        parsed = json.loads(result)
        if verify:
            parsed = _apply_requirements(parsed, args)
        print(json.dumps(parsed, indent=2))
        if verify and parsed.get("status") == "INVALID":
            sys.exit(2)
    except Exception as exc:
        print(
            f"[ERROR] Trace {'verification' if verify else 'lookup'} failed: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


def run_verify_receipt(args):
    """Verify a standalone receipt (trace, permit or outcome JSON) without a database."""
    try:
        gate_key, executors = _pinned_keys(args)
        if gate_key is None:
            raise ValueError("--gate-public-key is required")
        receipt = _read_text_argument(args.receipt, "receipt")
        result = verify_receipt(receipt, gate_key, executors or None)
    except Exception as exc:
        print(f"[ERROR] Receipt verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
    _print_verification(result, args)


def run_export_bundle(args):
    """Write one action as a self-contained evidence bundle (no private keys)."""
    db_path, keyfile = _resolve_paths(args)
    try:
        if os.path.exists(args.out) and not args.force:
            raise ValueError(f"{args.out} already exists (use --force to overwrite)")
        db = TempusDDB(db_path, keyfile)
        if args.create_checkpoint:
            trace = json.loads(db.get_trace(args.action_id))
            tenant = trace["authorization"]["authorization"]["tenant_id"]
            db.create_checkpoint(tenant)
        bundle = db.export_bundle(args.action_id, args.max_stream_events)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(bundle)
        parsed = json.loads(bundle)
        has_checkpoint = parsed.get("checkpoint") is not None
        print(
            json.dumps(
                {
                    "schema_version": "tempus.evidence-bundle.v1",
                    "action_id": args.action_id,
                    "out": args.out,
                    "bytes": len(bundle.encode("utf-8")),
                    "sha256": hashlib.sha256(bundle.encode("utf-8")).hexdigest(),
                    "bundle_digest": bundle_digest(bundle),
                    "verify_url": parsed.get("verify_url"),
                    "checkpoint_included": has_checkpoint,
                },
                indent=2,
            )
        )
        print(
            "Share the file and the gate PUBLIC key. Anyone verifies it at the verify_url "
            "(browser, no network) or with: tempus verify-bundle --bundle "
            f"{args.out} --gate-public-key <hex>",
            file=sys.stderr,
        )
        if not has_checkpoint:
            print(
                "NOTE: no checkpoint in the bundle (none covers this action yet, or "
                "its stream exceeds --max-stream-events): ledger inclusion cannot be "
                "shown. Re-run with --create-checkpoint to include one.",
                file=sys.stderr,
            )
    except Exception as exc:
        print(f"[ERROR] Bundle export failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_verify_bundle(args):
    """Verify an evidence bundle without a database, against a pinned gate key."""
    try:
        gate_key, executors = _pinned_keys(args)
        if gate_key is None:
            raise ValueError("--gate-public-key is required")
        bundle = _read_text_argument(args.bundle, "bundle")
        result = verify_bundle(bundle, gate_key, executors or None)
    except Exception as exc:
        print(f"[ERROR] Bundle verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
    _print_verification(result, args)


def _gate(args):
    db_path, keyfile = _resolve_paths(args)
    return TempusDDB(db_path, keyfile)


PLACEHOLDER_MARKER = "REPLACE_WITH_"


def _find_placeholders(node, path="$"):
    """Return (json path, value) for every string still holding a template placeholder."""
    found = []
    if isinstance(node, str):
        if PLACEHOLDER_MARKER in node:
            found.append((path, node))
    elif isinstance(node, dict):
        for key, value in node.items():
            found.extend(_find_placeholders(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_find_placeholders(value, f"{path}[{index}]"))
    return found


def _find_prefix_url_patterns(spec):
    """`http(s)` resource patterns whose `*` is not after a `/`.

    A `*` matches only as a whole component (split on `/` and `.`). A `*` that
    is not its own component matches nothing. A `*` that is the whole host
    matches every URL of that scheme.
    """
    constraints = spec.get("constraints") if isinstance(spec, dict) else None
    patterns = (
        constraints.get("allowed_resources") if isinstance(constraints, dict) else []
    )
    found = []
    for pattern in patterns if isinstance(patterns, list) else []:
        if not isinstance(pattern, str) or not pattern.endswith("*"):
            continue
        scheme, separator, rest = pattern.partition("://")
        if separator and scheme in ("http", "https") and "/" not in rest[:-1]:
            found.append(pattern)
    return found


def run_install_policy(args):
    """Install a signed deterministic policy and make it active for its tenant."""
    try:
        if args.allow_all_dev:
            if args.policy:
                print(
                    "[ERROR] --allow-all-dev cannot be combined with --policy",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(json.dumps(json.loads(_install_allow_all_dev(_gate(args))), indent=2))
            return
        if not args.policy:
            print(
                "[ERROR] Provide --policy FILE (or --allow-all-dev for local development)",
                file=sys.stderr,
            )
            sys.exit(1)
        spec = _load_json_argument(args.policy, "policy")
        placeholders = _find_placeholders(json.loads(spec))
        if placeholders:
            print(
                "[ERROR] Policy still contains template placeholders; replace them "
                "with real values (e.g. the executor's public_key from its key file) "
                "and try again:\n  "
                + "\n  ".join(f"{path}: {value}" for path, value in placeholders),
                file=sys.stderr,
            )
            sys.exit(1)
        for pattern in _find_prefix_url_patterns(json.loads(spec)):
            print(
                f"WARNING: allowed_resources pattern '{pattern}' has no '/' before '*'. "
                "A '*' matches only as a whole component (split on '/' and '.'). "
                "Glued to the host ('https://api.example.com*') the pattern matches "
                "nothing; write 'https://api.example.com/*' or 'https://*.example.com/*'. "
                "A star that is the whole host ('https://*') matches every URL of that "
                "scheme. Pin hosts with the executor's --allowed-domains.",
                file=sys.stderr,
            )
        print(json.dumps(json.loads(_gate(args).install_policy(spec)), indent=2))
    except Exception as exc:
        print(f"[ERROR] Policy installation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_list_policies(args):
    try:
        print(json.dumps(json.loads(_gate(args).list_policies()), indent=2))
    except Exception as exc:
        print(f"[ERROR] Policy listing failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_rotate_agent(args):
    try:
        with open(args.new_keyfile, encoding="utf-8") as handle:
            new_public_key = json.load(handle)["public_key"]
        result = _gate(args).rotate_agent(args.current_public_key, new_public_key)
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"[ERROR] Identity rotation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_revoke_agent(args):
    try:
        result = _gate(args).revoke_agent(args.public_key, args.reason)
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"[ERROR] Identity revocation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def run_identity_events(args):
    try:
        result = _gate(args).list_identity_events()
        print(json.dumps(json.loads(result), indent=2))
    except Exception as exc:
        print(f"[ERROR] Identity event listing failed: {exc}", file=sys.stderr)
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
                print(f"[OK] Checkpoint created -> {args.out}")
            else:
                print(json.dumps(json.loads(chk_str), indent=2))
        except Exception as exc:
            print(f"[ERROR] Checkpoint creation failed: {exc}", file=sys.stderr)
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
                print(f"[OK] Event stream exported -> {args.out}")
            else:
                print(json.dumps(json.loads(stream_str), indent=2))
        except Exception as exc:
            print(f"[ERROR] Event stream export failed: {exc}", file=sys.stderr)
            sys.exit(1)
    elif cmd == "verify":
        try:
            gate_key, _ = _pinned_keys(args)
            chk_raw = args.checkpoint
            if os.path.isfile(chk_raw):
                with open(chk_raw, "r", encoding="utf-8") as f:
                    chk_raw = f.read().strip()

            stream_raw = args.stream
            if os.path.isfile(stream_raw):
                with open(stream_raw, "r", encoding="utf-8") as f:
                    stream_raw = f.read().strip()

            if gate_key:
                # Independent: no database and no private key file involved.
                res_str = verify_checkpoint(chk_raw, stream_raw, gate_key)
                result = json.loads(res_str)
                result["trust"] = {
                    "mode": "PINNED_GATE_KEY",
                    "independent": True,
                    "gate_public_key": gate_key,
                }
            else:
                print(NOT_INDEPENDENT_WARNING, file=sys.stderr)
                gate = _gate(args)
                result = json.loads(gate.verify_checkpoint_stream(chk_raw, stream_raw))
                result["trust"] = {
                    "mode": "LOCAL_KEYFILE_OR_DATABASE_ROOT",
                    "independent": False,
                }
            print(json.dumps(result, indent=2))
            if result.get("status") != "VERIFIED":
                sys.exit(2)
        except Exception as exc:
            print(f"[ERROR] Checkpoint verification failed: {exc}", file=sys.stderr)
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
            dev_only = [
                policy
                for policy in active
                if policy.get("policy_version", "").startswith(
                    NON_PRODUCTION_POLICY_PREFIXES
                )
            ]
            if not active:
                add("active_policy", "FAIL", "none installed: every action is denied")
            elif dev_only:
                add(
                    "active_policy",
                    "FAIL",
                    "development allow-all policy is active: "
                    + ", ".join(p["policy_version"] for p in dev_only),
                )
            else:
                add("active_policy", "PASS", f"active={len(active)}")
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


def _add_pin_arguments(parser, *, required=False, executors=True):
    """Arguments that pin the verifier's trust root out of band."""
    parser.add_argument(
        "--gate-public-key",
        required=required,
        metavar="HEX|FILE",
        help="Gate Ed25519 public key (64 hex chars, or a file holding it) pinned "
        "by the verifier. Without it the result is NOT independent",
    )
    if executors:
        parser.add_argument(
            "--executor-public-key",
            action="append",
            metavar="HEX|FILE",
            help="Pin the executor public key (repeatable; requires --gate-public-key)",
        )
    if not required:
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Refuse to run without --gate-public-key",
        )


def _add_require_arguments(parser, *, checkpoint=False):
    """Conditions the verified evidence must meet for the command to exit 0."""
    parser.add_argument(
        "--require-execution",
        action="store_true",
        help="Exit 2 unless the evidence contains a verified execution with status "
        "SUCCEEDED (a BLOCKED, FAILED or missing outcome is not enough)",
    )
    parser.add_argument(
        "--require-decision",
        choices=["ALLOWED", "BLOCKED"],
        help="Exit 2 unless the gate's signed decision equals this value",
    )
    if checkpoint:
        parser.add_argument(
            "--require-checkpoint",
            action="store_true",
            help="Exit 2 unless the bundle holds a checkpoint that verifies and "
            "includes the permit and the outcome",
        )


def run_version():
    print(f"tempus {__version__}")


class _UsageErrorParser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error, which would collide with INVALID (2).

    Exit codes: 0 success / VERIFIED, 1 usage or operational error, 2 INVALID.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def run_guard(args):
    """`tempus guard ...` is `tempus-guard ...`: the client lives in its own package."""
    try:
        from tempus_guard.cli import main as guard_main
    except ImportError:
        print(
            "[ERROR] `tempus guard` needs the Tempus Guard CLI: pip install tempus-guard-cli "
            "(https://github.com/tempus-protocol/tempus-guard-cli)",
            file=sys.stderr,
        )
        sys.exit(2)
    guard_args = list(args.guard_args)
    if guard_args[:1] == ["--"]:
        guard_args = guard_args[1:]  # `tempus guard -- --version` reaches tempus-guard as `--version`
    sys.exit(guard_main(guard_args))


def main():
    parser = _UsageErrorParser(
        prog="tempus",
        description="Tempus DDB - The B2A security gate for autonomous agent actions",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    # Global arguments available to all subcommands
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        help=f"Path to the gate database (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--keyfile",
        default=DEFAULT_KEYFILE,
        help=f"Path to the Ed25519 key file (default: {DEFAULT_KEYFILE})",
    )

    subparsers = parser.add_subparsers(dest="command", required=False)

    # init
    init_p = subparsers.add_parser("init", help="Initialize keys and database")
    init_p.add_argument(
        "--allow-all-dev",
        action="store_true",
        help="DEVELOPMENT ONLY: also install an allow-all policy (default is deny-all)",
    )

    keygen_p = subparsers.add_parser(
        "keygen", help="Generate a workload Ed25519 keypair"
    )
    keygen_p.add_argument("--output", required=True, help="New key file path")

    # mcp
    mcp_parser = subparsers.add_parser("mcp", help="MCP server commands")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_cmd", required=True)
    mcp_sub.add_parser("start", help="Start the MCP server for agents (stdio)")

    # status
    subparsers.add_parser(
        "status", help="Show the gate's keys, database, identities and active policy"
    )

    # register-agent
    reg_agent_p = subparsers.add_parser(
        "register-agent", help="Register an agent identity in the gate"
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
    install_policy_p.add_argument("--policy", help="Policy JSON or file")
    install_policy_p.add_argument(
        "--allow-all-dev",
        action="store_true",
        help="DEVELOPMENT ONLY: install a signed policy that allows every action",
    )
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
    _add_pin_arguments(verify_trace_p)
    _add_require_arguments(verify_trace_p)

    verify_receipt_p = subparsers.add_parser(
        "verify-receipt",
        help="Verify a standalone receipt (trace/permit/outcome JSON) with no "
        "database, against a pinned gate public key",
    )
    verify_receipt_p.add_argument(
        "--receipt",
        required=True,
        help="Receipt JSON file (or '-' for stdin): tempus.action-trace.v1, "
        "tempus.authorization-result.v1 or tempus.execution-result.v1",
    )
    _add_pin_arguments(verify_receipt_p, required=True)
    _add_require_arguments(verify_receipt_p)

    export_bundle_p = subparsers.add_parser(
        "export-bundle",
        help="Export one action as a single self-contained evidence bundle "
        "(trace, signed policy, checkpoint if any; no private keys)",
    )
    export_bundle_p.add_argument("--action-id", required=True)
    export_bundle_p.add_argument("--out", required=True, help="Bundle file to write")
    export_bundle_p.add_argument(
        "--create-checkpoint",
        action="store_true",
        help="Sign a fresh checkpoint for the tenant first so the bundle can show "
        "ledger inclusion (needs the gate key)",
    )
    export_bundle_p.add_argument(
        "--max-stream-events",
        type=int,
        default=None,
        help="Omit the checkpoint if its event stream is larger than this "
        "(default 10000)",
    )
    export_bundle_p.add_argument(
        "--force", action="store_true", help="Overwrite an existing --out file"
    )

    verify_bundle_p = subparsers.add_parser(
        "verify-bundle",
        help="Verify an evidence bundle with no database, against a pinned gate "
        "public key",
    )
    verify_bundle_p.add_argument(
        "--bundle", required=True, help="Bundle JSON file (or '-' for stdin)"
    )
    _add_pin_arguments(verify_bundle_p, required=True)
    _add_require_arguments(verify_bundle_p, checkpoint=True)

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
    _add_pin_arguments(chk_verify, executors=False)

    # guard: the local client of Tempus Guard for GitHub (tempus-guard-cli), when installed.
    guard_p = subparsers.add_parser(
        "guard",
        help="Build and sign a github.push_branch intent for a local branch (needs tempus-guard-cli)",
        description=(
            "Delegates to the Tempus Guard CLI: `tempus guard intent ...`, `tempus guard request ...`, "
            "`tempus guard hook install`. Install it with `pip install tempus-guard-cli`."
        ),
    )
    guard_p.add_argument(
        "guard_args", nargs=argparse.REMAINDER, help="Arguments passed to `tempus-guard` unchanged"
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
        elif args.command == "status":
            run_status(args)
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
        elif args.command == "verify-receipt":
            run_verify_receipt(args)
        elif args.command == "export-bundle":
            run_export_bundle(args)
        elif args.command == "verify-bundle":
            run_verify_bundle(args)
        elif args.command == "checkpoint":
            run_checkpoint(args)
        elif args.command == "guard":
            run_guard(args)
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
