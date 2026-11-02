"""Unified Mediated Executor Runtime for Tempus B2A Security Gate.

This module provides the deep ExecutorRuntime engine and ActionAdapter interface
to ensure all mediated executors enforce identical permit verification, atomic
single-consumption, credential isolation, and crash recovery that records an
unknown outcome instead of retrying.
"""

import argparse
import datetime
import decimal
import errno
import http.client
import json
import reprlib
import ssl
import sys
from typing import Any, Dict, NamedTuple, Optional, Protocol, Set

from ._tempus_ddb import TempusExecutor

_I64_MIN, _U64_MAX = -(2**63), 2**64 - 1


MAX_OUTPUT_DEPTH = 64  # well inside the parser's 128 levels
MAX_OUTPUT_NODES = (
    100_000  # values visited; a shared reference counts each time it is walked
)
MAX_OUTPUT_CHARS = 4 * 1024 * 1024  # characters of every string and key kept
MAX_REPR_CHARS = 512
# Top-level key of the output the runtime writes when it cannot represent an adapter result.
# An adapter may not use it anywhere in its own result, so through the runtime the marker is
# always the runtime's; the verifier shows it as `output_degraded`.
DEGRADED_MARKER = "_tempus_output_degraded"

_SUMMARY = reprlib.Repr()
_SUMMARY.maxlevel = 3
_SUMMARY.maxstring = _SUMMARY.maxother = _SUMMARY.maxlong = 100
for _name in ("maxlist", "maxtuple", "maxset", "maxfrozenset", "maxdict", "maxdeque"):
    setattr(_SUMMARY, _name, 6)


class _Unrepresentable(ValueError):
    """The adapter result has no faithful JSON form."""


class _Budget:
    """Caps the work of one conversion, so a hostile or accidental result stays bounded."""

    def __init__(self) -> None:
        self.nodes = MAX_OUTPUT_NODES
        self.chars = MAX_OUTPUT_CHARS

    def spend(self, chars: int = 0) -> None:
        self.nodes -= 1
        self.chars -= chars
        if self.nodes < 0 or self.chars < 0:
            raise _Unrepresentable(
                f"result too large (more than {MAX_OUTPUT_NODES} values or "
                f"{MAX_OUTPUT_CHARS} characters)"
            )


def _bounded_repr(value: Any) -> str:
    """`repr` cut to MAX_REPR_CHARS; bytes are cut before they are rendered."""
    try:
        if isinstance(value, (bytes, bytearray)) and len(value) > MAX_REPR_CHARS:
            return (
                repr(bytes(value[:MAX_REPR_CHARS]))[:MAX_REPR_CHARS] + "...<truncated>"
            )
        text = repr(value)
    except Exception:  # a hostile or broken __repr__ must not lose the effect
        return f"<unrepresentable {type(value).__name__}>"
    return (
        text
        if len(text) <= MAX_REPR_CHARS
        else text[:MAX_REPR_CHARS] + "...<truncated>"
    )


def _summary(value: Any) -> str:
    """A short, work-bounded description of a whole payload (never expands containers)."""
    try:
        text = _SUMMARY.repr(value)
    except Exception:
        return f"<unrepresentable {type(value).__name__}>"
    return text[:MAX_REPR_CHARS]


def exact_json(
    value: Any,
    _depth: int = 0,
    _budget: Optional[_Budget] = None,
    _path: Optional[set] = None,
) -> Any:
    """Make a payload safe to sign: only integers in i64/u64 range stay numbers.

    The gate refuses signed documents that hold floats or larger integers, because JSON
    text can spell them several ways and the verifier could not tell which was signed. A
    downstream API answer is not under the executor's control, so such numbers become
    strings (`0.1` -> "0.1", a 30-digit integer -> its exact digits) instead of making the
    outcome of an effect that already happened impossible to record.

    Python values JSON has no form for are converted too: `Decimal` -> its exact string
    (`Decimal("19.990")` -> "19.990"), `datetime`/`date`/`time` -> ISO 8601, and anything
    else (bytes, sets, arbitrary objects) -> a bounded `repr`. Raises `_Unrepresentable`
    (see `sanitize_output`) for nesting deeper than MAX_OUTPUT_DEPTH, cycles, more than
    MAX_OUTPUT_NODES values or MAX_OUTPUT_CHARS characters, and two keys that would become
    the same JSON key (`1` and `"1"`).
    """
    budget = _budget if _budget is not None else _Budget()
    path = _path if _path is not None else set()
    if _depth > MAX_OUTPUT_DEPTH:
        raise _Unrepresentable(f"nesting deeper than {MAX_OUTPUT_DEPTH} levels")
    if isinstance(value, bool) or value is None:
        budget.spend()
        return value
    if isinstance(value, str):
        budget.spend(len(value))
        return value
    if isinstance(value, int):
        if _I64_MIN <= value <= _U64_MAX:
            budget.spend()
            return value
        text = str(value)
        budget.spend(len(text))
        return text
    if isinstance(value, float):
        text = repr(value)
        budget.spend(len(text))
        return text
    if isinstance(value, decimal.Decimal):
        text = str(value)
        budget.spend(len(text))
        return text
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        text = value.isoformat()
        budget.spend(len(text))
        return text
    if isinstance(value, (dict, list, tuple)):
        if id(value) in path:
            raise _Unrepresentable("cyclic reference")
        budget.spend()
        path.add(id(value))
        try:
            if isinstance(value, dict):
                converted: dict = {}
                for key, item in value.items():
                    name = key if isinstance(key, str) else str(key)
                    budget.spend(len(name))
                    if name == DEGRADED_MARKER:
                        raise _Unrepresentable(
                            f"the adapter result uses the reserved key {DEGRADED_MARKER}"
                        )
                    if name in converted:
                        raise _Unrepresentable(
                            f"two keys become the same JSON key {_bounded_repr(name)}"
                        )
                    converted[name] = exact_json(item, _depth + 1, budget, path)
                return converted
            return [exact_json(item, _depth + 1, budget, path) for item in value]
        finally:
            path.discard(id(value))
    text = _bounded_repr(value)
    budget.spend(len(text))
    return text


def sanitize_output(payload: Any) -> str:
    """JSON text of an adapter result that can always be signed.

    Criterion: a result the adapter *returned* is evidence about an effect that already
    happened, so a result that cannot be converted (too deep, cyclic, code in the adapter's
    own objects raising in `__repr__` / `__str__` / `isoformat` / `items`, ...) never turns
    into a recorded FAILED: the outcome keeps the adapter's own status and carries a marker
    with a bounded `repr` instead. An exception *raised by the adapter* is a different
    case: a validation failure or other definitive error is recorded FAILED. A
    transport failure where the effect may already have happened (timeout, reset,
    disconnect, TLS, EOF, HTTP 5xx) is recorded UNKNOWN. That choice uses the
    exception type, not the text of the message.
    """
    try:
        return json.dumps(exact_json(payload))
    except (
        Exception
    ) as exc:  # incl. code inside the adapter's own objects (__repr__...)
        reason = str(exc) if isinstance(exc, _Unrepresentable) else type(exc).__name__
        return json.dumps(
            {
                DEGRADED_MARKER: True,
                "reason": f"adapter result not representable as JSON: {reason}",
                "repr": _summary(payload),
            }
        )


class ExecutorRuntimeError(RuntimeError):
    """Base error for runtime and permit verification failures."""


def _reject_duplicate_keys(pairs):
    """object_pairs_hook: a repeated key is an error."""
    seen = {}
    for key, item in pairs:
        if key in seen:
            raise ValueError(
                f"DUPLICATE_JSON_KEY: object key {key!r} appears more than once"
            )
        seen[key] = item
    return seen


def _parse_permit(permit_json: str):
    """The permit object, or None when the text is not JSON.

    Repeated keys raise ExecutorRuntimeError with DUPLICATE_JSON_KEY before the
    permit is consumed. Any other parse failure is left to the Rust executor so
    its existing error text stays the one callers already match.
    """
    try:
        return json.loads(permit_json, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as exc:
        if "DUPLICATE_JSON_KEY" in str(exc):
            raise ExecutorRuntimeError(
                "DUPLICATE_JSON_KEY: permit repeats a JSON object key"
            ) from exc
        return None


class UnknownExecutionError(ExecutorRuntimeError):
    """The outcome is ambiguous (e.g. timeout or 5xx); must not be retried automatically."""

    def __init__(self, observation: str):
        super().__init__(f"Execution outcome is UNKNOWN: {observation}")
        self.observation = observation


class AmbiguousTransportError(ExecutorRuntimeError):
    """Raised by adapters when an external effect outcome cannot be definitively known."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# Errno values classified as an ambiguous transport outcome.
# Connection refused is not included.
_AMBIGUOUS_ERRNOS = frozenset(
    number
    for number in (
        errno.ETIMEDOUT,
        errno.ECONNRESET,
        errno.EPIPE,
        errno.ECONNABORTED,
        getattr(errno, "ENETRESET", None),
        getattr(errno, "WSAETIMEDOUT", None),
        getattr(errno, "WSAECONNRESET", None),
        getattr(errno, "WSAECONNABORTED", None),
    )
    if isinstance(number, int)
)

# Exception types classified as an ambiguous transport outcome.
# ConnectionRefusedError is not included.
_AMBIGUOUS_TYPES = (
    TimeoutError,
    BrokenPipeError,
    ConnectionAbortedError,
    ConnectionResetError,  # http.client.RemoteDisconnected is one of these
    ssl.SSLError,
    EOFError,
    http.client.IncompleteRead,
    http.client.BadStatusLine,
    http.client.RemoteDisconnected,
)


def _http_status(exc: BaseException) -> Optional[int]:
    for name in ("status_code", "code", "status"):
        value = getattr(exc, name, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def is_ambiguous_transport_error(exc: BaseException) -> bool:
    """Whether a transport outcome is ambiguous.

    The decision uses the exception type, an errno on an ``OSError``, or an HTTP
    status stored on the exception. ``URLError.reason`` and ``__cause__`` are
    walked the same way. The message text is not consulted.
    """
    pending = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        status = _http_status(current)
        number = getattr(current, "errno", None)
        if isinstance(current, ConnectionRefusedError):
            pass
        elif isinstance(current, _AMBIGUOUS_TYPES) or (
            isinstance(number, int) and number in _AMBIGUOUS_ERRNOS
        ):
            return True
        elif status is not None and status >= 500:
            return True
        reason = getattr(current, "reason", None)
        if isinstance(reason, BaseException):
            pending.append(reason)
        cause = current.__cause__
        if isinstance(cause, BaseException):
            pending.append(cause)
    return False


class ExecutionResult(NamedTuple):
    """Outcome of an adapter execution."""

    status: str  # "SUCCEEDED" or "FAILED"
    payload: Dict[str, Any]


class ActionAdapter(Protocol):
    """Protocol that all service-specific mediated adapters must implement."""

    @property
    def supported_actions(self) -> Set[str]:
        """Set of action_type strings handled by this adapter."""
        ...

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        """Execute the external effect with isolated credentials and return ExecutionResult.

        An adapter that reads money amounts sets ``reads_currency_exponents = True`` and also
        takes ``currency_exponents``: the signed policy's decimals per currency, empty when it
        names none.
        """
        ...


class ExecutorRuntime:
    """Deep execution engine managing atomic consumption, isolation, and outcome signing."""

    def __init__(
        self,
        executor_db: str,
        executor_keyfile: str,
        trusted_gate_id: str,
        trusted_tenant_id: str,
        executor_pool_size: int = 8,
        gate_db: Optional[str] = None,
    ):
        self._executor_db = executor_db
        self._executor_keyfile = executor_keyfile
        self._trusted_gate_id = trusted_gate_id
        self._trusted_tenant_id = trusted_tenant_id
        self._pool_size = executor_pool_size
        self._gate_db = gate_db
        self._executor = TempusExecutor(
            executor_db,
            executor_keyfile,
            trusted_gate_id,
            trusted_tenant_id,
            executor_pool_size,
            gate_db,
        )

    @property
    def raw_executor(self) -> TempusExecutor:
        """Underlying native TempusExecutor."""
        return self._executor

    def execute_permit(self, permit_json: str, adapter: ActionAdapter) -> str:
        """Enforce atomic permit consumption, invoke adapter, and sign outcome receipt."""
        # The verified intent is the top-level `intent`.
        permit_data = _parse_permit(permit_json)

        # 1. Enforce atomic single-consumption and schema verification
        consumed_auth_str = self._executor.verify_and_consume_permit(permit_json)
        consumed_auth = json.loads(consumed_auth_str)
        auth_id = consumed_auth["authorization_id"]
        action_id = consumed_auth["action_id"]

        try:
            if permit_data is None:
                permit_data = json.loads(permit_json)
            intent = permit_data.get("intent")
            if not isinstance(intent, dict):
                raise ExecutorRuntimeError(
                    "TEMPUS_INVALID_CONTRACT: verified intent must be a JSON object"
                )
            action_type = intent.get("action_type")

            if action_type not in adapter.supported_actions:
                err_code = getattr(
                    adapter, "unsupported_error_code", "ERR_UNSUPPORTED_ACTION"
                )
                error_payload = {
                    "error_code": err_code,
                    "message": f"Action '{action_type}' is not supported by {adapter.__class__.__name__}",
                }
                return self._executor.complete_execution(
                    auth_id,
                    action_id,
                    "FAILED",
                    json.dumps(error_payload),
                )

            # 2. Invoke adapter with isolated credentials
            if getattr(adapter, "reads_currency_exponents", False):
                policy = permit_data.get("policy_bundle")
                constraints = policy.get("constraints") if isinstance(policy, dict) else None
                exponents = (
                    constraints.get("currency_exponents")
                    if isinstance(constraints, dict)
                    else None
                )
                result = adapter.execute_action(intent, currency_exponents=exponents or {})
            else:
                result = adapter.execute_action(intent)
            status = (
                result.status if result.status in {"SUCCEEDED", "FAILED"} else "FAILED"
            )
            output_json = sanitize_output(result.payload)

            # 3. Complete and sign execution receipt
            return self._executor.complete_execution(
                auth_id,
                action_id,
                status,
                output_json,
            )

        except AmbiguousTransportError as exc:
            observation = self._executor.mark_unknown(auth_id, exc.reason)
            raise UnknownExecutionError(observation) from exc
        except UnknownExecutionError:
            raise
        except Exception as exc:
            if is_ambiguous_transport_error(exc):
                observation = self._executor.mark_unknown(
                    auth_id,
                    f"TRANSPORT_AMBIGUOUS: {type(exc).__name__}",
                )
                raise UnknownExecutionError(observation) from exc

            return self._executor.complete_execution(
                auth_id,
                action_id,
                "FAILED",
                json.dumps(
                    {"error_code": "EXECUTION_EXCEPTION", "message": str(exc)}
                ),
            )

    @classmethod
    def run_cli(
        cls,
        description: str,
        adapter_factory: Any,
        argv: Optional[list] = None,
        extra_args_fn: Optional[Any] = None,
    ) -> None:
        """Standard CLI runner for mediated executor entrypoints."""
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("--permit", required=True, help="Path to permit JSON file")
        parser.add_argument(
            "--executor-db", required=True, help="Path to executor SQLite DB"
        )
        parser.add_argument(
            "--executor-keyfile", required=True, help="Path to executor keys JSON"
        )
        parser.add_argument(
            "--gate-id", required=True, help="Trusted Tempus Gate public key"
        )
        parser.add_argument("--tenant-id", required=True, help="Expected tenant ID")
        parser.add_argument(
            "--executor-pool-size", type=int, default=8, help="Connection pool size"
        )
        parser.add_argument(
            "--gate-db",
            default=None,
            help="Optional path to Tempus Gate SQLite DB for revocation and replay verification",
        )

        if extra_args_fn:
            extra_args_fn(parser)

        args = parser.parse_args(argv)

        with open(args.permit, "r", encoding="utf-8") as f:
            permit_content = f.read()

        # Build the adapter first: a configuration the adapter refuses (for example
        # credentials without an allowlist) must stop the process before the permit is
        # read by the runtime, and without a traceback.
        try:
            adapter = adapter_factory(args)
        except Exception as exc:
            print(f"Executor configuration error: {exc}", file=sys.stderr)
            sys.exit(1)

        runtime = cls(
            executor_db=args.executor_db,
            executor_keyfile=args.executor_keyfile,
            trusted_gate_id=args.gate_id,
            trusted_tenant_id=args.tenant_id,
            executor_pool_size=args.executor_pool_size,
            gate_db=args.gate_db,
        )
        try:
            receipt = runtime.execute_permit(permit_content, adapter)
            print(receipt)
        except Exception as exc:
            print(f"Execution failed: {exc}", file=sys.stderr)
            sys.exit(1)
