"""Unified Mediated Executor Runtime for Tempus B2A Security Gate.

This module provides the deep ExecutorRuntime engine and ActionAdapter interface
to ensure all mediated executors enforce identical permit verification, atomic
single-consumption, credential isolation, and fail-closed crash recovery.
"""

import argparse
import json
import sys
from typing import Any, Dict, NamedTuple, Optional, Protocol, Set

from ._tempus_ddb import TempusExecutor


class ExecutorRuntimeError(RuntimeError):
    """Base error for runtime and permit verification failures."""


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
        """Execute the external effect with isolated credentials and return ExecutionResult."""
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
        # 1. Enforce atomic single-consumption and schema verification
        consumed_auth_str = self._executor.verify_and_consume_permit(permit_json)
        consumed_auth = json.loads(consumed_auth_str)
        auth_id = consumed_auth["authorization_id"]
        action_id = consumed_auth["action_id"]

        try:
            permit_data = json.loads(permit_json)
            intent = permit_data.get("intent") or permit_data.get(
                "authorization", {}
            ).get("intent", {})
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
            result = adapter.execute_action(intent)
            status = (
                result.status if result.status in {"SUCCEEDED", "FAILED"} else "FAILED"
            )
            output_json = json.dumps(result.payload)

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
            err_msg = str(exc)
            # Check if this was a fatal network ambiguity
            if (
                "500" in err_msg
                or "timeout" in err_msg.lower()
                or "socket" in err_msg.lower()
                or "connection reset" in err_msg.lower()
            ):
                observation = self._executor.mark_unknown(
                    auth_id,
                    f"TRANSPORT_AMBIGUOUS: {exc.__class__.__name__}",
                )
                raise UnknownExecutionError(observation) from exc

            return self._executor.complete_execution(
                auth_id,
                action_id,
                "FAILED",
                json.dumps({"error_code": "EXECUTION_EXCEPTION", "message": err_msg}),
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

        runtime = cls(
            executor_db=args.executor_db,
            executor_keyfile=args.executor_keyfile,
            trusted_gate_id=args.gate_id,
            trusted_tenant_id=args.tenant_id,
            executor_pool_size=args.executor_pool_size,
            gate_db=args.gate_db,
        )

        adapter = adapter_factory(args)
        try:
            receipt = runtime.execute_permit(permit_content, adapter)
            print(receipt)
        except Exception as exc:
            print(f"Execution failed: {exc}", file=sys.stderr)
            sys.exit(1)
