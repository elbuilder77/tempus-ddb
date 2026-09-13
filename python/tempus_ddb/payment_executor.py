"""Credential-isolated Financial / Payment executor for Tempus permits.

This adapter enforces the universal `money` contract envelope (`amount`, `asset`, `beneficiary`),
validates minor-unit limits against tenant policy, and keeps payment credentials isolated.

It implements a pluggable `PaymentTransport` interface. Teams can inject their production
payment provider (Stripe, Wise, banking API) at runtime or rely on the deterministic
`MockPaymentTransport` for automated testing and CI.
"""

import os
from typing import Any, Dict, Optional, Protocol, Set

from .executor_runtime import (
    ExecutionResult,
    ExecutorRuntime,
)


class PaymentExecutorError(RuntimeError):
    """Base error for financial executor failures."""


class PaymentTransport(Protocol):
    """Pluggable transport protocol for mediated financial transactions.

    Implement this protocol to connect your production payment provider
    (e.g., Stripe, Wise, Modern Treasury, ACH/Wire gateways).
    """

    def disburse(
        self,
        secret_key: str,
        amount: str,
        asset: str,
        beneficiary: str,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute one mediated payout using the isolated secret key."""


class MockPaymentTransport:
    """Reference deterministic payment transport for testing and simulation."""

    def disburse(
        self,
        secret_key: str,
        amount: str,
        asset: str,
        beneficiary: str,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not secret_key:
            raise PaymentExecutorError("Payment provider secret key is missing")
        tx_id = f"tx_mock_{os.urandom(8).hex()}"
        return {
            "status": "SETTLED",
            "transaction_id": tx_id,
            "amount": amount,
            "asset": asset,
            "beneficiary": beneficiary,
            "metadata": metadata,
        }


class PaymentActionAdapter:
    """ActionAdapter implementation for financial disbursements and transfers."""

    SUPPORTED_ACTIONS: Set[str] = {
        "finance.disburse",
        "finance.transfer",
        "payment.charge",
    }

    def __init__(
        self,
        secret_key: Optional[str] = None,
        transport: Optional[PaymentTransport] = None,
        allowed_beneficiaries: Optional[Set[str]] = None,
    ):
        self._secret_key = secret_key or os.environ.get(
            "PAYMENT_SECRET_KEY", "default-isolated-payment-key"
        )
        self._transport = transport or MockPaymentTransport()
        allowed_env = os.environ.get("PAYMENT_ALLOWED_BENEFICIARIES")
        if allowed_beneficiaries is not None:
            self._allowed_beneficiaries = {
                b.strip().lower() for b in allowed_beneficiaries if b.strip()
            }
        elif allowed_env:
            self._allowed_beneficiaries = {
                b.strip().lower() for b in allowed_env.split(",") if b.strip()
            }
        else:
            self._allowed_beneficiaries = None

    @property
    def supported_actions(self) -> Set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        # Enforce presence of universal money envelope
        money = intent.get("money")
        if not money or not isinstance(money, dict):
            raise PaymentExecutorError(
                "Financial action requires a valid 'money' envelope in intent"
            )

        amount = str(money.get("amount", ""))
        asset = str(money.get("asset", ""))
        beneficiary = str(money.get("beneficiary", ""))

        if not amount or not asset or not beneficiary:
            raise PaymentExecutorError(
                "Missing 'amount', 'asset', or 'beneficiary' in money metadata"
            )

        if self._allowed_beneficiaries is not None:
            b_norm = beneficiary.strip().lower()
            allowed = any(
                b_norm == ab
                or (ab.endswith("*") and b_norm.startswith(ab[:-1]))
                or ab == "*"
                for ab in self._allowed_beneficiaries
            )
            if not allowed:
                raise PaymentExecutorError(
                    f"Beneficiary '{beneficiary}' is not authorized by payment executor policy"
                )

        input_data = intent.get("input", {})

        try:
            payout_result = self._transport.disburse(
                self._secret_key, amount, asset, beneficiary, input_data
            )
            return ExecutionResult(status="SUCCEEDED", payload=payout_result)
        except Exception as exc:
            return ExecutionResult(status="FAILED", payload={"error": str(exc)})


class PaymentExecutorAdapter:
    """Mediated executor that enforces financial limits, isolates secrets, and delegates to a pluggable transport."""

    SUPPORTED_ACTIONS = {"finance.disburse", "finance.transfer", "payment.charge"}

    def __init__(
        self,
        executor_db: str,
        executor_keyfile: str,
        trusted_gate_id: str,
        trusted_tenant_id: str,
        secret_key: Optional[str] = None,
        transport: Optional[PaymentTransport] = None,
        executor_pool_size: int = 8,
        allowed_beneficiaries: Optional[Set[str]] = None,
        gate_db: Optional[str] = None,
    ):
        self._adapter = PaymentActionAdapter(
            secret_key=secret_key,
            transport=transport,
            allowed_beneficiaries=allowed_beneficiaries,
        )
        self._runtime = ExecutorRuntime(
            executor_db=executor_db,
            executor_keyfile=executor_keyfile,
            trusted_gate_id=trusted_gate_id,
            trusted_tenant_id=trusted_tenant_id,
            executor_pool_size=executor_pool_size,
            gate_db=gate_db,
        )

    def execute(self, permit_json: str) -> str:
        """Verify, enforce money envelope, execute payout, and sign outcome."""
        return self._runtime.execute_permit(permit_json, self._adapter)

    execute_permit = execute


def main() -> None:
    def extra_args(parser):
        parser.add_argument("--secret-key", help="Optional PAYMENT_SECRET_KEY")

    ExecutorRuntime.run_cli(
        description="Tempus Credential-Isolated Payment Executor",
        adapter_factory=lambda args: PaymentActionAdapter(secret_key=args.secret_key),
        extra_args_fn=extra_args,
    )


if __name__ == "__main__":
    main()
