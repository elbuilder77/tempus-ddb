"""Credential-isolated Financial / Payment executor for Tempus permits.

This adapter enforces the universal `money` contract envelope (`amount` or `amount_minor`, `asset` or `currency`, `beneficiary`),
validates minor-unit limits against tenant policy, and keeps payment credentials isolated.

It implements a pluggable `PaymentTransport` interface. Teams can inject their production
payment provider (Stripe, Wise, banking API) at runtime or rely on the deterministic
`MockPaymentTransport` for automated testing and CI.
"""

import os
import re
from typing import Any, Dict, Optional, Protocol, Set, Tuple

from tempus_ddb.executor_runtime import (
    AmbiguousTransportError,
    ExecutionResult,
    ExecutorRuntime,
    is_ambiguous_transport_error,
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


# ASCII digits only (`\d` would take any Unicode digit); same grammar as the gate's
# `parse_minor_units`: a `.` needs a digit, there are no more fractional digits than the
# currency has decimals, and minor units fit in a u64.
_DECIMAL_AMOUNT = re.compile(r"([0-9]+)(?:\.([0-9]+))?")
_DEFAULT_EXPONENT = 2
_MAX_EXPONENT = 8
_DIGIT_WORDS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight")
# Same rule as the gate: an exact 3-letter code.
_EXACT_CURRENCY = re.compile(r"[A-Z]{3}")
_U64_MAX = 2**64 - 1


def _exponent(currency_exponents: Optional[Dict[str, Any]], asset: str) -> int:
    """The decimals of a currency in the signed policy (`phase3::currency_exponent`)."""
    if not currency_exponents or asset not in currency_exponents:
        return _DEFAULT_EXPONENT
    exponent = currency_exponents[asset]
    if (
        isinstance(exponent, bool)
        or not isinstance(exponent, int)
        or not 0 <= exponent <= _MAX_EXPONENT
    ):
        raise PaymentExecutorError(
            f"currency_exponents.{asset} must be an integer from 0 to {_MAX_EXPONENT}"
        )
    return exponent


def _minor_units(text: str, exponent: int = _DEFAULT_EXPONENT) -> int:
    """Minor units of a decimal amount string, or PaymentExecutorError."""
    match = _DECIMAL_AMOUNT.fullmatch(text)
    fractional = (match.group(2) or "") if match else ""
    if not match or len(fractional) > exponent:
        digits = f"at most {_DIGIT_WORDS[exponent]}" if exponent else "no"
        raise PaymentExecutorError(
            f"money.amount must be an unsigned decimal with {digits} fractional digits"
        )
    whole = match.group(1).lstrip("0") or "0"
    if len(whole) > 20:  # also keeps int() away from absurdly long digit strings
        raise PaymentExecutorError("money.amount is too large")
    minor = int(whole) * 10**exponent + int(fractional.ljust(exponent, "0") or "0")
    if minor > _U64_MAX:
        raise PaymentExecutorError("money.amount is too large")
    return minor


def _format_minor(minor: int, exponent: int) -> str:
    if not exponent:
        return str(minor)
    scale = 10**exponent
    return f"{minor // scale}.{minor % scale:0{exponent}d}"


def canonical_money(
    money: Dict[str, Any], currency_exponents: Optional[Dict[str, Any]] = None
) -> Tuple[str, str]:
    """(amount, asset) exactly as the gate's policy reads them (`phase3::validate_money`).

    `amount` / `amount_minor` are two spellings of one value and `currency` / `asset` two
    names of one field. The policy evaluates whichever is present, so an executor must not
    send one while the policy evaluated the other: if both spellings are present they must
    agree, and a field of the wrong type is an error, never skipped. `currency_exponents`
    is the signed policy's: a currency it does not name has two decimals.
    """
    names = {}
    for field in ("currency", "asset"):
        if field in money:
            value = money[field]
            if not isinstance(value, str) or not value:
                raise PaymentExecutorError(f"money.{field} must be a non-empty string")
            if _EXACT_CURRENCY.fullmatch(value) is None:
                raise PaymentExecutorError(
                    f"money.{field} must be an exact 3-letter currency code"
                )
            names[field] = value
    if not names:
        raise PaymentExecutorError("Missing 'asset' (or 'currency') in money")
    if len(set(names.values())) > 1:
        raise PaymentExecutorError(
            "money.currency and money.asset must be the same value"
        )
    asset = next(iter(names.values()))

    text = money.get("amount")
    minor = money.get("amount_minor")
    if text is not None and not isinstance(text, str):
        raise PaymentExecutorError("money.amount must be a decimal string")
    if "amount_minor" in money and (
        isinstance(minor, bool)
        or not isinstance(minor, int)
        or not 0 <= minor <= _U64_MAX
    ):
        raise PaymentExecutorError("money.amount_minor must be an unsigned integer")
    exponent = _exponent(currency_exponents, asset)
    from_text = _minor_units(text, exponent) if text is not None else None
    if from_text is not None and minor is not None and from_text != minor:
        raise PaymentExecutorError(
            f"money.amount ({from_text} minor units) and money.amount_minor ({minor}) disagree"
        )
    if text is not None:
        return text, asset
    if minor is None:
        raise PaymentExecutorError("Missing 'amount' (or 'amount_minor') in money")
    return _format_minor(minor, exponent), asset


def component_pattern_matches(pattern: str, candidate: str) -> bool:
    """Whether ``pattern`` matches ``candidate`` the way the policy does.

    The same component rules as ``phase3::pattern_matches``: ``*`` matches only
    as a whole component split on ``.`` and ``/``. A ``*`` glued to text matches
    nothing, so a pattern that no longer applies authorizes nobody.
    """
    if pattern == "*" or pattern == candidate:
        return True
    pattern_pieces = _component_pieces(pattern, wildcards=True)
    candidate_pieces = _component_pieces(candidate, wildcards=False)
    if pattern_pieces is None or candidate_pieces is None:
        return False
    return _pieces_match(pattern_pieces, candidate_pieces)


def _component_pieces(value: str, wildcards: bool):
    pieces = []
    start = 0
    for index, char in enumerate(value):
        if char in "./":
            if start < index and not _push_piece(pieces, value[start:index], wildcards):
                return None
            pieces.append(("sep", char))
            start = index + 1
    if start < len(value) and not _push_piece(pieces, value[start:], wildcards):
        return None
    return pieces


def _push_piece(pieces, text: str, wildcards: bool) -> bool:
    if wildcards and "*" in text:
        if text != "*":
            return False
        pieces.append(("wild",))
    else:
        pieces.append(("text", text))
    return True


def _pieces_match(pattern, candidate) -> bool:
    if not pattern:
        return not candidate
    head, rest = pattern[0], pattern[1:]
    kind = head[0]
    if kind == "wild":
        return _wildcard_matches(rest, candidate)
    if kind == "sep":
        return bool(candidate) and candidate[0] == head and _pieces_match(rest, candidate[1:])
    if kind == "text":
        return bool(candidate) and candidate[0] == head and _pieces_match(rest, candidate[1:])
    return False


def _wildcard_matches(rest, candidate) -> bool:
    if not rest:
        return bool(candidate)
    bound = rest[0][1] if rest[0][0] == "sep" else None
    index = 0
    texts = 0
    while index < len(candidate):
        kind = candidate[index][0]
        if kind == "text":
            texts += 1
            index += 1
            if _pieces_match(rest, candidate[index:]):
                return True
        elif kind == "sep":
            if texts == 0 or bound != candidate[index][1]:
                return False
            index += 1
        else:
            return False
    return False


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
                b.strip() for b in allowed_beneficiaries if b.strip()
            }
        elif allowed_env:
            self._allowed_beneficiaries = {
                b.strip() for b in allowed_env.split(",") if b.strip()
            }
        else:
            self._allowed_beneficiaries = None

    # Amounts mean what the signed policy says: the runtime passes its `currency_exponents`.
    reads_currency_exponents = True

    @property
    def supported_actions(self) -> Set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(
        self,
        intent: Dict[str, Any],
        currency_exponents: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        # Enforce presence of universal money envelope
        money = intent.get("money")
        if not money or not isinstance(money, dict):
            raise PaymentExecutorError(
                "Financial action requires a valid 'money' envelope in intent"
            )

        # The same reading the policy evaluated, never a field it skipped.
        amount, asset = canonical_money(money, currency_exponents)
        if _minor_units(amount, _exponent(currency_exponents, asset)) == 0:
            raise PaymentExecutorError("a payment action requires a non-zero amount")
        # Paid exactly as written: never str() of a null/number/list ("None" was paid).
        beneficiary = money.get("beneficiary")
        if not isinstance(beneficiary, str) or not beneficiary:
            raise PaymentExecutorError("money.beneficiary must be a non-empty string")

        if self._allowed_beneficiaries is not None:
            # Compare the value the transport will receive, as written: no strip or
            # case-folding that would let "ALICE " pass for "alice" and then be paid as is.
            # Wildcards are the policy's component rules, not a textual prefix.
            allowed = any(
                component_pattern_matches(ab, beneficiary)
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
        except AmbiguousTransportError:
            raise
        except Exception as exc:
            if is_ambiguous_transport_error(exc):
                raise AmbiguousTransportError(
                    f"PAYMENT_TRANSPORT_AMBIGUOUS: {type(exc).__name__}"
                ) from exc
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
