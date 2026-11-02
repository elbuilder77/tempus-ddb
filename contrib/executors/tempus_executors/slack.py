"""Credential-isolated Slack executor for Tempus permits."""

import json
import os
import re
from typing import Any, Dict, Optional, Protocol, Set
from urllib import error, request

from tempus_ddb._http import RedirectRefused, open_request
from tempus_ddb.executor_runtime import (
    AmbiguousTransportError,
    ExecutionResult,
    ExecutorRuntime,
    is_ambiguous_transport_error,
)

from . import __version__

# One conversation: a Slack ID (public C, private/group G, direct message D) or a #name
# (lowercase letters, digits, `-` and `_`). `resource` is sent as `channel`, which Slack
# also reads as a comma-separated list, so commas, spaces and everything else are refused.
_CHANNEL_ID = re.compile(r"[CGD][A-Z0-9]{2,31}", re.ASCII)
_CHANNEL_NAME = re.compile(r"#[a-z0-9][a-z0-9_-]{0,79}", re.ASCII)


def _valid_channel(channel: Any) -> bool:
    return isinstance(channel, str) and bool(
        _CHANNEL_ID.fullmatch(channel) or _CHANNEL_NAME.fullmatch(channel)
    )


class SlackExecutorError(RuntimeError):
    """Base error for Slack executor failures."""


class SlackTransport(Protocol):
    """Transport protocol for Slack API requests."""

    def request(
        self, endpoint: str, token: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute one Slack API call."""


class UrllibSlackTransport:
    """Builtin HTTPS Slack transport."""

    API_BASE = "https://slack.com/api/"

    def request(
        self, endpoint: str, token: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        url = f"{self.API_BASE}{endpoint.lstrip('/')}"
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"Tempus-Slack-Executor/{__version__}",
        }
        req = request.Request(url, data=data, headers=headers, method="POST")
        try:
            with open_request(req, timeout=30) as response:  # nosec B310
                raw = response.read().decode("utf-8")
                parsed = json.loads(raw)
                if not parsed.get("ok", False):
                    raise SlackExecutorError(
                        f"Slack API error: {parsed.get('error', 'unknown')}"
                    )
                return parsed
        except RedirectRefused as exc:
            raise SlackExecutorError(f"Slack transport failed: {exc}") from exc
        except error.HTTPError as exc:
            if exc.code >= 500:
                raise AmbiguousTransportError(
                    f"SLACK_SERVER_RESPONSE_{exc.code}"
                ) from exc
            err_body = exc.read().decode("utf-8", errors="replace")
            raise SlackExecutorError(
                f"Slack HTTP error {exc.code}: {err_body}"
            ) from exc
        except AmbiguousTransportError:
            raise
        except Exception as exc:
            if is_ambiguous_transport_error(exc):
                raise AmbiguousTransportError(
                    f"SLACK_TRANSPORT_AMBIGUOUS: {type(exc).__name__}"
                ) from exc
            raise SlackExecutorError(f"Slack transport failed: {exc}") from exc


class SlackActionAdapter:
    """ActionAdapter implementation for Slack API notifications and messages."""

    SUPPORTED_ACTIONS: Set[str] = {"slack.post_message", "slack.send_alert"}

    def __init__(
        self,
        token: Optional[str] = None,
        transport: Optional[SlackTransport] = None,
    ):
        self._token = token or os.environ.get("SLACK_BOT_TOKEN")
        self._transport = transport or UrllibSlackTransport()

    @property
    def supported_actions(self) -> Set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        if not self._token:
            raise SlackExecutorError("SLACK_BOT_TOKEN must be provided to the executor")

        channel = intent.get("resource")
        if not _valid_channel(channel):
            return ExecutionResult(
                status="FAILED",
                payload={
                    "error_code": "TEMPUS_SLACK_BINDING_REJECTED",
                    "message": (
                        "Slack resource must be exactly one channel: an ID such as "
                        "C0123ABCD (C, G or D + uppercase letters/digits) or a "
                        "#channel-name (lowercase letters, digits, - and _), "
                        "without commas or spaces"
                    ),
                },
            )
        input_data = intent.get("input", {})
        text = input_data.get("text") or input_data.get("message")
        if not text:
            raise SlackExecutorError("Missing 'text' or 'message' field in input")

        slack_payload = {
            "channel": channel,
            "text": text,
        }
        if "blocks" in input_data:
            slack_payload["blocks"] = input_data["blocks"]

        try:
            res = self._transport.request(
                "chat.postMessage", self._token, slack_payload
            )
            output_payload = {
                "channel": channel,
                "ts": res.get("ts"),
                "message_id": res.get("message", {}).get("ts"),
            }
            return ExecutionResult(status="SUCCEEDED", payload=output_payload)
        except AmbiguousTransportError:
            raise
        except Exception as exc:
            if is_ambiguous_transport_error(exc):
                raise AmbiguousTransportError(
                    f"SLACK_TRANSPORT_AMBIGUOUS: {type(exc).__name__}"
                ) from exc
            return ExecutionResult(status="FAILED", payload={"error": str(exc)})


class SlackExecutorAdapter:
    """Mediated executor for Slack notifications and alerts."""

    SUPPORTED_ACTIONS = {"slack.post_message", "slack.send_alert"}

    def __init__(
        self,
        executor_db: str,
        executor_keyfile: str,
        trusted_gate_id: str,
        trusted_tenant_id: str,
        token: Optional[str] = None,
        transport: Optional[SlackTransport] = None,
        executor_pool_size: int = 8,
        gate_db: Optional[str] = None,
    ):
        self._adapter = SlackActionAdapter(token=token, transport=transport)
        self._runtime = ExecutorRuntime(
            executor_db=executor_db,
            executor_keyfile=executor_keyfile,
            trusted_gate_id=trusted_gate_id,
            trusted_tenant_id=trusted_tenant_id,
            executor_pool_size=executor_pool_size,
            gate_db=gate_db,
        )

    def execute(self, permit_json: str) -> str:
        """Verify permit, post to Slack with isolated token, and sign outcome."""
        return self._runtime.execute_permit(permit_json, self._adapter)

    execute_permit = execute


def main() -> None:
    def extra_args(parser):
        parser.add_argument("--token", help="Optional SLACK_BOT_TOKEN")

    ExecutorRuntime.run_cli(
        description="Tempus Credential-Isolated Slack Executor",
        adapter_factory=lambda args: SlackActionAdapter(token=args.token),
        extra_args_fn=extra_args,
    )


if __name__ == "__main__":
    main()
