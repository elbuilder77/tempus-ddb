"""Credential-isolated Slack executor for Tempus permits."""

import json
import os
from typing import Any, Dict, Optional, Protocol, Set
from urllib import error, request

from . import __version__
from .executor_runtime import (
    ExecutionResult,
    ExecutorRuntime,
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

    def request(
        self, endpoint: str, token: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        url = f"https://slack.com/api/{endpoint.lstrip('/')}"
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"Tempus-Slack-Executor/{__version__}",
        }
        req = request.Request(url, data=data, headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=30) as response:  # nosec B310
                raw = response.read().decode("utf-8")
                parsed = json.loads(raw)
                if not parsed.get("ok", False):
                    raise SlackExecutorError(
                        f"Slack API error: {parsed.get('error', 'unknown')}"
                    )
                return parsed
        except error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise SlackExecutorError(
                f"Slack HTTP error {exc.code}: {err_body}"
            ) from exc
        except Exception as exc:
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
        except Exception as exc:
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
