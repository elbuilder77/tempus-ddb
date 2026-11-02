"""Conformance tests for the GitHub reference adapter and a third-party adapter.

The HTTP, Slack and payment adapters live in `contrib/executors/`; their conformance
tests are in `contrib/executors/tests/test_conformance.py`.
"""

from typing import Any, Dict, Set

from tempus_ddb import GitHubActionAdapter
from tempus_ddb.executor_runtime import ExecutionResult
from tempus_ddb.testing import AdapterConformanceHarness


class MockGitHubTransport:
    def request(self, method, url, headers, payload):
        return {
            "id": 1234,
            "number": 99,
            "html_url": "https://github.com/acme/repo/issues/99",
        }


class CustomDatabaseAdapter:
    """Example third-party adapter showing how to build secure DB executors in < 30 lines."""

    SUPPORTED_ACTIONS: Set[str] = {"db:insert_user", "db:update_status"}

    @property
    def supported_actions(self) -> Set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        # Mock database query execution
        query_input = intent.get("input", {})
        return ExecutionResult(
            status="SUCCEEDED",
            payload={"rows_affected": 1, "query_echo": query_input},
        )


def test_github_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: GitHubActionAdapter(
            token="ghp_mock_token_12345",
            transport=MockGitHubTransport(),
        ),
        valid_action_type="github.create_issue",
        valid_resource="acme/widget-repo",
        valid_input={"title": "Test Conformance Issue", "body": "Testing"},
    )
    harness.run_all_checks()


def test_custom_database_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: CustomDatabaseAdapter(),
        valid_action_type="db:insert_user",
        valid_resource="db://users_table",
        valid_input={"username": "alice", "role": "admin"},
    )
    harness.run_all_checks()
