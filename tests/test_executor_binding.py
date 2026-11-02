"""An executor sends exactly the value it validated (and the policy evaluated).

Audit of the packaged executors for the pattern "policy/validation reads X, the request
uses Y": the GitHub executor accepted `.`/`..` as owner or repository (the request path
then left `/repos/<owner>/<repo>`). The HTTP and payment cases are in
`contrib/executors/tests/test_executor_binding.py`.
"""

import pytest
from tempus_ddb.github_executor import GitHubActionAdapter


class Recorder:
    def __init__(self):
        self.calls = []

    def request(self, *args):
        self.calls.append(args)
        return {"ok": True, "id": 1}


@pytest.mark.parametrize(
    "resource", ["acme/..", "../repo", "./repo", "acme/.", "../..", "acme/a..b/"[:-1]]
)
def test_github_executor_refuses_dot_segments_but_keeps_dotted_names(resource):
    recorder = Recorder()
    adapter = GitHubActionAdapter(token="t", transport=recorder)
    result = adapter.execute_action(
        {
            "action_type": "github.create_issue",
            "resource": resource,
            "input": {"title": "x"},
        }
    )
    if (
        resource == "acme/a..b"
    ):  # a name that merely contains dots is a valid repository
        assert result.status == "SUCCEEDED"
        assert recorder.calls[0][1].endswith("/repos/acme/a..b/issues")
    else:
        assert result.status == "FAILED"
        assert result.payload["error_code"] == "TEMPUS_GITHUB_BINDING_REJECTED"
        assert recorder.calls == []
