"""S1: Slack `resource` is exactly one channel.

Slack's `channel` parameter accepts a comma-separated list, so a policy of `C0123*` let
`C0123,C9999` and `#alerts,#general` through to several conversations. Attacks come from
the forge-5 audit (`audit_gs.py`).
"""

import pytest
from tempus_executors.slack import SlackActionAdapter


class Transport:
    def __init__(self):
        self.sent = []

    def request(self, endpoint, token, payload):
        self.sent.append(payload)
        return {"ok": True, "ts": "1.2", "message": {"ts": "1.2"}}


def _run(resource):
    transport = Transport()
    adapter = SlackActionAdapter(token="xoxb-test", transport=transport)
    result = adapter.execute_action(
        {
            "action_type": "slack.post_message",
            "resource": resource,
            "input": {"text": "hi"},
        }
    )
    return result, transport


GOOD = [
    "C0123",
    "C0123ABCD",
    "CABCDEFGHIJ",
    "G0123ABCD",
    "D0123ABCD",
    "C123",
    "#alerts",
    "#alerts-prod",
    "#security_alerts",
    "#a",
    "#team-2",
]

BAD = [
    "C0123,C9999",
    "#alerts,#general",
    "C0123 C9999",
    "C0123,",
    ",C0123",
    "C0123\n",
    "C0123\x00",
    "c0123",
    "C0123 ",
    " C0123",
    "#ALERTS",
    "#alerts general",
    "#alerts\n",
    "#alerts\x00",
    "#",
    "##alerts",
    "#-alerts",
    "alerts",
    "@someone",
    "U0123ABCD",
    "W0123ABCD",
    "C0123;C9999",
    "C0123/../C9999",
    "C0123\u200b",
    "C0123\u202e",
    "C0123\ud7ff",
    "C\u0661\u0662\u0663",
    "#alerts\u200b",
    "#\u0430lerts",
    "#alerts.prod",
    "#" + "a" * 81,
    "",
    "C",
    "CA",
    None,
    123,
    ["C0123", "C9999"],
]


@pytest.mark.parametrize("resource", GOOD)
def test_a_single_channel_is_posted(resource):
    result, transport = _run(resource)
    assert result.status == "SUCCEEDED"
    assert [payload["channel"] for payload in transport.sent] == [resource]


@pytest.mark.parametrize("resource", BAD)
def test_anything_else_is_rejected_before_calling_slack(resource):
    result, transport = _run(resource)
    assert result.status == "FAILED"
    assert result.payload["error_code"] == "TEMPUS_SLACK_BINDING_REJECTED"
    assert "exactly one channel" in result.payload["message"]
    assert transport.sent == [], "nothing may reach Slack"
