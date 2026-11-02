"""An executor sends exactly the value it validated (and the policy evaluated).

Audit of the packaged executors for the pattern "policy/validation reads X, the request
uses Y": the HTTP executor validated `resource.strip()` and requested the raw string,
Python's URL parser drops tabs/newlines that urllib keeps, URLs may carry credentials,
and the payment allowlist compared a lower-cased, stripped beneficiary while the
transport received the original one. The GitHub case (`.`/`..` as owner or repository)
is covered by `tests/test_executor_binding.py` in the repository root.
"""

import pytest
from tempus_executors.http import HttpActionAdapter, HttpExecutorError
from tempus_executors.payment import PaymentActionAdapter, PaymentExecutorError


class Recorder:
    def __init__(self):
        self.calls = []

    def request(self, *args):
        self.calls.append(args)
        return {"ok": True, "id": 1}

    def disburse(self, *args):
        self.calls.append(args)
        return {"status": "SETTLED"}


HTTP_REFUSED = [
    " https://api.example.com/hook",
    "https://api.example.com/hook ",
    "https://api.example.com/hook\n",
    "https://api.exam\tple.com/hook",
    "https://api.example.com/ho\rok",
    "https://api.example.com\\@evil.example.net/hook",
    "https://user:secret@api.example.com/hook",
    "https://api.example.com@evil.example.net/hook",
    "https://api.example.com/\x00hook",
]


@pytest.mark.parametrize("url", HTTP_REFUSED, ids=[repr(u) for u in HTTP_REFUSED])
def test_http_executor_refuses_urls_that_parse_differently_from_how_they_are_sent(url):
    recorder = Recorder()
    adapter = HttpActionAdapter(transport=recorder, allowed_domains={"api.example.com"})
    with pytest.raises(HttpExecutorError):
        adapter.execute_action(
            {"action_type": "http.post", "resource": url, "input": {}}
        )
    assert recorder.calls == []


def test_http_executor_still_sends_a_plain_url_unchanged():
    recorder = Recorder()
    adapter = HttpActionAdapter(transport=recorder, allowed_domains={"api.example.com"})
    adapter.execute_action(
        {
            "action_type": "http.post",
            "resource": "https://api.example.com/v1/hook?x=1",
            "input": {"a": 1},
        }
    )
    assert recorder.calls[0][1] == "https://api.example.com/v1/hook?x=1"


@pytest.mark.parametrize(
    "beneficiary", [" alice", "alice ", "ALICE", "Alice", "alice\n"]
)
def test_payment_allowlist_compares_the_value_the_transport_receives(beneficiary):
    recorder = Recorder()
    adapter = PaymentActionAdapter(transport=recorder, allowed_beneficiaries={"alice"})
    with pytest.raises(PaymentExecutorError):
        adapter.execute_action(
            {
                "action_type": "payment.charge",
                "money": {"amount": "1.00", "asset": "USD", "beneficiary": beneficiary},
            }
        )
    assert recorder.calls == []


def test_payment_allowlist_matches_exact_values_and_component_wildcards():
    accepted = (({"alice"}, "alice"), ({"vendor/*"}, "vendor/42"), ({"*"}, "vendor-42"))
    for allowed, beneficiary in accepted:
        recorder = Recorder()
        adapter = PaymentActionAdapter(
            transport=recorder, allowed_beneficiaries=allowed
        )
        result = adapter.execute_action(
            {
                "action_type": "payment.charge",
                "money": {"amount": "1.00", "asset": "USD", "beneficiary": beneficiary},
            }
        )
        assert result.status == "SUCCEEDED"
        assert recorder.calls[0][3] == beneficiary

    recorder = Recorder()
    adapter = PaymentActionAdapter(
        transport=recorder, allowed_beneficiaries={"vendor-*"}
    )
    with pytest.raises(PaymentExecutorError):
        adapter.execute_action(
            {
                "action_type": "payment.charge",
                "money": {"amount": "1.00", "asset": "USD", "beneficiary": "vendor-42"},
            }
        )
    assert recorder.calls == []
