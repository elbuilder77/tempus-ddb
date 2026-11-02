"""The HTTP executor allowlist matches on component boundaries.

A `*` is a whole component split on `/` and `.`. A `*` that is not its own
component matches nothing. The gate-side policy patterns are covered by
`tests/test_pattern_boundaries.py` in the repository root.
"""

import pytest
from tempus_executors.http import HttpExecutorError, _validate_https_url


def _allows(url, domains):
    _validate_https_url(url, domains)


def _refuses(url, domains):
    with pytest.raises(HttpExecutorError, match="allowed domains"):
        _validate_https_url(url, domains)


def test_exact_host_matches_only_that_host():
    _allows("https://api.example.com/v1", {"api.example.com"})
    _refuses("https://api.example.com.evil.com/v1", {"api.example.com"})
    _refuses("https://foo.api.example.com/v1", {"api.example.com"})
    _refuses("https://evilexample.com/v1", {"example.com"})


def test_star_domain_matches_subdomains_only():
    domains = {"*.example.com"}
    _allows("https://a.example.com/v1", domains)
    _allows("https://a.b.example.com/x", domains)
    _refuses("https://example.com/v1", domains)
    _refuses("https://evilexample.com/v1", domains)
    _refuses("https://example.com.evil.com/v1", domains)
    _refuses("https://a.example.com.evil.com/v1", domains)


def test_glued_host_star_matches_nothing():
    domains = {"host*"}
    _refuses("https://host.evil.com/v1", domains)
    _refuses("https://host.example/v1", domains)
    _refuses("https://api.example.com.evil.com/x", {"api.example.com*"})
    _refuses("https://api.example.com/x", {"api.example.com*"})


def test_bare_star_allowlist_still_matches_a_public_host():
    _allows("https://api.example.com/v1", {"*"})
