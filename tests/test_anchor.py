"""`tempus anchor`: proofs from a local log and timestamp authority, over real HTTP, and
timestamp tokens that get one thing wrong. Real services' answers are covered by the vectors
in `tests/vectors/anchor/`; nothing here touches the network beyond localhost."""

import base64
import datetime as dt
import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest
from tempus_ddb import (
    TempusDDB,
    anchor_checkpoint_digest,
    create_anchor,
    gen_keys,
    verify_anchor,
    verify_bundle,
)
from tempus_ddb.anchor import AnchorError, checkpoint_from_text
from tempus_ddb.cli import _format_micros
from test_cli import run_cli

_spec = importlib.util.spec_from_file_location(
    "anchor_test_authority",
    Path(__file__).resolve().parents[1] / "scripts" / "anchor_test_authority.py",
)
authority_module = importlib.util.module_from_spec(_spec)
sys.modules["anchor_test_authority"] = authority_module
_spec.loader.exec_module(authority_module)

Authority = authority_module.Authority
issue = authority_module.issue
make_response = authority_module.make_response
make_token = authority_module.make_token
new_key = authority_module.new_key
UTC = dt.timezone.utc
NOW = dt.datetime.now(UTC)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    """A gate with one action, its checkpoint and its evidence bundle, as files."""
    root = tmp_path_factory.mktemp("anchor")
    gate_keys, agent_keys = root / "gate.keys.json", root / "agent.keys.json"
    gen_keys(str(gate_keys))
    gen_keys(str(agent_keys))
    gate_id = json.loads(gate_keys.read_text())["public_key"]
    agent_id = json.loads(agent_keys.read_text())["public_key"]
    gate = TempusDDB(str(root / "gate.db"), str(gate_keys))
    gate.register_agent(gate_id, "gate", json.dumps({"can_delegate": True}))
    gate.install_allow_all_dev_policy()
    gate.register_agent(agent_id, "agent", "{}")
    permit = json.loads(
        gate.request_action(
            json.dumps(
                {
                    "schema_version": "tempus.action-intent.v1",
                    "tenant_id": "acme",
                    "agent_id": agent_id,
                    "idempotency_key": "report-1",
                    "action_type": "report.read",
                    "resource": "reports/q3",
                    "requested_at": time.time_ns() // 1_000,
                    "input": {},
                }
            ),
            str(agent_keys),
            3_600,
        )
    )
    action_id = permit["authorization"]["action_id"]
    checkpoint = gate.create_checkpoint("acme")
    bundle = gate.export_bundle(action_id, None)
    other = gate.create_checkpoint("acme")
    (root / "checkpoint.json").write_text(checkpoint, encoding="utf-8")
    (root / "other.json").write_text(other, encoding="utf-8")
    (root / "bundle.json").write_text(bundle, encoding="utf-8")
    yield {
        "root": root,
        "gate_id": gate_id,
        "checkpoint": checkpoint,
        "checkpoint_file": str(root / "checkpoint.json"),
        "other": other,
        "bundle": bundle,
        "bundle_file": str(root / "bundle.json"),
        "digest": anchor_checkpoint_digest(checkpoint),
    }
    del gate


@pytest.fixture(scope="module")
def authority():
    return Authority()


@pytest.fixture
def fresh():
    """An authority a test may reconfigure."""
    return Authority()


def anchor_document(world, proofs):
    checkpoint = json.loads(world["checkpoint"])
    return {
        "schema_version": "tempus.anchor.v1",
        "checkpoint_id": checkpoint["checkpoint_id"],
        "tenant_id": checkpoint["tenant_id"],
        "checkpoint_digest": world["digest"],
        "proofs": proofs,
    }


def write_roots(authority, directory):
    log = directory / "log.pem"
    root = directory / "tsa_root.pem"
    log.write_text(authority.roots()["rekor_public_keys"][0], encoding="utf-8")
    root.write_text(authority.roots()["tsa_roots"][0], encoding="utf-8")
    return ["--rekor-public-key", str(log), "--tsa-root", str(root)]


# ---------------------------------------------------------------- create, over HTTP


def test_create_gets_a_proof_from_each_backend_and_they_verify(world, authority):
    with authority.serve() as (rekor, tsa):
        document, failures = create_anchor(world["checkpoint"], rekor_url=rekor, tsa_url=tsa)
    assert failures == {}
    assert [proof["backend"] for proof in document["proofs"]] == ["rekor", "rfc3161"]
    assert document["checkpoint_digest"] == world["digest"]
    result = json.loads(
        verify_anchor(json.dumps(document), world["checkpoint"], authority.roots_json())
    )
    assert result["status"] == "VERIFIED", result
    assert [proof["status"] for proof in result["proofs"]] == ["VERIFIED", "VERIFIED"]
    assert result["anchored_at"] <= (time.time_ns() // 1_000)
    assert any("TSA_REVOCATION" in entry for entry in result["not_checked"])


def test_the_anchor_alone_dates_bytes_and_says_it_did_not_check_the_gate(
    world, authority, tmp_path
):
    forged = {**json.loads(world["checkpoint"]), "signature": "00" * 64}
    forged_json = json.dumps(forged)
    digest = anchor_checkpoint_digest(forged_json)
    document = {
        **anchor_document(world, [authority.rekor_proof(digest)]),
        "checkpoint_digest": digest,
    }
    result = json.loads(verify_anchor(json.dumps(document), forged_json, authority.roots_json()))
    assert result["status"] == "VERIFIED", result
    assert any("CHECKPOINT_SIGNATURE" in entry for entry in result["not_checked"])

    anchor, checkpoint = tmp_path / "anchor.json", tmp_path / "checkpoint.json"
    anchor.write_text(json.dumps(document), encoding="utf-8")
    checkpoint.write_text(forged_json, encoding="utf-8")
    code, stdout, stderr = run_cli(
        ["anchor", "verify", "--anchor", str(anchor), "--checkpoint", str(checkpoint)]
        + write_roots(authority, tmp_path),
        cwd=tmp_path,
    )
    assert code == 0, stdout + stderr
    assert "These checkpoint bytes existed no later than" in stderr
    assert "not checked here" in stderr


def test_informational_fields_still_have_a_type(world, authority):
    for backend, field, value in (
        ("rekor", "log_url", 7),
        ("rekor", "entry_uuid", ["x"]),
        ("rfc3161", "tsa_url", 7),
    ):
        proof = (
            authority.rekor_proof(world["digest"])
            if backend == "rekor"
            else {
                "backend": "rfc3161",
                "token": base64.b64encode(authority.token(bytes.fromhex(world["digest"]))).decode(),
            }
        )
        proof[field] = value
        result = json.loads(
            verify_anchor(
                json.dumps(anchor_document(world, [proof])),
                world["checkpoint"],
                authority.roots_json(),
            )
        )
        assert result["status"] == "INVALID", result
        assert f"ANCHOR_MALFORMED (anchor.proofs[0].{field})" in result["errors"]


def test_a_number_that_is_not_exact_is_refused_wherever_it_sits(world, authority):
    proof = authority.rekor_proof(world["digest"])
    proof["log_url"] = 1.5
    result = json.loads(
        verify_anchor(
            json.dumps(anchor_document(world, [proof])),
            world["checkpoint"],
            authority.roots_json(),
        )
    )
    assert result["status"] == "INVALID", result
    assert "ANCHOR_MALFORMED (anchor.proofs[0].log_url)" in result["errors"]


def test_the_log_checks_the_signature_it_is_sent(world, fresh):
    """An independent implementation accepts the entry: the throwaway key signs the raw hash."""
    with fresh.serve() as (rekor, _):
        document, failures = create_anchor(
            world["checkpoint"], backends=("rekor",), rekor_url=rekor
        )
    assert failures == {}
    assert len(fresh.bodies) == 1


def test_an_entry_says_nothing_about_the_tenant_or_the_gate(world, fresh):
    with fresh.serve() as (rekor, _):
        create_anchor(world["checkpoint"], backends=("rekor",), rekor_url=rekor)
        first_key = json.loads(fresh.bodies[0])["spec"]["signature"]["publicKey"]["content"]
        create_anchor(world["checkpoint"], backends=("rekor",), rekor_url=rekor)
        second_key = json.loads(fresh.bodies[1])["spec"]["signature"]["publicKey"]["content"]
    assert first_key != second_key
    logged = fresh.bodies[0].decode()
    assert "acme" not in logged
    assert world["gate_id"] not in logged


def test_a_log_that_returns_the_proof_later_is_polled(world, fresh):
    fresh.proof_after_gets = 2
    with fresh.serve() as (rekor, _):
        document, failures = create_anchor(
            world["checkpoint"], backends=("rekor",), rekor_url=rekor, poll_interval=0
        )
    assert failures == {}
    assert document["proofs"][0]["inclusion_proof"]["tree_size"] == 1
    assert fresh.gets >= 2


def test_an_entry_already_logged_is_read_back(world, fresh):
    fresh.conflict_next = True
    with fresh.serve() as (rekor, _):
        document, failures = create_anchor(
            world["checkpoint"], backends=("rekor",), rekor_url=rekor
        )
    assert failures == {}
    assert document["proofs"][0]["backend"] == "rekor"
    assert any(request.startswith("GET ") for request in fresh.requests)


def test_a_redirect_is_refused_and_named(world, fresh):
    fresh.redirect = True
    with fresh.serve() as (rekor, tsa):
        document, failures = create_anchor(world["checkpoint"], rekor_url=rekor, tsa_url=tsa)
    assert document["proofs"] == []
    assert "redirect refused" in failures["rekor"]
    assert "redirect refused" in failures["rfc3161"]
    assert "steal" not in failures["rekor"]


def test_a_url_that_is_not_http_is_refused(world):
    document, failures = create_anchor(
        world["checkpoint"], rekor_url="file:///etc/passwd", tsa_url="ftp://x.example"
    )
    assert document["proofs"] == []
    assert "not an http(s) URL" in failures["rekor"]
    assert "not an http(s) URL" in failures["rfc3161"]


def test_a_proof_about_something_else_is_never_kept(world, fresh):
    fresh.log_digest_override = "00" * 32
    fresh.tsa_digest_override = bytes(32)
    with fresh.serve() as (rekor, tsa):
        document, failures = create_anchor(world["checkpoint"], rekor_url=rekor, tsa_url=tsa)
    assert document["proofs"] == []
    assert "ANCHOR_REKOR_ENTRY_MISMATCH" in failures["rekor"]
    assert "ANCHOR_TSA_IMPRINT_MISMATCH" in failures["rfc3161"]


def test_a_response_with_the_wrong_nonce_is_refused(world, fresh):
    fresh.tsa_nonce_override = 42
    with fresh.serve() as (_, tsa):
        document, failures = create_anchor(
            world["checkpoint"], backends=("rfc3161",), tsa_url=tsa
        )
    assert document["proofs"] == []
    assert "nonce" in failures["rfc3161"]


def test_the_tsa_url_comes_from_the_environment_when_not_given(world, fresh, monkeypatch):
    with fresh.serve() as (_, tsa):
        monkeypatch.setenv("TEMPUS_TSA_URL", tsa)
        document, failures = create_anchor(world["checkpoint"], backends=("rfc3161",))
    assert failures == {}
    assert document["proofs"][0]["tsa_url"] == tsa


def test_a_non_checkpoint_or_a_bundle_without_one_cannot_be_anchored(world):
    with pytest.raises(AnchorError, match="not a tempus.checkpoint.v1"):
        checkpoint_from_text('{"schema_version": "tempus.action-intent.v1"}')
    with pytest.raises(AnchorError, match="holds no checkpoint"):
        checkpoint_from_text('{"schema_version": "tempus.evidence-bundle.v1", "checkpoint": null}')
    with pytest.raises(AnchorError, match="repeats a JSON key"):
        checkpoint_from_text('{"a": 1, "a": 2}')
    assert checkpoint_from_text(world["bundle"]) == json.loads(world["checkpoint"])


# ---------------------------------------------------------------------------- CLI


def test_cli_create_verify_and_the_auditors_sentence(world, authority, tmp_path):
    out = tmp_path / "anchor.json"
    with authority.serve() as (rekor, tsa):
        code, stdout, stderr = run_cli(
            [
                "anchor", "create", "--checkpoint", world["checkpoint_file"],
                "--rekor-url", rekor, "--tsa-url", tsa, "--out", str(out),
            ],
            cwd=tmp_path,
        )  # fmt: skip
    assert code == 0, stdout + stderr
    assert json.loads(stdout)["backends"] == ["rekor", "rfc3161"]
    code, stdout, stderr = run_cli(
        ["anchor", "verify", "--anchor", str(out), "--checkpoint", world["checkpoint_file"]]
        + write_roots(authority, tmp_path),
        cwd=tmp_path,
    )
    assert code == 0, stdout + stderr
    assert json.loads(stdout)["status"] == "VERIFIED"
    assert "existed no later than" in stderr


def test_cli_without_roots_exits_nonzero_and_says_why(world, authority, tmp_path):
    anchor = tmp_path / "anchor.json"
    anchor.write_text(
        json.dumps(anchor_document(world, [authority.rekor_proof(world["digest"])])),
        encoding="utf-8",
    )
    code, stdout, stderr = run_cli(
        ["anchor", "verify", "--anchor", str(anchor), "--checkpoint", world["checkpoint_file"]],
        cwd=tmp_path,
    )
    assert code == 2
    assert json.loads(stdout)["status"] == "NOT_CHECKED"
    assert "nothing was verified" in stderr


def test_cli_one_backend_down_keeps_the_other_and_a_retry_fills_the_gap(world, fresh, tmp_path):
    out = tmp_path / "anchor.json"
    arguments = ["anchor", "create", "--checkpoint", world["checkpoint_file"], "--out", str(out)]
    with fresh.serve() as (rekor, tsa):
        urls = ["--rekor-url", rekor, "--tsa-url", tsa]
        fresh.tsa_status = 503
        code, _, stderr = run_cli(arguments + urls, cwd=tmp_path)
        assert code == 1
        assert "HTTP 503" in stderr
        assert [p["backend"] for p in json.loads(out.read_text())["proofs"]] == ["rekor"]

        fresh.tsa_status = None
        code, _, stderr = run_cli(arguments + urls, cwd=tmp_path)
        assert code == 0, stderr
        proofs = json.loads(out.read_text())["proofs"]
        assert [p["backend"] for p in proofs] == ["rekor", "rfc3161"]
        assert len(fresh.bodies) == 1, "the log must not be asked again for what the file holds"

        # Nothing left to ask for, nothing asked.
        before = len(fresh.requests)
        code, _, _ = run_cli(arguments + urls, cwd=tmp_path)
        assert code == 0
        assert len(fresh.requests) == before


def test_cli_every_backend_down_writes_nothing(world, fresh, tmp_path):
    out = tmp_path / "anchor.json"
    fresh.rekor_status = fresh.tsa_status = 500
    with fresh.serve() as (rekor, tsa):
        code, _, stderr = run_cli(
            [
                "anchor", "create", "--checkpoint", world["checkpoint_file"],
                "--rekor-url", rekor, "--tsa-url", tsa, "--out", str(out),
            ],
            cwd=tmp_path,
        )  # fmt: skip
    assert code == 1
    assert "rekor" in stderr and "rfc3161" in stderr
    assert not out.exists()


def test_cli_an_anchor_file_for_another_checkpoint_is_left_alone(world, authority, tmp_path):
    out = tmp_path / "anchor.json"
    held = json.dumps(anchor_document(world, [authority.rekor_proof(world["digest"])]))
    out.write_text(held, encoding="utf-8")
    (tmp_path / "other.json").write_text(world["other"], encoding="utf-8")
    code, _, stderr = run_cli(
        [
            "anchor", "create", "--checkpoint", str(tmp_path / "other.json"),
            "--backend", "rfc3161", "--tsa-url", "http://127.0.0.1:9", "--out", str(out),
        ],
        cwd=tmp_path,
    )  # fmt: skip
    assert code == 1
    assert "another checkpoint" in stderr
    assert out.read_text(encoding="utf-8") == held


def test_cli_a_corrupted_anchor_file_is_not_extended(world, authority, tmp_path):
    proof = authority.rekor_proof(world["digest"])
    proof["inclusion_proof"]["log_index"] = 7
    out = tmp_path / "anchor.json"
    held = json.dumps(anchor_document(world, [proof]))
    out.write_text(held, encoding="utf-8")
    code, _, stderr = run_cli(
        [
            "anchor", "create", "--checkpoint", world["checkpoint_file"],
            "--backend", "rfc3161", "--tsa-url", "http://127.0.0.1:9", "--out", str(out),
        ],
        cwd=tmp_path,
    )  # fmt: skip
    assert code == 1
    assert "existing anchor does not verify" in stderr
    assert out.read_text(encoding="utf-8") == held

    # One with no list of proofs is an answer too, not a traceback.
    held = json.dumps({"checkpoint_digest": world["digest"]})
    out.write_text(held, encoding="utf-8")
    code, _, stderr = run_cli(
        [
            "anchor", "create", "--checkpoint", world["checkpoint_file"],
            "--backend", "rfc3161", "--tsa-url", "http://127.0.0.1:9", "--out", str(out),
        ],
        cwd=tmp_path,
    )  # fmt: skip
    assert code == 1
    assert "no list of proofs" in stderr
    assert out.read_text(encoding="utf-8") == held


def test_cli_checkpoint_may_be_an_evidence_bundle(world, authority, tmp_path):
    with authority.serve() as (rekor, _):
        code, stdout, stderr = run_cli(
            [
                "anchor", "create", "--checkpoint", world["bundle_file"],
                "--backend", "rekor", "--rekor-url", rekor,
            ],
            cwd=tmp_path,
        )  # fmt: skip
    assert code == 0, stderr
    assert json.loads(stdout)["checkpoint_digest"] == world["digest"]


def _verify_bundle_cli(world, tmp_path, *extra):
    return run_cli(
        ["verify-bundle", "--bundle", world["bundle_file"], "--gate-public-key", world["gate_id"]]
        + list(extra),
        cwd=tmp_path,
    )


def test_cli_verify_bundle_with_requirements(world, authority, tmp_path):
    at = int(time.time())
    anchor = tmp_path / "anchor.json"
    anchor.write_text(
        json.dumps(anchor_document(world, [authority.rekor_proof(world["digest"], at)])),
        encoding="utf-8",
    )
    roots = write_roots(authority, tmp_path)
    with_anchor = ["--anchor", str(anchor)] + roots

    code, stdout, stderr = _verify_bundle_cli(world, tmp_path, *with_anchor, "--require-anchor")
    assert code == 0, stdout + stderr
    assert json.loads(stdout)["checks"]["anchor"] == "VERIFIED"
    assert "existed no later than" in stderr

    tomorrow = (NOW + dt.timedelta(days=1)).date().isoformat()
    code, _, _ = _verify_bundle_cli(world, tmp_path, *with_anchor, "--anchored-before", tomorrow)
    assert code == 0

    # A bare date means the end of that day, however it is written.
    today = dt.datetime.fromtimestamp(at, tz=UTC)
    spellings = [today.strftime("%Y-%m-%d"), today.strftime("%Y%m%d")]
    if sys.version_info >= (3, 11):  # Python reads week dates from here on.
        year, week, day = today.isocalendar()
        spellings += [f"{year}-W{week:02}-{day}", f"{year}W{week:02}{day}"]
    for spelled in spellings:
        code, _, _ = _verify_bundle_cli(
            world, tmp_path, *with_anchor, "--anchored-before", spelled
        )
        assert code == 0, spelled

    code, stdout, _ = _verify_bundle_cli(
        world, tmp_path, *with_anchor, "--anchored-before", "2020-01-01"
    )
    assert code == 2
    assert "REQUIREMENT_NOT_MET (anchor date" in stdout

    # With time and zone too.
    moment = dt.datetime.fromtimestamp(at + 3_600, tz=UTC).isoformat().replace("+00:00", "Z")
    code, _, _ = _verify_bundle_cli(world, tmp_path, *with_anchor, "--anchored-before", moment)
    assert code == 0

    code, stdout, _ = _verify_bundle_cli(world, tmp_path, "--require-anchor")
    assert code == 2
    assert "got NOT_PRESENT" in stdout

    # An anchor nobody pinned a root for is not enough.
    code, stdout, _ = _verify_bundle_cli(world, tmp_path, "--anchor", str(anchor), "--require-anchor")
    assert code == 2
    assert "got NOT_CHECKED" in stdout

    # Implied by --anchored-before.
    code, stdout, _ = _verify_bundle_cli(world, tmp_path, "--anchored-before", tomorrow)
    assert code == 2
    assert "REQUIREMENT_NOT_MET (anchor" in stdout

    # Without any requirement, a bundle with no anchor still verifies, as it always did.
    code, stdout, _ = _verify_bundle_cli(world, tmp_path)
    assert code == 0
    assert json.loads(stdout)["checks"]["anchor"] == "NOT_PRESENT"


def test_cli_usage_mistakes_are_errors_not_verdicts(world, authority, tmp_path):
    anchor = tmp_path / "anchor.json"
    anchor.write_text(
        json.dumps(anchor_document(world, [authority.rekor_proof(world["digest"])])),
        encoding="utf-8",
    )
    code, _, stderr = _verify_bundle_cli(
        world, tmp_path, "--anchor", str(anchor), "--anchored-before", "soon"
    )
    assert code == 1 and "not an ISO 8601 date" in stderr
    # An unset variable in a script must not turn the requirement off.
    code, _, stderr = _verify_bundle_cli(world, tmp_path, "--anchored-before", "")
    assert code == 1 and "not an ISO 8601 date" in stderr
    code, _, stderr = _verify_bundle_cli(world, tmp_path, "--rekor-public-key", "x")
    assert code == 1 and "need --anchor" in stderr
    code, _, stderr = _verify_bundle_cli(
        world, tmp_path, "--anchor", str(anchor), "--rekor-public-key", "no/such/file.pem"
    )
    assert code == 1 and "not PEM or base64" in stderr


# ------------------------------------------------------------------- hostile tokens


def _checked(world, token_bytes, roots):
    proof = {
        "backend": "rfc3161",
        "tsa_url": "http://x",
        "token": base64.b64encode(token_bytes).decode(),
    }
    return json.loads(
        verify_anchor(
            json.dumps(anchor_document(world, [proof])),
            world["checkpoint"],
            json.dumps({"tsa_roots": roots}),
        )
    )


def _digest(world):
    return bytes.fromhex(world["digest"])


class Chain:
    """A root, an intermediate and a signer, with knobs on each."""

    def __init__(self, signer_key_kind="p256", intermediate=None, signer=None):
        self.root_key = new_key()
        self.root = issue("Root", self.root_key, ca=True)
        self.intermediate_key = new_key()
        self.intermediate = issue(
            "Intermediate",
            self.intermediate_key,
            (self.root, self.root_key),
            **{"ca": True, **(intermediate or {})},
        )
        self.signer_key = new_key(signer_key_kind)
        self.signer = issue(
            "Signer",
            self.signer_key,
            (self.intermediate, self.intermediate_key),
            **{"timestamping": True, **(signer or {})},
        )

    def roots(self):
        return [authority_module.cert_pem(self.root)]

    def token(self, world, **options):
        return make_token(
            _digest(world), self.signer_key, self.signer, (self.intermediate,), **options
        )


def _assert_refused(world, chain, code, **options):
    result = _checked(world, chain.token(world, **options), chain.roots())
    assert result["status"] == "INVALID", result
    assert code in result["errors"], result


def test_a_good_chain_verifies(world):
    chain = Chain()
    result = _checked(world, chain.token(world), chain.roots())
    assert result["status"] == "VERIFIED", result


def test_the_date_is_the_latest_the_token_allows(world):
    chain = Chain()
    moment = NOW.replace(microsecond=0)
    second = int(moment.timestamp())
    text = moment.strftime("%Y%m%d%H%M%S")
    seq, tlv, integer = (
        authority_module.seq,
        authority_module.tlv,
        authority_module.integer,
    )
    for options, added in (
        ({"gen_time": moment}, 0),
        ({"gen_time": moment, "accuracy": seq()}, 0),
        ({"gen_time": moment, "accuracy": seq(integer(3600))}, 3600),
        ({"gen_time": moment, "accuracy": seq(tlv(0x80, b"\x01\xf4"))}, 1),  # 500 ms
        ({"gen_time": moment, "accuracy": seq(tlv(0x81, b"\x01"))}, 1),  # 1 microsecond
        ({"gen_time": moment, "accuracy": seq(integer(2), tlv(0x80, b"\x01"))}, 3),
        ({"gen_time": moment, "accuracy": seq(integer(2**32 - 1))}, 2**32 - 1),
        ({"gen_time_text": f"{text}.9Z"}, 1),
        ({"gen_time_text": f"{text}.9Z", "accuracy": seq(integer(1))}, 2),
    ):
        result = _checked(world, chain.token(world, **options), chain.roots())
        assert result["status"] == "VERIFIED", result
        assert result["anchored_at"] == (second + added) * 1_000_000, options


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(b"\x02\x01\xff", id="negative seconds"),
        pytest.param(b"\x80\x02\x03\xe8", id="1000 milliseconds"),
        pytest.param(b"\x81\x02\x03\xe8", id="1000 microseconds"),
        pytest.param(b"\x02\x06\x01\x00\x00\x00\x00\x00", id="seconds out of range"),
        pytest.param(b"\x02\x05\x7f\xff\xff\xff\xff", id="seconds past 32 bits"),
        pytest.param(b"\x02\x02\x00\x01", id="seconds not minimal"),
        pytest.param(b"\x04\x01\x01", id="a field that does not belong"),
    ],
)
def test_an_accuracy_that_makes_no_sense_is_malformed(world, bad):
    chain = Chain()
    token = chain.token(world, accuracy=authority_module.tlv(0x30, bad))
    assert _checked(world, token, chain.roots())["errors"] == ["ANCHOR_TSA_TOKEN_MALFORMED"]


@pytest.mark.parametrize("kind", ["p256", "p384", "rsa2048"])
@pytest.mark.parametrize("digest", ["sha256", "sha384", "sha512"])
def test_accepted_algorithms(world, kind, digest):
    chain = Chain(kind)
    result = _checked(world, chain.token(world, digest=digest), chain.roots())
    assert result["status"] == "VERIFIED", result


def test_the_older_signing_certificate_attribute_is_accepted(world):
    chain = Chain()
    token = chain.token(world, signing_certificate="v1")
    assert _checked(world, token, chain.roots())["status"] == "VERIFIED"


def test_a_short_rsa_key_is_refused(world):
    _assert_refused(world, Chain("rsa1024"), "ANCHOR_TSA_ALGORITHM_UNSUPPORTED")


def test_sha1_is_refused_as_a_signature_digest(world):
    chain = Chain("rsa2048")
    _assert_refused(world, chain, "ANCHOR_TSA_ALGORITHM_UNSUPPORTED", digest="sha1")


def test_rsa_pss_is_refused(world):
    _assert_refused(
        world, Chain("rsa2048"), "ANCHOR_TSA_ALGORITHM_UNSUPPORTED", scheme="pss"
    )


def test_a_signature_by_another_key_is_refused(world):
    _assert_refused(world, Chain(), "ANCHOR_TSA_SIGNATURE_INVALID", signature_key=new_key())


def test_wrong_attributes_are_refused(world):
    chain = Chain()
    _assert_refused(world, chain, "ANCHOR_TSA_ATTRIBUTES_INVALID", message_digest=bytes(32))
    _assert_refused(world, chain, "ANCHOR_TSA_ATTRIBUTES_INVALID", content_type="1.2.3.4")
    _assert_refused(world, chain, "ANCHOR_TSA_ATTRIBUTES_INVALID", signing_certificate=None)
    _assert_refused(
        world, chain, "ANCHOR_TSA_ATTRIBUTES_INVALID", signing_certificate_for=chain.root
    )


def test_an_imprint_of_another_digest_or_algorithm_is_refused(world):
    chain = Chain()
    wrong = make_token(bytes(32), chain.signer_key, chain.signer, (chain.intermediate,))
    assert "ANCHOR_TSA_IMPRINT_MISMATCH" in _checked(world, wrong, chain.roots())["errors"]
    _assert_refused(world, chain, "ANCHOR_TSA_IMPRINT_MISMATCH", imprint_digest="sha512")


@pytest.mark.parametrize(
    "signer",
    [{"timestamping": False}, {"timestamping": "plain"}, {"timestamping": "extra"}],
)
def test_a_signer_not_marked_for_timestamping_is_refused(world, signer):
    _assert_refused(world, Chain(signer=signer), "ANCHOR_TSA_SIGNER_INVALID")


def test_a_critical_extension_nobody_understands_is_refused(world):
    _assert_refused(
        world, Chain(signer={"unknown_critical": True}), "ANCHOR_TSA_SIGNER_INVALID"
    )
    _assert_refused(
        world, Chain(intermediate={"unknown_critical": True}), "ANCHOR_TSA_CHAIN_INVALID"
    )


def test_certificates_are_judged_at_the_tokens_time(world):
    past = NOW - dt.timedelta(days=400)
    # Long expired today, but valid when it signed: old evidence keeps verifying.
    chain = Chain(
        signer={
            "not_before": past - dt.timedelta(days=30),
            "not_after": past + dt.timedelta(days=30),
        }
    )
    # The checkpoint is newer than this token, so only the date check complains.
    result = _checked(world, chain.token(world, gen_time=past), chain.roots())
    assert result["errors"] == ["ANCHOR_BEFORE_CHECKPOINT"], result
    # Valid today, not when it signed.
    _assert_refused(
        world,
        Chain(signer={"not_before": NOW + dt.timedelta(days=1)}),
        "ANCHOR_TSA_SIGNER_INVALID",
    )
    # An expired signer, at the time of signing.
    _assert_refused(
        world,
        Chain(signer={"not_before": past, "not_after": past + dt.timedelta(days=1)}),
        "ANCHOR_TSA_SIGNER_INVALID",
    )
    # An intermediate expired at the time of signing.
    _assert_refused(
        world,
        Chain(intermediate={"not_before": past, "not_after": past + dt.timedelta(days=1)}),
        "ANCHOR_TSA_CHAIN_INVALID",
    )


def test_an_intermediate_that_may_not_sign_certificates_is_refused(world):
    _assert_refused(world, Chain(intermediate={"ca": False}), "ANCHOR_TSA_CHAIN_INVALID")


@pytest.mark.parametrize("length,verified", [(0, False), (1, False), (2, True), (None, True)])
def test_path_length_counts_the_intermediates_below(world, length, verified):
    root_key = new_key()
    root = issue("Root", root_key, ca=True, path_length=length)
    middle_key = new_key()
    middle = issue("Middle", middle_key, (root, root_key), ca=True)
    lower_key = new_key()
    lower = issue("Lower", lower_key, (middle, middle_key), ca=True)
    signer_key = new_key()
    signer = issue("Signer", signer_key, (lower, lower_key), timestamping=True)
    token = make_token(_digest(world), signer_key, signer, (lower, middle))
    result = _checked(world, token, [authority_module.cert_pem(root)])
    if verified:
        assert result["status"] == "VERIFIED", result
    else:
        assert result["errors"] == ["ANCHOR_TSA_CHAIN_INVALID"], result


def test_a_path_length_of_zero_still_allows_a_leaf(world):
    root_key = new_key()
    root = issue("Root", root_key, ca=True, path_length=0)
    signer_key = new_key()
    signer = issue("Signer", signer_key, (root, root_key), timestamping=True)
    token = make_token(_digest(world), signer_key, signer)
    result = _checked(world, token, [authority_module.cert_pem(root)])
    assert result["status"] == "VERIFIED", result


def test_a_chain_to_another_root_is_refused(world):
    chain = Chain()
    other = Chain()
    result = _checked(world, chain.token(world), other.roots())
    assert result["errors"] == ["ANCHOR_TSA_CHAIN_INVALID"]


def test_an_expired_certificate_of_the_same_name_and_key_is_passed_over(world):
    chain = Chain()
    past = NOW - dt.timedelta(days=400)
    dates = {"not_before": past, "not_after": past + dt.timedelta(days=1)}
    # Next to its reissued self, ahead of it in the token.
    stale = issue("Intermediate", chain.intermediate_key, (chain.root, chain.root_key), ca=True, **dates)
    token = make_token(_digest(world), chain.signer_key, chain.signer, (stale, chain.intermediate))
    result = _checked(world, token, chain.roots())
    assert result["status"] == "VERIFIED", result
    # Alone, it does not make a chain.
    token = make_token(_digest(world), chain.signer_key, chain.signer, (stale,))
    assert _checked(world, token, chain.roots())["errors"] == ["ANCHOR_TSA_CHAIN_INVALID"]
    # The same among the pinned roots, whichever comes first.
    stale_root = issue("Root", chain.root_key, ca=True, **dates)
    roots = [authority_module.cert_pem(stale_root), *chain.roots()]
    result = _checked(world, chain.token(world), roots)
    assert result["status"] == "VERIFIED", result
    assert _checked(
        world, chain.token(world), [authority_module.cert_pem(stale_root)]
    )["errors"] == ["ANCHOR_TSA_CHAIN_INVALID"]


def test_a_root_placed_in_the_token_is_not_trusted_because_of_that(world):
    rogue_key = new_key()
    rogue = issue("Root", rogue_key, ca=True)
    signer_key = new_key()
    signer = issue("Signer", signer_key, (rogue, rogue_key), timestamping=True)
    token = make_token(_digest(world), signer_key, signer, (rogue,))
    assert _checked(world, token, Chain().roots())["errors"] == ["ANCHOR_TSA_CHAIN_INVALID"]


def test_more_than_one_signer_or_garbage_is_malformed(world):
    chain = Chain()
    _assert_refused(world, chain, "ANCHOR_TSA_TOKEN_MALFORMED", extra_signer=True)
    for garbage in (b"", b"not der", make_response(chain.token(world))):
        result = _checked(world, garbage, chain.roots())
        assert result["errors"] == ["ANCHOR_TSA_TOKEN_MALFORMED"], result


def test_a_bundle_with_a_token_that_fails_is_invalid(world):
    chain = Chain()
    token = chain.token(world, message_digest=bytes(32))
    proof = {"backend": "rfc3161", "tsa_url": "x", "token": base64.b64encode(token).decode()}
    result = json.loads(
        verify_bundle(
            world["bundle"],
            world["gate_id"],
            None,
            json.dumps(anchor_document(world, [proof])),
            json.dumps({"tsa_roots": chain.roots()}),
        )
    )
    assert result["status"] == "INVALID"
    assert result["checks"]["anchor"] == "FAILED"
    assert "ANCHOR_TSA_ATTRIBUTES_INVALID" in result["errors"]


def test_a_date_no_calendar_can_hold_is_still_reported():
    assert _format_micros(0) == "1970-01-01T00:00:00Z"
    # The C library stops at the year 3000 on Windows.
    assert _format_micros(32_503_680_000_000_000) == "3000-01-01T00:00:00Z"
    # A token under a pinned root can say so, and that is no reason to crash after verifying it.
    assert _format_micros(10**18) == f"{10**18} microseconds after 1970"
