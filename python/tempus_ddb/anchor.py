"""Proof from outside that a checkpoint existed by a date.

A public log (Rekor) and a timestamp authority (RFC 3161) each hand back a proof about the
digest of a signed checkpoint. The proofs go into a ``tempus.anchor.v1`` document that anyone
verifies offline against roots they pinned themselves.

The gate never calls this and stays offline; the operator anchors from the CLI or cron. Only
bytes move here: every signature is built and checked in Rust, in code shared with the
browser verifier. Only a hash ever leaves the machine, under a key that exists for one entry,
so a public entry says nothing about the tenant and cannot be linked to the gate.
"""

import base64
import json
import os
import re
import time
from urllib import error, parse, request

from . import __version__
from ._http import open_request
from ._tempus_ddb import (
    anchor_checkpoint_digest,
    anchor_rekor_entry,
    anchor_tsa_request,
    anchor_tsa_token,
    verify_anchor,
)

ANCHOR_SCHEMA = "tempus.anchor.v1"
BUNDLE_SCHEMA = "tempus.evidence-bundle.v1"
BACKENDS = ("rekor", "rfc3161")
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
DEFAULT_TSA_URL = "http://timestamp.digicert.com"

_MAX_RESPONSE_BYTES = 1_048_576
_MAX_DOCUMENT_POLLS = 30
_ENTRY_PATH = "/api/v1/log/entries"
_UUID = re.compile(r"^[0-9a-f]{64,80}$")
_USER_AGENT = f"tempus-ddb/{__version__}"


class AnchorError(Exception):
    """A backend gave no usable proof, or a document cannot be anchored."""


def _strict_loads(text, label):
    def no_repeats(pairs):
        names = [name for name, _ in pairs]
        if len(names) != len(set(names)):
            raise AnchorError(f"{label} repeats a JSON key")
        return dict(pairs)

    try:
        return json.loads(text, object_pairs_hook=no_repeats)
    except ValueError as exc:
        raise AnchorError(f"{label} is not valid JSON: {exc}") from exc


def checkpoint_from_text(text):
    """The checkpoint in a checkpoint file or in an evidence bundle."""
    document = _strict_loads(text, "Checkpoint")
    if not isinstance(document, dict):
        raise AnchorError("Checkpoint must be a JSON object")
    if document.get("schema_version") == BUNDLE_SCHEMA:
        section = document.get("checkpoint")
        document = section.get("checkpoint") if isinstance(section, dict) else None
        if not isinstance(document, dict):
            raise AnchorError(
                "the bundle holds no checkpoint (export it with --create-checkpoint)"
            )
    if document.get("schema_version") != "tempus.checkpoint.v1":
        raise AnchorError("not a tempus.checkpoint.v1 or an evidence bundle holding one")
    return document


def _base_url(url):
    parts = parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AnchorError(f"not an http(s) URL: {url}")
    return url.rstrip("/")


def _exchange(req, timeout):
    """(status, headers, body) of a request; redirects raise, as for every other client here."""
    req.add_header("User-Agent", _USER_AGENT)
    try:
        with open_request(req, timeout) as response:  # nosec B310
            return response.status, response.headers, response.read(_MAX_RESPONSE_BYTES)
    except error.HTTPError as exc:
        with exc:
            return exc.code, exc.headers, b""


def _single_entry(body):
    entries = _strict_loads(body.decode("utf-8", "replace"), "The log's answer")
    if not isinstance(entries, dict) or len(entries) != 1:
        raise AnchorError("the log did not answer with one entry")
    uuid, entry = next(iter(entries.items()))
    if not _UUID.match(uuid) or not isinstance(entry, dict):
        raise AnchorError("the log answered with a malformed entry")
    return uuid, entry


def _inclusion(entry):
    verification = entry.get("verification")
    return verification.get("inclusionProof") if isinstance(verification, dict) else None


def _entry_uuid_from_location(location, base):
    # Only the id is taken from the header: the next request stays on the log the operator chose.
    uuid = parse.urlsplit(location or "").path.rstrip("/").rsplit("/", 1)[-1]
    if not _UUID.match(uuid):
        raise AnchorError(f"{base} answered 409 without naming the existing entry")
    return uuid


def _rekor_proof(digest, url, timeout, poll_interval):
    base = _base_url(url)
    status, headers, body = _exchange(
        request.Request(
            base + _ENTRY_PATH,
            data=anchor_rekor_entry(digest).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        ),
        timeout,
    )
    if status == 201:
        uuid, entry = _single_entry(body)
    elif status == 409:
        uuid, entry = _entry_uuid_from_location(headers.get("Location"), base), None
    else:
        raise AnchorError(f"the log answered HTTP {status}")

    # A log may sign the entry before the tree that holds it, so the proof can come later.
    for attempt in range(_MAX_DOCUMENT_POLLS):
        if entry is not None and isinstance(_inclusion(entry), dict):
            break
        if attempt:
            time.sleep(poll_interval)
        status, _, body = _exchange(
            request.Request(
                f"{base}{_ENTRY_PATH}/{uuid}", headers={"Accept": "application/json"}
            ),
            timeout,
        )
        if status == 200:
            _, entry = _single_entry(body)
        elif status != 404:
            raise AnchorError(f"the log answered HTTP {status} when asked for the entry")
    else:
        raise AnchorError("the log gave no inclusion proof in time")

    inclusion = _inclusion(entry)
    return {
        "backend": "rekor",
        "log_url": base,
        "entry_uuid": uuid,
        "body": entry.get("body"),
        "integrated_time": entry.get("integratedTime"),
        "log_id": entry.get("logID"),
        "log_index": entry.get("logIndex"),
        "signed_entry_timestamp": entry["verification"].get("signedEntryTimestamp"),
        "inclusion_proof": {
            "log_index": inclusion.get("logIndex"),
            "tree_size": inclusion.get("treeSize"),
            "root_hash": inclusion.get("rootHash"),
            "hashes": inclusion.get("hashes"),
            "checkpoint": inclusion.get("checkpoint"),
        },
    }


def _rfc3161_proof(digest, url, timeout):
    base = _base_url(url)
    prepared = json.loads(anchor_tsa_request(digest))
    status, _, body = _exchange(
        request.Request(
            url,
            data=base64.b64decode(prepared["request"]),
            method="POST",
            headers={
                "Content-Type": "application/timestamp-query",
                "Accept": "application/timestamp-reply",
            },
        ),
        timeout,
    )
    if status != 200:
        raise AnchorError(f"the timestamp authority answered HTTP {status}")
    token = anchor_tsa_token(base64.b64encode(body).decode("ascii"), prepared["nonce"])
    return {"backend": "rfc3161", "tsa_url": base, "token": token}


def _refuse_if_invalid(document, checkpoint_json, what):
    """With no roots this checks what needs none: the proof is about this very checkpoint."""
    result = json.loads(verify_anchor(json.dumps(document), checkpoint_json))
    if result["status"] == "INVALID":
        raise AnchorError(f"{what} does not verify: {', '.join(result['errors'])}")


def _start_document(checkpoint, digest, existing):
    document = {
        "schema_version": ANCHOR_SCHEMA,
        "checkpoint_id": checkpoint.get("checkpoint_id"),
        "tenant_id": checkpoint.get("tenant_id"),
        "checkpoint_digest": digest,
        "proofs": [],
    }
    if existing is None:
        return document
    held = _strict_loads(existing, "The existing anchor")
    if not isinstance(held, dict) or held.get("checkpoint_digest") != digest:
        raise AnchorError("the existing anchor belongs to another checkpoint")
    return held


def create_anchor(
    checkpoint_text,
    backends=BACKENDS,
    rekor_url=None,
    tsa_url=None,
    existing=None,
    timeout=30,
    poll_interval=1.0,
):
    """Ask each backend for a proof. Returns ``(document, {backend: why it failed})``.

    A backend the ``existing`` document (JSON text) already holds is not asked again, so a
    retry from cron only fills the gap. Every proof is checked before it is kept.
    """
    checkpoint = checkpoint_from_text(checkpoint_text)
    checkpoint_json = json.dumps(checkpoint)
    digest = anchor_checkpoint_digest(checkpoint_json)
    document = _start_document(checkpoint, digest, existing)
    if document["proofs"]:
        _refuse_if_invalid(document, checkpoint_json, "the existing anchor")
    held = {proof.get("backend") for proof in document["proofs"]}

    failures = {}
    for backend in backends:
        if backend in held:
            continue
        try:
            if backend == "rekor":
                proof = _rekor_proof(
                    digest, rekor_url or DEFAULT_REKOR_URL, timeout, poll_interval
                )
            elif backend == "rfc3161":
                chosen = tsa_url or os.environ.get("TEMPUS_TSA_URL") or DEFAULT_TSA_URL
                proof = _rfc3161_proof(digest, chosen, timeout)
            else:
                raise AnchorError(f"unknown backend {backend}")
            _refuse_if_invalid(
                {**document, "proofs": [proof]}, checkpoint_json, f"the {backend} proof"
            )
        except Exception as exc:  # one backend down must not cost the other's proof
            failures[backend] = str(exc)
            continue
        document["proofs"].append(proof)
        held.add(backend)
    return document, failures
