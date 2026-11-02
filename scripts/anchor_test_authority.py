"""A throwaway transparency log and timestamp authority, for tests and fixtures only.

It behaves like the real services closely enough that the same code talks to both: a Rekor
v1 API over a real RFC 6962 tree, and an RFC 3161 service issuing real CMS tokens. Its keys
live in memory and die with the process, so nothing it signs proves anything to anyone who
did not pin its public keys for a test.

Used by ``tests/test_anchor.py`` (over localhost) and by
``scripts/generate_conformance_evidence.py`` (fixtures). Requires ``cryptography``.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = dt.timezone.utc

SIGNED_DATA = "1.2.840.113549.1.7.2"
TST_INFO = "1.2.840.113549.1.9.16.1.4"
CONTENT_TYPE = "1.2.840.113549.1.9.3"
MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
SHA_OIDS = {
    "sha1": "1.3.14.3.2.26",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}
ECDSA_OIDS = {
    "sha256": "1.2.840.10045.4.3.2",
    "sha384": "1.2.840.10045.4.3.3",
    "sha512": "1.2.840.10045.4.3.4",
}
RSA_OIDS = {
    "sha1": "1.2.840.113549.1.1.5",
    "sha256": "1.2.840.113549.1.1.11",
    "sha384": "1.2.840.113549.1.1.12",
    "sha512": "1.2.840.113549.1.1.13",
}
RSA_PSS = "1.2.840.113549.1.1.10"
HASHES = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


# ------------------------------------------------------------------------------ DER


def tlv(tag: int, *parts: bytes) -> bytes:
    value = b"".join(parts)
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, *parts)


def set_of(*parts: bytes) -> bytes:
    return tlv(0x31, *sorted(parts))


def oid(dotted: str) -> bytes:
    numbers = [int(part) for part in dotted.split(".")]
    out = bytearray([numbers[0] * 40 + numbers[1]])
    for number in numbers[2:]:
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append(0x80 | (number & 0x7F))
            number >>= 7
        out.extend(reversed(chunk))
    return tlv(0x06, bytes(out))


def integer(value: int) -> bytes:
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big", signed=True))


def octets(value: bytes) -> bytes:
    return tlv(0x04, value)


def generalized_time(moment: dt.datetime) -> bytes:
    return tlv(0x18, moment.astimezone(UTC).strftime("%Y%m%d%H%M%SZ").encode())


def algorithm(dotted: str, null: bool = False) -> bytes:
    return seq(oid(dotted), tlv(0x05) if null else b"")


def read_tlv(data: bytes, at: int = 0) -> tuple[int, bytes, int]:
    """(tag, value, next offset) of the element at ``at``."""
    tag, length = data[at], data[at + 1]
    at += 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[at : at + size], "big")
        at += size
    return tag, data[at : at + length], at + length


def parse_request(request_der: bytes) -> tuple[bytes, int | None]:
    """The SHA-256 digest and nonce of a ``TimeStampReq``."""
    _, body, _ = read_tlv(request_der)
    _, _, at = read_tlv(body)
    _, imprint, at = read_tlv(body, at)
    _, _, inner = read_tlv(imprint)
    _, digest, _ = read_tlv(imprint, inner)
    nonce = None
    if at < len(body) and body[at] == 0x02:
        _, value, _ = read_tlv(body, at)
        nonce = int.from_bytes(value, "big")
    return digest, nonce


# ----------------------------------------------------------------------- certificates


def new_key(kind: str = "p256"):
    if kind == "p256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "p384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(kind[3:]))
    raise ValueError(kind)


def public_pem(key) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def spki_der(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def cert_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def cert_der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def issue(
    subject: str,
    key,
    issuer: tuple | None = None,
    *,
    ca: bool = False,
    path_length: int | None = None,
    timestamping: bool | str = False,
    key_usage: bool = True,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    unknown_critical: bool = False,
    signature_hash=None,
) -> x509.Certificate:
    """A certificate for ``key``, signed by ``issuer = (certificate, key)`` or by itself.

    ``timestamping`` is True for a critical extended key usage, "plain" for one that is not
    critical, False for none.
    """
    now = dt.datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name, signing_key = (issuer[0].subject, issuer[1]) if issuer else (name, key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - dt.timedelta(days=3650))
        .not_valid_after(not_after or now + dt.timedelta(days=3650))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if timestamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=timestamping is True,
        )
    if unknown_critical:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00"),
            critical=True,
        )
    return builder.sign(signing_key, signature_hash or hashes.SHA256())


# ----------------------------------------------------------------------------- tokens


def sign_cms(key, data: bytes, digest: str, scheme: str = "pkcs1") -> tuple[bytes, bytes]:
    """(signature, algorithm identifier) as a CMS signer would write them."""
    chosen = HASHES[digest]()
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(chosen)), algorithm(ECDSA_OIDS[digest])
    if scheme == "pss":
        pss = padding.PSS(mgf=padding.MGF1(chosen), salt_length=chosen.digest_size)
        return key.sign(data, pss, chosen), algorithm(RSA_PSS)
    return key.sign(data, padding.PKCS1v15(), chosen), algorithm(RSA_OIDS[digest], null=True)


def make_token(
    imprint: bytes,
    signer_key,
    signer_cert: x509.Certificate,
    chain: tuple[x509.Certificate, ...] = (),
    *,
    gen_time: dt.datetime | None = None,
    nonce: int | None = None,
    digest: str = "sha256",
    imprint_digest: str = "sha256",
    scheme: str = "pkcs1",
    message_digest: bytes | None = None,
    content_type: str = TST_INFO,
    signing_certificate: str | None = "v2",
    signing_certificate_for: x509.Certificate | None = None,
    signature_key=None,
    extra_signer: bool = False,
) -> bytes:
    """A ``TimeStampToken``. Every keyword exists so that a test can get one thing wrong."""
    moment = gen_time or dt.datetime.now(UTC)
    tst_info = seq(
        integer(1),
        oid("1.3.6.1.4.1.99999.2"),
        seq(algorithm(SHA_OIDS[imprint_digest], null=True), octets(imprint)),
        integer(x509.random_serial_number()),
        generalized_time(moment),
        integer(nonce) if nonce is not None else b"",
    )
    hasher = hashlib.new(digest)
    hasher.update(tst_info)
    attributes = [
        seq(oid(CONTENT_TYPE), set_of(oid(content_type))),
        seq(oid(MESSAGE_DIGEST), set_of(octets(message_digest or hasher.digest()))),
    ]
    named = cert_der(signing_certificate_for or signer_cert)
    if signing_certificate == "v2":
        attributes.append(
            seq(
                oid(SIGNING_CERT_V2),
                set_of(seq(seq(seq(octets(hashlib.sha256(named).digest()))))),
            )
        )
    elif signing_certificate == "v1":
        attributes.append(
            seq(
                oid(SIGNING_CERT),
                set_of(seq(seq(seq(octets(hashlib.sha1(named, usedforsecurity=False).digest()))))),
            )
        )
    signed_attributes = set_of(*attributes)
    signature, signature_algorithm = sign_cms(
        signature_key or signer_key, signed_attributes, digest, scheme
    )
    issuer_and_serial = seq(
        signer_cert.issuer.public_bytes(), integer(signer_cert.serial_number)
    )
    signer_info = seq(
        integer(1),
        issuer_and_serial,
        algorithm(SHA_OIDS[digest], null=True),
        tlv(0xA0, signed_attributes[2 if signed_attributes[1] < 0x80 else 2 + (signed_attributes[1] & 0x7F) :]),
        signature_algorithm,
        octets(signature),
    )
    certificates = b"".join(cert_der(item) for item in (signer_cert, *chain))
    signed_data = seq(
        integer(3),
        set_of(algorithm(SHA_OIDS[digest], null=True)),
        seq(oid(TST_INFO), tlv(0xA0, octets(tst_info))),
        tlv(0xA0, certificates),
        tlv(0x31, signer_info + (signer_info if extra_signer else b"")),
    )
    return seq(oid(SIGNED_DATA), tlv(0xA0, signed_data))


def make_response(token: bytes | None, status: int = 0) -> bytes:
    return seq(seq(integer(status)), token or b"")


# ---------------------------------------------------------------------------- the log


def _leaf(body: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + body).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(size: int) -> int:
    k = 1
    while k * 2 < size:
        k *= 2
    return k


def tree_root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(tree_root(leaves[:k]), tree_root(leaves[k:]))


def audit_path(index: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return audit_path(index, leaves[:k]) + [tree_root(leaves[k:])]
    return audit_path(index - k, leaves[k:]) + [tree_root(leaves[:k])]


class Authority:
    """One log and one timestamp authority, with their own keys, served from one port."""

    ORIGIN = "fake.log - 1"

    def __init__(self, tsa_key_kind: str = "p256"):
        self.log_key = new_key()
        self.root_key = new_key()
        self.root = issue("Test TSA Root", self.root_key, ca=True)
        self.tsa_key = new_key(tsa_key_kind)
        self.tsa_cert = issue(
            "Test TSA", self.tsa_key, (self.root, self.root_key), timestamping=True
        )
        self.bodies: list[bytes] = []
        self.times: list[int] = []
        # Things a test can make go wrong, read by the server.
        self.rekor_status: int | None = None
        self.tsa_status: int | None = None
        self.redirect = False
        self.proof_after_gets = 0
        self.conflict_next = False
        self.integrated_time: int | None = None
        self.gets = 0
        self.log_digest_override: str | None = None
        self.tsa_digest_override: bytes | None = None
        self.tsa_nonce_override: int | None = None
        self.requests: list[str] = []

    # --- what a verifier pins

    def roots(self) -> dict:
        return {"rekor_public_keys": [public_pem(self.log_key)], "tsa_roots": [cert_pem(self.root)]}

    def roots_json(self) -> str:
        return json.dumps(self.roots())

    # --- the log

    @property
    def log_id(self) -> str:
        return hashlib.sha256(spki_der(self.log_key)).hexdigest()

    def _log_sign(self, payload: bytes) -> bytes:
        return self.log_key.sign(payload, ec.ECDSA(hashes.SHA256()))

    def _note(self, size: int, root: bytes) -> str:
        text = f"{self.ORIGIN}\n{size}\n{base64.b64encode(root).decode()}\n"
        raw = bytes.fromhex(self.log_id)[:4] + self._log_sign(text.encode())
        return f"{text}\n— fake.log {base64.b64encode(raw).decode()}\n"

    def add_entry(self, entry: dict, integrated_time: int | None = None) -> str:
        """Log an entry and return its uuid."""
        body = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        self.bodies.append(body)
        moment = integrated_time or self.integrated_time or int(dt.datetime.now(UTC).timestamp())
        self.times.append(moment)
        return _leaf(body).hex()

    def entry_response(self, uuid: str, with_proof: bool = True) -> dict:
        leaves = [_leaf(body) for body in self.bodies]
        index = leaves.index(bytes.fromhex(uuid))
        body = base64.b64encode(self.bodies[index]).decode()
        signed = json.dumps(
            {
                "body": body,
                "integratedTime": self.times[index],
                "logID": self.log_id,
                "logIndex": index,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        verification = {"signedEntryTimestamp": base64.b64encode(self._log_sign(signed)).decode()}
        if with_proof:
            root = tree_root(leaves)
            verification["inclusionProof"] = {
                "logIndex": index,
                "treeSize": len(leaves),
                "rootHash": root.hex(),
                "hashes": [item.hex() for item in audit_path(index, leaves)],
                "checkpoint": self._note(len(leaves), root),
            }
        return {
            uuid: {
                "body": body,
                "integratedTime": self.times[index],
                "logID": self.log_id,
                "logIndex": index,
                "verification": verification,
            }
        }

    def accept_entry(self, entry: dict) -> str:
        """What a real log does on upload: refuse an entry whose signature does not verify."""
        if entry.get("kind") != "hashedrekord" or entry.get("apiVersion") != "0.0.1":
            raise ValueError("unsupported entry kind")
        spec = entry["spec"]
        digest = bytes.fromhex(spec["data"]["hash"]["value"])
        key = serialization.load_pem_public_key(
            base64.b64decode(spec["signature"]["publicKey"]["content"])
        )
        key.verify(
            base64.b64decode(spec["signature"]["content"]),
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        if self.log_digest_override:
            spec["data"]["hash"]["value"] = self.log_digest_override
        return self.add_entry(entry)

    def rekor_proof(self, digest_hex: str, integrated_time: int | None = None) -> dict:
        """The proof ``tempus anchor create`` would store, without going over HTTP."""
        entry = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {"data": {"hash": {"algorithm": "sha256", "value": digest_hex}}},
        }
        uuid = self.add_entry(entry, integrated_time)
        logged = self.entry_response(uuid)[uuid]
        inclusion = logged["verification"]["inclusionProof"]
        return {
            "backend": "rekor",
            "log_url": "http://127.0.0.1/",
            "entry_uuid": uuid,
            "body": logged["body"],
            "integrated_time": logged["integratedTime"],
            "log_id": logged["logID"],
            "log_index": logged["logIndex"],
            "signed_entry_timestamp": logged["verification"]["signedEntryTimestamp"],
            "inclusion_proof": {
                "log_index": inclusion["logIndex"],
                "tree_size": inclusion["treeSize"],
                "root_hash": inclusion["rootHash"],
                "hashes": inclusion["hashes"],
                "checkpoint": inclusion["checkpoint"],
            },
        }

    # --- the TSA

    def token(self, digest: bytes, **options) -> bytes:
        return make_token(digest, self.tsa_key, self.tsa_cert, **options)

    def rfc3161_proof(self, digest_hex: str, **options) -> dict:
        token = self.token(bytes.fromhex(digest_hex), **options)
        return {
            "backend": "rfc3161",
            "tsa_url": "http://127.0.0.1/",
            "token": base64.b64encode(token).decode(),
        }

    def respond_to_timestamp(self, request_der: bytes) -> bytes:
        digest, nonce = parse_request(request_der)
        nonce = self.tsa_nonce_override if self.tsa_nonce_override is not None else nonce
        return make_response(self.token(self.tsa_digest_override or digest, nonce=nonce))

    # --- HTTP

    @contextlib.contextmanager
    def serve(self):
        """Serve on localhost; yields ``(rekor_url, tsa_url)``."""
        server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            yield base, f"{base}/tsa"
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


def _handler(authority: Authority):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep test output clean
            pass

        def _send(self, status: int, body: bytes = b"", content_type="application/json", **headers):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            payload = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            authority.requests.append(f"POST {self.path}")
            if authority.redirect:
                self._send(302, Location="https://elsewhere.example/steal")
            elif self.path == "/api/v1/log/entries":
                self._post_entry(payload)
            elif self.path == "/tsa":
                self._post_timestamp(payload)
            else:
                self._send(404)

        def _post_entry(self, payload: bytes):
            if authority.rekor_status:
                self._send(authority.rekor_status)
                return
            try:
                uuid = authority.accept_entry(json.loads(payload))
            except Exception as exc:  # a real log answers 400, and says little
                self._send(400, json.dumps({"message": str(exc)}).encode())
                return
            location = f"/api/v1/log/entries/{uuid}"
            if authority.conflict_next:
                authority.conflict_next = False
                self._send(409, b"{}", Location=location)
                return
            with_proof = authority.proof_after_gets == 0
            body = json.dumps(authority.entry_response(uuid, with_proof)).encode()
            self._send(201, body, Location=location)

        def _post_timestamp(self, payload: bytes):
            if authority.tsa_status:
                self._send(authority.tsa_status)
                return
            if self.headers.get("Content-Type") != "application/timestamp-query":
                self._send(415)
                return
            self._send(
                200,
                authority.respond_to_timestamp(payload),
                content_type="application/timestamp-reply",
            )

        def do_GET(self):
            authority.requests.append(f"GET {self.path}")
            prefix = "/api/v1/log/entries/"
            if not self.path.startswith(prefix):
                self._send(404)
                return
            authority.gets += 1
            if authority.gets <= authority.proof_after_gets and authority.proof_after_gets > 1:
                self._send(404)
                return
            uuid = self.path[len(prefix) :]
            self._send(200, json.dumps(authority.entry_response(uuid)).encode())

    return Handler
