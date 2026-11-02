# Anchor test vectors

Real data from public services, used to prove the parsers against what the services return.

| File | What it is |
|---|---|
| `rekor_hashedrekord.json` | An entry read from the public Rekor log, as its API returns it. It was signed with a bare key, so it holds no identity. |
| `rekor_public_key.pem` | The public key of that log, from the Sigstore trust root. |
| `tsr_digicert.der` | A `TimeStampResp` from `http://timestamp.digicert.com`: RSA, with a cross-signed chain. |
| `tsr_sigstore.der` | A `TimeStampResp` from the Sigstore timestamp authority: P-384 over SHA-256. |
| `digicert_trusted_root_g4.pem`, `sigstore_tsa_root.pem` | The roots those tokens chain to. |

Both tokens stamp the same constant, the SHA-256 of `tempus-ddb rfc3161 test vector`, with the
nonce `0x01020304050607`. Nothing about any Tempus user was ever sent.

FreeTSA was checked by hand too. Its token is not committed, because its certificates carry a
personal e-mail address.
