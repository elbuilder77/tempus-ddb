//! Signature verification for anchors: ECDSA P-256 and P-384, RSA PKCS#1 v1.5, always
//! over a hash computed by the caller, because real timestamp tokens mix curves and digests
//! (Sigstore signs SHA-256 with a P-384 key). Public keys come from SPKI structures.
//!
//! RSA is verify-only over `crypto-bigint` on purpose. The `rsa` crate carries
//! RUSTSEC-2023-0071, unpatched, about private-key timing, which does not apply to a
//! verifier but would fail `cargo audit` for everyone downstream. Nothing here is secret,
//! and the check builds the one valid encoding and compares bytes, so there is no padding
//! parser to fool (the Bleichenbacher 2006 forgery needs one).

use crate::der::{self, nested, DerError};
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha384, Sha512};

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
pub(crate) const OID_RSA_ENCRYPTION: &[u8] =
    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];
const OID_RSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_RSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
const OID_RSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];

const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub(crate) fn from_oid(oid: &[u8]) -> Option<Self> {
        match oid {
            OID_SHA256 => Some(Self::Sha256),
            OID_SHA384 => Some(Self::Sha384),
            OID_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// DER `DigestInfo` up to the hash value (RFC 8017, section 9.2, note 1).
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// What a signature algorithm identifier says about the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureHash {
    /// `ecdsa-with-SHA256`, `sha256WithRSAEncryption` and the like.
    Named(HashAlg),
    /// Bare `rsaEncryption`, as CMS allows: the hash is the digest algorithm's.
    FromContext,
}

/// The hash a certificate or CMS signature algorithm names, or `None` when the algorithm
/// is not one this verifier accepts (RSA-PSS, SHA-1, anything else).
pub(crate) fn signature_hash(oid: &[u8]) -> Option<SignatureHash> {
    match oid {
        OID_ECDSA_SHA256 | OID_RSA_SHA256 => Some(SignatureHash::Named(HashAlg::Sha256)),
        OID_ECDSA_SHA384 | OID_RSA_SHA384 => Some(SignatureHash::Named(HashAlg::Sha384)),
        OID_ECDSA_SHA512 | OID_RSA_SHA512 => Some(SignatureHash::Named(HashAlg::Sha512)),
        OID_RSA_ENCRYPTION => Some(SignatureHash::FromContext),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// Well-formed, but not an algorithm or size this verifier accepts.
    Unsupported,
    Malformed,
}

impl From<DerError> for KeyError {
    fn from(_: DerError) -> Self {
        Self::Malformed
    }
}

/// Read a DER `SubjectPublicKeyInfo`.
pub(crate) fn parse_spki(spki: &[u8]) -> Result<PublicKey, KeyError> {
    let outer = der::single(spki)?;
    if outer.tag != der::SEQUENCE {
        return Err(KeyError::Malformed);
    }
    let mut fields = nested(&outer);
    let algorithm = fields.expect(der::SEQUENCE)?;
    let key_bits = der::bit_string_bytes(&fields.next_tlv()?)?;
    fields.finish()?;
    let mut algorithm = nested(&algorithm);
    let oid = algorithm.expect(der::OID)?;
    match oid.value {
        OID_EC_PUBLIC_KEY => {
            let curve = algorithm.expect(der::OID)?;
            match curve.value {
                OID_P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bits)
                    .map(PublicKey::P256)
                    .map_err(|_| KeyError::Malformed),
                OID_P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bits)
                    .map(PublicKey::P384)
                    .map_err(|_| KeyError::Malformed),
                _ => Err(KeyError::Unsupported),
            }
        }
        OID_RSA_ENCRYPTION => {
            let inner = der::single(key_bits)?;
            if inner.tag != der::SEQUENCE {
                return Err(KeyError::Malformed);
            }
            let mut numbers = nested(&inner);
            let modulus = der::unsigned_integer(&numbers.next_tlv()?)?;
            let exponent = der::unsigned_integer(&numbers.next_tlv()?)?;
            numbers.finish()?;
            let bits = bit_length(modulus);
            if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
                return Err(KeyError::Unsupported);
            }
            // The modulus must be odd, and so must a usable exponent, which is small in
            // practice. e = 1 would make every message its own signature.
            let odd = |bytes: &[u8]| bytes.last().is_some_and(|byte| byte & 1 == 1);
            if !odd(modulus) || !odd(exponent) || exponent == [1] || exponent.len() > 8 {
                return Err(KeyError::Malformed);
            }
            Ok(PublicKey::Rsa {
                modulus: modulus.to_vec(),
                exponent: exponent.to_vec(),
            })
        }
        _ => Err(KeyError::Unsupported),
    }
}

fn bit_length(magnitude: &[u8]) -> usize {
    match magnitude.first() {
        Some(first) => magnitude.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    }
}

/// Split a DER `ECDSA-Sig-Value` into fixed-width `r || s`.
fn ecdsa_fixed(signature: &[u8], width: usize) -> Option<Vec<u8>> {
    let outer = der::single(signature).ok()?;
    if outer.tag != der::SEQUENCE {
        return None;
    }
    let mut numbers = nested(&outer);
    let r = der::unsigned_integer(&numbers.next_tlv().ok()?).ok()?;
    let s = der::unsigned_integer(&numbers.next_tlv().ok()?).ok()?;
    numbers.finish().ok()?;
    if r.len() > width || s.len() > width {
        return None;
    }
    let mut fixed = vec![0u8; width * 2];
    fixed[width - r.len()..width].copy_from_slice(r);
    fixed[width * 2 - s.len()..].copy_from_slice(s);
    Some(fixed)
}

fn rsa_verify(
    modulus: &[u8],
    exponent: &[u8],
    hash: HashAlg,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    let size = modulus.len();
    if signature.len() != size || digest.len() != hash.digest(b"").len() {
        return false;
    }
    let bits = (size * 8) as u32;
    let parse = |bytes: &[u8]| BoxedUint::from_be_slice(bytes, bits).ok();
    let (Some(n), Some(e), Some(s)) = (parse(modulus), parse(exponent), parse(signature)) else {
        return false;
    };
    if s >= n {
        return false;
    }
    let Some(n) = Option::<Odd<BoxedUint>>::from(Odd::new(n)) else {
        return false;
    };
    let params = BoxedMontyParams::new(n);
    let recovered = BoxedMontyForm::new(s, &params)
        .pow(&e)
        .retrieve()
        .to_be_bytes();
    // `to_be_bytes` is padded to the limb size; the value itself fits in `size` bytes.
    let Some(padding) = recovered.len().checked_sub(size) else {
        return false;
    };
    if recovered[..padding].iter().any(|byte| *byte != 0) {
        return false;
    }
    let recovered = &recovered[padding..];
    let prefix = hash.digest_info_prefix();
    let Some(fill) = size.checked_sub(3 + prefix.len() + digest.len()) else {
        return false;
    };
    if fill < 8 {
        return false;
    }
    let mut expected = Vec::with_capacity(size);
    expected.extend_from_slice(&[0x00, 0x01]);
    expected.extend(std::iter::repeat_n(0xFF, fill));
    expected.push(0x00);
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(digest);
    recovered == expected.as_slice()
}

/// Verify `signature` (DER for ECDSA, raw for RSA) over `digest`, a hash made with `hash`.
pub(crate) fn verify_digest(
    key: &PublicKey,
    hash: HashAlg,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    match key {
        PublicKey::P256(key) => ecdsa_fixed(signature, 32)
            .and_then(|fixed| p256::ecdsa::Signature::from_slice(&fixed).ok())
            .is_some_and(|signature| key.verify_prehash(digest, &signature).is_ok()),
        PublicKey::P384(key) => ecdsa_fixed(signature, 48)
            .and_then(|fixed| p384::ecdsa::Signature::from_slice(&fixed).ok())
            .is_some_and(|signature| key.verify_prehash(digest, &signature).is_ok()),
        PublicKey::Rsa { modulus, exponent } => {
            rsa_verify(modulus, exponent, hash, digest, signature)
        }
    }
}

/// Verify a signature over `message` under an algorithm identifier. `context_hash` is the
/// digest algorithm CMS declares beside the signature; it must agree with one named in the
/// identifier. `None` means the algorithm is not accepted or does not fit the key.
pub(crate) fn verify_message(
    key: &PublicKey,
    algorithm_oid: &[u8],
    context_hash: Option<HashAlg>,
    message: &[u8],
    signature: &[u8],
) -> Option<bool> {
    let is_ecdsa = matches!(
        algorithm_oid,
        OID_ECDSA_SHA256 | OID_ECDSA_SHA384 | OID_ECDSA_SHA512
    );
    let hash = match (signature_hash(algorithm_oid)?, context_hash) {
        (SignatureHash::Named(named), Some(context)) if named != context => return None,
        (SignatureHash::Named(named), _) => named,
        (SignatureHash::FromContext, Some(context)) => context,
        (SignatureHash::FromContext, None) => return None,
    };
    let fits = match key {
        PublicKey::P256(_) | PublicKey::P384(_) => is_ecdsa,
        PublicKey::Rsa { .. } => !is_ecdsa,
    };
    if !fits {
        return None;
    }
    Some(verify_digest(key, hash, &hash.digest(message), signature))
}

/// Native only: a fresh P-256 key used for one signature over `digest` and dropped.
/// Returns (DER `SubjectPublicKeyInfo`, DER `ECDSA-Sig-Value`).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn sign_with_ephemeral_p256(digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use rand::RngCore;

    let mut secret = [0u8; 32];
    let key = loop {
        rand::rngs::OsRng.fill_bytes(&mut secret);
        // A random 32-byte value is out of range only with negligible probability.
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&secret) {
            break key;
        }
    };
    secret.fill(0);
    let signature: p256::ecdsa::Signature = key
        .sign_prehash(digest)
        .map_err(|e| format!("Ephemeral signature failed: {e}"))?;
    // SEQUENCE { SEQUENCE { ecPublicKey, prime256v1 }, BIT STRING point }
    let point = key.verifying_key().to_sec1_point(false);
    let mut spki = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200")
        .map_err(|e| e.to_string())?;
    spki.extend_from_slice(point.as_bytes());
    let fixed = signature.to_bytes();
    let (r, s) = fixed.split_at(32);
    Ok((spki, ecdsa_der(r, s)))
}

#[cfg(not(target_arch = "wasm32"))]
fn ecdsa_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn integer(value: &[u8]) -> Vec<u8> {
        let start = value
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(value.len() - 1);
        let value = &value[start..];
        let mut out = vec![der::INTEGER];
        let pad = value[0] & 0x80 != 0;
        out.push((value.len() + usize::from(pad)) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(value);
        out
    }
    let body = [integer(r), integer(s)].concat();
    let mut out = vec![der::SEQUENCE, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::Value;

    const REKOR_KEY: &str = include_str!("../tests/vectors/anchor/rekor_public_key.pem");
    const REKOR_ENTRY: &str = include_str!("../tests/vectors/anchor/rekor_hashedrekord.json");
    const DIGICERT_ROOT: &str =
        include_str!("../tests/vectors/anchor/digicert_trusted_root_g4.pem");
    const SIGSTORE_ROOT: &str = include_str!("../tests/vectors/anchor/sigstore_tsa_root.pem");

    fn pem(text: &str, label: &str) -> Vec<u8> {
        der::pem_or_base64_blocks(text, label).unwrap().remove(0)
    }

    /// (spki, tbs, signature algorithm oid, signature) of a certificate.
    fn cert_parts(cert: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let outer = der::single(cert).unwrap();
        let mut fields = nested(&outer);
        let tbs = fields.expect(der::SEQUENCE).unwrap();
        let algorithm = fields.expect(der::SEQUENCE).unwrap();
        let signature = der::bit_string_bytes(&fields.next_tlv().unwrap()).unwrap();
        let oid = nested(&algorithm).expect(der::OID).unwrap();
        let mut tbs_fields = nested(&tbs);
        tbs_fields.expect(der::context(0)).unwrap();
        tbs_fields.expect(der::INTEGER).unwrap();
        tbs_fields.expect(der::SEQUENCE).unwrap();
        tbs_fields.expect(der::SEQUENCE).unwrap();
        tbs_fields.expect(der::SEQUENCE).unwrap();
        tbs_fields.expect(der::SEQUENCE).unwrap();
        let spki = tbs_fields.expect(der::SEQUENCE).unwrap();
        (
            spki.raw.to_vec(),
            tbs.raw.to_vec(),
            oid.value.to_vec(),
            signature.to_vec(),
        )
    }

    /// The real Rekor entry's own signature proves how `hashedrekord` signs: ECDSA over the
    /// hash in the entry, not over a hash of that hash.
    #[test]
    fn ecdsa_p256_verifies_a_real_rekor_entry_signature() {
        let entry: Value = serde_json::from_str(REKOR_ENTRY).unwrap();
        let body: Value =
            serde_json::from_slice(&STANDARD.decode(entry["body"].as_str().unwrap()).unwrap())
                .unwrap();
        let digest = hex::decode(body["spec"]["data"]["hash"]["value"].as_str().unwrap()).unwrap();
        let signature = STANDARD
            .decode(body["spec"]["signature"]["content"].as_str().unwrap())
            .unwrap();
        let key_pem = String::from_utf8(
            STANDARD
                .decode(
                    body["spec"]["signature"]["publicKey"]["content"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        let key = parse_spki(&pem(&key_pem, "PUBLIC KEY")).unwrap();
        assert!(matches!(key, PublicKey::P256(_)));
        assert!(verify_digest(&key, HashAlg::Sha256, &digest, &signature));
        let mut other = digest.clone();
        other[0] ^= 1;
        assert!(!verify_digest(&key, HashAlg::Sha256, &other, &signature));
        let mut bad = signature.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!verify_digest(&key, HashAlg::Sha256, &digest, &bad));
    }

    #[test]
    fn rekor_key_is_p256() {
        let key = parse_spki(&pem(REKOR_KEY, "PUBLIC KEY")).unwrap();
        assert!(matches!(key, PublicKey::P256(_)));
    }

    #[test]
    fn ecdsa_p384_verifies_a_real_self_signed_root() {
        let cert = pem(SIGSTORE_ROOT, "CERTIFICATE");
        let (spki, tbs, oid, signature) = cert_parts(&cert);
        let key = parse_spki(&spki).unwrap();
        assert!(matches!(key, PublicKey::P384(_)));
        let Some(SignatureHash::Named(hash)) = signature_hash(&oid) else {
            panic!("named hash expected")
        };
        assert_eq!(hash, HashAlg::Sha384);
        assert!(verify_digest(&key, hash, &hash.digest(&tbs), &signature));
        assert!(!verify_digest(
            &key,
            hash,
            &hash.digest(b"other"),
            &signature
        ));
    }

    #[test]
    fn rsa_verifies_a_real_self_signed_root() {
        let cert = pem(DIGICERT_ROOT, "CERTIFICATE");
        let (spki, tbs, oid, signature) = cert_parts(&cert);
        let key = parse_spki(&spki).unwrap();
        assert!(matches!(key, PublicKey::Rsa { .. }));
        let Some(SignatureHash::Named(hash)) = signature_hash(&oid) else {
            panic!("named hash expected")
        };
        assert_eq!(hash, HashAlg::Sha384);
        assert!(verify_digest(&key, hash, &hash.digest(&tbs), &signature));
        assert!(!verify_digest(
            &key,
            hash,
            &hash.digest(b"other"),
            &signature
        ));
        // The same value under another hash has another encoding.
        assert!(!verify_digest(
            &key,
            HashAlg::Sha512,
            &HashAlg::Sha512.digest(&tbs),
            &signature
        ));
        let mut bad = signature.clone();
        bad[100] ^= 1;
        assert!(!verify_digest(&key, hash, &hash.digest(&tbs), &bad));
        assert!(!verify_digest(
            &key,
            hash,
            &hash.digest(&tbs),
            &signature[1..]
        ));
    }

    fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if value.len() < 0x80 {
                out.push(value.len() as u8);
            } else if value.len() < 0x100 {
                out.extend_from_slice(&[0x81, value.len() as u8]);
            } else {
                out.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]);
            }
            out.extend_from_slice(value);
            out
        }
        let integer = |bytes: &[u8]| {
            let mut value = Vec::new();
            if bytes[0] & 0x80 != 0 {
                value.push(0);
            }
            value.extend_from_slice(bytes);
            tlv(der::INTEGER, &value)
        };
        let numbers = tlv(
            der::SEQUENCE,
            &[integer(modulus), integer(exponent)].concat(),
        );
        let mut bits = vec![0u8];
        bits.extend_from_slice(&numbers);
        let algorithm = tlv(
            der::SEQUENCE,
            &[tlv(der::OID, OID_RSA_ENCRYPTION), tlv(0x05, &[])].concat(),
        );
        tlv(
            der::SEQUENCE,
            &[algorithm, tlv(der::BIT_STRING, &bits)].concat(),
        )
    }

    #[test]
    fn rsa_key_shapes_are_refused() {
        let good = {
            let mut modulus = vec![0xFF; 256];
            modulus[255] = 0xFD;
            modulus
        };
        assert!(parse_spki(&rsa_spki(&good, &[1, 0, 1])).is_ok());
        let short = vec![0xFD; 128];
        assert_eq!(
            parse_spki(&rsa_spki(&short, &[1, 0, 1])).unwrap_err(),
            KeyError::Unsupported
        );
        let huge = vec![0xFD; 1025];
        assert_eq!(
            parse_spki(&rsa_spki(&huge, &[1, 0, 1])).unwrap_err(),
            KeyError::Unsupported
        );
        let mut even = good.clone();
        even[255] = 0xFC;
        assert_eq!(
            parse_spki(&rsa_spki(&even, &[1, 0, 1])).unwrap_err(),
            KeyError::Malformed
        );
        assert_eq!(
            parse_spki(&rsa_spki(&good, &[1])).unwrap_err(),
            KeyError::Malformed,
            "e = 1 makes every message its own signature"
        );
        assert_eq!(
            parse_spki(&rsa_spki(&good, &[2])).unwrap_err(),
            KeyError::Malformed
        );
    }

    #[test]
    fn unknown_signature_algorithms_have_no_hash() {
        // sha1WithRSAEncryption and RSASSA-PSS.
        assert!(signature_hash(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]).is_none());
        assert!(signature_hash(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A]).is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn ephemeral_signature_verifies_and_keys_differ() {
        let digest = HashAlg::Sha256.digest(b"checkpoint");
        for _ in 0..16 {
            // Repeated because the DER integers vary in length with their leading bits.
            let (spki, signature) = sign_with_ephemeral_p256(&digest).unwrap();
            let key = parse_spki(&spki).unwrap();
            assert!(verify_digest(&key, HashAlg::Sha256, &digest, &signature));
        }
        let (first, _) = sign_with_ephemeral_p256(&digest).unwrap();
        let (second, _) = sign_with_ephemeral_p256(&digest).unwrap();
        assert_ne!(first, second);
    }
}
