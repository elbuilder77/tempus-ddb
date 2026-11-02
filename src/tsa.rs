//! Offline verification of an RFC 3161 timestamp token: a CMS `SignedData` over a `TSTInfo`
//! that names the checkpoint digest, signed by a certificate marked for timestamping whose
//! chain, taken only from the token, reaches a root the verifier pinned. Certificates are
//! judged at the token's `genTime`, so old evidence keeps verifying after they expire.
//! Revocation cannot be checked offline; the verifier says so in `trust.not_checked`.

use crate::anchor::ProofVerdict;
use crate::b2a::unknown_fields;
use crate::der::{self, nested, DerError, Tlv};
use crate::sigverify::{self, HashAlg, KeyError, PublicKey};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

const PROOF_FIELDS: &[&str] = &["backend", "tsa_url", "token"];

const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SIGNING_CERT: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0C,
];
const OID_SIGNING_CERT_V2: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];
const OID_EXT_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1D, 0x0E];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const OID_EXT_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const OID_EXT_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
const OID_KP_TIME_STAMPING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

const KU_DIGITAL_SIGNATURE: u16 = 0x8000;
const KU_NON_REPUDIATION: u16 = 0x4000;
const KU_KEY_CERT_SIGN: u16 = 0x0400;

const TOKEN_MALFORMED: &str = "ANCHOR_TSA_TOKEN_MALFORMED";
const IMPRINT_MISMATCH: &str = "ANCHOR_TSA_IMPRINT_MISMATCH";
const ATTRIBUTES_INVALID: &str = "ANCHOR_TSA_ATTRIBUTES_INVALID";
const SIGNATURE_INVALID: &str = "ANCHOR_TSA_SIGNATURE_INVALID";
const ALGORITHM_UNSUPPORTED: &str = "ANCHOR_TSA_ALGORITHM_UNSUPPORTED";
const SIGNER_INVALID: &str = "ANCHOR_TSA_SIGNER_INVALID";
const CHAIN_INVALID: &str = "ANCHOR_TSA_CHAIN_INVALID";

const MAX_TOKEN_BASE64: usize = 256 * 1024;
const MAX_CHAIN_DEPTH: u64 = 8;

#[derive(Debug)]
struct Certificate<'a> {
    raw: &'a [u8],
    tbs: &'a [u8],
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: i64,
    not_after: i64,
    spki: &'a [u8],
    is_ca: bool,
    path_len: Option<u64>,
    key_usage: Option<u16>,
    timestamping: bool,
    eku_critical: bool,
    subject_key_id: Option<&'a [u8]>,
    unknown_critical: bool,
}

impl<'a> Certificate<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self, DerError> {
        Self::from_tlv(&der::single(raw)?)
    }

    fn from_tlv(outer: &Tlv<'a>) -> Result<Self, DerError> {
        if outer.tag != der::SEQUENCE {
            return Err(DerError);
        }
        let mut fields = nested(outer);
        let tbs = fields.expect(der::SEQUENCE)?;
        let algorithm = fields.expect(der::SEQUENCE)?;
        let signature = der::bit_string_bytes(&fields.next_tlv()?)?;
        fields.finish()?;

        let mut tbs_fields = nested(&tbs);
        tbs_fields.optional(der::context(0))?;
        let serial = tbs_fields.expect(der::INTEGER)?;
        let inner_algorithm = tbs_fields.expect(der::SEQUENCE)?;
        // RFC 5280: the two copies must agree; only the outer one is outside the signature.
        if inner_algorithm.raw != algorithm.raw {
            return Err(DerError);
        }
        let issuer = tbs_fields.expect(der::SEQUENCE)?;
        let validity = tbs_fields.expect(der::SEQUENCE)?;
        let subject = tbs_fields.expect(der::SEQUENCE)?;
        let spki = tbs_fields.expect(der::SEQUENCE)?;
        tbs_fields.optional(der::context_primitive(1))?;
        tbs_fields.optional(der::context_primitive(2))?;
        let extensions = tbs_fields.optional(der::context(3))?;
        tbs_fields.finish()?;

        let mut validity_fields = nested(&validity);
        let not_before = der::time_seconds(&validity_fields.next_tlv()?)?;
        let not_after = der::time_seconds(&validity_fields.next_tlv()?)?;
        validity_fields.finish()?;

        let mut certificate = Self {
            raw: outer.raw,
            tbs: tbs.raw,
            signature_algorithm: nested(&algorithm).expect(der::OID)?.value,
            signature,
            serial: serial.value,
            issuer: issuer.raw,
            subject: subject.raw,
            not_before,
            not_after,
            spki: spki.raw,
            is_ca: false,
            path_len: None,
            key_usage: None,
            timestamping: false,
            eku_critical: false,
            subject_key_id: None,
            unknown_critical: false,
        };
        if let Some(extensions) = extensions {
            let list = der::single(extensions.value)?;
            if list.tag != der::SEQUENCE {
                return Err(DerError);
            }
            certificate.read_extensions(&list)?;
        }
        Ok(certificate)
    }

    fn read_extensions(&mut self, list: &Tlv<'a>) -> Result<(), DerError> {
        let mut seen: Vec<&[u8]> = Vec::new();
        let mut items = nested(list);
        while !items.is_empty() {
            let extension = items.expect(der::SEQUENCE)?;
            let mut fields = nested(&extension);
            let oid = fields.expect(der::OID)?.value;
            if seen.contains(&oid) {
                return Err(DerError);
            }
            seen.push(oid);
            let critical = match fields.optional(der::BOOLEAN)? {
                Some(flag) => der::boolean(&flag)?,
                None => false,
            };
            let value = fields.expect(der::OCTET_STRING)?.value;
            fields.finish()?;
            match oid {
                OID_EXT_BASIC_CONSTRAINTS => {
                    let constraints = der::single(value)?;
                    let mut inner = nested(&constraints);
                    if let Some(flag) = inner.optional(der::BOOLEAN)? {
                        self.is_ca = der::boolean(&flag)?;
                    }
                    if let Some(length) = inner.optional(der::INTEGER)? {
                        let digits = der::unsigned_integer(&length)?;
                        if digits.len() > 4 {
                            return Err(DerError);
                        }
                        self.path_len = Some(
                            digits
                                .iter()
                                .fold(0u64, |total, byte| total << 8 | *byte as u64),
                        );
                    }
                    inner.finish()?;
                }
                OID_EXT_KEY_USAGE => {
                    let bits = der::single(value)?;
                    match (bits.tag, bits.value) {
                        (der::BIT_STRING, [_, first]) => {
                            self.key_usage = Some((*first as u16) << 8);
                        }
                        (der::BIT_STRING, [_, first, second, ..]) => {
                            self.key_usage = Some((*first as u16) << 8 | *second as u16);
                        }
                        _ => return Err(DerError),
                    }
                }
                OID_EXT_EXTENDED_KEY_USAGE => {
                    let purposes = der::single(value)?;
                    let mut inner = nested(&purposes);
                    let (mut named, mut count) = (false, 0);
                    while !inner.is_empty() {
                        named |= inner.expect(der::OID)?.value == OID_KP_TIME_STAMPING;
                        count += 1;
                    }
                    // RFC 3161, section 2.3: timestamping, and nothing else.
                    self.timestamping = named && count == 1;
                    self.eku_critical = critical;
                }
                OID_EXT_SUBJECT_KEY_ID => {
                    self.subject_key_id = Some(der::single(value)?.value);
                }
                _ if critical => self.unknown_critical = true,
                _ => {}
            }
        }
        Ok(())
    }

    fn valid_at(&self, seconds: i64) -> bool {
        self.not_before <= seconds && seconds <= self.not_after
    }

    fn may_sign_certificates(&self) -> bool {
        self.is_ca
            && !self.unknown_critical
            && self
                .key_usage
                .is_none_or(|usage| usage & KU_KEY_CERT_SIGN != 0)
    }

    fn public_key(&self) -> Result<PublicKey, &'static str> {
        sigverify::parse_spki(self.spki).map_err(|error| match error {
            KeyError::Unsupported => ALGORITHM_UNSUPPORTED,
            KeyError::Malformed => TOKEN_MALFORMED,
        })
    }

    /// Whether `issuer` signed this certificate.
    fn signed_by(&self, issuer: &Certificate<'_>) -> Result<bool, &'static str> {
        if self.issuer != issuer.subject {
            return Ok(false);
        }
        let key = issuer.public_key()?;
        sigverify::verify_message(
            &key,
            self.signature_algorithm,
            None,
            self.tbs,
            self.signature,
        )
        .ok_or(ALGORITHM_UNSUPPORTED)
    }
}

#[derive(Debug)]
enum SignerId<'a> {
    IssuerAndSerial { issuer: &'a [u8], serial: &'a [u8] },
    SubjectKeyId(&'a [u8]),
}

#[derive(Debug)]
struct Token<'a> {
    tst_info: &'a [u8],
    certificates: Vec<Certificate<'a>>,
    signer: SignerId<'a>,
    digest_algorithm: &'a [u8],
    signed_attributes: Tlv<'a>,
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
}

fn algorithm_oid<'a>(identifier: &Tlv<'a>) -> Result<&'a [u8], DerError> {
    Ok(nested(identifier).expect(der::OID)?.value)
}

fn parse_token(token: &[u8]) -> Result<Token<'_>, DerError> {
    let content_info = der::single(token)?;
    if content_info.tag != der::SEQUENCE {
        return Err(DerError);
    }
    let mut fields = nested(&content_info);
    if fields.expect(der::OID)?.value != OID_SIGNED_DATA {
        return Err(DerError);
    }
    let wrapper = fields.expect(der::context(0))?;
    fields.finish()?;
    let signed_data = der::single(wrapper.value)?;
    if signed_data.tag != der::SEQUENCE {
        return Err(DerError);
    }
    let mut data = nested(&signed_data);
    data.expect(der::INTEGER)?;
    data.expect(der::SET)?;
    let encapsulated = data.expect(der::SEQUENCE)?;
    let certificates_set = data.optional(der::context(0))?;
    data.optional(der::context(1))?;
    let signer_infos = data.expect(der::SET)?;
    data.finish()?;

    let mut encapsulated = nested(&encapsulated);
    if encapsulated.expect(der::OID)?.value != OID_TST_INFO {
        return Err(DerError);
    }
    let content = encapsulated.expect(der::context(0))?;
    encapsulated.finish()?;
    let tst_info = der::single(content.value)?;
    if tst_info.tag != der::OCTET_STRING {
        return Err(DerError);
    }

    let mut certificates = Vec::new();
    if let Some(set) = certificates_set {
        let mut items = nested(&set);
        while !items.is_empty() {
            certificates.push(Certificate::from_tlv(&items.next_tlv()?)?);
            if certificates.len() > 16 {
                return Err(DerError);
            }
        }
    }

    // RFC 3161: exactly one signer.
    let signer_info = der::single(signer_infos.value)?;
    if signer_info.tag != der::SEQUENCE {
        return Err(DerError);
    }
    let mut info = nested(&signer_info);
    info.expect(der::INTEGER)?;
    let identifier = info.next_tlv()?;
    let signer = match identifier.tag {
        der::SEQUENCE => {
            let mut parts = nested(&identifier);
            let issuer = parts.expect(der::SEQUENCE)?.raw;
            let serial = parts.expect(der::INTEGER)?.value;
            parts.finish()?;
            SignerId::IssuerAndSerial { issuer, serial }
        }
        tag if tag == der::context_primitive(0) => SignerId::SubjectKeyId(identifier.value),
        _ => return Err(DerError),
    };
    let digest_algorithm = algorithm_oid(&info.expect(der::SEQUENCE)?)?;
    let signed_attributes = info.expect(der::context(0))?;
    let signature_algorithm = algorithm_oid(&info.expect(der::SEQUENCE)?)?;
    let signature = info.expect(der::OCTET_STRING)?.value;
    info.optional(der::context(1))?;
    info.finish()?;

    Ok(Token {
        tst_info: tst_info.value,
        certificates,
        signer,
        digest_algorithm,
        signed_attributes,
        signature_algorithm,
        signature,
    })
}

struct TstInfo<'a> {
    imprint_algorithm: &'a [u8],
    imprint: &'a [u8],
    gen_time: i64,
    /// The latest moment `gen_time` can stand for, which is all a proof may claim.
    latest: i64,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))] // read when a token is first obtained
    nonce: Option<&'a [u8]>,
}

fn parse_tst_info(raw: &[u8]) -> Result<TstInfo<'_>, DerError> {
    let outer = der::single(raw)?;
    if outer.tag != der::SEQUENCE {
        return Err(DerError);
    }
    let mut fields = nested(&outer);
    fields.expect(der::INTEGER)?;
    fields.expect(der::OID)?;
    let imprint = fields.expect(der::SEQUENCE)?;
    fields.expect(der::INTEGER)?;
    let gen_time = fields.expect(der::GENERALIZED_TIME)?;
    let accuracy = fields.optional(der::SEQUENCE)?;
    fields.optional(der::BOOLEAN)?; // ordering
    let nonce = fields.optional(der::INTEGER)?;
    let mut imprint_fields = nested(&imprint);
    let imprint_algorithm = algorithm_oid(&imprint_fields.expect(der::SEQUENCE)?)?;
    let hashed = imprint_fields.expect(der::OCTET_STRING)?.value;
    imprint_fields.finish()?;
    let seconds = der::time_seconds(&gen_time)?;
    Ok(TstInfo {
        imprint_algorithm,
        imprint: hashed,
        gen_time: seconds,
        latest: seconds + allowance(accuracy.as_ref(), &gen_time)?,
        nonce: nonce.map(|nonce| nonce.value),
    })
}

/// RFC 3161, section 2.4.2: the time is `genTime` give or take its `accuracy`, so a token can
/// only say "no later than" the two added. In whole seconds, rounding up, because the fraction
/// `genTime` may hold is floored when it is read.
fn allowance(accuracy: Option<&Tlv<'_>>, gen_time: &Tlv<'_>) -> Result<i64, DerError> {
    let mut seconds = i64::from(gen_time.value.contains(&b'.'));
    if let Some(accuracy) = accuracy {
        let mut fields = nested(accuracy);
        if let Some(whole) = fields.optional(der::INTEGER)? {
            seconds += small_integer(whole.value)?;
        }
        let mut below_a_second = false;
        for number in [0, 1] {
            if let Some(part) = fields.optional(der::context_primitive(number))? {
                let part = small_integer(part.value)?;
                if part > 999 {
                    return Err(DerError);
                }
                below_a_second |= part > 0;
            }
        }
        fields.finish()?;
        seconds += i64::from(below_a_second);
    }
    Ok(seconds)
}

/// The content of a small non-negative DER integer, however it is tagged. Enough for 136 years.
fn small_integer(content: &[u8]) -> Result<i64, DerError> {
    if content.is_empty() || content.len() > 5 || content[0] & 0x80 != 0 {
        return Err(DerError);
    }
    Ok(content
        .iter()
        .fold(0, |total, byte| total << 8 | i64::from(*byte)))
}

/// Check the signed attributes; returns the hash of the signing-certificate attribute to
/// compare with the signer's certificate, when the token carries the V2 form.
fn check_attributes(
    token: &Token<'_>,
    hash: HashAlg,
) -> Result<Option<(HashAlg, Vec<u8>)>, &'static str> {
    let bad = |_: DerError| ATTRIBUTES_INVALID;
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut content_type_ok = false;
    let mut digest_ok = false;
    let mut signing_certificate = false;
    let mut certificate_hash = None;
    let mut attributes = nested(&token.signed_attributes);
    while !attributes.is_empty() {
        let attribute = attributes.expect(der::SEQUENCE).map_err(bad)?;
        let mut fields = nested(&attribute);
        let oid = fields.expect(der::OID).map_err(bad)?.value;
        if seen.contains(&oid) {
            return Err(ATTRIBUTES_INVALID);
        }
        seen.push(oid);
        let values = fields.expect(der::SET).map_err(bad)?;
        fields.finish().map_err(bad)?;
        match oid {
            OID_CONTENT_TYPE => {
                let value = der::single(values.value).map_err(bad)?;
                content_type_ok = value.tag == der::OID && value.value == OID_TST_INFO;
            }
            OID_MESSAGE_DIGEST => {
                let value = der::single(values.value).map_err(bad)?;
                digest_ok = value.tag == der::OCTET_STRING
                    && value.value == hash.digest(token.tst_info).as_slice();
            }
            OID_SIGNING_CERT => signing_certificate = true,
            OID_SIGNING_CERT_V2 => {
                signing_certificate = true;
                certificate_hash =
                    Some(read_signing_certificate_v2(values.value).map_err(|error| {
                        if error == ALGORITHM_UNSUPPORTED {
                            ALGORITHM_UNSUPPORTED
                        } else {
                            ATTRIBUTES_INVALID
                        }
                    })?);
            }
            _ => {}
        }
    }
    if content_type_ok && digest_ok && signing_certificate {
        Ok(certificate_hash)
    } else {
        Err(ATTRIBUTES_INVALID)
    }
}

/// `SigningCertificateV2`: the first `ESSCertIDv2` names the signer (RFC 5035).
fn read_signing_certificate_v2(values: &[u8]) -> Result<(HashAlg, Vec<u8>), &'static str> {
    let bad = |_: DerError| ATTRIBUTES_INVALID;
    let certificate = der::single(values).map_err(bad)?;
    let mut fields = nested(&certificate);
    let list = fields.expect(der::SEQUENCE).map_err(bad)?;
    let mut list = nested(&list);
    let first = list.expect(der::SEQUENCE).map_err(bad)?;
    let mut id = nested(&first);
    let hash = match id.optional(der::SEQUENCE).map_err(bad)? {
        Some(algorithm) => HashAlg::from_oid(algorithm_oid(&algorithm).map_err(bad)?)
            .ok_or(ALGORITHM_UNSUPPORTED)?,
        None => HashAlg::Sha256, // the DEFAULT in RFC 5035
    };
    Ok((
        hash,
        id.expect(der::OCTET_STRING).map_err(bad)?.value.to_vec(),
    ))
}

fn find_signer<'t, 'a>(token: &'t Token<'a>) -> Option<&'t Certificate<'a>> {
    token
        .certificates
        .iter()
        .find(|certificate| match token.signer {
            SignerId::IssuerAndSerial { issuer, serial } => {
                certificate.issuer == issuer && certificate.serial == serial
            }
            SignerId::SubjectKeyId(id) => certificate.subject_key_id == Some(id),
        })
}

/// Walk from the signer to a pinned root using only the token's certificates. A candidate
/// that cannot be checked is skipped, not fatal: two certificates may share a name, and only
/// when no path exists does the unsupported algorithm become the reason.
fn chain_reaches_root(
    token: &Token<'_>,
    signer: &Certificate<'_>,
    roots: &[Certificate<'_>],
    at: i64,
) -> Result<(), &'static str> {
    let mut failure = CHAIN_INVALID;
    let mut signed_by = |current: &Certificate<'_>, issuer: &Certificate<'_>| {
        current.signed_by(issuer).unwrap_or_else(|code| {
            failure = code;
            false
        })
    };
    let mut current = signer;
    let mut used: Vec<&[u8]> = vec![signer.raw];
    // `intermediates_below`: those between the leaf and the certificate considered as issuer.
    for intermediates_below in 0..MAX_CHAIN_DEPTH {
        // One that could not serve is passed over, not fatal: a CA reissued under the same name
        // and key can sit next to its expired self, in a token or among the pinned roots.
        let may_issue = |issuer: &Certificate<'_>| {
            issuer.valid_at(at)
                && issuer.may_sign_certificates()
                && issuer
                    .path_len
                    .is_none_or(|limit| intermediates_below <= limit)
        };
        for root in roots {
            // The verifier may pin the certificate itself, at any level of the chain.
            if (root.raw == current.raw && root.valid_at(at))
                || (may_issue(root) && signed_by(current, root))
            {
                return Ok(());
            }
        }
        let next = token.certificates.iter().find(|candidate| {
            !used.contains(&candidate.raw)
                && candidate.subject == current.issuer
                && may_issue(candidate)
                && signed_by(current, candidate)
        });
        let Some(issuer) = next else {
            break;
        };
        used.push(issuer.raw);
        current = issuer;
    }
    Err(failure)
}

/// `Ok(Some(seconds))` when verified, `Ok(None)` when consistent but no root was pinned.
fn check_token(
    token_bytes: &[u8],
    digest: &[u8],
    roots: &[Vec<u8>],
) -> Result<Option<u64>, String> {
    check_token_codes(token_bytes, digest, roots).map_err(str::to_string)
}

fn check_token_codes(
    token_bytes: &[u8],
    digest: &[u8],
    roots: &[Vec<u8>],
) -> Result<Option<u64>, &'static str> {
    let token = parse_token(token_bytes).map_err(|_| TOKEN_MALFORMED)?;
    let info = parse_tst_info(token.tst_info).map_err(|_| TOKEN_MALFORMED)?;
    if HashAlg::from_oid(info.imprint_algorithm) != Some(HashAlg::Sha256) || info.imprint != digest
    {
        return Err(IMPRINT_MISMATCH);
    }
    let hash = HashAlg::from_oid(token.digest_algorithm).ok_or(ALGORITHM_UNSUPPORTED)?;
    let certificate_hash = check_attributes(&token, hash)?;

    let signer = find_signer(&token).ok_or(SIGNER_INVALID)?;
    if let Some((certificate_hash_alg, expected)) = certificate_hash {
        if certificate_hash_alg.digest(signer.raw) != expected {
            return Err(ATTRIBUTES_INVALID);
        }
    }
    // RFC 3161, section 2.3: a critical extended key usage naming timestamping.
    let usable = signer.timestamping
        && signer.eku_critical
        && !signer.unknown_critical
        && signer
            .key_usage
            .is_none_or(|usage| usage & (KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION) != 0);
    if !usable {
        return Err(SIGNER_INVALID);
    }
    let key = signer.public_key()?;
    // CMS signs the attributes re-tagged as a SET, not as the [0] they are stored under.
    let mut signed = token.signed_attributes.raw.to_vec();
    signed[0] = der::SET;
    match sigverify::verify_message(
        &key,
        token.signature_algorithm,
        Some(hash),
        &signed,
        token.signature,
    ) {
        None => return Err(ALGORITHM_UNSUPPORTED),
        Some(false) => return Err(SIGNATURE_INVALID),
        Some(true) => {}
    }
    if !signer.valid_at(info.gen_time) {
        return Err(SIGNER_INVALID);
    }
    u64::try_from(info.gen_time).map_err(|_| TOKEN_MALFORMED)?;
    let seconds = u64::try_from(info.latest).map_err(|_| TOKEN_MALFORMED)?;
    if roots.is_empty() {
        return Ok(None);
    }
    let parsed = roots
        .iter()
        .map(|root| Certificate::parse(root))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CHAIN_INVALID)?;
    chain_reaches_root(&token, signer, &parsed, info.gen_time)?;
    Ok(Some(seconds))
}

/// Whether `raw` reads as a certificate this verifier could use as a root.
pub(crate) fn is_certificate(raw: &[u8]) -> bool {
    Certificate::parse(raw).is_ok()
}

/// Verify one `rfc3161` proof of an anchor against the checkpoint digest.
pub(crate) fn verify_proof(
    proof: &Value,
    path: &str,
    digest_hex: &str,
    roots: &[Vec<u8>],
) -> ProofVerdict {
    let mut errors = unknown_fields(proof, path, PROOF_FIELDS);
    // Informational and never trusted, but still what the contract says it is.
    if proof.get("tsa_url").is_some_and(|value| !value.is_string()) {
        errors.push(format!("ANCHOR_MALFORMED ({path}.tsa_url)"));
    }
    let outcome = proof
        .get("token")
        .and_then(Value::as_str)
        .filter(|token| token.len() <= MAX_TOKEN_BASE64)
        .ok_or_else(|| "ANCHOR_MALFORMED (rfc3161.token)".to_string())
        .and_then(|token| {
            STANDARD
                .decode(token)
                .map_err(|_| "ANCHOR_MALFORMED (rfc3161.token)".to_string())
        })
        .and_then(|token| {
            let digest = hex::decode(digest_hex).map_err(|_| IMPRINT_MISMATCH.to_string())?;
            check_token(&token, &digest, roots)
        });
    ProofVerdict::from_check("rfc3161", outcome, errors)
}

#[cfg(not(target_arch = "wasm32"))]
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        // Only short requests are built here.
        out.extend_from_slice(&[0x81, value.len() as u8]);
    }
    out.extend_from_slice(value);
    out
}

/// Native only: a `TimeStampReq` for a SHA-256 digest, asking for the signer's certificates.
/// `nonce` is a positive integer, big-endian, with no leading zero byte.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn build_request(digest: &[u8], nonce: &[u8]) -> Vec<u8> {
    const SHA256_ALGORITHM: [u8; 15] = [
        0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ];
    let imprint = tlv(
        der::SEQUENCE,
        &[&SHA256_ALGORITHM[..], &tlv(der::OCTET_STRING, digest)].concat(),
    );
    let body = [
        tlv(der::INTEGER, &[1]),
        imprint,
        tlv(der::INTEGER, nonce),
        tlv(der::BOOLEAN, &[0xFF]),
    ]
    .concat();
    tlv(der::SEQUENCE, &body)
}

/// Native only: the token inside a `TimeStampResp`, after checking the status is granted and
/// the nonce is the one requested. The token's signature is checked later by `verify_proof`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn token_from_response(response: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let malformed = |_: DerError| "the TSA response is not a valid TimeStampResp".to_string();
    let outer = der::single(response).map_err(malformed)?;
    let mut fields = nested(&outer);
    let status = fields.expect(der::SEQUENCE).map_err(malformed)?;
    let code = nested(&status).expect(der::INTEGER).map_err(malformed)?;
    // 0 = granted, 1 = grantedWithMods; anything else is a refusal.
    if !matches!(code.value, [0] | [1]) {
        return Err(format!(
            "the TSA refused the request (PKIStatus {})",
            hex::encode(code.value)
        ));
    }
    let token = fields.expect(der::SEQUENCE).map_err(malformed)?;
    let parsed = parse_token(token.raw).map_err(|_| TOKEN_MALFORMED.to_string())?;
    let info = parse_tst_info(parsed.tst_info).map_err(|_| TOKEN_MALFORMED.to_string())?;
    if info.nonce != Some(nonce) {
        return Err("the TSA response does not carry the nonce that was requested".to_string());
    }
    Ok(token.raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::ProofStatus;

    const DIGICERT: &[u8] = include_bytes!("../tests/vectors/anchor/tsr_digicert.der");
    const SIGSTORE: &[u8] = include_bytes!("../tests/vectors/anchor/tsr_sigstore.der");
    const DIGICERT_ROOT: &str =
        include_str!("../tests/vectors/anchor/digicert_trusted_root_g4.pem");
    const SIGSTORE_ROOT: &str = include_str!("../tests/vectors/anchor/sigstore_tsa_root.pem");
    /// SHA-256 of "tempus-ddb rfc3161 test vector", what the committed tokens stamp.
    const DIGEST: &str = "4f3ac8e029334308e7ca4b664ef04da183a6cb75f56d255b6dca228eed212a43";
    const NONCE: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];

    fn root(pem: &str) -> Vec<u8> {
        der::pem_or_base64_blocks(pem, "CERTIFICATE")
            .unwrap()
            .remove(0)
    }

    fn token_of(response: &[u8]) -> Vec<u8> {
        token_from_response(response, &NONCE).unwrap()
    }

    fn digest() -> Vec<u8> {
        hex::decode(DIGEST).unwrap()
    }

    #[test]
    fn real_digicert_token_verifies_with_rsa_and_a_cross_signed_chain() {
        let token = token_of(DIGICERT);
        let time = check_token_codes(&token, &digest(), &[root(DIGICERT_ROOT)]).unwrap();
        // 2026-11-02T01:27:47Z, as openssl prints it for this token.
        assert_eq!(time, Some(1_793_582_867));
    }

    #[test]
    fn real_sigstore_token_verifies_with_p384_over_sha256() {
        let token = token_of(SIGSTORE);
        let time = check_token_codes(&token, &digest(), &[root(SIGSTORE_ROOT)]).unwrap();
        // 2026-11-02T01:27:48Z with an accuracy of 1 second, as openssl prints it for this token.
        assert_eq!(time, Some(1_793_582_869));
    }

    #[test]
    fn a_pinned_certificate_at_any_level_is_accepted() {
        // The signer itself, as an operator running their own TSA might pin it.
        let token_bytes = token_of(SIGSTORE);
        let parsed = parse_token(&token_bytes).unwrap();
        let signer = find_signer(&parsed).unwrap().raw.to_vec();
        assert!(check_token_codes(&token_bytes, &digest(), &[signer])
            .unwrap()
            .is_some());
    }

    #[test]
    fn no_root_means_not_checked_and_the_wrong_root_fails() {
        let token = token_of(DIGICERT);
        assert_eq!(check_token_codes(&token, &digest(), &[]), Ok(None));
        assert_eq!(
            check_token_codes(&token, &digest(), &[root(SIGSTORE_ROOT)]),
            Err(CHAIN_INVALID)
        );
    }

    #[test]
    fn another_digest_is_an_imprint_mismatch_even_with_no_root() {
        let token = token_of(SIGSTORE);
        let other = [0u8; 32];
        assert_eq!(
            check_token_codes(&token, &other, &[]),
            Err(IMPRINT_MISMATCH)
        );
        assert_eq!(
            check_token_codes(&token, &other, &[root(SIGSTORE_ROOT)]),
            Err(IMPRINT_MISMATCH)
        );
    }

    /// Any change to a token either fails or leaves what it proves untouched: bytes outside
    /// the signature (version numbers, the digest algorithm list, certificates not on the
    /// path) carry no meaning, and the time and the imprint are always the original ones.
    #[test]
    fn mutating_a_real_token_never_changes_what_it_proves_and_never_panics() {
        for (response, root_pem, stride) in
            [(SIGSTORE, SIGSTORE_ROOT, 3), (DIGICERT, DIGICERT_ROOT, 41)]
        {
            let token = token_of(response);
            let roots = [root(root_pem)];
            let expected = check_token_codes(&token, &digest(), &roots).unwrap();
            let mut survivors = 0;
            for index in (0..token.len()).step_by(stride) {
                let mut mutated = token.clone();
                mutated[index] ^= 0x01;
                if let Ok(time) = check_token_codes(&mutated, &digest(), &roots) {
                    assert_eq!(time, expected, "byte {index}");
                    let parsed = parse_token(&mutated).unwrap();
                    let original = parse_token(&token).unwrap();
                    assert_eq!(parsed.tst_info, original.tst_info, "byte {index}");
                    survivors += 1;
                }
            }
            assert!(
                survivors * stride < token.len() / 2,
                "{survivors} mutations survived"
            );
            for length in (0..token.len()).step_by(stride) {
                assert!(check_token_codes(&token[..length], &digest(), &roots).is_err());
            }
        }
    }

    #[test]
    fn validity_is_judged_at_gen_time_not_today() {
        let token_bytes = token_of(SIGSTORE);
        let parsed = parse_token(&token_bytes).unwrap();
        let signer = find_signer(&parsed).unwrap();
        // The signer is valid 2025-2035: the token's time is inside, later times are not.
        assert!(signer.valid_at(1_793_582_868));
        assert!(!signer.valid_at(signer.not_after + 1));
        assert!(!signer.valid_at(signer.not_before - 1));
    }

    #[test]
    fn a_signer_without_timestamping_usage_is_refused() {
        let token_bytes = token_of(SIGSTORE);
        let parsed = parse_token(&token_bytes).unwrap();
        let signer = find_signer(&parsed).unwrap();
        assert!(signer.timestamping && signer.eku_critical);
        // A root is a real certificate, but it cannot sign timestamps or lacks the usage.
        let root_bytes = root(SIGSTORE_ROOT);
        let authority = Certificate::parse(&root_bytes).unwrap();
        assert!(!authority.timestamping);
        assert!(authority.may_sign_certificates());
        assert!(!signer.may_sign_certificates());
    }

    #[test]
    fn the_response_must_be_granted_and_echo_the_nonce() {
        assert!(token_from_response(SIGSTORE, &[9, 9])
            .unwrap_err()
            .contains("nonce"));
        // PKIStatus 2 = rejection, no token.
        let refusal = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        assert!(token_from_response(&refusal, &NONCE)
            .unwrap_err()
            .contains("refused"));
        assert!(token_from_response(b"not der", &NONCE).is_err());
    }

    #[test]
    fn the_request_is_byte_for_byte_what_the_tsas_accepted() {
        // The request sent to DigiCert, Sigstore and FreeTSA when the vectors were taken.
        let expected = format!(
            "30420201013031300d060960864801650304020105000420{DIGEST}0207010203040506070101ff"
        );
        assert_eq!(hex::encode(build_request(&digest(), &NONCE)), expected);
    }

    #[test]
    fn proofs_report_status_through_the_shared_verdict() {
        use serde_json::json;
        let token = STANDARD.encode(token_of(SIGSTORE));
        let proof = json!({"backend": "rfc3161", "tsa_url": "https://tsa.example", "token": token});
        let verdict = verify_proof(&proof, "anchor.proofs[1]", DIGEST, &[root(SIGSTORE_ROOT)]);
        assert_eq!(verdict.status, ProofStatus::Verified);
        assert_eq!(verdict.time_seconds, Some(1_793_582_869));
        let verdict = verify_proof(&proof, "anchor.proofs[1]", DIGEST, &[]);
        assert_eq!(verdict.status, ProofStatus::NotChecked);

        let mut extra = proof.clone();
        extra["note"] = json!("x");
        let verdict = verify_proof(&extra, "anchor.proofs[1]", DIGEST, &[root(SIGSTORE_ROOT)]);
        assert_eq!(
            verdict.errors,
            vec!["UNKNOWN_FIELD (anchor.proofs[1].note)"]
        );

        let verdict = verify_proof(&json!({"token": 5}), "p", DIGEST, &[]);
        assert_eq!(verdict.status, ProofStatus::Failed);
    }
}
