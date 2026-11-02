//! A strict DER reader: definite minimal lengths, single-byte tags, every length checked
//! against the bytes actually present. It hands out exact byte slices, because signatures
//! cover the bytes as they were encoded and a decode-and-re-encode cannot promise them.
//! Malformed input is an error, never a panic: this code reads hostile documents.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerError;

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OID: u8 = 0x06;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;

/// Context-specific tag `[number]`, constructed (`EXPLICIT`, or `IMPLICIT` over a
/// constructed type).
pub(crate) const fn context(number: u8) -> u8 {
    0xA0 | number
}

/// Context-specific tag `[number]`, primitive (`IMPLICIT` over a primitive type).
pub(crate) const fn context_primitive(number: u8) -> u8 {
    0x80 | number
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    /// Header and content, as encoded.
    pub raw: &'a [u8],
    /// Content only.
    pub value: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    pub(crate) fn next_tlv(&mut self) -> Result<Tlv<'a>, DerError> {
        let tag = *self.data.first().ok_or(DerError)?;
        // High-tag-number form never appears in the structures read here.
        if tag & 0x1F == 0x1F {
            return Err(DerError);
        }
        let first = *self.data.get(1).ok_or(DerError)?;
        let (length, header) = if first < 0x80 {
            (first as usize, 2usize)
        } else {
            let count = (first & 0x7F) as usize;
            // 0x80 is the BER indefinite form; more than 4 length bytes is not a document.
            if count == 0 || count > 4 {
                return Err(DerError);
            }
            let bytes = self.data.get(2..2 + count).ok_or(DerError)?;
            // DER: the shortest form, so no leading zero and no long form under 128.
            if bytes[0] == 0 {
                return Err(DerError);
            }
            let mut length = 0usize;
            for byte in bytes {
                length = (length << 8) | *byte as usize;
            }
            if length < 0x80 {
                return Err(DerError);
            }
            (length, 2 + count)
        };
        let end = header.checked_add(length).ok_or(DerError)?;
        let raw = self.data.get(..end).ok_or(DerError)?;
        let value = &raw[header..];
        self.data = &self.data[end..];
        Ok(Tlv { tag, raw, value })
    }

    pub(crate) fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, DerError> {
        let tlv = self.next_tlv()?;
        if tlv.tag == tag {
            Ok(tlv)
        } else {
            Err(DerError)
        }
    }

    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, DerError> {
        if self.peek_tag() == Some(tag) {
            self.next_tlv().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Fail unless every byte was consumed: trailing data would be unauthenticated.
    pub(crate) fn finish(&self) -> Result<(), DerError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(DerError)
        }
    }
}

/// Reader over a constructed value.
pub(crate) fn nested<'a>(tlv: &Tlv<'a>) -> Reader<'a> {
    Reader::new(tlv.value)
}

/// One complete DER element with nothing after it.
pub(crate) fn single(data: &[u8]) -> Result<Tlv<'_>, DerError> {
    let mut reader = Reader::new(data);
    let tlv = reader.next_tlv()?;
    reader.finish()?;
    Ok(tlv)
}

/// The magnitude of a non-negative INTEGER, without its sign padding.
pub(crate) fn unsigned_integer<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], DerError> {
    if tlv.tag != INTEGER || tlv.value.is_empty() {
        return Err(DerError);
    }
    if tlv.value[0] & 0x80 != 0 {
        return Err(DerError);
    }
    if tlv.value.len() > 1 && tlv.value[0] == 0 {
        if tlv.value[1] & 0x80 == 0 {
            return Err(DerError);
        }
        return Ok(&tlv.value[1..]);
    }
    Ok(tlv.value)
}

/// The bytes of a BIT STRING that has no unused bits.
pub(crate) fn bit_string_bytes<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], DerError> {
    if tlv.tag != BIT_STRING {
        return Err(DerError);
    }
    match tlv.value.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err(DerError),
    }
}

pub(crate) fn boolean(tlv: &Tlv<'_>) -> Result<bool, DerError> {
    match (tlv.tag, tlv.value) {
        (BOOLEAN, [0xFF]) => Ok(true),
        (BOOLEAN, [0x00]) => Ok(false),
        _ => Err(DerError),
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146097 + day_of_era - 719468
}

fn digits(text: &[u8]) -> Result<i64, DerError> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return Err(DerError);
    }
    Ok(text
        .iter()
        .fold(0i64, |total, digit| total * 10 + (digit - b'0') as i64))
}

fn civil_to_unix(fields: &[u8], year: i64) -> Result<i64, DerError> {
    // `fields` is MMDDHHMMSS.
    let month = digits(&fields[0..2])?;
    let day = digits(&fields[2..4])?;
    let hour = digits(&fields[4..6])?;
    let minute = digits(&fields[6..8])?;
    let second = digits(&fields[8..10])?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(DerError),
    };
    if !(1..=month_days).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return Err(DerError);
    }
    Ok(days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second)
}

/// Unix seconds of a `UTCTime` (`YYMMDDHHMMSSZ`, RFC 5280 windowing) or a
/// `GeneralizedTime` (`YYYYMMDDHHMMSS[.f...]Z`; fractions are floored).
pub(crate) fn time_seconds(tlv: &Tlv<'_>) -> Result<i64, DerError> {
    match tlv.tag {
        UTC_TIME => {
            if tlv.value.len() != 13 || tlv.value[12] != b'Z' {
                return Err(DerError);
            }
            let short = digits(&tlv.value[0..2])?;
            let year = if short >= 50 {
                1900 + short
            } else {
                2000 + short
            };
            civil_to_unix(&tlv.value[2..12], year)
        }
        GENERALIZED_TIME => {
            let text = tlv.value.strip_suffix(b"Z").ok_or(DerError)?;
            let (seconds, fraction) = match text.iter().position(|byte| *byte == b'.') {
                Some(dot) => (&text[..dot], Some(&text[dot + 1..])),
                None => (text, None),
            };
            if seconds.len() != 14 {
                return Err(DerError);
            }
            if let Some(fraction) = fraction {
                if fraction.is_empty()
                    || !fraction.iter().all(u8::is_ascii_digit)
                    || fraction.last() == Some(&b'0')
                {
                    return Err(DerError);
                }
            }
            civil_to_unix(&seconds[4..14], digits(&seconds[0..4])?)
        }
        _ => Err(DerError),
    }
}

/// Strip PEM armor and whitespace, or take bare base64, into DER blocks. Accepts CRLF,
/// blank lines, text outside the armor and several blocks: this is what people paste.
pub(crate) fn pem_or_base64_blocks(text: &str, label: &str) -> Result<Vec<Vec<u8>>, DerError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let decode = |body: &str| -> Result<Vec<u8>, DerError> {
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        STANDARD.decode(compact).map_err(|_| DerError)
    };
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    if !text.contains("-----BEGIN ") {
        return decode(text).map(|block| vec![block]);
    }
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let stop = after.find(&end).ok_or(DerError)?;
        blocks.push(decode(&after[..stop])?);
        rest = &after[stop + end.len()..];
    }
    if blocks.is_empty() {
        return Err(DerError);
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_rejects_non_der() {
        for bad in [
            &b""[..],
            &[0x30][..],                               // no length
            &[0x30, 0x80, 0x00, 0x00][..],             // BER indefinite length
            &[0x30, 0x81, 0x01, 0x00][..],             // long form for a short length
            &[0x30, 0x82, 0x00, 0x80][..],             // leading zero in the length
            &[0x30, 0x02, 0x01][..],                   // truncated content
            &[0x1F, 0x01, 0x00][..],                   // high-tag-number form
            &[0x30, 0x85, 1, 1, 1, 1, 1][..],          // absurd length-of-length
            &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF][..], // length beyond the data
        ] {
            assert_eq!(
                Reader::new(bad).next_tlv().unwrap_err(),
                DerError,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn der_reads_nested_values_and_exact_slices() {
        let data = [0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xAA];
        let outer = single(&data).unwrap();
        assert_eq!(outer.raw, &data);
        let mut inner = nested(&outer);
        assert_eq!(unsigned_integer(&inner.next_tlv().unwrap()).unwrap(), [5]);
        assert_eq!(inner.expect(OCTET_STRING).unwrap().value, [0xAA]);
        assert!(inner.is_empty());
        assert!(
            single(&[0x05, 0x00, 0x00]).is_err(),
            "trailing byte refused"
        );
    }

    #[test]
    fn integers_must_be_minimal_and_non_negative() {
        let integer = |value: &'static [u8]| Tlv {
            tag: INTEGER,
            raw: value,
            value,
        };
        assert_eq!(unsigned_integer(&integer(&[0x00, 0x80])).unwrap(), [0x80]);
        assert!(unsigned_integer(&integer(&[0x00, 0x01])).is_err());
        assert!(unsigned_integer(&integer(&[0x80])).is_err());
        assert!(unsigned_integer(&integer(&[])).is_err());
    }

    #[test]
    fn times_read_both_encodings() {
        let time = |tag, value: &'static [u8]| Tlv {
            tag,
            raw: value,
            value,
        };
        // Known instants, checked against `date -u -d @...`.
        assert_eq!(
            time_seconds(&time(UTC_TIME, b"260805000000Z")).unwrap(),
            1_785_888_000
        );
        assert_eq!(
            time_seconds(&time(GENERALIZED_TIME, b"20261102012748Z")).unwrap(),
            1_793_582_868
        );
        assert_eq!(
            time_seconds(&time(GENERALIZED_TIME, b"20261102012748.5Z")).unwrap(),
            1_793_582_868
        );
        assert_eq!(
            time_seconds(&time(UTC_TIME, b"500101000000Z")).unwrap(),
            -631_152_000
        );
        for bad in [
            &b"20261302012748Z"[..],    // month 13
            &b"20260230012748Z"[..],    // February 30
            &b"20261102012748"[..],     // no Z
            &b"20261102012748.Z"[..],   // empty fraction
            &b"20261102012748.50Z"[..], // trailing zero in the fraction
            &b"2026110201274Z"[..],     // short
        ] {
            assert!(
                time_seconds(&time(GENERALIZED_TIME, bad)).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn pem_variants_decode() {
        let bare = "AQID";
        let armored = "-----BEGIN KEY-----\nAQID\n-----END KEY-----\n";
        let crlf = "noise\r\n-----BEGIN KEY-----\r\nAQ\r\nID\r\n\r\n-----END KEY-----\r\n";
        let two = "-----BEGIN KEY-----\nAQID\n-----END KEY-----\n-----BEGIN KEY-----\nBAUG\n-----END KEY-----";
        assert_eq!(
            pem_or_base64_blocks(bare, "KEY").unwrap(),
            vec![vec![1, 2, 3]]
        );
        assert_eq!(
            pem_or_base64_blocks(armored, "KEY").unwrap(),
            vec![vec![1, 2, 3]]
        );
        assert_eq!(
            pem_or_base64_blocks(crlf, "KEY").unwrap(),
            vec![vec![1, 2, 3]]
        );
        assert_eq!(
            pem_or_base64_blocks(two, "KEY").unwrap(),
            vec![vec![1, 2, 3], vec![4, 5, 6]]
        );
        assert!(
            pem_or_base64_blocks("-----BEGIN OTHER-----\nAQID\n-----END OTHER-----", "KEY")
                .is_err()
        );
        assert!(pem_or_base64_blocks("not base64!", "KEY").is_err());
    }
}
