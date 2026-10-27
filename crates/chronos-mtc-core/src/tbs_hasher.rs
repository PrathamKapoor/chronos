//! Strict-DER guard and the single-pass streaming `TBSCertificate` leaf hasher
//! (`draft-ietf-plants-merkle-tree-certs-07` §7.2 and §12.6).
//!
//! Two properties matter here and are enforced by tests:
//!
//! 1. **Zero allocation on the hash path.** The hasher borrows `&[u8]` slices and folds them into
//!    one SHA-256 state; the only allocation is the canonicalized extension list, which is derived
//!    once per certificate.
//! 2. **No BER malleability.** Every TLV must use the minimal-length DER encoding, so two distinct
//!    byte strings can never collapse onto the same leaf hash.

use super::error::{MtcError, MtcResult};
use super::subtrees::{MAX_UINT48, MTC_LEAF_PREFIX};
use sha2::{Digest, Sha256};

/// DER tag for `SEQUENCE`.
pub const TAG_SEQUENCE: u8 = 0x30;
/// DER tag for `OCTET STRING`.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// DER tag for `OBJECT IDENTIFIER`.
pub const TAG_OID: u8 = 0x06;

/// Signed Certificate Timestamp extension OID `1.3.6.1.4.1.11129.2.4.2` (contents, no tag/length).
pub const SCT_EXTENSION_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02];

/// Encoded prefix that replaces `subjectPublicKeyInfo` during leaf hashing: `0x04 0x20`.
pub const SPKI_DIGEST_PREFIX: [u8; 2] = [TAG_OCTET_STRING, 0x20];

/// Zero-copy view of the `TBSCertificate` fields that take part in the leaf hash.
#[derive(Debug, Clone, Copy)]
pub struct TbsCertFields<'a> {
    /// Raw DER of the `[0] EXPLICIT version` field (absent means v1: `[0x02, 0x01, 0x02]`).
    pub version_raw: &'a [u8],
    /// Serial number; must fit the 48-bit serial space.
    pub serial_number: u64,
    /// Log number whose 48-bit serial prefix is mixed in (§12.3).
    pub log_number: u16,
    /// Raw OID contents of the signature algorithm identifier (no tag/length octets).
    pub signature_alg_oid: &'a [u8],
    /// Complete DER `Name` TLV of the issuer.
    pub issuer_dn: &'a [u8],
    /// `notBefore`, unix seconds.
    pub not_before: u64,
    /// `notAfter`, unix seconds.
    pub not_after: u64,
    /// Complete DER `Name` TLV of the subject.
    pub subject_dn: &'a [u8],
    /// Complete DER `SubjectPublicKeyInfo` TLV (1,952 B for ML-DSA-65).
    pub subject_public_key_info: &'a [u8],
    /// Complete DER `Extensions` SEQUENCE TLV, or empty when the certificate has no extensions.
    pub extensions_der: &'a [u8],
}

/// Compressed 64-bit serial: `(log_number << 48) | (serial & MAX_UINT48)`.
pub fn compressed_serial(log_number: u16, serial_number: u64) -> u64 {
    ((log_number as u64) << 48) | (serial_number & MAX_UINT48)
}

/// A parsed TLV header plus its content slice.
#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Reads exactly one canonical TLV from the head of `input`, returning it with the consumed length.
///
/// Trailing bytes are allowed here (a sequence contains several TLVs); callers that require a
/// single TLV use [`parse_canonical_tlv`].
fn take_canonical_tlv(input: &[u8]) -> MtcResult<(Tlv<'_>, usize)> {
    validate_canonical_tlv_header(input)?;

    let length_byte = input[1];
    let (header_len, content_len) = if length_byte & 0x80 == 0 {
        (2usize, length_byte as usize)
    } else {
        let count = (length_byte & 0x7F) as usize;
        let mut value = 0usize;
        for byte in &input[2..2 + count] {
            value = (value << 8) | *byte as usize;
        }
        (2 + count, value)
    };

    let total = header_len + content_len;
    if input.len() < total {
        return Err(MtcError::DerTruncated);
    }

    Ok((
        Tlv {
            tag: input[0],
            content: &input[header_len..total],
        },
        total,
    ))
}

/// Reads exactly one canonical TLV and rejects any trailing bytes.
fn parse_canonical_tlv(input: &[u8]) -> MtcResult<Tlv<'_>> {
    let (tlv, consumed) = take_canonical_tlv(input)?;
    if consumed != input.len() {
        return Err(MtcError::DerTruncated);
    }
    Ok(tlv)
}

/// Canonical minimal-length DER header guard.
///
/// Checks the encoding rules (no indefinite length, minimal long form, no leading zero) and that
/// the declared content length fits the buffer. Full-consumption is checked by
/// [`parse_canonical_tlv`].
fn validate_canonical_tlv_header(input: &[u8]) -> MtcResult<()> {
    if input.len() < 2 {
        return Err(MtcError::DerTruncated);
    }

    let length_byte = input[1];
    if length_byte == 0x80 {
        return Err(MtcError::NonCanonicalDer(
            "Indefinite length 0x80 forbidden in DER".into(),
        ));
    }

    if length_byte & 0x80 == 0 {
        let content_len = length_byte as usize;
        if input.len() < 2 + content_len {
            return Err(MtcError::DerTruncated);
        }
        return Ok(());
    }

    let count = (length_byte & 0x7F) as usize;
    if count == 0 || count > 4 {
        return Err(MtcError::NonCanonicalDer(format!(
            "unsupported DER long-form length width {count}"
        )));
    }
    if input.len() < 2 + count {
        return Err(MtcError::DerTruncated);
    }
    if input[2] == 0x00 {
        return Err(MtcError::NonCanonicalDer(
            "leading zero byte in DER length".into(),
        ));
    }

    let mut content_len = 0usize;
    for byte in &input[2..2 + count] {
        content_len = (content_len << 8) | *byte as usize;
    }
    if content_len < 128 {
        return Err(MtcError::NonCanonicalDer(
            "Non-minimal multi-byte DER length".into(),
        ));
    }
    if input.len() < 2 + count + content_len {
        return Err(MtcError::DerTruncated);
    }

    Ok(())
}

/// Canonical minimal-length DER guard (draft §12.6).
///
/// The input must be exactly one TLV with no trailing bytes:
/// `input.len() == 2 + num_len_bytes + decoded_len`. Rejects indefinite length (`0x80`),
/// non-minimal long-form lengths, leading-zero length bytes, truncation and trailing bytes.
pub fn validate_canonical_der_tlv(input: &[u8]) -> MtcResult<()> {
    validate_canonical_tlv_header(input)?;
    let (_, consumed) = take_canonical_tlv(input)?;
    if consumed != input.len() {
        return Err(MtcError::DerTruncated);
    }
    Ok(())
}

/// Encodes a minimal-length DER length prefix for `len`.
fn encode_der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

/// Removes volatile Signed Certificate Timestamps from an `Extensions` SEQUENCE TLV.
///
/// Returns a canonically re-encoded SEQUENCE (or an empty `Vec` when there is nothing left, or
/// when the caller passed no extensions at all). Volatile SCT extensions are per-connection and
/// would otherwise make two otherwise identical certificates hash differently.
pub fn strip_volatile_extensions(extensions_der: &[u8]) -> MtcResult<Vec<u8>> {
    if extensions_der.is_empty() {
        return Ok(Vec::new());
    }

    let sequence = parse_canonical_tlv(extensions_der)?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(MtcError::WireEncoding(
            "extensions must be a SEQUENCE TLV".into(),
        ));
    }

    let mut kept: Vec<u8> = Vec::with_capacity(sequence.content.len());
    let mut cursor = 0usize;
    while cursor < sequence.content.len() {
        let child = &sequence.content[cursor..];
        let (tlv, consumed) = take_canonical_tlv(child)?;
        if !is_sct_extension(&tlv) {
            kept.extend_from_slice(&child[..consumed]);
        }
        cursor += consumed;
    }

    if kept.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(kept.len() + 6);
    out.push(TAG_SEQUENCE);
    encode_der_length(kept.len(), &mut out);
    out.extend_from_slice(&kept);
    Ok(out)
}

/// True when a TLV is an `Extension` whose first child is the SCT `extnID`.
fn is_sct_extension(tlv: &Tlv<'_>) -> bool {
    if tlv.tag != TAG_SEQUENCE || tlv.content.is_empty() {
        return false;
    }
    match take_canonical_tlv(tlv.content) {
        Ok((inner, _)) => inner.tag == TAG_OID && inner.content == SCT_EXTENSION_OID,
        Err(_) => false,
    }
}

/// Streams the canonical leaf representation of a certificate and returns `MTH({entry})`.
///
/// Byte stream (see `flow.md` §2.3.2):
/// `0x00 ‖ version ‖ uint64_be(compressed serial) ‖ sigAlgOID ‖ issuer ‖ uint64_be(notBefore) ‖
/// uint64_be(notAfter) ‖ subject ‖ 0x04 0x20 ‖ SHA256(SPKI) ‖ canonical extensions`.
pub fn hash_tbs_certificate_streaming(fields: &TbsCertFields<'_>) -> MtcResult<[u8; 32]> {
    if fields.serial_number > MAX_UINT48 {
        return Err(MtcError::SerialOutOfBounds {
            serial: fields.serial_number,
        });
    }
    validate_canonical_der_tlv(fields.subject_public_key_info)?;
    let canonical_extensions = strip_volatile_extensions(fields.extensions_der)?;

    let spki_digest: [u8; 32] = Sha256::digest(fields.subject_public_key_info).into();

    let mut hasher = Sha256::new();
    hasher.update([MTC_LEAF_PREFIX]);
    hasher.update(fields.version_raw);
    hasher.update(compressed_serial(fields.log_number, fields.serial_number).to_be_bytes());
    hasher.update(fields.signature_alg_oid);
    hasher.update(fields.issuer_dn);
    hasher.update(fields.not_before.to_be_bytes());
    hasher.update(fields.not_after.to_be_bytes());
    hasher.update(fields.subject_dn);
    hasher.update(SPKI_DIGEST_PREFIX);
    hasher.update(spki_digest);
    hasher.update(&canonical_extensions);

    Ok(hasher.finalize().into())
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::*;

    /// Builds `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`
    fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let mut content = Vec::new();
        let mut oid_tlv = vec![TAG_OID];
        encode_der_length(oid.len(), &mut oid_tlv);
        oid_tlv.extend_from_slice(oid);
        content.extend_from_slice(&oid_tlv);
        if critical {
            content.extend_from_slice(&[0x01, 0x01, 0xFF]);
        }
        let mut octet = vec![TAG_OCTET_STRING];
        encode_der_length(value.len(), &mut octet);
        octet.extend_from_slice(value);
        content.extend_from_slice(&octet);

        let mut out = vec![TAG_SEQUENCE];
        encode_der_length(content.len(), &mut out);
        out.extend_from_slice(&content);
        out
    }

    fn extensions(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut content = Vec::new();
        for ext in extensions {
            content.extend_from_slice(ext);
        }
        let mut out = vec![TAG_SEQUENCE];
        encode_der_length(content.len(), &mut out);
        out.extend_from_slice(&content);
        out
    }

    fn sample_fields<'a>(version: &'a [u8], spki: &'a [u8], exts: &'a [u8]) -> TbsCertFields<'a> {
        TbsCertFields {
            version_raw: version,
            serial_number: 0x2A,
            log_number: 7,
            signature_alg_oid: &[0x2B, 0x65, 0x70],
            issuer_dn: &[0x30, 0x03, 0x13, 0x01, 0x41],
            not_before: 1_700_000_000,
            not_after: 1_900_000_000,
            subject_dn: &[0x30, 0x03, 0x13, 0x01, 0x42],
            subject_public_key_info: spki,
            extensions_der: exts,
        }
    }

    /// A canonical `SubjectPublicKeyInfo` whose key payload is a 1,952-byte ML-DSA-65 key.
    fn ml_dsa_65_spki_with(fill: u8) -> Vec<u8> {
        let mut bit_string_content = vec![0u8];
        bit_string_content.extend_from_slice(&[fill; 1952]);
        let mut bit_string = vec![0x03];
        encode_der_length(bit_string_content.len(), &mut bit_string);
        bit_string.extend_from_slice(&bit_string_content);

        let mut out = vec![TAG_SEQUENCE];
        encode_der_length(bit_string.len(), &mut out);
        out.extend_from_slice(&bit_string);
        out
    }

    fn ml_dsa_65_spki() -> Vec<u8> {
        ml_dsa_65_spki_with(0x5A)
    }

    #[test]
    fn der_guard_accepts_canonical_encodings() {
        assert!(validate_canonical_der_tlv(&[0x04, 0x00]).is_ok());
        let octet: Vec<u8> = std::iter::once(0x04)
            .chain(std::iter::once(0x20))
            .chain(std::iter::repeat_n(0xAB, 32))
            .collect();
        assert!(validate_canonical_der_tlv(&octet).is_ok());
        assert!(validate_canonical_der_tlv(&[0x02, 0x01, 0x05]).is_ok());
        // 0x81 0x80 -> 128 bytes, minimal long form.
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend_from_slice(&[0u8; 128]);
        assert!(validate_canonical_der_tlv(&long).is_ok());
        // 0x82 0x01 0x00 -> 256 bytes.
        let mut longer = vec![0x04, 0x82, 0x01, 0x00];
        longer.extend_from_slice(&[0u8; 256]);
        assert!(validate_canonical_der_tlv(&longer).is_ok());
    }

    #[test]
    fn der_guard_rejects_malleable_encodings() {
        // Indefinite length.
        assert!(matches!(
            validate_canonical_der_tlv(&[0x30, 0x80, 0x00, 0x00]),
            Err(MtcError::NonCanonicalDer(_))
        ));
        // Non-minimal long form for a 127-byte value.
        let mut non_minimal = vec![0x30, 0x81, 0x7F];
        non_minimal.extend_from_slice(&[0u8; 127]);
        assert!(matches!(
            validate_canonical_der_tlv(&non_minimal),
            Err(MtcError::NonCanonicalDer(_))
        ));
        // Leading zero in a multi-byte length.
        let mut leading_zero = vec![0x30, 0x82, 0x00, 0x80];
        leading_zero.extend_from_slice(&[0u8; 128]);
        assert!(matches!(
            validate_canonical_der_tlv(&leading_zero),
            Err(MtcError::NonCanonicalDer(_))
        ));
        // Reserved width 0x88.
        assert!(matches!(
            validate_canonical_der_tlv(&[0x30, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(MtcError::NonCanonicalDer(_))
        ));
        // Truncated content and trailing bytes.
        assert_eq!(
            validate_canonical_der_tlv(&[0x04]),
            Err(MtcError::DerTruncated)
        );
        assert_eq!(
            validate_canonical_der_tlv(&[0x04, 0x04, 0x01]),
            Err(MtcError::DerTruncated)
        );
        assert_eq!(
            validate_canonical_der_tlv(&[0x04, 0x01, 0x01, 0x02]),
            Err(MtcError::DerTruncated)
        );
    }

    #[test]
    fn der_guard_rejects_long_form_widths_it_cannot_verify() {
        // Reserved width 0xFF (would need 127 length octets) and oversized width 0x88.
        assert!(matches!(
            validate_canonical_der_tlv(&[0x30, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(MtcError::NonCanonicalDer(_))
        ));
        // Header shorter than its own length prefix.
        assert_eq!(
            validate_canonical_der_tlv(&[0x30, 0x84, 0x01]),
            Err(MtcError::DerTruncated)
        );
    }

    #[test]
    fn strips_only_sct_extensions() {
        let basic_constraints = extension(&[0x55, 0x1D, 0x13], true, &[0x30, 0x00]);
        let key_usage = extension(&[0x55, 0x1D, 0x0F], false, &[0x03, 0x02, 0x01, 0x86]);
        let sct = extension(SCT_EXTENSION_OID, false, &[0x04, 0x01, 0xAA]);

        let with_sct = extensions(&[basic_constraints.clone(), sct.clone(), key_usage.clone()]);
        let without_sct = extensions(&[basic_constraints.clone(), key_usage.clone()]);

        assert_eq!(
            strip_volatile_extensions(&with_sct).unwrap(),
            without_sct,
            "SCT extension must be removed and the SEQUENCE re-encoded minimally"
        );

        // All-SCT input canonicalizes to the empty list.
        let only_sct = extensions(&[sct]);
        assert!(strip_volatile_extensions(&only_sct).unwrap().is_empty());
        // Empty input stays empty.
        assert!(strip_volatile_extensions(&[]).unwrap().is_empty());
    }

    #[test]
    fn stream_order_matches_a_single_shot_reference() {
        let spki = ml_dsa_65_spki();
        let exts = extensions(&[extension(&[0x55, 0x1D, 0x13], true, &[0x30, 0x00])]);
        let version = [0xA0, 0x03, 0x02, 0x01, 0x02];
        let fields = sample_fields(&version, &spki, &exts);

        let mut reference = Vec::new();
        reference.push(MTC_LEAF_PREFIX);
        reference.extend_from_slice(&version);
        reference.extend_from_slice(&compressed_serial(7, 0x2A).to_be_bytes());
        reference.extend_from_slice(&[0x2B, 0x65, 0x70]);
        reference.extend_from_slice(&[0x30, 0x03, 0x13, 0x01, 0x41]);
        reference.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        reference.extend_from_slice(&1_900_000_000u64.to_be_bytes());
        reference.extend_from_slice(&[0x30, 0x03, 0x13, 0x01, 0x42]);
        reference.extend_from_slice(&SPKI_DIGEST_PREFIX);
        reference.extend_from_slice(&Sha256::digest(&spki));
        reference.extend_from_slice(&strip_volatile_extensions(&exts).unwrap());

        let expected: [u8; 32] = Sha256::digest(&reference).into();
        assert_eq!(hash_tbs_certificate_streaming(&fields).unwrap(), expected);
    }

    #[test]
    fn spki_is_replaced_by_its_digest() {
        let version = [0xA0, 0x03, 0x02, 0x01, 0x02];
        let spki = ml_dsa_65_spki_with(0x5A);
        let other_spki = ml_dsa_65_spki_with(0x5B);

        let base = hash_tbs_certificate_streaming(&sample_fields(&version, &spki, &[])).unwrap();
        let other =
            hash_tbs_certificate_streaming(&sample_fields(&version, &other_spki, &[])).unwrap();
        assert_ne!(base, other, "distinct keys must yield distinct leaf hashes");

        // The hashed stream must contain SHA256(SPKI), never the 1,952-byte key itself.
        let mut probe = Sha256::new();
        probe.update([MTC_LEAF_PREFIX]);
        probe.update(version);
        probe.update(compressed_serial(7, 0x2A).to_be_bytes());
        probe.update([0x2B, 0x65, 0x70]);
        probe.update([0x30, 0x03, 0x13, 0x01, 0x41]);
        probe.update(1_700_000_000u64.to_be_bytes());
        probe.update(1_900_000_000u64.to_be_bytes());
        probe.update([0x30, 0x03, 0x13, 0x01, 0x42]);
        probe.update(SPKI_DIGEST_PREFIX);
        probe.update(Sha256::digest(&spki));
        let expected: [u8; 32] = probe.finalize().into();
        assert_eq!(base, expected);

        // Two certificates that differ only by a volatile SCT must share a leaf hash.
        let mut with_sct = sample_fields(&version, &spki, &[]);
        let sct = extension(SCT_EXTENSION_OID, false, &[0x04, 0x02, 0xAA, 0xBB]);
        let sct_extensions = extensions(&[sct]);
        with_sct.extensions_der = &sct_extensions;
        assert_eq!(hash_tbs_certificate_streaming(&with_sct).unwrap(), base);
    }

    #[test]
    fn rejects_serial_outside_the_48_bit_space() {
        let spki = ml_dsa_65_spki();
        let mut fields = sample_fields(&[], &spki, &[]);
        fields.serial_number = MAX_UINT48 + 1;
        assert_eq!(
            hash_tbs_certificate_streaming(&fields),
            Err(MtcError::SerialOutOfBounds {
                serial: MAX_UINT48 + 1
            })
        );
        fields.serial_number = MAX_UINT48;
        assert!(hash_tbs_certificate_streaming(&fields).is_ok());
    }

    #[test]
    fn rejects_non_canonical_spki() {
        let version = [0xA0, 0x03, 0x02, 0x01, 0x02];
        let mut spki = ml_dsa_65_spki();
        // Corrupt the length into a non-minimal long form.
        spki[1] = 0x84;
        let fields = sample_fields(&version, &spki, &[]);
        assert!(matches!(
            hash_tbs_certificate_streaming(&fields),
            Err(MtcError::NonCanonicalDer(_)) | Err(MtcError::DerTruncated)
        ));
    }

    #[test]
    fn compressed_serial_mixes_log_number() {
        assert_eq!(compressed_serial(0, 1), 1);
        assert_eq!(compressed_serial(1, 1), (1u64 << 48) | 1);
        assert_eq!(compressed_serial(0xFFFF, MAX_UINT48), u64::MAX);
    }
}
