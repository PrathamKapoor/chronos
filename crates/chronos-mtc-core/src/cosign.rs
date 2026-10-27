//! Canonical `MTCProof` codec and C2SP-style subtree signatures
//! (`draft-ietf-plants-merkle-tree-certs-07` §5.3.1 and §6.2).
//!
//! The draft encodes both structures with the TLS presentation language (RFC 9846 §3), so lengths
//! are explicit and the encodings are unambiguous:
//!
//! ```text
//! struct {
//!     uint8 label[12]            = "subtree/v1\n\0";
//!     opaque cosigner_name<1..2^8-1>;
//!     uint64 timestamp;
//!     opaque log_origin<1..2^8-1>;
//!     uint64 start;
//!     uint64 end;
//!     HashValue subtree_hash;
//! } CosignedSubtree;
//!
//! struct { TrustAnchorID cosigner_id; opaque signature<0..2^16-1>; } Cosignature;
//!
//! struct {
//!     MTCLogEntryExtension extensions<0..2^16-1>;
//!     uint48 start;
//!     uint48 end;
//!     opaque inclusion_proof<0..2^16-1>;
//!     Cosignature signatures<0..2^24-1>;
//! } MTCProof;
//! ```
//!
//! §6.2 also fixes the canonical cosigner ordering that closed `merkle-tree-certs` issues #341/#342:
//! shorter identifiers first, then lexicographic; duplicates are rejected; RFC 8701 GREASE entries
//! stay on the wire but never count toward quorum.

use super::error::{MtcError, MtcResult};
use serde::{Deserialize, Serialize};

/// `id-alg-mtcProof` = 1.3.6.1.5.5.7.6.67, as a DER OBJECT IDENTIFIER TLV (draft §6.2).
pub const ID_ALG_MTC_PROOF: [u8; 10] = [0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x43];

/// Alias retained for callers that speak in terms of "the MTC proof OID".
pub const OID_MTC_PROOF: [u8; 10] = ID_ALG_MTC_PROOF;

/// Domain separator prefixing every cosigned subtree statement: `"subtree/v1\n\0"`.
pub const COSIGN_CONTEXT_HEADER: [u8; 12] = *b"subtree/v1\n\0";

/// Fixed prefix of a trust anchor ID string: `oid/1.3.6.1.4.1.`.
pub const TRUST_ANCHOR_ID_PREFIX: &[u8] = b"oid/1.3.6.1.4.1.";

/// Encoded size of the fixed part of a `CosignedSubtree`: 12 + 8 + 8 + 8 + 32.
pub const COSIGNED_SUBTREE_FIXED_LEN: usize = 68;

/// A checkpoint-style signature with a timestamp (used by `tlog-witness`-style integration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampedSignature {
    /// Unix seconds at which the signer signed.
    pub timestamp: u64,
    /// Raw signature bytes (3,309 B for ML-DSA-65).
    pub signature: Vec<u8>,
}

impl TimestampedSignature {
    /// Builds a record.
    pub fn new(timestamp: u64, signature: Vec<u8>) -> Self {
        Self {
            timestamp,
            signature,
        }
    }

    /// Serializes to `uint64_be(timestamp) || signature`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.signature.len());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parses `uint64_be(timestamp) || signature`.
    pub fn from_bytes(bytes: &[u8]) -> MtcResult<Self> {
        if bytes.len() < 8 {
            return Err(MtcError::WireEncoding(
                "TimestampedSignature needs at least 8 bytes".into(),
            ));
        }
        let mut stamp = [0u8; 8];
        stamp.copy_from_slice(&bytes[..8]);
        Ok(Self {
            timestamp: u64::from_be_bytes(stamp),
            signature: bytes[8..].to_vec(),
        })
    }
}

/// Builds a trust anchor ID string such as `oid/1.3.6.1.4.1.32473.1` (draft §5.3.1).
pub fn trust_anchor_id_string(trust_anchor_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRUST_ANCHOR_ID_PREFIX.len() + trust_anchor_id.len());
    out.extend_from_slice(TRUST_ANCHOR_ID_PREFIX);
    out.extend_from_slice(trust_anchor_id.as_bytes());
    out
}

/// The statement a cosigner signs for a subtree (draft §5.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosignedSubtree {
    /// `"oid/1.3.6.1.4.1.<cosigner trust anchor id>"`.
    pub cosigner_name: Vec<u8>,
    /// Signing time in seconds since the epoch (`0` inside an MTCProof, per §6.2).
    pub timestamp: u64,
    /// `"oid/1.3.6.1.4.1.<issuance log id>"`.
    pub log_origin: Vec<u8>,
    /// Subtree start index (draft uses the full `uint64` here).
    pub start: u64,
    /// Subtree end index.
    pub end: u64,
    /// Hash of the subtree being signed.
    pub subtree_hash: [u8; 32],
}

impl CosignedSubtree {
    /// Builds a statement for `ca_id`/`log_id` strings, e.g. `("32473.1", "32473.2")`.
    pub fn new(
        ca_id: &str,
        log_id: &str,
        timestamp: u64,
        start: u64,
        end: u64,
        subtree_hash: [u8; 32],
    ) -> Self {
        Self {
            cosigner_name: trust_anchor_id_string(ca_id),
            timestamp,
            log_origin: trust_anchor_id_string(log_id),
            start,
            end,
            subtree_hash,
        }
    }

    /// TLS-presentation-language encoding.
    pub fn to_bytes(&self) -> MtcResult<Vec<u8>> {
        if self.cosigner_name.is_empty() || self.cosigner_name.len() > u8::MAX as usize {
            return Err(MtcError::WireEncoding(
                "cosigner_name must be 1..=255 bytes".into(),
            ));
        }
        if self.log_origin.is_empty() || self.log_origin.len() > u8::MAX as usize {
            return Err(MtcError::WireEncoding(
                "log_origin must be 1..=255 bytes".into(),
            ));
        }

        let mut out = Vec::with_capacity(
            COSIGNED_SUBTREE_FIXED_LEN + self.cosigner_name.len() + self.log_origin.len(),
        );
        out.extend_from_slice(&COSIGN_CONTEXT_HEADER);
        out.push(self.cosigner_name.len() as u8);
        out.extend_from_slice(&self.cosigner_name);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.push(self.log_origin.len() as u8);
        out.extend_from_slice(&self.log_origin);
        out.extend_from_slice(&self.start.to_be_bytes());
        out.extend_from_slice(&self.end.to_be_bytes());
        out.extend_from_slice(&self.subtree_hash);
        Ok(out)
    }
}

/// One cosignature entry inside an `MTCProof` (draft §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosignature {
    /// Cosigner ID in its binary (relative OID) representation.
    pub cosigner_id: Vec<u8>,
    /// Signature over the corresponding `CosignedSubtree` statement.
    pub signature: Vec<u8>,
}

impl Cosignature {
    /// Builds an entry.
    pub fn new(cosigner_id: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            cosigner_id,
            signature,
        }
    }

    /// The `CosignedSubtree` this entry signs, given the certificate parameters.
    pub fn statement(
        &self,
        log_id: &str,
        start: u64,
        end: u64,
        subtree_hash: [u8; 32],
    ) -> CosignedSubtree {
        CosignedSubtree {
            cosigner_name: self.cosigner_id.clone(),
            timestamp: 0,
            log_origin: trust_anchor_id_string(log_id),
            start,
            end,
            subtree_hash,
        }
    }
}

/// RFC 8701 GREASE identifier test: two bytes of the form `0x?A?A`.
pub fn is_grease_cosigner_id(id: &[u8]) -> bool {
    id.len() == 2 && (id[0] & 0x0F) == 0x0A && (id[1] & 0x0F) == 0x0A
}

/// Sorts cosignatures into the canonical §6.2 order and rejects duplicates.
///
/// Shorter identifiers come first, then lexicographic comparison. Reordering is the only legal
/// fix; a duplicate identifier means a split-view witness and is a hard error.
pub fn canonicalize_cosignatures(entries: &mut [Cosignature]) -> MtcResult<()> {
    entries.sort_by(|a, b| {
        a.cosigner_id
            .len()
            .cmp(&b.cosigner_id.len())
            .then_with(|| a.cosigner_id.cmp(&b.cosigner_id))
    });

    for pair in entries.windows(2) {
        if pair[0].cosigner_id == pair[1].cosigner_id {
            return Err(MtcError::DuplicateCosignerId);
        }
    }

    Ok(())
}

/// True when `entries` are already in canonical order with strictly increasing identifiers.
pub fn is_canonical_cosigner_order(entries: &[Cosignature]) -> bool {
    entries.windows(2).all(|pair| {
        let (a, b) = (&pair[0].cosigner_id, &pair[1].cosigner_id);
        match a.len().cmp(&b.len()) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => a < b,
        }
    })
}

/// Counts cosignatures that count toward quorum, ignoring RFC 8701 GREASE identifiers.
pub fn count_quorum(entries: &[Cosignature]) -> usize {
    entries
        .iter()
        .filter(|entry| !is_grease_cosigner_id(&entry.cosigner_id))
        .count()
}

/// A Merkle Tree Certificate proof (draft §6.2), carried in an `id-alg-mtcProof` signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtcProof {
    /// The log entry's extensions value.
    pub extensions: Vec<u8>,
    /// Subtree start index.
    pub start: u64,
    /// Subtree end index.
    pub end: u64,
    /// Subtree inclusion proof hashes, concatenated in order.
    pub inclusion_proof: Vec<[u8; 32]>,
    /// Canonical, duplicate-free subtree signatures.
    pub signatures: Vec<Cosignature>,
}

impl MtcProof {
    /// Canonicalizes the witness list in place.
    pub fn canonicalize(&mut self) -> MtcResult<()> {
        canonicalize_cosignatures(&mut self.signatures)
    }

    /// Number of signatures that count toward quorum.
    pub fn quorum(&self) -> usize {
        count_quorum(&self.signatures)
    }

    /// TLS-presentation-language encoding (draft §6.2).
    pub fn encode(&self) -> MtcResult<Vec<u8>> {
        if self
            .signatures
            .windows(2)
            .any(|pair| pair[0].cosigner_id == pair[1].cosigner_id)
        {
            return Err(MtcError::DuplicateCosignerId);
        }
        if !is_canonical_cosigner_order(&self.signatures) {
            return Err(MtcError::CosignersOutOfOrder);
        }
        if self.extensions.len() > u16::MAX as usize {
            return Err(MtcError::WireEncoding(
                "MTCProof extensions exceed 2^16-1".into(),
            ));
        }
        let proof_len = self.inclusion_proof.len().saturating_mul(32);
        if proof_len > u16::MAX as usize {
            return Err(MtcError::WireEncoding(
                "MTCProof inclusion proof exceeds 2^16-1 bytes".into(),
            ));
        }

        let mut signature_bytes: Vec<u8> = Vec::new();
        for entry in &self.signatures {
            if entry.cosigner_id.is_empty() || entry.cosigner_id.len() > u8::MAX as usize {
                return Err(MtcError::WireEncoding(
                    "cosigner_id must be 1..=255 bytes".into(),
                ));
            }
            if entry.signature.len() > u16::MAX as usize {
                return Err(MtcError::WireEncoding(
                    "cosignature exceeds 2^16-1 bytes".into(),
                ));
            }
            signature_bytes.push(entry.cosigner_id.len() as u8);
            signature_bytes.extend_from_slice(&entry.cosigner_id);
            signature_bytes.extend_from_slice(&(entry.signature.len() as u16).to_be_bytes());
            signature_bytes.extend_from_slice(&entry.signature);
        }
        if signature_bytes.len() > 0xFF_FFFF {
            return Err(MtcError::WireEncoding(
                "MTCProof signatures exceed 2^24-1 bytes".into(),
            ));
        }

        let mut out = Vec::with_capacity(
            2 + self.extensions.len() + 12 + proof_len + 3 + signature_bytes.len(),
        );
        out.extend_from_slice(&(self.extensions.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.extensions);
        out.extend_from_slice(&self.start.to_be_bytes()[2..8]);
        out.extend_from_slice(&self.end.to_be_bytes()[2..8]);
        out.extend_from_slice(&(proof_len as u16).to_be_bytes());
        for hash in &self.inclusion_proof {
            out.extend_from_slice(hash);
        }
        out.extend_from_slice(&signature_bytes.len().to_be_bytes()[5..8]);
        out.extend_from_slice(&signature_bytes);
        Ok(out)
    }

    /// Strictly parses the encoding, rejecting any non-canonical witness order.
    pub fn decode(bytes: &[u8]) -> MtcResult<Self> {
        let mut reader = Reader::new(bytes);

        let extensions_len = reader.u16()? as usize;
        let extensions = reader.take(extensions_len)?.to_vec();
        let start = reader.u48()?;
        let end = reader.u48()?;
        let proof_len = reader.u16()? as usize;
        if !proof_len.is_multiple_of(32) {
            return Err(MtcError::WireEncoding(
                "inclusion proof length is not a multiple of 32".into(),
            ));
        }
        let mut inclusion_proof = Vec::with_capacity(proof_len / 32);
        for _ in 0..proof_len / 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(reader.take(32)?);
            inclusion_proof.push(hash);
        }

        let signature_bytes_len = reader.u24()? as usize;
        let signature_bytes = reader.take(signature_bytes_len)?;

        let mut inner = Reader::new(signature_bytes);
        let mut signatures = Vec::new();
        while !inner.is_exhausted() {
            let id_len = inner.u8()? as usize;
            let cosigner_id = inner.take(id_len)?.to_vec();
            let sig_len = inner.u16()? as usize;
            let signature = inner.take(sig_len)?.to_vec();
            signatures.push(Cosignature::new(cosigner_id, signature));
        }

        if !reader.is_exhausted() {
            return Err(MtcError::WireEncoding(
                "trailing bytes after MTCProof".into(),
            ));
        }
        if !is_canonical_cosigner_order(&signatures) {
            return Err(MtcError::CosignersOutOfOrder);
        }
        for pair in signatures.windows(2) {
            if pair[0].cosigner_id == pair[1].cosigner_id {
                return Err(MtcError::DuplicateCosignerId);
            }
        }

        Ok(Self {
            extensions,
            start,
            end,
            inclusion_proof,
            signatures,
        })
    }
}

/// Minimal cursor over a byte slice with bounds-checked primitives.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> MtcResult<&'a [u8]> {
        if self.pos + len > self.bytes.len() {
            return Err(MtcError::WireEncoding("MTCProof truncated".into()));
        }
        let out = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn u8(&mut self) -> MtcResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> MtcResult<u16> {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(buf))
    }

    fn u24(&mut self) -> MtcResult<u32> {
        let mut buf = [0u8; 4];
        buf[1..].copy_from_slice(self.take(3)?);
        Ok(u32::from_be_bytes(buf))
    }

    fn u48(&mut self) -> MtcResult<u64> {
        let mut buf = [0u8; 8];
        buf[2..].copy_from_slice(self.take(6)?);
        Ok(u64::from_be_bytes(buf))
    }

    fn is_exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::*;

    fn cosignature(id: &[u8]) -> Cosignature {
        Cosignature::new(id.to_vec(), vec![0xA5; 3_309])
    }

    #[test]
    fn trust_anchor_id_string_matches_the_draft_example() {
        assert_eq!(
            trust_anchor_id_string("32473.1"),
            b"oid/1.3.6.1.4.1.32473.1".to_vec()
        );
    }

    #[test]
    fn cosigned_subtree_layout_is_exact() {
        let statement = CosignedSubtree::new("32473.1", "32473.2", 0, 3, 12, [0x42; 32]);
        let bytes = statement.to_bytes().unwrap();

        assert_eq!(&bytes[0..12], b"subtree/v1\n\0");
        assert_eq!(bytes[12], 23, "oid/1.3.6.1.4.1.32473.1 is 23 bytes");
        assert_eq!(&bytes[13..36], b"oid/1.3.6.1.4.1.32473.1");
        assert_eq!(&bytes[36..44], &0u64.to_be_bytes(), "timestamp is uint64");
        assert_eq!(bytes[44], 23);
        assert_eq!(&bytes[45..68], b"oid/1.3.6.1.4.1.32473.2");
        assert_eq!(
            &bytes[68..76],
            &3u64.to_be_bytes(),
            "start is a full uint64"
        );
        assert_eq!(&bytes[76..84], &12u64.to_be_bytes(), "end is a full uint64");
        assert_eq!(&bytes[84..116], &[0x42u8; 32]);
        assert_eq!(bytes.len(), 116);
    }

    #[test]
    fn cosigned_subtree_rejects_oversized_names() {
        let long = vec![b'x'; 256];
        let statement = CosignedSubtree {
            cosigner_name: long,
            timestamp: 0,
            log_origin: b"oid/1.3.6.1.4.1.1".to_vec(),
            start: 0,
            end: 1,
            subtree_hash: [0u8; 32],
        };
        assert!(statement.to_bytes().is_err());
    }

    #[test]
    fn timestamped_signature_roundtrip() {
        let record = TimestampedSignature::new(1_700_000_000, vec![1, 2, 3, 4]);
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[..8], &1_700_000_000u64.to_be_bytes());
        assert_eq!(TimestampedSignature::from_bytes(&bytes).unwrap(), record);
        assert!(TimestampedSignature::from_bytes(&[0u8; 7]).is_err());
    }

    #[test]
    fn grease_detection_matches_rfc8701() {
        assert!(is_grease_cosigner_id(&[0x0A, 0x0A]));
        assert!(is_grease_cosigner_id(&[0xFA, 0xFA]));
        assert!(is_grease_cosigner_id(&[0x1A, 0x2A]));
        assert!(!is_grease_cosigner_id(&[0x0A, 0x0B]));
        assert!(!is_grease_cosigner_id(&[0x0A, 0x0A, 0x0A]));
        assert!(!is_grease_cosigner_id(&[]));
    }

    #[test]
    fn canonicalization_is_length_first() {
        let mut entries = vec![
            cosignature(&[0x01, 0x02, 0x03]),
            cosignature(&[0xFF]),
            cosignature(&[0x01, 0x02]),
        ];
        canonicalize_cosignatures(&mut entries).unwrap();
        let ids: Vec<Vec<u8>> = entries.iter().map(|e| e.cosigner_id.clone()).collect();
        assert_eq!(
            ids,
            vec![vec![0xFF], vec![0x01, 0x02], vec![0x01, 0x02, 0x03]]
        );
        assert!(is_canonical_cosigner_order(&entries));
    }

    #[test]
    fn duplicate_cosigners_are_rejected() {
        let mut entries = vec![cosignature(&[0x2A]), cosignature(&[0x2A])];
        assert_eq!(
            canonicalize_cosignatures(&mut entries),
            Err(MtcError::DuplicateCosignerId)
        );
    }

    #[test]
    fn grease_stays_on_the_wire_but_never_counts() {
        let mut entries = vec![
            cosignature(&[0x0A, 0x0A]),
            cosignature(&[0x2A]),
            cosignature(&[0x2B]),
            cosignature(&[0xFA, 0xFA]),
        ];
        canonicalize_cosignatures(&mut entries).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(count_quorum(&entries), 2);
    }

    #[test]
    fn proof_encoding_roundtrips_and_is_stable_under_shuffling() {
        let mut base = MtcProof {
            extensions: vec![0x30, 0x00],
            start: 4,
            end: 12,
            inclusion_proof: vec![[0x22; 32], [0x33; 32], [0x44; 32]],
            signatures: vec![
                cosignature(&[0x01, 0x02]),
                cosignature(&[0x0A, 0x0A]),
                cosignature(&[0xFF]),
            ],
        };
        base.canonicalize().unwrap();
        let encoded = base.encode().unwrap();
        let decoded = MtcProof::decode(&encoded).unwrap();
        assert_eq!(decoded, base);
        assert_eq!(decoded.encode().unwrap(), encoded);

        let permutations: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        for perm in permutations {
            let mut shuffled = base.clone();
            shuffled.signatures = perm.iter().map(|i| base.signatures[*i].clone()).collect();
            shuffled.canonicalize().unwrap();
            assert_eq!(shuffled.encode().unwrap(), encoded, "permutation {perm:?}");
        }
    }

    #[test]
    fn encoding_rejects_non_canonical_and_duplicate_lists() {
        let unsorted = MtcProof {
            extensions: vec![],
            start: 0,
            end: 1,
            inclusion_proof: vec![],
            signatures: vec![cosignature(&[0xFF]), cosignature(&[0x01])],
        };
        assert_eq!(unsorted.encode(), Err(MtcError::CosignersOutOfOrder));

        let duplicated = MtcProof {
            extensions: vec![],
            start: 0,
            end: 1,
            inclusion_proof: vec![],
            signatures: vec![cosignature(&[0x2A]), cosignature(&[0x2A])],
        };
        assert_eq!(duplicated.encode(), Err(MtcError::DuplicateCosignerId));
    }

    #[test]
    fn decode_rejects_corrupt_or_foreign_input() {
        let base = MtcProof {
            extensions: vec![0x30, 0x01, 0x00],
            start: 1,
            end: 2,
            inclusion_proof: vec![[0x01; 32]],
            signatures: vec![cosignature(&[0x2A])],
        };
        let encoded = base.encode().unwrap();

        assert!(MtcProof::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0x00);
        assert!(MtcProof::decode(&trailing).is_err());

        // A proof whose cosigners were serialized out of order must be rejected.
        let mut misordered = MtcProof {
            extensions: vec![],
            start: 0,
            end: 1,
            inclusion_proof: vec![],
            signatures: vec![cosignature(&[0x01]), cosignature(&[0x01, 0x02])],
        };
        misordered.canonicalize().unwrap();
        let canonical = misordered.encode().unwrap();
        let first_len = 1 + 1 + 2 + 3_309;
        let second_len = 1 + 2 + 2 + 3_309;
        let head_len = canonical.len() - first_len - second_len;
        let mut body = Vec::new();
        body.extend_from_slice(&canonical[..head_len]);
        body.extend_from_slice(&canonical[head_len + first_len..]);
        body.extend_from_slice(&canonical[head_len..head_len + first_len]);
        assert_eq!(body.len(), canonical.len());
        assert!(MtcProof::decode(&body).is_err());
    }

    #[test]
    fn proof_oid_is_the_algorithm_identifier() {
        assert_eq!(
            ID_ALG_MTC_PROOF,
            [0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x43]
        );
        // 1.3.6.1.5.5.7.6.67 after the tag and length.
        assert_eq!(
            &ID_ALG_MTC_PROOF[2..],
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x43]
        );
    }
}
