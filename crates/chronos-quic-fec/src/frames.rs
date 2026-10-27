//! Custom QUIC frames for handshake erasure coding: `FEC_SOURCE` (0x3f51),
//! `FEC_REPAIR` (0x3f52) and `FEC_RECOVERED` (0x3f53).
//!
//! All three are carried as ordinary QUIC frames, so every length is an explicit QUIC varint or a
//! fixed-width big-endian field and the encodings are unambiguous:
//!
//! ```text
//! FEC_SOURCE    0x3f51: varint type, block_id u32, k u8, r u8, shard_index u8,
//!                            original_payload_len u16, crc32c u32, shard bytes   [13 B header]
//! FEC_REPAIR    0x3f52: varint type, block_id u32, k u8, r u8, parity_index u8,
//!                            shard_len u16, crc32c u32, parity bytes             [13 B header]
//! FEC_RECOVERED 0x3f53: varint type, block_id u32, recovered_count u8,
//!                            varint-prefixed list of u64 packet numbers
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `FEC_SOURCE` frame type.
pub const FEC_SOURCE: u64 = 0x3f51;
/// `FEC_REPAIR` frame type.
pub const FEC_REPAIR: u64 = 0x3f52;
/// `FEC_RECOVERED` frame type.
pub const FEC_RECOVERED: u64 = 0x3f53;

/// Wire size of a `FEC_SOURCE` header, excluding the frame type varint.
pub const FEC_SOURCE_HEADER_BYTES: usize = 13;
/// Wire size of a `FEC_REPAIR` header, excluding the frame type varint.
pub const FEC_REPAIR_HEADER_BYTES: usize = 13;
/// Wire size of a `FEC_RECOVERED` header, excluding the type varint and packet-number list.
pub const FEC_RECOVERED_HEADER_BYTES: usize = 5;

/// Errors produced while encoding or decoding FEC frames.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FecError {
    /// The frame type varint was missing, truncated or not the expected type.
    #[error("expected frame type {expected:#x}, found {found:#x}")]
    WrongFrameType {
        /// Type this decoder expects.
        expected: u64,
        /// Type that was actually present.
        found: u64,
    },

    /// The buffer ended before a field or the shard payload.
    #[error("FEC frame truncated at offset {offset}")]
    Truncated {
        /// Byte offset where decoding stopped.
        offset: usize,
    },

    /// A field carried a value outside its legal range.
    #[error("illegal FEC field {field}: {value}")]
    IllegalField {
        /// Field name.
        field: &'static str,
        /// Offending value.
        value: u64,
    },

    /// The CRC32c of a shard did not match the carried tag.
    #[error(
        "CRC32c mismatch for shard {index}: expected {expected:#010x}, computed {computed:#010x}"
    )]
    CrcMismatch {
        /// Shard index that failed validation.
        index: u8,
        /// Tag carried in the frame.
        expected: u32,
        /// Tag computed over the received bytes.
        computed: u32,
    },

    /// The shard count or parity count was outside the supported range.
    #[error("shard configuration k={k}, r={r} is out of range")]
    ShardConfiguration {
        /// Data shard count.
        k: u8,
        /// Parity shard count.
        r: u8,
    },

    /// The underlying Reed-Solomon coder rejected the configuration or the data.
    #[error("Reed-Solomon failure: {0}")]
    ReedSolomon(String),
}

/// Largest value a QUIC varint can carry (2^62 - 1, RFC 9000 §16).
pub const MAX_VARINT: u64 = (1u64 << 62) - 1;

/// Encodes a QUIC variable-length integer in its shortest form (RFC 9000 §16).
///
/// The two most significant bits of the first byte encode the width (1, 2, 4 or 8 bytes), so the
/// value is OR-ed with the width prefix rather than written verbatim. Values above [`MAX_VARINT`]
/// are not representable on the wire; only internally derived small constants are encoded here, and
/// a debug build catches a mistake at the source.
pub fn encode_varint(value: u64) -> Vec<u8> {
    debug_assert!(value <= MAX_VARINT, "QUIC varints carry at most 2^62 - 1");
    match value {
        0..=0x3F => vec![value as u8],
        0x40..=0x3FFF => ((value as u16) | 0x4000).to_be_bytes().to_vec(),
        0x4000..=0x3FFF_FFFF => ((value as u32) | 0x8000_0000).to_be_bytes().to_vec(),
        _ => (value | 0xC000_0000_0000_0000).to_be_bytes().to_vec(),
    }
}

/// Decodes a QUIC variable-length integer, returning `(value, bytes_consumed)`.
pub fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), FecError> {
    let first = *bytes.first().ok_or(FecError::Truncated { offset: 0 })?;
    let width = 1usize << (first >> 6);
    if bytes.len() < width {
        return Err(FecError::Truncated {
            offset: bytes.len(),
        });
    }
    let mut value = u64::from(first & 0x3F);
    for byte in &bytes[1..width] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, width))
}

/// One data shard inside a `FEC_SOURCE` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecSourceFrame {
    /// Block this shard belongs to.
    pub block_id: u32,
    /// Total data shard count `k`.
    pub data_shards: u8,
    /// Total parity shard count `r`.
    pub parity_shards: u8,
    /// Index of this shard in `0..k`.
    pub shard_index: u8,
    /// Length of the original payload before sharding (used to strip padding).
    pub original_payload_len: u16,
    /// CRC32c (Castagnoli) over `shard`.
    pub crc32c: u32,
    /// Shard bytes, 64-byte aligned.
    pub shard: Vec<u8>,
}

impl FecSourceFrame {
    /// Builds a frame, computing the CRC32c tag.
    pub fn new(
        block_id: u32,
        data_shards: u8,
        parity_shards: u8,
        shard_index: u8,
        original_payload_len: u16,
        shard: Vec<u8>,
    ) -> Self {
        Self {
            block_id,
            data_shards,
            parity_shards,
            shard_index,
            original_payload_len,
            crc32c: crc32fast::hash(&shard),
            shard,
        }
    }

    /// Verifies the shard against its CRC32c tag.
    pub fn verify_crc(&self) -> Result<(), FecError> {
        let computed = crc32fast::hash(&self.shard);
        if computed == self.crc32c {
            return Ok(());
        }
        Err(FecError::CrcMismatch {
            index: self.shard_index,
            expected: self.crc32c,
            computed,
        })
    }

    /// Encodes `varint(0x3f51) || header || shard`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + FEC_SOURCE_HEADER_BYTES + self.shard.len());
        out.extend_from_slice(&encode_varint(FEC_SOURCE));
        out.extend_from_slice(&self.block_id.to_be_bytes());
        out.push(self.data_shards);
        out.push(self.parity_shards);
        out.push(self.shard_index);
        out.extend_from_slice(&self.original_payload_len.to_be_bytes());
        out.extend_from_slice(&self.crc32c.to_be_bytes());
        out.extend_from_slice(&self.shard);
        out
    }

    /// Decodes a `FEC_SOURCE` frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, FecError> {
        let (frame_type, consumed) = decode_varint(bytes)?;
        if frame_type != FEC_SOURCE {
            return Err(FecError::WrongFrameType {
                expected: FEC_SOURCE,
                found: frame_type,
            });
        }
        let body = bytes
            .get(consumed..)
            .ok_or(FecError::Truncated { offset: consumed })?;
        if body.len() < FEC_SOURCE_HEADER_BYTES {
            return Err(FecError::Truncated {
                offset: consumed + body.len(),
            });
        }

        let block_id = u32::from_be_bytes(body[0..4].try_into().expect("4 bytes"));
        let data_shards = body[4];
        let parity_shards = body[5];
        let shard_index = body[6];
        let original_payload_len = u16::from_be_bytes(body[7..9].try_into().expect("2 bytes"));
        let crc32c = u32::from_be_bytes(body[9..13].try_into().expect("4 bytes"));
        let shard = body[FEC_SOURCE_HEADER_BYTES..].to_vec();

        Ok(Self {
            block_id,
            data_shards,
            parity_shards,
            shard_index,
            original_payload_len,
            crc32c,
            shard,
        })
    }
}

/// One parity shard inside a `FEC_REPAIR` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecRepairFrame {
    /// Block this parity shard belongs to.
    pub block_id: u32,
    /// Total data shard count `k`.
    pub data_shards: u8,
    /// Total parity shard count `r`.
    pub parity_shards: u8,
    /// Index of this parity shard in `0..r`.
    pub parity_index: u8,
    /// Length of the parity payload.
    pub shard_len: u16,
    /// CRC32c (Castagnoli) over `parity`.
    pub crc32c: u32,
    /// Parity bytes, 64-byte aligned.
    pub parity: Vec<u8>,
}

impl FecRepairFrame {
    /// Builds a frame, computing the CRC32c tag.
    pub fn new(
        block_id: u32,
        data_shards: u8,
        parity_shards: u8,
        parity_index: u8,
        parity: Vec<u8>,
    ) -> Self {
        Self {
            block_id,
            data_shards,
            parity_shards,
            parity_index,
            shard_len: parity.len() as u16,
            crc32c: crc32fast::hash(&parity),
            parity,
        }
    }

    /// Verifies the parity shard against its CRC32c tag.
    pub fn verify_crc(&self) -> Result<(), FecError> {
        let computed = crc32fast::hash(&self.parity);
        if computed == self.crc32c {
            return Ok(());
        }
        Err(FecError::CrcMismatch {
            index: self.parity_index,
            expected: self.crc32c,
            computed,
        })
    }

    /// Encodes `varint(0x3f52) || header || parity`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + FEC_REPAIR_HEADER_BYTES + self.parity.len());
        out.extend_from_slice(&encode_varint(FEC_REPAIR));
        out.extend_from_slice(&self.block_id.to_be_bytes());
        out.push(self.data_shards);
        out.push(self.parity_shards);
        out.push(self.parity_index);
        out.extend_from_slice(&self.shard_len.to_be_bytes());
        out.extend_from_slice(&self.crc32c.to_be_bytes());
        out.extend_from_slice(&self.parity);
        out
    }

    /// Decodes a `FEC_REPAIR` frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, FecError> {
        let (frame_type, consumed) = decode_varint(bytes)?;
        if frame_type != FEC_REPAIR {
            return Err(FecError::WrongFrameType {
                expected: FEC_REPAIR,
                found: frame_type,
            });
        }
        let body = bytes
            .get(consumed..)
            .ok_or(FecError::Truncated { offset: consumed })?;
        if body.len() < FEC_REPAIR_HEADER_BYTES {
            return Err(FecError::Truncated {
                offset: consumed + body.len(),
            });
        }

        let block_id = u32::from_be_bytes(body[0..4].try_into().expect("4 bytes"));
        let data_shards = body[4];
        let parity_shards = body[5];
        let parity_index = body[6];
        let shard_len = u16::from_be_bytes(body[7..9].try_into().expect("2 bytes"));
        let crc32c = u32::from_be_bytes(body[9..13].try_into().expect("4 bytes"));
        let parity = body[FEC_REPAIR_HEADER_BYTES..].to_vec();
        if parity.len() != shard_len as usize {
            return Err(FecError::Truncated {
                offset: consumed + FEC_REPAIR_HEADER_BYTES + parity.len(),
            });
        }

        Ok(Self {
            block_id,
            data_shards,
            parity_shards,
            parity_index,
            shard_len,
            crc32c,
            parity,
        })
    }
}

/// The client's congestion-signal frame (`FEC_RECOVERED`, 0x3f53).
///
/// The server marks these packet numbers delivered for handshake purposes but still feeds them to
/// the RFC 9002 loss detector, so FEC recovery never hides congestion (ADR-010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecRecoveredFrame {
    /// Block the reconstruction belonged to.
    pub block_id: u32,
    /// Packet numbers recovered through parity.
    pub recovered_packet_numbers: Vec<u64>,
}

impl FecRecoveredFrame {
    /// Builds a frame.
    pub fn new(block_id: u32, recovered_packet_numbers: Vec<u64>) -> Self {
        Self {
            block_id,
            recovered_packet_numbers,
        }
    }

    /// Number of reconstructed packets.
    pub fn recovered_count(&self) -> u8 {
        self.recovered_packet_numbers.len() as u8
    }

    /// Encodes `varint(0x3f53) || block_id || count || varint-prefixed packet numbers`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + FEC_RECOVERED_HEADER_BYTES + 9);
        out.extend_from_slice(&encode_varint(FEC_RECOVERED));
        out.extend_from_slice(&self.block_id.to_be_bytes());
        out.push(self.recovered_count());
        out.extend_from_slice(&encode_varint(self.recovered_packet_numbers.len() as u64));
        for number in &self.recovered_packet_numbers {
            out.extend_from_slice(&number.to_be_bytes());
        }
        out
    }

    /// Decodes a `FEC_RECOVERED` frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, FecError> {
        let (frame_type, consumed) = decode_varint(bytes)?;
        if frame_type != FEC_RECOVERED {
            return Err(FecError::WrongFrameType {
                expected: FEC_RECOVERED,
                found: frame_type,
            });
        }
        let body = bytes
            .get(consumed..)
            .ok_or(FecError::Truncated { offset: consumed })?;
        if body.len() < FEC_RECOVERED_HEADER_BYTES {
            return Err(FecError::Truncated {
                offset: consumed + body.len(),
            });
        }

        let block_id = u32::from_be_bytes(body[0..4].try_into().expect("4 bytes"));
        let count = body[4];
        let (list_len, list_len_bytes) = decode_varint(&body[5..])?;
        let list_start = 5 + list_len_bytes;
        if list_len != u64::from(count) {
            return Err(FecError::IllegalField {
                field: "recovered packet count",
                value: list_len,
            });
        }
        let list = &body[list_start..];
        if list.len() != count as usize * 8 {
            return Err(FecError::Truncated {
                offset: consumed + list_start + list.len(),
            });
        }

        let mut numbers = Vec::with_capacity(count as usize);
        for chunk in list.as_chunks::<8>().0 {
            numbers.push(u64::from_be_bytes(*chunk));
        }

        Ok(Self {
            block_id,
            recovered_packet_numbers: numbers,
        })
    }
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::*;

    #[test]
    fn frame_types_encode_to_their_two_byte_varints() {
        // 0x3f51 needs the 2-byte form because it exceeds 63.
        assert_eq!(encode_varint(FEC_SOURCE), vec![0x7F, 0x51]);
        assert_eq!(encode_varint(FEC_REPAIR), vec![0x7F, 0x52]);
        assert_eq!(encode_varint(FEC_RECOVERED), vec![0x7F, 0x53]);
    }

    #[test]
    fn varint_roundtrips_every_width() {
        for value in [
            0u64,
            1,
            63,
            64,
            1_000,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            MAX_VARINT,
        ] {
            let encoded = encode_varint(value);
            let (decoded, consumed) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(consumed, encoded.len());
        }
        assert_eq!(encode_varint(63).len(), 1);
        assert_eq!(encode_varint(64).len(), 2);
        assert_eq!(encode_varint(16_384).len(), 4);
        assert_eq!(encode_varint(1u64 << 32).len(), 8);
        assert_eq!(MAX_VARINT, 4_611_686_018_427_387_903);
    }

    #[test]
    fn varint_rejects_truncated_input() {
        assert_eq!(decode_varint(&[]), Err(FecError::Truncated { offset: 0 }));
        assert!(matches!(
            decode_varint(&[0x7F]),
            Err(FecError::Truncated { .. })
        ));
    }

    #[test]
    fn source_frame_roundtrip_and_crc() {
        let shard = vec![0x5A; 64];
        let frame = FecSourceFrame::new(7, 4, 2, 3, 1_234, shard.clone());
        let encoded = frame.encode();
        assert_eq!(encoded.len(), 2 + FEC_SOURCE_HEADER_BYTES + 64);

        let decoded = FecSourceFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        decoded.verify_crc().unwrap();

        // A single flipped byte must be caught before the shard can poison reconstruction.
        let mut corrupted = encoded.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        let corrupted_frame = FecSourceFrame::decode(&corrupted).unwrap();
        assert!(matches!(
            corrupted_frame.verify_crc(),
            Err(FecError::CrcMismatch { index: 3, .. })
        ));
    }

    #[test]
    fn repair_frame_roundtrip_and_crc() {
        let parity = vec![0x11; 128];
        let frame = FecRepairFrame::new(9, 2, 1, 0, parity);
        let encoded = frame.encode();
        assert_eq!(encoded.len(), 2 + FEC_REPAIR_HEADER_BYTES + 128);

        let decoded = FecRepairFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        decoded.verify_crc().unwrap();

        let mut corrupted = encoded;
        corrupted[20] ^= 0x80;
        assert!(
            FecRepairFrame::decode(&corrupted).is_err() || {
                FecRepairFrame::decode(&corrupted)
                    .unwrap()
                    .verify_crc()
                    .is_err()
            }
        );
    }

    #[test]
    fn recovered_frame_roundtrip() {
        let frame = FecRecoveredFrame::new(3, vec![11, 12, 13]);
        let encoded = frame.encode();
        assert_eq!(encoded.len(), 2 + FEC_RECOVERED_HEADER_BYTES + 1 + 3 * 8);

        let decoded = FecRecoveredFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(decoded.recovered_count(), 3);
    }

    #[test]
    fn decoders_reject_foreign_frame_types_and_truncation() {
        let source = FecSourceFrame::new(1, 2, 0, 0, 4, vec![0; 64]).encode();
        let repair = FecRepairFrame::new(1, 2, 1, 0, vec![0; 64]).encode();

        assert!(matches!(
            FecRepairFrame::decode(&source),
            Err(FecError::WrongFrameType { .. })
        ));
        assert!(matches!(
            FecSourceFrame::decode(&repair),
            Err(FecError::WrongFrameType { .. })
        ));
        assert!(matches!(
            FecRecoveredFrame::decode(&source),
            Err(FecError::WrongFrameType { .. })
        ));

        assert!(
            FecSourceFrame::decode(&source[..10]).is_err(),
            "truncated header"
        );
        assert!(FecSourceFrame::decode(&[]).is_err());
        // A repair frame carries its own length, so truncation is caught here; a source frame's
        // shard length is implied by the datagram and is enforced by `FecBlockAssembler`.
        assert!(FecRepairFrame::decode(&repair[..repair.len() - 1]).is_err());
        assert!(FecRepairFrame::decode(&repair).is_ok());
    }
}
