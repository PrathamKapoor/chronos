//! Leopard-RS SIMD erasure coding of handshake CRYPTO payloads.
//!
//! `reed-solomon-simd` hard-requires a non-zero **even** shard length; ChronosMTC additionally
//! rounds every shard up to a 64-byte multiple so the coder stays on its full-chunk SIMD path and no
//! tail encoding is needed. The original payload length travels in the `FEC_SOURCE` header, so the
//! receiver strips the padding exactly.
//!
//! Wire discipline that this module enforces:
//!
//! * every shard is CRC32c-tagged and a shard that fails its tag **never** enters a decode, so a
//!   Byzantine bit flip cannot poison Galois-field reconstruction;
//! * reconstruction is indexed, not order-dependent: `FecBlockAssembler` keys shards by index, so a
//!   reordering or duplication of datagrams cannot change the result (Post-Mortem 2, ADR-012).

use super::frames::{
    FecError, FecRepairFrame, FecSourceFrame, FEC_REPAIR_HEADER_BYTES, FEC_SOURCE_HEADER_BYTES,
};
use bytes::{Bytes, BytesMut};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

/// Shard alignment, in bytes.
pub const SHARD_ALIGNMENT: usize = 64;
/// Smallest supported data shard count.
pub const MIN_DATA_SHARDS: usize = 2;
/// Largest supported data shard count.
pub const MAX_DATA_SHARDS: usize = 8;
/// Largest payload that fits in the `original_payload_len: u16` header field.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// Result alias for this module.
pub type FecResult<T> = Result<T, FecError>;

/// Rounds `length` up to the next multiple of [`SHARD_ALIGNMENT`], with a 64-byte floor.
pub fn align_shard_len(length: usize) -> usize {
    let floored = length.max(SHARD_ALIGNMENT);
    floored.div_ceil(SHARD_ALIGNMENT) * SHARD_ALIGNMENT
}

/// Validates a `(k, r)` shard configuration.
pub fn validate_shard_counts(k: usize, r: usize) -> FecResult<()> {
    if !(MIN_DATA_SHARDS..=MAX_DATA_SHARDS).contains(&k) || r > k {
        return Err(FecError::ShardConfiguration {
            k: k as u8,
            r: r as u8,
        });
    }
    Ok(())
}

/// The shard geometry for one payload, computed without encoding anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardLayout {
    /// Payload length before padding.
    pub payload_len: usize,
    /// Data shard count `k`.
    pub k: usize,
    /// Parity shard count `r`.
    pub r: usize,
    /// Aligned size of every shard.
    pub shard_len: usize,
}

impl ShardLayout {
    /// Computes the geometry for `(payload_len, k, r)`.
    pub fn new(payload_len: usize, k: usize, r: usize) -> FecResult<Self> {
        validate_shard_counts(k, r)?;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(FecError::IllegalField {
                field: "payload_len",
                value: payload_len as u64,
            });
        }
        let raw_shard = payload_len.div_ceil(k);
        let shard_len = align_shard_len(raw_shard);
        Ok(Self {
            payload_len,
            k,
            r,
            shard_len,
        })
    }

    /// Total wire bytes of the block: `(k + r)` frames, each carrying a shard plus its header.
    pub fn total_wire_bytes(&self) -> usize {
        self.k * (self.shard_len + FEC_SOURCE_HEADER_BYTES)
            + self.r * (self.shard_len + FEC_REPAIR_HEADER_BYTES)
    }

    /// Wire bytes contributed by the data shards alone.
    pub fn source_wire_bytes(&self) -> usize {
        self.k * (self.shard_len + FEC_SOURCE_HEADER_BYTES)
    }

    /// Wire bytes contributed by the parity shards.
    pub fn repair_wire_bytes(&self) -> usize {
        self.r * (self.shard_len + FEC_REPAIR_HEADER_BYTES)
    }

    /// Total wire bytes for an arbitrary payload length with the same `(k, r)`.
    pub fn total_wire_bytes_for(payload_len: usize, k: usize, r: usize) -> FecResult<usize> {
        Ok(Self::new(payload_len, k, r)?.total_wire_bytes())
    }
}

/// An encoded FEC block: the data shards and (optionally) the parity shards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedBlock {
    /// Block identifier echoed in every frame.
    pub block_id: u32,
    /// Layout used for this block.
    pub layout: ShardLayout,
    /// `FEC_SOURCE` frames in shard order.
    pub source_frames: Vec<FecSourceFrame>,
    /// `FEC_REPAIR` frames in parity order.
    pub repair_frames: Vec<FecRepairFrame>,
}

impl EncodedBlock {
    /// Total wire bytes of the block.
    pub fn total_wire_bytes(&self) -> usize {
        self.layout.total_wire_bytes()
    }
}

/// Encodes a CRYPTO payload into `k` data shards plus `r` parity shards.
///
/// The padded shard buffer is built once and sliced, so encoding performs a single allocation per
/// shard *view* rather than one `resize` per shard.
pub fn encode_block(block_id: u32, payload: &[u8], k: usize, r: usize) -> FecResult<EncodedBlock> {
    let layout = ShardLayout::new(payload.len(), k, r)?;

    // One padded buffer holding every data shard back to back.
    let mut padded = BytesMut::with_capacity(layout.shard_len * layout.k);
    padded.extend_from_slice(payload);
    padded.resize(layout.shard_len * layout.k, 0u8);
    let padded: Bytes = padded.freeze();

    let mut source_frames = Vec::with_capacity(layout.k);
    for index in 0..layout.k {
        let start = index * layout.shard_len;
        let shard = padded.slice(start..start + layout.shard_len);
        source_frames.push(FecSourceFrame::new(
            block_id,
            layout.k as u8,
            layout.r as u8,
            index as u8,
            layout.payload_len as u16,
            shard.to_vec(),
        ));
    }

    let mut repair_frames = Vec::with_capacity(layout.r);
    if layout.r > 0 {
        let mut encoder = ReedSolomonEncoder::new(layout.k, layout.r, layout.shard_len)
            .map_err(|e| FecError::ReedSolomon(format!("encoder: {e}")))?;
        for frame in &source_frames {
            encoder
                .add_original_shard(&frame.shard)
                .map_err(|e| FecError::ReedSolomon(format!("add original shard: {e}")))?;
        }
        let result = encoder
            .encode()
            .map_err(|e| FecError::ReedSolomon(format!("encode: {e}")))?;
        for index in 0..layout.r {
            let parity = result.recovery(index).ok_or_else(|| {
                FecError::ReedSolomon(format!("recovery shard {index} was not produced"))
            })?;
            repair_frames.push(FecRepairFrame::new(
                block_id,
                layout.k as u8,
                layout.r as u8,
                index as u8,
                parity.to_vec(),
            ));
        }
    }

    Ok(EncodedBlock {
        block_id,
        layout,
        source_frames,
        repair_frames,
    })
}

/// Outcome of a successful reassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyOutcome {
    /// The reconstructed payload, padding stripped.
    pub payload: Vec<u8>,
    /// Indices of data shards that had to be reconstructed from parity.
    pub recovered_shard_indices: Vec<u8>,
    /// Number of shards that arrived intact.
    pub intact_shard_count: usize,
}

/// Receiver-side accumulator for one FEC block.
#[derive(Debug, Clone)]
pub struct FecBlockAssembler {
    block_id: u32,
    k: usize,
    r: usize,
    original_payload_len: usize,
    shard_len: usize,
    sources: Vec<Option<Vec<u8>>>,
    repairs: Vec<Option<Vec<u8>>>,
    rejected_shards: usize,
}

impl FecBlockAssembler {
    /// Creates an assembler for a block.
    pub fn new(
        block_id: u32,
        k: usize,
        r: usize,
        shard_len: usize,
        original_payload_len: usize,
    ) -> FecResult<Self> {
        validate_shard_counts(k, r)?;
        Ok(Self {
            block_id,
            k,
            r,
            original_payload_len,
            shard_len,
            sources: vec![None; k],
            repairs: vec![None; r],
            rejected_shards: 0,
        })
    }

    /// Block identifier.
    pub fn block_id(&self) -> u32 {
        self.block_id
    }

    /// Number of shards that failed their CRC32c check and were discarded.
    pub fn rejected_shards(&self) -> usize {
        self.rejected_shards
    }

    /// Number of data shards received intact.
    pub fn intact_count(&self) -> usize {
        self.sources.iter().filter(|slot| slot.is_some()).count()
    }

    /// Number of parity shards received intact.
    pub fn repair_count(&self) -> usize {
        self.repairs.iter().filter(|slot| slot.is_some()).count()
    }

    /// True once `sources + repairs >= k`, i.e. the payload can be reconstructed.
    pub fn is_complete(&self) -> bool {
        self.intact_count() + self.repair_count() >= self.k
    }

    /// Offers a data shard. CRC failures are counted and discarded, never decoded.
    pub fn add_source(&mut self, frame: &FecSourceFrame) -> FecResult<()> {
        if frame.block_id != self.block_id
            || frame.data_shards as usize != self.k
            || frame.parity_shards as usize != self.r
        {
            return Err(FecError::ShardConfiguration {
                k: frame.data_shards,
                r: frame.parity_shards,
            });
        }
        if frame.shard.len() != self.shard_len {
            return Err(FecError::IllegalField {
                field: "shard_len",
                value: frame.shard.len() as u64,
            });
        }
        if frame.verify_crc().is_err() {
            self.rejected_shards += 1;
            return Ok(());
        }
        let index = frame.shard_index as usize;
        if index >= self.k {
            return Err(FecError::IllegalField {
                field: "shard_index",
                value: u64::from(frame.shard_index),
            });
        }
        self.sources[index] = Some(frame.shard.clone());
        Ok(())
    }

    /// Offers a parity shard. CRC failures are counted and discarded, never decoded.
    pub fn add_repair(&mut self, frame: &FecRepairFrame) -> FecResult<()> {
        if frame.block_id != self.block_id
            || frame.data_shards as usize != self.k
            || frame.parity_shards as usize != self.r
        {
            return Err(FecError::ShardConfiguration {
                k: frame.data_shards,
                r: frame.parity_shards,
            });
        }
        if frame.verify_crc().is_err() {
            self.rejected_shards += 1;
            return Ok(());
        }
        let index = frame.parity_index as usize;
        if index >= self.r {
            return Err(FecError::IllegalField {
                field: "parity_index",
                value: u64::from(frame.parity_index),
            });
        }
        self.repairs[index] = Some(frame.parity.clone());
        Ok(())
    }

    /// Reassembles the payload, reconstructing any missing data shards from parity.
    pub fn assemble(&self) -> FecResult<AssemblyOutcome> {
        if !self.is_complete() {
            return Err(FecError::ReedSolomon(format!(
                "not enough shards: {} sources + {} repairs < {}",
                self.intact_count(),
                self.repair_count(),
                self.k
            )));
        }

        let intact = self.intact_count();
        let mut recovered = Vec::new();

        if intact == self.k {
            // Fast path: everything arrived, concatenate in index order.
            let mut payload = Vec::with_capacity(self.shard_len * self.k);
            for slot in &self.sources {
                payload.extend_from_slice(slot.as_ref().expect("all sources present"));
            }
            payload.truncate(self.original_payload_len);
            return Ok(AssemblyOutcome {
                payload,
                recovered_shard_indices: recovered,
                intact_shard_count: intact,
            });
        }

        let mut decoder = ReedSolomonDecoder::new(self.k, self.r, self.shard_len)
            .map_err(|e| FecError::ReedSolomon(format!("decoder: {e}")))?;
        for (index, slot) in self.sources.iter().enumerate() {
            if let Some(shard) = slot {
                decoder
                    .add_original_shard(index, shard)
                    .map_err(|e| FecError::ReedSolomon(format!("add original {index}: {e}")))?;
            }
        }
        for (index, slot) in self.repairs.iter().enumerate() {
            if let Some(shard) = slot {
                decoder
                    .add_recovery_shard(index, shard)
                    .map_err(|e| FecError::ReedSolomon(format!("add recovery {index}: {e}")))?;
            }
        }

        let result = decoder
            .decode()
            .map_err(|e| FecError::ReedSolomon(format!("decode: {e}")))?;

        let mut payload = Vec::with_capacity(self.shard_len * self.k);
        for index in 0..self.k {
            match &self.sources[index] {
                Some(shard) => payload.extend_from_slice(shard),
                None => {
                    let restored = result.restored_original(index).ok_or_else(|| {
                        FecError::ReedSolomon(format!("shard {index} was not reconstructed"))
                    })?;
                    payload.extend_from_slice(restored);
                    recovered.push(index as u8);
                }
            }
        }
        payload.truncate(self.original_payload_len);

        Ok(AssemblyOutcome {
            payload,
            recovered_shard_indices: recovered,
            intact_shard_count: intact,
        })
    }
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::*;

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn assembler_for(block: &EncodedBlock) -> FecBlockAssembler {
        FecBlockAssembler::new(
            block.block_id,
            block.layout.k,
            block.layout.r,
            block.layout.shard_len,
            block.layout.payload_len,
        )
        .unwrap()
    }

    #[test]
    fn shard_alignment_is_respected() {
        assert_eq!(align_shard_len(1), 64);
        assert_eq!(align_shard_len(64), 64);
        assert_eq!(align_shard_len(65), 128);
        assert_eq!(align_shard_len(988), 1024);
        for len in 1..2_000usize {
            assert!(align_shard_len(len).is_multiple_of(SHARD_ALIGNMENT));
            assert!(align_shard_len(len) >= len);
        }
    }

    #[test]
    fn layout_rejects_illegal_configurations() {
        assert!(ShardLayout::new(100, 1, 0).is_err(), "k < 2");
        assert!(ShardLayout::new(100, 9, 0).is_err(), "k > 8");
        assert!(ShardLayout::new(100, 2, 3).is_err(), "r > k");
        assert!(ShardLayout::new(70_000, 2, 0).is_err(), "payload too large");
        let layout = ShardLayout::new(1_976, 2, 1).unwrap();
        assert_eq!(layout.shard_len, 1024);
        assert_eq!(
            layout.total_wire_bytes(),
            3 * (1024 + FEC_SOURCE_HEADER_BYTES)
        );
    }

    #[test]
    fn every_configuration_recovers_exactly_r_losses() {
        for k in MIN_DATA_SHARDS..=MAX_DATA_SHARDS {
            for r in 0..=k {
                let data = payload(64 * k + 17);
                let block = encode_block(11, &data, k, r).unwrap();
                assert_eq!(block.source_frames.len(), k);
                assert_eq!(block.repair_frames.len(), r);

                for lost in 0..=r {
                    let mut assembler = assembler_for(&block);
                    let mut lost_indices = Vec::new();
                    for index in 0..k {
                        if lost_indices.len() == lost {
                            break;
                        }
                        lost_indices.push(index);
                    }
                    // Offer repairs first so lost data shards are the only gap.
                    for frame in &block.repair_frames {
                        assembler.add_repair(frame).unwrap();
                    }
                    for (index, frame) in block.source_frames.iter().enumerate() {
                        if lost_indices.contains(&index) {
                            continue;
                        }
                        assembler.add_source(frame).unwrap();
                    }
                    assert!(assembler.is_complete(), "k={k} r={r} lost={lost}");
                    let outcome = assembler.assemble().unwrap();
                    assert_eq!(outcome.payload, data, "k={k} r={r} lost={lost}");
                    assert_eq!(outcome.recovered_shard_indices.len(), lost);
                }
            }
        }
    }

    #[test]
    fn too_few_shards_is_an_error_not_a_silent_truncation() {
        let data = payload(1_000);
        let block = encode_block(1, &data, 4, 2).unwrap();
        let mut assembler = assembler_for(&block);
        assembler.add_source(&block.source_frames[0]).unwrap();
        assembler.add_repair(&block.repair_frames[0]).unwrap();
        assert!(!assembler.is_complete());
        assert!(assembler.assemble().is_err());
    }

    #[test]
    fn corrupted_shards_never_enter_a_decode() {
        let data = payload(2_000);
        let block = encode_block(2, &data, 4, 2).unwrap();

        // Corrupt one data shard and one parity shard: the corrupted data shard is dropped, and the
        // remaining parity still reconstructs it.
        let mut assembler = assembler_for(&block);
        let mut corrupted_source = block.source_frames[1].clone();
        corrupted_source.shard[0] ^= 0xFF;
        assembler.add_source(&corrupted_source).unwrap();
        for index in [0usize, 2, 3] {
            assembler.add_source(&block.source_frames[index]).unwrap();
        }
        let mut corrupted_repair = block.repair_frames[0].clone();
        corrupted_repair.parity[5] ^= 0x01;
        assembler.add_repair(&corrupted_repair).unwrap();
        assembler.add_repair(&block.repair_frames[1]).unwrap();

        assert_eq!(assembler.rejected_shards(), 2);
        assert!(assembler.is_complete());
        let outcome = assembler.assemble().unwrap();
        assert_eq!(outcome.payload, data);
        assert_eq!(outcome.recovered_shard_indices, vec![1]);
    }

    #[test]
    fn assembler_rejects_mismatched_blocks_and_shard_sizes() {
        let block = encode_block(5, &payload(500), 2, 1).unwrap();
        let mut assembler = assembler_for(&block);

        let mut foreign = block.source_frames[0].clone();
        foreign.block_id = 6;
        assert!(assembler.add_source(&foreign).is_err());

        let mut wrong_shape = block.source_frames[0].clone();
        wrong_shape.data_shards = 3;
        assert!(assembler.add_source(&wrong_shape).is_err());

        let mut wrong_len = block.source_frames[0].clone();
        wrong_len.shard.truncate(32);
        wrong_len.crc32c = crc32fast::hash(&wrong_len.shard);
        assert!(assembler.add_source(&wrong_len).is_err());

        let mut bad_index = block.source_frames[0].clone();
        bad_index.shard_index = 5;
        assert!(assembler.add_source(&bad_index).is_err());
    }

    #[test]
    fn frames_round_trip_through_the_wire_format() {
        let data = payload(3_000);
        let block = encode_block(9, &data, 4, 2).unwrap();

        let mut assembler = FecBlockAssembler::new(
            block.block_id,
            block.layout.k,
            block.layout.r,
            block.layout.shard_len,
            block.layout.payload_len,
        )
        .unwrap();

        // Round trip every frame through its wire encoding, and deliver in reverse order to prove
        // that arrival order is irrelevant.
        let mut encoded_sources: Vec<Vec<u8>> = block
            .source_frames
            .iter()
            .map(|frame| frame.encode())
            .collect();
        let mut encoded_repairs: Vec<Vec<u8>> = block
            .repair_frames
            .iter()
            .map(|frame| frame.encode())
            .collect();
        encoded_sources.reverse();
        encoded_repairs.reverse();

        for bytes in &encoded_repairs {
            assembler
                .add_repair(&FecRepairFrame::decode(bytes).unwrap())
                .unwrap();
        }
        for bytes in &encoded_sources {
            assembler
                .add_source(&FecSourceFrame::decode(bytes).unwrap())
                .unwrap();
        }

        let outcome = assembler.assemble().unwrap();
        assert_eq!(outcome.payload, data);
        assert!(outcome.intact_shard_count >= 2);
    }
}
