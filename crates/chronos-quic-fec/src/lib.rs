//! # chronos-quic-fec
//!
//! The wire-budget and loss-resilience half of ChronosMTC:
//!
//! * [`budget`] — the RFC 9000 §8.1 3× anti-amplification Flight 1 planner, which searches
//!   `(k, r)` for the cheapest handshake flight that fits `3 · B_rx` and chooses between a
//!   landmark-relative proof, an in-band O(log N) skip-link delta, and a stateless Retry followed by
//!   a Standalone MTC.
//! * [`fec_coder`] — Leopard-RS SIMD (`reed-solomon-simd`) erasure coding of Flight 1 CRYPTO with
//!   64-byte aligned shards, CRC32c shard tags, and index-keyed reassembly that is immune to
//!   datagram reordering.
//! * [`frames`] — the three custom QUIC frames: `FEC_SOURCE` (0x3f51), `FEC_REPAIR` (0x3f52) and
//!   `FEC_RECOVERED` (0x3f53), the last of which keeps recovered packets visible to the RFC 9002 loss
//!   detector instead of hiding them.
//!
//! The crate is `#![forbid(unsafe_code)]`; the SIMD work happens inside `reed-solomon-simd`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod budget;
pub mod fec_coder;
pub mod frames;

pub use budget::{
    AmplificationPlanner, BudgetError, Flight1Mode, Flight1Plan, AMPLIFICATION_FACTOR,
    LANDMARK_MTC_PROOF_BYTES, QUIC_MIN_INITIAL_BYTES, RETRY_TOKEN_BYTES, SERVER_HELLO_PQC_BYTES,
    STANDALONE_MTC_PROOF_BYTES,
};
pub use fec_coder::{
    align_shard_len, encode_block, AssemblyOutcome, EncodedBlock, FecBlockAssembler, FecResult,
    ShardLayout, MAX_DATA_SHARDS, MIN_DATA_SHARDS, SHARD_ALIGNMENT,
};
pub use frames::{
    decode_varint, encode_varint, FecError, FecRecoveredFrame, FecRepairFrame, FecSourceFrame,
    FEC_RECOVERED, FEC_REPAIR, FEC_SOURCE,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_flight1_recovers_from_parity() {
        // Plan a stale-client flight at 3 % loss, then actually encode, lose parity-covered shards
        // and reassemble: the budget decision and the coder are checked against each other.
        let plan = AmplificationPlanner::new()
            .plan_flight1(1_200, 0, Some(0), 10_000, 10_000, 0.03)
            .expect("plan");
        assert!(plan.total_flight1_wire_bytes <= plan.credit);

        let payload: Vec<u8> = (0..plan.data_bytes).map(|i| (i % 253) as u8).collect();
        let block = encode_block(1, &payload, plan.k, plan.r).expect("encode");
        assert_eq!(block.total_wire_bytes(), plan.total_flight1_wire_bytes);

        let mut assembler = FecBlockAssembler::new(
            block.block_id,
            block.layout.k,
            block.layout.r,
            block.layout.shard_len,
            block.layout.payload_len,
        )
        .expect("assembler");

        // Lose the first `r` data shards; parity must cover exactly that many losses.
        for frame in &block.repair_frames {
            assembler.add_repair(frame).expect("repair");
        }
        for (index, frame) in block.source_frames.iter().enumerate() {
            if index >= plan.r {
                assembler.add_source(frame).expect("source");
            }
        }
        let outcome = assembler.assemble().expect("assemble");
        assert_eq!(outcome.payload, payload);
        assert_eq!(outcome.recovered_shard_indices.len(), plan.r);

        // The congestion signal names the reconstructed packets.
        let recovered = FecRecoveredFrame::new(block.block_id, vec![11, 12, 13]);
        let decoded = FecRecoveredFrame::decode(&recovered.encode()).expect("decode");
        assert_eq!(decoded, recovered);
    }
}
