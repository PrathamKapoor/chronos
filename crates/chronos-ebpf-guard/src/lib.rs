//! # chronos-ebpf-guard
//!
//! The downgrade guard: a bounded QUIC Initial sensor, a three-state policy matrix, ML-DSA-65 signed
//! alerts and a multishot Merkle verification batch.
//!
//! ## Why
//!
//! During a hybrid PQC migration an on-path attacker can drop fragmented PQC flights while letting
//! single-packet classical handshakes through. Nothing breaks; peers are silently downgraded
//! (`draft-gray-plants-mtc-deploy-use-cases-01` §3.6.1–3.6.4). The guard makes that observable and
//! enforces policy on the ingress path:
//!
//! | Rule | Condition | Verdict |
//! |---|---|---|
//! | 1 | `PqOnly` and no PQ key exchange offered | `AlgorithmDowngrade` |
//! | 2 | freeze record and issuance timestamp above it (missing ⇒ maximally recent) | `UnauthorizedIssuanceAfterFreeze` |
//! | 3 | `Hybrid`, no PQ offer, ≥ 5 PQ attempts, `drops × 10 >= attempts × 4` | `SelectiveFragmentDropAttack` |
//! | — | otherwise | `PassToBatchRing` |
//!
//! ## Shape
//!
//! * [`parser::parse_quic_initial_256b`] reads **at most 256 bytes** and returns bounded windows; it
//!   cannot be made to walk off the end of attacker-controlled data.
//! * [`policy`] classifies the signals visible without decryption (the X25519MLKEM768 group code
//!   point, the `trust_anchors` extension, the plaintext checkpoint hint) and evaluates the matrix in
//!   fixed-width integers — no floating point on the hot path.
//! * [`rings`] never grows: 64 alerts and 64 datagrams of 1,500 B, with explicit drop counters.
//! * [`kernel`] holds the eBPF program and the userspace pipeline that runs identical logic.
//!
//! The crate is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod kernel;
pub mod parser;
pub mod policy;
pub mod rings;

pub use kernel::{GuardConfig, PipelineOutcome, UserspaceGuard};
pub use parser::{
    parse_quic_initial_256b, CryptoWindow, MtcCheckpointHint, ParseError, QuicInitialSummary,
    MAX_CRYPTO_WINDOWS, MAX_EBPF_INSPECT_BYTES,
};
pub use policy::{
    alert_payload, classify, evaluate_packet, FrozenDeviceRecord, MigrationPhase, MonitorAlert,
    PacketClassification, PacketVerdict, PeerAddr, PeerCounters, VerdictCode, PQC_KEM_PATTERN,
    TRUST_ANCHORS_PATTERN,
};
pub use rings::{
    BatchVerifyStats, InclusionInputs, MonitorAlertRing, MultishotVerifyRing, QueuedPacket,
    RingError, ALERT_RING_CAPACITY, MAX_PACKET_BYTES, VERIFY_RING_SLOTS,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a QUIC v1 Initial carrying `payload` in a CRYPTO frame.
    fn initial(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0xC0 | 0x03];
        out.extend_from_slice(&1u32.to_be_bytes());
        out.push(4);
        out.extend_from_slice(b"dcid");
        out.push(4);
        out.extend_from_slice(b"scid");
        out.push(0x00);
        let length = 4 + 2 + payload.len();
        out.extend_from_slice(&(((length as u16) | 0x4000).to_be_bytes()));
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.push(0x06);
        out.push(0x00);
        out.push((payload.len() as u8) | 0x40);
        out.push((payload.len() >> 8) as u8);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn end_to_end_downgrade_is_caught_and_alerted() {
        let peer = PeerAddr {
            ip: [192, 0, 2, 1],
            port: 4433,
        };
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::PqOnly));

        let classical = initial(b"client hello without pq");
        let outcome = guard.inspect(&classical, peer, 1_700_000_000_000_000_000);
        assert_eq!(
            outcome.verdict.code(),
            Some(VerdictCode::AlgorithmDowngrade)
        );

        let mut payload = b"client hello with pq".to_vec();
        payload.extend_from_slice(&PQC_KEM_PATTERN);
        let outcome = guard.inspect(&initial(&payload), peer, 1);
        assert!(!outcome.verdict.is_drop(), "a PQ handshake must pass");

        assert_eq!(guard.passed(), 1);
        assert_eq!(guard.dropped(), 1);
        assert_eq!(guard.alerts().len(), 1);
        assert_eq!(guard.alerts().entries().front().unwrap().peer, peer);
    }

    #[test]
    fn the_public_surface_is_the_one_the_simulator_needs() {
        let datagram = initial(b"hello");
        let summary = parse_quic_initial_256b(&datagram).expect("parse");
        let classification = classify(&summary, &datagram);
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::PqOnly,
            None,
            PeerCounters::default(),
            PeerAddr {
                ip: [10, 0, 0, 1],
                port: 1,
            },
            0,
        );
        assert!(verdict.is_drop());

        let ring = MultishotVerifyRing::new();
        assert_eq!(ring.available(), VERIFY_RING_SLOTS);
        assert!(MonitorAlertRing::new().is_empty());
    }
}
