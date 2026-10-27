//! Classification and the three-state downgrade policy.
//!
//! During a hybrid PQC migration an on-path attacker can drop fragmented PQC flights while letting
//! single-packet classical handshakes through, which downgrades peers without ever breaking a
//! handshake (`draft-gray-plants-mtc-deploy-use-cases-01` §3.6.1–3.6.4). The policy below turns that
//! into three explicit rules over data visible in the first 256 bytes of a QUIC Initial.

use super::parser::{QuicInitialSummary, MAX_EBPF_INSPECT_BYTES};
#[cfg(chronos_bundled)]
use crate::chronos_pqc_sys;
#[cfg(chronos_bundled)]
use crate::chronos_pqc_sys::{
    ml_dsa_65_sign, ml_dsa_65_verify, ExternalMuHasher, MlDsa65PublicKey, MlDsa65SecretKey,
};
#[cfg(not(chronos_bundled))]
use chronos_pqc_sys::{
    ml_dsa_65_sign, ml_dsa_65_verify, ExternalMuHasher, MlDsa65PublicKey, MlDsa65SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Two-byte pattern of the X25519MLKEM768 TLS group (`0x11EC`).
pub const PQC_KEM_PATTERN: [u8; 2] = [0x11, 0xEC];
/// Two-byte pattern of the `trust_anchors` extension (`0x003B`).
pub const TRUST_ANCHORS_PATTERN: [u8; 2] = [0x00, 0x3B];
/// Domain separator for `MonitorAlert` signatures.
pub const MONITOR_ALERT_CONTEXT: &[u8] = b"monitor/v1\n\0";
/// Fraction numerator for the selective-drop rule: 40 % of fragments vanished.
pub const SELECTIVE_DROP_NUMERATOR: u32 = 4;
/// Fraction denominator for the selective-drop rule (10 × numerator ⇒ 40 %).
pub const SELECTIVE_DROP_DENOMINATOR: u32 = 10;
/// Minimum PQC attempts before the selective-drop heuristic may fire.
pub const MIN_PQC_ATTEMPTS_FOR_HEURISTIC: u32 = 5;

/// Deployment phase of a monitored device or network segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationPhase {
    /// Classical key exchange only; nothing is enforced yet.
    ClassicalOnly,
    /// Both classical and PQ handshakes are accepted.
    Hybrid,
    /// Only PQ handshakes are accepted; a classical one is a downgrade.
    PqOnly,
}

/// A freeze record: after `freeze_timestamp` no certificate may be issued.
///
/// Absence of an issuance timestamp is treated as *maximally recent*, because "issued after the
/// freeze" must fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenDeviceRecord {
    /// Microseconds since the Unix epoch.
    pub freeze_timestamp: u64,
}

/// Per-peer counters feeding the selective-fragment-drop heuristic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCounters {
    /// Handshakes in which this peer offered a PQ key exchange.
    pub pqc_attempts: u32,
    /// Handshakes in which this peer fell back to a classical-only exchange.
    pub classical_fallbacks: u32,
    /// PQC fragments that vanished before reassembly.
    pub pqc_fragment_drops: u32,
}

/// IPv4 peer identity used in verdicts and alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerAddr {
    /// IPv4 address.
    pub ip: [u8; 4],
    /// UDP port.
    pub port: u16,
}

/// What the bounded parser could determine about one datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketClassification {
    /// The datagram offered X25519MLKEM768.
    pub offers_pqc_kem: bool,
    /// The datagram carried the `trust_anchors` extension.
    pub offers_mtc_trust_anchor: bool,
    /// Compressed certificate serial, when the client appended a checkpoint hint.
    pub cert_serial: Option<u64>,
    /// Certificate issuance timestamp in microseconds, when hinted.
    pub cert_issuance_timestamp: Option<u64>,
    /// SHA-256 over the inspected window.
    pub packet_digest: [u8; 32],
}

/// Why a datagram was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictCode {
    /// The packet was not a well-formed QUIC Initial.
    MalformedInitial,
    /// `PqOnly` was in force and the client offered no PQ key exchange.
    AlgorithmDowngrade,
    /// The certificate was issued after the freeze timestamp.
    UnauthorizedIssuanceAfterFreeze,
    /// ≥ 40 % of this peer's PQC fragments vanished while classical handshakes still completed.
    SelectiveFragmentDropAttack,
}

impl VerdictCode {
    /// Wire code carried in the signed alert.
    pub fn code(&self) -> u16 {
        match self {
            Self::MalformedInitial => 1,
            Self::AlgorithmDowngrade => 2,
            Self::UnauthorizedIssuanceAfterFreeze => 3,
            Self::SelectiveFragmentDropAttack => 4,
        }
    }

    /// Human-readable label for logs and the CLI scorecard.
    pub fn label(&self) -> &'static str {
        match self {
            Self::MalformedInitial => "MalformedInitial",
            Self::AlgorithmDowngrade => "AlgorithmDowngrade",
            Self::UnauthorizedIssuanceAfterFreeze => "UnauthorizedIssuanceAfterFreeze",
            Self::SelectiveFragmentDropAttack => "SelectiveFragmentDropAttack",
        }
    }
}

/// The guard's decision for one datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketVerdict {
    /// Forward the datagram and queue the MTC proof for batch verification.
    PassToBatchRing {
        /// Bounded CRYPTO windows the batch stage should look at.
        crypto_windows: usize,
        /// Whether a PQ key exchange was offered.
        offers_pqc_kem: bool,
    },
    /// Drop the datagram; a signed alert accompanies the drop.
    Drop {
        /// Why it was dropped.
        code: VerdictCode,
        /// The plaintext alert payload to sign and record.
        alert: MonitorAlert,
    },
}

impl PacketVerdict {
    /// True when the packet was dropped.
    pub fn is_drop(&self) -> bool {
        matches!(self, Self::Drop { .. })
    }

    /// The verdict code, when the packet was dropped.
    pub fn code(&self) -> Option<VerdictCode> {
        match self {
            Self::Drop { code, .. } => Some(*code),
            Self::PassToBatchRing { .. } => None,
        }
    }
}

/// Classifies one bounded datagram view.
///
/// The signals are searched inside the CRYPTO windows, because that is where the TLS ClientHello
/// lives. If the packet carried no CRYPTO frame inside the window (a fragmented first flight, for
/// example), the whole inspected window is searched instead — a fragment of the handshake is still
/// evidence, and the digest always covers exactly the bytes that were inspected.
pub fn classify(summary: &QuicInitialSummary, inspected: &[u8]) -> PacketClassification {
    let window = &inspected[..inspected.len().min(MAX_EBPF_INSPECT_BYTES)];

    let search_ranges: Vec<(usize, usize)> = if summary.crypto_windows.is_empty() {
        vec![(0, window.len())]
    } else {
        summary
            .crypto_windows
            .iter()
            .map(|crypto| (crypto.offset, crypto.offset + crypto.len))
            .filter(|(start, end)| *start <= window.len() && *end <= window.len())
            .collect()
    };

    let mut offers_pqc_kem = false;
    let mut offers_mtc_trust_anchor = false;
    for (start, end) in search_ranges {
        if let Some(bytes) = window.get(start..end) {
            offers_pqc_kem |= contains(bytes, &PQC_KEM_PATTERN);
            offers_mtc_trust_anchor |= contains(bytes, &TRUST_ANCHORS_PATTERN);
        }
    }

    let hint = summary.checkpoint_hint(inspected);

    PacketClassification {
        offers_pqc_kem,
        offers_mtc_trust_anchor,
        cert_serial: hint.map(|hint| hint.serial),
        cert_issuance_timestamp: hint.map(|hint| hint.issuance_timestamp),
        packet_digest: Sha256::digest(window).into(),
    }
}

/// True when `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Evaluates the three-state policy matrix.
///
/// ```text
/// Rule 1  phase == PqOnly  && !offers_pqc_kem                  -> Drop(AlgorithmDowngrade)
/// Rule 2  phase has a freeze record && issuance > freeze        -> Drop(UnauthorizedIssuanceAfterFreeze)
/// Rule 3  phase == Hybrid && !offers_pqc_kem && attempts >= 5
///         && drops * 10 >= attempts * 4                          -> Drop(SelectiveFragmentDropAttack)
/// otherwise                                                      -> PassToBatchRing
/// ```
///
/// Rule 3 is written in fixed-width integers: `drops × 10 >= attempts × 4` is "at least 40 % of this
/// peer's PQC fragments vanished while at least one classical fallback appeared", evaluated with no
/// floating point on the hot path.
pub fn evaluate_packet(
    classification: &PacketClassification,
    phase: MigrationPhase,
    frozen: Option<FrozenDeviceRecord>,
    counters: PeerCounters,
    peer: PeerAddr,
    timestamp_ns: u64,
) -> PacketVerdict {
    if phase == MigrationPhase::PqOnly && !classification.offers_pqc_kem {
        return drop(
            VerdictCode::AlgorithmDowngrade,
            classification,
            peer,
            timestamp_ns,
        );
    }

    if let Some(record) = frozen {
        let issuance = classification.cert_issuance_timestamp.unwrap_or(u64::MAX);
        if issuance > record.freeze_timestamp {
            return drop(
                VerdictCode::UnauthorizedIssuanceAfterFreeze,
                classification,
                peer,
                timestamp_ns,
            );
        }
    }

    if phase == MigrationPhase::Hybrid
        && !classification.offers_pqc_kem
        && counters.pqc_attempts >= MIN_PQC_ATTEMPTS_FOR_HEURISTIC
        && counters
            .pqc_fragment_drops
            .saturating_mul(SELECTIVE_DROP_DENOMINATOR)
            >= counters
                .pqc_attempts
                .saturating_mul(SELECTIVE_DROP_NUMERATOR)
    {
        return drop(
            VerdictCode::SelectiveFragmentDropAttack,
            classification,
            peer,
            timestamp_ns,
        );
    }

    PacketVerdict::PassToBatchRing {
        crypto_windows: classification.cert_serial.is_some() as usize,
        offers_pqc_kem: classification.offers_pqc_kem,
    }
}

/// Builds a drop verdict with an unsigned alert; the caller signs it.
fn drop(
    code: VerdictCode,
    classification: &PacketClassification,
    peer: PeerAddr,
    timestamp_ns: u64,
) -> PacketVerdict {
    PacketVerdict::Drop {
        code,
        alert: MonitorAlert {
            code: code.code(),
            peer,
            timestamp_ns,
            packet_digest: classification.packet_digest,
            signature: Vec::new(),
        },
    }
}

/// The exact message a `MonitorAlert` signature covers.
pub fn alert_payload(
    code: u16,
    peer: PeerAddr,
    timestamp_ns: u64,
    packet_digest: &[u8; 32],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(MONITOR_ALERT_CONTEXT.len() + 4 + 6 + 8 + 32);
    payload.extend_from_slice(MONITOR_ALERT_CONTEXT);
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(&peer.ip);
    payload.extend_from_slice(&peer.port.to_be_bytes());
    payload.extend_from_slice(&timestamp_ns.to_be_bytes());
    payload.extend_from_slice(packet_digest);
    payload
}

/// A monitor alert about a dropped datagram, signed with ML-DSA-65.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorAlert {
    /// [`VerdictCode::code`].
    pub code: u16,
    /// Peer the alert concerns.
    pub peer: PeerAddr,
    /// When the drop happened (nanoseconds since the Unix epoch).
    pub timestamp_ns: u64,
    /// SHA-256 of the inspected window.
    pub packet_digest: [u8; 32],
    /// ML-DSA-65 signature over [`alert_payload`].
    pub signature: Vec<u8>,
}

impl MonitorAlert {
    /// Signs the alert in place with the monitor's ML-DSA-65 key.
    pub fn sign(&mut self, key: &MlDsa65SecretKey, public_key: &MlDsa65PublicKey) {
        let tr = public_key.key_hash();
        let payload = alert_payload(self.code, self.peer, self.timestamp_ns, &self.packet_digest);
        let mu = ExternalMuHasher::digest(&tr, MONITOR_ALERT_CONTEXT, &payload)
            .expect("the alert context is 13 bytes, well under the 255-byte FIPS 204 limit");
        self.signature = ml_dsa_65_sign(key, &mu).as_bytes().to_vec();
    }

    /// Verifies the alert signature against the monitor's public key.
    pub fn verify(&self, public_key: &MlDsa65PublicKey) -> bool {
        let tr = public_key.key_hash();
        let payload = alert_payload(self.code, self.peer, self.timestamp_ns, &self.packet_digest);
        let Ok(mu) = ExternalMuHasher::digest(&tr, MONITOR_ALERT_CONTEXT, &payload) else {
            return false;
        };
        let Ok(signature) = parse_signature(&self.signature) else {
            return false;
        };
        ml_dsa_65_verify(public_key, &mu, &signature)
    }
}

/// Rebuilds a signature object from raw bytes for verification.
fn parse_signature(bytes: &[u8]) -> Result<chronos_pqc_sys::MlDsa65Signature, ()> {
    let array: [u8; chronos_pqc_sys::ML_DSA_65_SIGNATURE_LEN] = bytes.try_into().map_err(|_| ())?;
    Ok(chronos_pqc_sys::MlDsa65Signature::from_bytes(array))
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::super::parser::parse_quic_initial_256b;
    use super::*;
    use chronos_pqc_sys::ml_dsa_65_keygen;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn peer() -> PeerAddr {
        PeerAddr {
            ip: [203, 0, 113, 7],
            port: 4433,
        }
    }

    fn initial_with_crypto(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0xC0 | 0x03);
        out.extend_from_slice(&1u32.to_be_bytes());
        out.push(4);
        out.extend_from_slice(b"dcid");
        out.push(4);
        out.extend_from_slice(b"scid");
        out.push(0x00);
        out.push(0x00); // length varint (unused by the fast path beyond the PN)
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.push(0x06);
        out.push(0x00);
        out.push((payload.len() as u8) | 0x40);
        out.push((payload.len() >> 8) as u8);
        out.extend_from_slice(payload);
        out
    }

    fn classification_for(payload: &[u8]) -> PacketClassification {
        let datagram = initial_with_crypto(payload);
        let summary = parse_quic_initial_256b(&datagram).expect("well-formed Initial");
        classify(&summary, &datagram)
    }

    fn counters(attempts: u32, drops: u32) -> PeerCounters {
        PeerCounters {
            pqc_attempts: attempts,
            classical_fallbacks: 1,
            pqc_fragment_drops: drops,
        }
    }

    #[test]
    fn classification_sees_the_pq_group_and_trust_anchors() {
        let mut payload = b"client hello".to_vec();
        payload.extend_from_slice(&PQC_KEM_PATTERN);
        payload.extend_from_slice(&TRUST_ANCHORS_PATTERN);

        let classification = classification_for(&payload);
        assert!(classification.offers_pqc_kem);
        assert!(classification.offers_mtc_trust_anchor);
        assert_eq!(classification.cert_serial, None);
        assert_eq!(classification.packet_digest.len(), 32);
    }

    #[test]
    fn classification_is_absent_when_the_signals_are() {
        let classification = classification_for(b"classical client hello");
        assert!(!classification.offers_pqc_kem);
        assert!(!classification.offers_mtc_trust_anchor);
    }

    #[test]
    fn pq_only_phase_drops_classical_handshakes() {
        let classification = classification_for(b"classical only");
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::PqOnly,
            None,
            PeerCounters::default(),
            peer(),
            1,
        );
        assert_eq!(verdict.code(), Some(VerdictCode::AlgorithmDowngrade));
        assert!(verdict.is_drop());
    }

    #[test]
    fn pq_only_phase_passes_pq_handshakes() {
        let mut payload = b"hybrid hello".to_vec();
        payload.extend_from_slice(&PQC_KEM_PATTERN);
        let classification = classification_for(&payload);

        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::PqOnly,
            None,
            PeerCounters::default(),
            peer(),
            1,
        );
        assert!(!verdict.is_drop());
        assert!(matches!(
            verdict,
            PacketVerdict::PassToBatchRing {
                offers_pqc_kem: true,
                ..
            }
        ));
    }

    #[test]
    fn classical_only_phase_never_drops() {
        let classification = classification_for(b"classical only");
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::ClassicalOnly,
            None,
            counters(1_000, 1_000),
            peer(),
            1,
        );
        assert!(!verdict.is_drop(), "ClassicalOnly enforces nothing");
    }

    #[test]
    fn freeze_record_rejects_late_issuance() {
        let frozen = FrozenDeviceRecord {
            freeze_timestamp: 1_700_000_000_000,
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(&PQC_KEM_PATTERN);
        payload.extend_from_slice(&super::super::parser::MTC_HINT_MAGIC);
        payload.push(super::super::parser::MTC_HINT_VERSION);
        payload.extend_from_slice(&[0u8; 6]); // serial
        payload.extend_from_slice(&(frozen.freeze_timestamp + 1).to_be_bytes()[2..]);

        let classification = classification_for(&payload);
        assert_eq!(
            classification.cert_issuance_timestamp,
            Some(frozen.freeze_timestamp + 1)
        );
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::Hybrid,
            Some(frozen),
            PeerCounters::default(),
            peer(),
            1,
        );
        assert_eq!(
            verdict.code(),
            Some(VerdictCode::UnauthorizedIssuanceAfterFreeze)
        );
    }

    #[test]
    fn a_missing_timestamp_fails_closed_against_a_freeze() {
        let frozen = FrozenDeviceRecord {
            freeze_timestamp: 1_700_000_000_000,
        };
        let classification = classification_for(b"no hint at all");
        assert_eq!(classification.cert_issuance_timestamp, None);

        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::Hybrid,
            Some(frozen),
            PeerCounters::default(),
            peer(),
            1,
        );
        assert_eq!(
            verdict.code(),
            Some(VerdictCode::UnauthorizedIssuanceAfterFreeze),
            "unknown issuance must be treated as maximally recent"
        );
    }

    #[test]
    fn pre_freeze_issuance_passes() {
        let frozen = FrozenDeviceRecord {
            freeze_timestamp: 1_700_000_000_000,
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(&PQC_KEM_PATTERN);
        payload.extend_from_slice(&super::super::parser::MTC_HINT_MAGIC);
        payload.push(super::super::parser::MTC_HINT_VERSION);
        payload.extend_from_slice(&[0u8; 6]);
        payload.extend_from_slice(&(frozen.freeze_timestamp - 1_000).to_be_bytes()[2..]);

        let classification = classification_for(&payload);
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::Hybrid,
            Some(frozen),
            PeerCounters::default(),
            peer(),
            1,
        );
        assert!(!verdict.is_drop());
    }

    #[test]
    fn selective_fragment_drop_needs_enough_evidence() {
        let classification = classification_for(b"classical only");

        // Below the attempt threshold: pass.
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::Hybrid,
            None,
            counters(4, 4),
            peer(),
            1,
        );
        assert!(!verdict.is_drop(), "fewer than 5 attempts is not evidence");

        // 5 attempts, 2 drops = 40 % exactly: drop.
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::Hybrid,
            None,
            counters(5, 2),
            peer(),
            1,
        );
        assert_eq!(
            verdict.code(),
            Some(VerdictCode::SelectiveFragmentDropAttack)
        );

        // 5 attempts, 1 drop = 20 %: pass.
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::Hybrid,
            None,
            counters(5, 1),
            peer(),
            1,
        );
        assert!(!verdict.is_drop());
    }

    #[test]
    fn selective_drop_does_not_fire_when_the_peer_offers_pqc() {
        let mut payload = b"hybrid hello".to_vec();
        payload.extend_from_slice(&PQC_KEM_PATTERN);
        let classification = classification_for(&payload);
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::Hybrid,
            None,
            counters(1_000, 1_000),
            peer(),
            1,
        );
        assert!(!verdict.is_drop());
    }

    #[test]
    fn the_integer_comparison_cannot_overflow() {
        let classification = classification_for(b"classical only");
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::Hybrid,
            None,
            counters(u32::MAX, u32::MAX),
            peer(),
            1,
        );
        assert_eq!(
            verdict.code(),
            Some(VerdictCode::SelectiveFragmentDropAttack)
        );
    }

    #[test]
    fn alerts_are_signed_and_verifiable() {
        let mut rng = ChaCha8Rng::seed_from_u64(0x9F4A_2C01);
        let (public_key, secret_key) = ml_dsa_65_keygen(&mut rng);

        let classification = classification_for(b"classical only");
        let verdict = evaluate_packet(
            &classification,
            MigrationPhase::PqOnly,
            None,
            PeerCounters::default(),
            peer(),
            1_700_000_000_000_000_000,
        );
        let PacketVerdict::Drop { code, mut alert } = verdict else {
            panic!("expected a drop verdict");
        };
        assert_eq!(code, VerdictCode::AlgorithmDowngrade);
        assert_eq!(alert.code, 2);
        assert_eq!(alert.peer, peer());
        assert_eq!(alert.packet_digest, classification.packet_digest);
        assert!(alert.signature.is_empty(), "unsigned by evaluate_packet");

        alert.sign(&secret_key, &public_key);
        assert_eq!(
            alert.signature.len(),
            chronos_pqc_sys::ML_DSA_65_SIGNATURE_LEN
        );
        assert!(alert.verify(&public_key));

        // Any tampering fails verification.
        let mut tampered = alert.clone();
        tampered.packet_digest[0] ^= 0x01;
        assert!(!tampered.verify(&public_key));

        let mut tampered = alert.clone();
        tampered.peer.port ^= 1;
        assert!(!tampered.verify(&public_key));

        let mut tampered = alert;
        tampered.signature.truncate(10);
        assert!(!tampered.verify(&public_key));
    }

    #[test]
    fn alert_payload_is_exactly_domain_plus_fields() {
        let payload = alert_payload(2, peer(), 42, &[0xAA; 32]);
        assert_eq!(
            payload.len(),
            MONITOR_ALERT_CONTEXT.len() + 2 + 4 + 2 + 8 + 32
        );
        assert_eq!(&payload[..MONITOR_ALERT_CONTEXT.len()], b"monitor/v1\n\0");
        assert_eq!(&payload[12..14], &[0x00, 0x02], "code");
        assert_eq!(&payload[14..18], &[203, 0, 113, 7], "peer ip");
        assert_eq!(&payload[18..20], &4433u16.to_be_bytes(), "peer port");
        assert_eq!(&payload[20..28], &42u64.to_be_bytes(), "timestamp");
        assert_eq!(&payload[28..60], &[0xAAu8; 32], "packet digest");
    }
}
