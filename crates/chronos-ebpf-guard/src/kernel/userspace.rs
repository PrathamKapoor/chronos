//! The userspace guard pipeline: the *same* policy the kernel fast path applies, running over a
//! userspace ring.
//!
//! This is deliberately not a re-implementation. `parser::parse_quic_initial_256b`,
//! `policy::classify` and `policy::evaluate_packet` are called directly, so the chaos harness and the
//! unit tests exercise production logic rather than a look-alike. The kernel program in
//! [`super::program`] mirrors these steps in C for the in-kernel fast path; the two are held to the
//! same golden vectors.

use super::super::parser::{parse_quic_initial_256b, ParseError, MAX_EBPF_INSPECT_BYTES};
use super::super::policy::{
    classify, evaluate_packet, FrozenDeviceRecord, MigrationPhase, MonitorAlert, PacketVerdict,
    PeerAddr, PeerCounters, VerdictCode,
};
use super::super::rings::MonitorAlertRing;
#[cfg(chronos_bundled)]
use crate::chronos_pqc_sys;
use serde::{Deserialize, Serialize};

/// Configuration of the guard pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GuardConfig {
    /// Current deployment phase.
    pub phase: MigrationPhase,
    /// Optional freeze record.
    pub frozen: Option<FrozenDeviceRecord>,
}

impl GuardConfig {
    /// A configuration with the given phase and no freeze record.
    pub fn new(phase: MigrationPhase) -> Self {
        Self {
            phase,
            frozen: None,
        }
    }

    /// Installs a freeze record.
    pub fn with_freeze(mut self, freeze_timestamp: u64) -> Self {
        self.frozen = Some(FrozenDeviceRecord { freeze_timestamp });
        self
    }
}

/// Per-peer state the pipeline maintains between datagrams.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerState {
    /// Counters feeding the selective-fragment-drop heuristic.
    pub counters: PeerCounters,
}

/// What the pipeline did with one datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineOutcome {
    /// The verdict, including the (possibly unsigned) alert for a drop.
    pub verdict: PacketVerdict,
    /// True when the datagram could not be parsed as a QUIC Initial.
    pub malformed: bool,
}

/// The userspace guard pipeline.
#[derive(Debug, Clone)]
pub struct UserspaceGuard {
    config: GuardConfig,
    peers: Vec<(PeerAddr, PeerState)>,
    alerts: MonitorAlertRing,
    passed: u64,
    dropped: u64,
    malformed: u64,
}

impl UserspaceGuard {
    /// Creates a pipeline with the given configuration.
    pub fn new(config: GuardConfig) -> Self {
        Self {
            config,
            peers: Vec::new(),
            alerts: MonitorAlertRing::new(),
            passed: 0,
            dropped: 0,
            malformed: 0,
        }
    }

    /// Current configuration.
    pub fn config(&self) -> GuardConfig {
        self.config
    }

    /// Replaces the configuration (a policy reload).
    pub fn set_config(&mut self, config: GuardConfig) {
        self.config = config;
    }

    /// The alert ring.
    pub fn alerts(&self) -> &MonitorAlertRing {
        &self.alerts
    }

    /// Datagrams forwarded to the batch ring.
    pub fn passed(&self) -> u64 {
        self.passed
    }

    /// Datagrams dropped by the policy.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Datagrams that were not well-formed QUIC Initials.
    pub fn malformed(&self) -> u64 {
        self.malformed
    }

    /// Counters recorded for one peer.
    pub fn peer_state(&self, peer: PeerAddr) -> Option<PeerState> {
        self.peers
            .iter()
            .find(|(address, _)| *address == peer)
            .map(|(_, state)| *state)
    }

    /// Runs the full pipeline for one datagram: parse → classify → evaluate → record.
    ///
    /// `timestamp_ns` is supplied by the caller so that a deterministic simulation produces
    /// byte-identical alerts on every run.
    pub fn inspect(
        &mut self,
        datagram: &[u8],
        peer: PeerAddr,
        timestamp_ns: u64,
    ) -> PipelineOutcome {
        let summary = match parse_quic_initial_256b(datagram) {
            Ok(summary) => summary,
            Err(ParseError::NotInitial(packet_type)) => {
                // A non-Initial packet is not this guard's business; pass it through untouched.
                let _ = packet_type;
                self.passed += 1;
                return PipelineOutcome {
                    verdict: PacketVerdict::PassToBatchRing {
                        crypto_windows: 0,
                        offers_pqc_kem: false,
                    },
                    malformed: false,
                };
            }
            Err(_) => {
                self.malformed += 1;
                self.dropped += 1;
                let alert = MonitorAlert {
                    code: VerdictCode::MalformedInitial.code(),
                    peer,
                    timestamp_ns,
                    packet_digest: digest_of(datagram),
                    signature: Vec::new(),
                };
                // The alert is recorded unsigned: signing needs the monitor key, which the pipeline
                // does not own. `sign_alerts` applies it afterwards.
                self.alerts.push(alert.clone());
                return PipelineOutcome {
                    verdict: PacketVerdict::Drop {
                        code: VerdictCode::MalformedInitial,
                        alert,
                    },
                    malformed: true,
                };
            }
        };

        let inspection_len = datagram.len().min(MAX_EBPF_INSPECT_BYTES);
        let classification = classify(&summary, &datagram[..inspection_len]);
        let counters = self.state_for(peer);
        let verdict = evaluate_packet(
            &classification,
            self.config.phase,
            self.config.frozen,
            counters,
            peer,
            timestamp_ns,
        );

        // The observed offer updates the peer counters *after* the verdict, so the decision always
        // uses the counters accumulated before this datagram.
        let state = self.state_for_mut(peer);
        if classification.offers_pqc_kem {
            state.counters.pqc_attempts = state.counters.pqc_attempts.saturating_add(1);
        } else {
            state.counters.classical_fallbacks =
                state.counters.classical_fallbacks.saturating_add(1);
        }

        if verdict.is_drop() {
            self.dropped += 1;
            if let PacketVerdict::Drop { alert, .. } = &verdict {
                self.alerts.push(alert.clone());
            }
        } else {
            self.passed += 1;
        }

        PipelineOutcome {
            verdict,
            malformed: false,
        }
    }

    /// Signs every retained alert with the monitor key, in place.
    pub fn sign_alerts(
        &mut self,
        secret_key: &chronos_pqc_sys::MlDsa65SecretKey,
        public_key: &chronos_pqc_sys::MlDsa65PublicKey,
    ) {
        self.alerts.sign_all(secret_key, public_key);
    }

    fn state_for(&mut self, peer: PeerAddr) -> PeerCounters {
        if let Some(position) = self.peers.iter().position(|(address, _)| *address == peer) {
            return self.peers[position].1.counters;
        }
        let state = PeerState::default();
        self.peers.push((peer, state));
        state.counters
    }

    /// Records the outcome of a PQC fragment loss for one peer.
    pub fn record_fragment_drops(&mut self, peer: PeerAddr, drops: u32) {
        let counters = &mut self.state_for_mut(peer).counters;
        counters.pqc_fragment_drops = counters.pqc_fragment_drops.saturating_add(drops);
    }

    fn state_for_mut(&mut self, peer: PeerAddr) -> &mut PeerState {
        if let Some(position) = self.peers.iter().position(|(address, _)| *address == peer) {
            return &mut self.peers[position].1;
        }
        self.peers.push((peer, PeerState::default()));
        let last = self.peers.len() - 1;
        &mut self.peers[last].1
    }
}

/// SHA-256 over the inspected slice.
fn digest_of(datagram: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&datagram[..datagram.len().min(MAX_EBPF_INSPECT_BYTES)]);
    hasher.finalize().into()
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::super::super::policy::{VerdictCode, PQC_KEM_PATTERN, TRUST_ANCHORS_PATTERN};
    use super::*;

    fn peer() -> PeerAddr {
        PeerAddr {
            ip: [198, 51, 100, 4],
            port: 5555,
        }
    }

    /// Builds a syntactically valid QUIC v1 Initial carrying `payload` in a CRYPTO frame.
    fn initial(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0xC0 | 0x03];
        out.extend_from_slice(&1u32.to_be_bytes());
        out.push(4);
        out.extend_from_slice(b"dcid");
        out.push(4);
        out.extend_from_slice(b"scid");
        out.push(0x00); // token length
        let length = 4 + 2 + payload.len();
        out.extend_from_slice(&(((length as u16) | 0x4000).to_be_bytes()));
        out.extend_from_slice(&[0, 0, 0, 0]); // packet number
        out.push(0x06);
        out.push(0x00);
        out.push((payload.len() as u8) | 0x40);
        out.push((payload.len() >> 8) as u8);
        out.extend_from_slice(payload);
        out
    }

    fn pq_initial() -> Vec<u8> {
        let mut payload = b"client hello".to_vec();
        payload.extend_from_slice(&PQC_KEM_PATTERN);
        payload.extend_from_slice(&TRUST_ANCHORS_PATTERN);
        initial(&payload)
    }

    #[test]
    fn classical_handshakes_pass_in_hybrid_mode() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::Hybrid));
        let outcome = guard.inspect(&initial(b"client hello"), peer(), 1);
        assert!(!outcome.verdict.is_drop());
        assert!(!outcome.malformed);
        assert_eq!(guard.passed(), 1);
        assert_eq!(guard.dropped(), 0);
    }

    #[test]
    fn classical_handshakes_are_dropped_in_pq_only_mode() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::PqOnly));
        let outcome = guard.inspect(&initial(b"client hello"), peer(), 2);
        assert_eq!(
            outcome.verdict.code(),
            Some(VerdictCode::AlgorithmDowngrade)
        );
        assert_eq!(guard.dropped(), 1);
        assert_eq!(guard.alerts().len(), 1);
        assert_eq!(guard.alerts().entries().front().unwrap().code, 2);
    }

    #[test]
    fn pq_handshakes_survive_pq_only_mode() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::PqOnly));
        let outcome = guard.inspect(&pq_initial(), peer(), 3);
        assert!(!outcome.verdict.is_drop());
        assert_eq!(guard.passed(), 1);
    }

    #[test]
    fn the_selective_drop_heuristic_fires_after_evidence_accumulates() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::Hybrid));

        // Five PQC handshakes, then three lost fragments (60 % > 40 %).
        for index in 0..5u64 {
            guard.inspect(&pq_initial(), peer(), index + 10);
        }
        guard.record_fragment_drops(peer(), 3);

        let outcome = guard.inspect(&initial(b"client hello"), peer(), 100);
        assert_eq!(
            outcome.verdict.code(),
            Some(VerdictCode::SelectiveFragmentDropAttack)
        );
        assert_eq!(guard.dropped(), 1);
    }

    #[test]
    fn fragment_drops_are_counted_per_peer() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::Hybrid));
        let other = PeerAddr {
            ip: [203, 0, 113, 9],
            port: 7777,
        };
        for index in 0..5u64 {
            guard.inspect(&pq_initial(), other, index);
        }
        guard.record_fragment_drops(other, 9);
        guard.record_fragment_drops(peer(), 1);

        assert_eq!(
            guard.peer_state(other).unwrap().counters.pqc_fragment_drops,
            9
        );
        assert_eq!(
            guard
                .peer_state(peer())
                .unwrap()
                .counters
                .pqc_fragment_drops,
            1
        );
        assert_eq!(guard.peer_state(peer()).unwrap().counters.pqc_attempts, 0);
    }

    #[test]
    fn a_freeze_record_drops_post_freeze_issuance() {
        let freeze = 1_700_000_000_000u64;
        let guard_config = GuardConfig::new(MigrationPhase::Hybrid).with_freeze(freeze);
        let mut guard = UserspaceGuard::new(guard_config);

        let mut payload = b"client hello".to_vec();
        payload.extend_from_slice(&PQC_KEM_PATTERN);
        payload.extend_from_slice(&super::super::super::parser::MTC_HINT_MAGIC);
        payload.push(super::super::super::parser::MTC_HINT_VERSION);
        payload.extend_from_slice(&[0u8; 6]);
        payload.extend_from_slice(&(freeze + 1).to_be_bytes()[2..]);

        let outcome = guard.inspect(&initial(&payload), peer(), 5);
        assert_eq!(
            outcome.verdict.code(),
            Some(VerdictCode::UnauthorizedIssuanceAfterFreeze)
        );
    }

    #[test]
    fn malformed_packets_are_counted_and_alerted() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::Hybrid));
        let outcome = guard.inspect(&[0x40, 0x11, 0x22], peer(), 9);
        assert!(outcome.malformed);
        assert_eq!(outcome.verdict.code(), Some(VerdictCode::MalformedInitial));
        assert_eq!(guard.malformed(), 1);
        assert_eq!(guard.alerts().len(), 1);
    }

    #[test]
    fn non_initial_packets_pass_through_untouched() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::PqOnly));
        // 0b01 in the packet-type field = 0-RTT.
        let mut datagram = vec![0xD0 | 0x03];
        datagram.extend_from_slice(&[0u8; 20]);
        let outcome = guard.inspect(&datagram, peer(), 11);
        assert!(!outcome.verdict.is_drop());
        assert!(!outcome.malformed);
    }

    #[test]
    fn alerts_are_signed_on_demand_and_verify() {
        use chronos_pqc_sys::ml_dsa_65_keygen;
        use rand_chacha::ChaCha8Rng;
        use rand_core::SeedableRng;

        let mut rng = ChaCha8Rng::seed_from_u64(0x9F4A_2C01);
        let (public_key, secret_key) = ml_dsa_65_keygen(&mut rng);

        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::PqOnly));
        guard.inspect(&initial(b"client hello"), peer(), 42);
        assert!(guard
            .alerts()
            .entries()
            .front()
            .unwrap()
            .signature
            .is_empty());

        guard.sign_alerts(&secret_key, &public_key);
        let alerts = guard.alerts();
        assert_eq!(alerts.len(), 1);
        assert!(alerts.entries().front().unwrap().verify(&public_key));
        assert_eq!(alerts.total_pushed(), 1, "re-pushing must not double count");
    }

    #[test]
    fn a_policy_reload_takes_effect_immediately() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::ClassicalOnly));
        assert!(!guard
            .inspect(&initial(b"client hello"), peer(), 1)
            .verdict
            .is_drop());

        guard.set_config(GuardConfig::new(MigrationPhase::PqOnly));
        assert!(guard
            .inspect(&initial(b"client hello"), peer(), 2)
            .verdict
            .is_drop());
        assert_eq!(guard.config().phase, MigrationPhase::PqOnly);
    }

    #[test]
    fn a_flood_cannot_grow_the_alert_ring() {
        let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::PqOnly));
        for index in 0..200u64 {
            guard.inspect(&initial(b"client hello"), peer(), index);
        }
        assert_eq!(guard.dropped(), 200);
        assert_eq!(
            guard.alerts().len(),
            super::super::super::rings::ALERT_RING_CAPACITY
        );
        assert_eq!(
            guard.alerts().total_dropped(),
            200 - super::super::super::rings::ALERT_RING_CAPACITY as u64
        );
    }
}
