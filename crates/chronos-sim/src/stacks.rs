//! The four protocol stacks and the handshake state machine the chaos harness drives.
//!
//! | Stack | Server Flight 1 | Packets | FEC | Skip-links |
//! |---|---|---|---|---|
//! | `ClassicalQuic` | 1,850 B (X25519 + ECDSA P-256 chain) | 2 | none | none |
//! | `NaivePqcQuic` | 11,400 B (full ML-DSA-65 chain + 2 SCTs) | 10 | none | none |
//! | `DraftMtcQuic` | 8,200 B Standalone MTC | 7 | none | none |
//! | `ChronosMtc` | `1240 + 736 + hops·40`, ≤ 3,600 B | `k + r` | RS `(k, r)` | yes |
//!
//! `NaivePqcQuic` and `DraftMtcQuic` exceed the 3,600 B anti-amplification limit on first contact: only
//! three 1,200 B datagrams leave before the client's ACK validates the address, and the rest waits a
//! full round trip. That stall — not cryptography — is what ChronosMTC exists to remove.
//!
//! With FEC stacks, `losses <= r` costs zero extra round trips (the shards are reconstructed in place
//! and reported through `FEC_RECOVERED`); beyond `r` a PTO with exponential backoff is charged.

use crate::deps::*;
use crate::net::{mtu_blackhole, Channel, FaultKind, FaultLog};
use crate::profile::{costs, Layer, LayerBreakdown};
use crate::rng::SimRng;
use serde::{Deserialize, Serialize};

/// Largest datagram the path carries.
pub const PATH_MTU: usize = 1_200;
/// Client Initial datagram size.
pub const CLIENT_INITIAL_BYTES: usize = 1_200;
/// Maximum PTO retransmission attempts before a handshake is declared failed.
pub const MAX_PTO_ATTEMPTS: u32 = 5;

/// Classical stack Flight 1 size.
pub const CLASSICAL_FLIGHT1_BYTES: usize = 1_850;
/// Naive PQ stack Flight 1 size (full ML-DSA-65 chain plus two SCTs).
pub const NAIVE_PQ_FLIGHT1_BYTES: usize = 11_400;
/// Draft-MTC stack Flight 1 size (Standalone MTC).
pub const DRAFT_MTC_FLIGHT1_BYTES: usize = 8_200;

/// The four stacks under comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StackKind {
    /// X25519 + ECDSA P-256, no MTC.
    ClassicalQuic,
    /// Full ML-DSA-65 chain, no MTC, no amplification planning.
    NaivePqcQuic,
    /// MTC Standalone proof, no amplification planning, no FEC.
    DraftMtcQuic,
    /// Landmark-relative MTC, skip-links, planned FEC.
    ChronosMtc,
}

impl StackKind {
    /// All stacks, controls first and the target last.
    pub const ALL: [StackKind; 4] = [
        StackKind::ClassicalQuic,
        StackKind::NaivePqcQuic,
        StackKind::DraftMtcQuic,
        StackKind::ChronosMtc,
    ];

    /// Short label used in reports and the CSV matrix.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ClassicalQuic => "ClassicalQuic",
            Self::NaivePqcQuic => "NaivePqcQuic",
            Self::DraftMtcQuic => "DraftMtcQuic",
            Self::ChronosMtc => "ChronosMtc",
        }
    }

    /// Whether the stack uses post-quantum key establishment.
    pub fn uses_pq(&self) -> bool {
        !matches!(self, Self::ClassicalQuic)
    }

    /// Whether the stack authenticates with a Merkle Tree Certificate.
    pub fn uses_mtc(&self) -> bool {
        matches!(self, Self::DraftMtcQuic | Self::ChronosMtc)
    }

    /// Whether the stack erasure-codes Flight 1.
    pub fn uses_fec(&self) -> bool {
        matches!(self, Self::ChronosMtc)
    }

    /// Whether the stack ships an O(log N) skip-link delta.
    pub fn uses_skip_links(&self) -> bool {
        matches!(self, Self::ChronosMtc)
    }
}

/// What the server sends in Flight 1, after planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flight1Shape {
    /// Total payload bytes (excluding frame headers).
    pub payload_bytes: usize,
    /// Number of datagrams.
    pub packets: usize,
    /// Data shards, when FEC is used.
    pub data_shards: usize,
    /// Parity shards, when FEC is used.
    pub parity_shards: usize,
    /// Skip-link hops carried inline.
    pub skip_link_hops: usize,
    /// Authentication mode chosen by the planner.
    pub mode: Flight1ModeLabel,
    /// Bytes that cannot leave before the client's address is validated.
    pub stalled_bytes: usize,
}

/// Planner outcome, flattened for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Flight1ModeLabel {
    /// Landmark-relative MTC proof.
    FreshLandmarkRelative,
    /// Landmark-relative MTC proof plus skip-links.
    InBandSkipLinkDelta,
    /// Stateless Retry, then the Standalone MTC.
    StatelessRetryThenStandalone,
}

impl From<Flight1Mode> for Flight1ModeLabel {
    fn from(mode: Flight1Mode) -> Self {
        match mode {
            Flight1Mode::FreshLandmarkRelative => Self::FreshLandmarkRelative,
            Flight1Mode::InBandSkipLinkDelta => Self::InBandSkipLinkDelta,
            Flight1Mode::StatelessRetryThenStandalone => Self::StatelessRetryThenStandalone,
        }
    }
}

/// The outcome of one simulated handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeOutcome {
    /// Which stack ran.
    pub stack: StackKind,
    /// Round trips the handshake needed, including amplification stalls and PTOs.
    pub rounds: u32,
    /// Total simulated nanoseconds across all five layers.
    pub total_ns: u64,
    /// Bytes put on the wire, including retransmissions.
    pub wire_bytes: u64,
    /// Datagrams transmitted, including retransmissions.
    pub packets_sent: u32,
    /// Datagrams lost by the channel.
    pub packets_lost: u32,
    /// Shards reconstructed from parity.
    pub fec_recovered: u32,
    /// Probe timeouts charged.
    pub pto_events: u32,
    /// Round trips lost to the anti-amplification limit.
    pub amplification_stall_rounds: u32,
    /// Whether the handshake completed inside [`MAX_PTO_ATTEMPTS`].
    pub success: bool,
    /// Per-layer cost breakdown.
    pub layers: LayerBreakdown,
}

impl HandshakeOutcome {
    /// Round trips the handshake needed.
    pub fn rounds(&self) -> u32 {
        self.rounds
    }

    /// Total simulated nanoseconds.
    pub fn total_ns(&self) -> u64 {
        self.total_ns
    }
}

/// How stale the client's landmark is, in epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StalenessProfile {
    /// Landmarks behind the current one.
    pub delta: u64,
    /// The client's claimed landmark id.
    pub client_landmark: u64,
    /// The landmark stamped on the certificate.
    pub cert_landmark: u64,
    /// The current landmark.
    pub current_landmark: u64,
}

impl StalenessProfile {
    /// A fresh client: its landmark matches the certificate.
    pub fn fresh(current_landmark: u64) -> Self {
        Self {
            delta: 0,
            client_landmark: current_landmark,
            cert_landmark: current_landmark,
            current_landmark,
        }
    }

    /// A client `delta` epochs behind.
    pub fn stale(current_landmark: u64, delta: u64) -> Self {
        let client_landmark = current_landmark.saturating_sub(delta);
        Self {
            delta,
            client_landmark,
            cert_landmark: current_landmark,
            current_landmark,
        }
    }
}

/// Smoothed loss estimate driving parity sizing.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LossProfile {
    /// Target loss rate of the channel.
    pub target_loss: f64,
}

impl LossProfile {
    /// Builds a profile for a target loss rate.
    pub fn new(target_loss: f64) -> Self {
        Self { target_loss }
    }
}

/// Computes Flight 1 for a stack under the given staleness and loss profiles.
///
/// `ChronosMtc` goes through the real [`AmplificationPlanner`]; the control stacks use their fixed
/// geometry, because they have no planner to call.
pub fn plan_flight1(
    stack: StackKind,
    staleness: StalenessProfile,
    loss: LossProfile,
) -> Flight1Shape {
    match stack {
        StackKind::ChronosMtc => {
            let plan = AmplificationPlanner::new()
                .plan_flight1(
                    CLIENT_INITIAL_BYTES,
                    0,
                    Some(staleness.client_landmark),
                    staleness.cert_landmark,
                    staleness.current_landmark,
                    loss.target_loss,
                )
                .expect("the client Initial always meets the 1,200 B minimum");

            let packets = if plan.k == 0 { 1 } else { plan.k + plan.r };
            Flight1Shape {
                payload_bytes: plan.total_flight1_wire_bytes,
                packets,
                data_shards: plan.k,
                parity_shards: plan.r,
                skip_link_hops: plan.skip_link_hops,
                mode: plan.mode.into(),
                stalled_bytes: 0,
            }
        }
        StackKind::ClassicalQuic => Flight1Shape {
            payload_bytes: CLASSICAL_FLIGHT1_BYTES,
            packets: 2,
            data_shards: 0,
            parity_shards: 0,
            skip_link_hops: 0,
            mode: Flight1ModeLabel::FreshLandmarkRelative,
            stalled_bytes: 0,
        },
        StackKind::NaivePqcQuic => {
            let credit = credit_bytes();
            Flight1Shape {
                payload_bytes: NAIVE_PQ_FLIGHT1_BYTES,
                packets: 10,
                data_shards: 0,
                parity_shards: 0,
                skip_link_hops: 0,
                mode: Flight1ModeLabel::FreshLandmarkRelative,
                stalled_bytes: NAIVE_PQ_FLIGHT1_BYTES.saturating_sub(credit),
            }
        }
        StackKind::DraftMtcQuic => {
            let credit = credit_bytes();
            Flight1Shape {
                payload_bytes: DRAFT_MTC_FLIGHT1_BYTES,
                data_shards: 0,
                parity_shards: 0,
                packets: 7,
                skip_link_hops: 0,
                mode: Flight1ModeLabel::FreshLandmarkRelative,
                stalled_bytes: DRAFT_MTC_FLIGHT1_BYTES.saturating_sub(credit),
            }
        }
    }
}

/// Anti-amplification credit available on first contact.
pub fn credit_bytes() -> usize {
    CLIENT_INITIAL_BYTES * 3
}

/// Simulates one handshake of `stack` over `channel`.
pub fn simulate_handshake(
    stack: StackKind,
    channel: &mut Channel,
    rng: &mut SimRng,
    staleness: StalenessProfile,
    loss: LossProfile,
    faults: &mut FaultLog,
) -> HandshakeOutcome {
    let shape = plan_flight1(stack, staleness, loss);
    let mut layers = LayerBreakdown::zero();

    // ---- L1: client key share and trust anchors -------------------------------------------
    layers.add(
        Layer::L1InitAndKeyShare,
        if stack.uses_pq() {
            costs::KEYGEN_HYBRID_NS
        } else {
            costs::KEYGEN_CLASSICAL_NS
        },
    );
    if stack.uses_pqc_trust_anchor() {
        layers.add(Layer::L1InitAndKeyShare, costs::TRUST_ANCHOR_ENCODE_NS);
    }

    // ---- L2: server Flight 1 -------------------------------------------------------------
    layers.add(
        Layer::L2ServerFlightAndFec,
        if stack == StackKind::ChronosMtc {
            costs::PLAN_NS
        } else {
            0
        },
    );
    if stack.uses_pq() {
        layers.add(Layer::L2ServerFlightAndFec, costs::ENCAPSULATE_NS);
    }
    if stack.uses_mtc() {
        layers.add(Layer::L2ServerFlightAndFec, costs::PROOF_BUILD_NS);
    }
    layers.add_repeated(
        Layer::L2ServerFlightAndFec,
        costs::HOP_LOOKUP_NS,
        shape.skip_link_hops as u64,
    );
    if stack.uses_fec() && shape.data_shards > 0 {
        layers.add_repeated(
            Layer::L2ServerFlightAndFec,
            costs::RS_ENCODE_SHARD_NS,
            (shape.data_shards + shape.parity_shards) as u64,
        );
    }

    // ---- L3: transport -------------------------------------------------------------------
    let credit = credit_bytes();
    let mut rounds = 1u32;
    let mut pto_events = 0u32;
    let mut packets_lost = 0u32;
    let mut packets_sent = 0u32;
    let mut wire_bytes = 0u64;

    // The client's Initial datagram is always inspected by the guard.
    let mut guard_datagrams = 1u64;

    let packets = shape.packets.max(1);
    let per_packet_bytes = shape.payload_bytes.div_ceil(packets).max(1);

    // Datagrams that may leave before the address is validated.
    let immediately_sendable = (credit / PATH_MTU).max(1);
    let stall_rounds: u32 = if shape.stalled_bytes > 0 {
        let stalled_packets = shape.packets.saturating_sub(immediately_sendable);
        let rounds_needed = stalled_packets.div_ceil(immediately_sendable.max(1)) as u32;
        rounds += rounds_needed;
        layers.add_repeated(
            Layer::L3NetworkTransportAndRtt,
            costs::RTT_NS,
            u64::from(rounds_needed),
        );
        rounds_needed
    } else {
        0
    };

    // First transmission pass.
    let mut outstanding = 0u32;
    for index in 0..packets {
        if index < immediately_sendable || stall_rounds > 0 {
            let size = per_packet_bytes.min(PATH_MTU);
            packets_sent += 1;
            wire_bytes += size as u64;
            guard_datagrams += 1;

            if mtu_blackhole(size, PATH_MTU, index as u64, faults) {
                outstanding += 1;
                packets_lost += 1;
                continue;
            }
            if channel.drops(rng) {
                packets_lost += 1;
                outstanding += 1;
            }
        }
    }

    // FEC absorbs up to `r` losses in place.
    let recoverable = if stack.uses_fec() {
        shape.parity_shards as u32
    } else {
        0
    };
    let mut fec_recovered = 0u32;
    if outstanding <= recoverable {
        fec_recovered = outstanding;
    }

    // Anything beyond the parity budget needs a PTO with exponential backoff.
    let mut attempt = 0u32;
    while outstanding > recoverable {
        attempt += 1;
        if attempt > MAX_PTO_ATTEMPTS {
            return HandshakeOutcome {
                stack,
                rounds,
                total_ns: layers.total(),
                wire_bytes,
                packets_sent,
                packets_lost,
                fec_recovered,
                pto_events,
                amplification_stall_rounds: stall_rounds,
                success: false,
                layers,
            };
        }
        pto_events += 1;
        rounds += 1;
        let backoff = costs::PTO_BASE_NS.saturating_mul(1u64 << (attempt - 1));
        layers.add(Layer::L3NetworkTransportAndRtt, backoff + costs::RTT_NS);

        // Retransmit the outstanding datagrams; some may be lost again.
        let mut still_lost = 0u32;
        for _ in 0..outstanding {
            packets_sent += 1;
            wire_bytes += per_packet_bytes.min(PATH_MTU) as u64;
            guard_datagrams += 1;
            if channel.drops(rng) {
                packets_lost += 1;
                still_lost += 1;
            }
        }
        outstanding = still_lost;
    }

    // ---- L4: client verification ----------------------------------------------------------
    layers.add_repeated(
        Layer::L4ClientFecDecodeAndMtcVerify,
        costs::RS_DECODE_SHARD_NS,
        fec_recovered as u64,
    );
    layers.add_repeated(
        Layer::L4ClientFecDecodeAndMtcVerify,
        costs::HOP_VERIFY_NS,
        shape.skip_link_hops as u64,
    );
    if stack.uses_mtc() || stack.uses_pq() {
        layers.add(
            Layer::L4ClientFecDecodeAndMtcVerify,
            costs::ML_DSA_VERIFY_NS,
        );
    }

    // ---- L5: guard ------------------------------------------------------------------------
    layers.add_repeated(
        Layer::L5EbpfGuardAndAlert,
        costs::CLASSIFY_NS,
        guard_datagrams,
    );
    layers.add_repeated(
        Layer::L5EbpfGuardAndAlert,
        costs::POLICY_NS,
        guard_datagrams,
    );

    HandshakeOutcome {
        stack,
        rounds,
        total_ns: layers.total(),
        wire_bytes,
        packets_sent,
        packets_lost,
        fec_recovered,
        pto_events,
        amplification_stall_rounds: stall_rounds,
        success: true,
        layers,
    }
}

impl StackKind {
    /// Whether the client sends a `trust_anchors` extension in its Initial.
    pub fn uses_pqc_trust_anchor(&self) -> bool {
        matches!(self, Self::ChronosMtc)
    }
}

/// Payload geometry a ChronosMTC client receives at a given staleness, for reporting.
pub fn chronos_flight1_summary(staleness: StalenessProfile, loss: LossProfile) -> Flight1Shape {
    plan_flight1(StackKind::ChronosMtc, staleness, loss)
}

/// Bytes a ChronosMTC Flight 1 carries before planning: `ServerHello + proof + skip-links`.
pub fn chronos_planned_payload(staleness: StalenessProfile) -> usize {
    SERVER_HELLO_PQC_BYTES
        + LANDMARK_MTC_PROOF_BYTES
        + hop_count_for(staleness.delta) * chronos_mtc_core::skip_link::SKIP_LINK_HOP_BYTES
}

/// Bytes an unknown-CA client must be served with (Retry now, Standalone MTC later).
pub fn unknown_ca_bytes() -> usize {
    RETRY_TOKEN_BYTES + STANDALONE_MTC_PROOF_BYTES
}

/// Fault kinds that the harness may inject for a stack, for the scorecard.
pub fn injected_fault_kinds() -> [FaultKind; 5] {
    [
        FaultKind::BurstLoss,
        FaultKind::MtuBlackhole,
        FaultKind::BitFlip,
        FaultKind::Reorder,
        FaultKind::SplitViewFork,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DEFAULT_SEED;

    fn run(stack: StackKind, loss: f64, staleness: StalenessProfile) -> HandshakeOutcome {
        let master = SimRng::new(DEFAULT_SEED);
        let mut rng = master.sub(&format!("handshake::{stack:?}"));
        let mut channel = Channel::for_target_loss(loss);
        let mut faults = FaultLog::new();
        simulate_handshake(
            stack,
            &mut channel,
            &mut rng,
            staleness,
            LossProfile::new(loss),
            &mut faults,
        )
    }

    #[test]
    fn control_stack_geometries_match_the_specification() {
        let fresh = StalenessProfile::fresh(10_000);
        let loss = LossProfile::new(0.03);

        let classical = plan_flight1(StackKind::ClassicalQuic, fresh, loss);
        assert_eq!(classical.payload_bytes, CLASSICAL_FLIGHT1_BYTES);
        assert_eq!(classical.packets, 2);
        assert_eq!(classical.stalled_bytes, 0, "1,850 B fits the credit");

        let naive = plan_flight1(StackKind::NaivePqcQuic, fresh, loss);
        assert_eq!(naive.payload_bytes, NAIVE_PQ_FLIGHT1_BYTES);
        assert_eq!(naive.packets, 10);
        assert_eq!(naive.stalled_bytes, NAIVE_PQ_FLIGHT1_BYTES - 3_600);

        let draft = plan_flight1(StackKind::DraftMtcQuic, fresh, loss);
        assert_eq!(draft.payload_bytes, DRAFT_MTC_FLIGHT1_BYTES);
        assert_eq!(draft.packets, 7);
        assert_eq!(draft.stalled_bytes, DRAFT_MTC_FLIGHT1_BYTES - 3_600);
    }

    #[test]
    fn chronos_never_stalls_and_always_fits_the_credit() {
        for delta in [0u64, 1, 64, 10_000, 1_000_000] {
            for loss in [0.0, 0.01, 0.03, 0.05, 0.2] {
                let shape = chronos_flight1_summary(
                    StalenessProfile::stale(1_000_000, delta),
                    LossProfile::new(loss),
                );
                assert_eq!(shape.stalled_bytes, 0, "delta {delta} loss {loss}");
                assert!(
                    shape.payload_bytes <= credit_bytes(),
                    "delta {delta} loss {loss}: {} B",
                    shape.payload_bytes
                );
                assert!(
                    shape.data_shards >= 2
                        || shape.mode == Flight1ModeLabel::StatelessRetryThenStandalone
                );
            }
        }
    }

    #[test]
    fn chronos_plans_mode_b_by_staleness() {
        let fresh =
            chronos_flight1_summary(StalenessProfile::fresh(10_000), LossProfile::new(0.01));
        assert_eq!(fresh.mode, Flight1ModeLabel::FreshLandmarkRelative);
        assert_eq!(fresh.skip_link_hops, 0);

        let stale = chronos_flight1_summary(
            StalenessProfile::stale(10_000, 10_000),
            LossProfile::new(0.01),
        );
        assert_eq!(stale.mode, Flight1ModeLabel::InBandSkipLinkDelta);
        assert_eq!(stale.skip_link_hops, hop_count_for(10_000));
    }

    #[test]
    fn a_clean_network_gives_every_stack_one_round_trip() {
        for stack in StackKind::ALL {
            let outcome = run(stack, 0.0, StalenessProfile::fresh(10_000));
            assert!(outcome.success, "{stack:?}");
            assert_eq!(outcome.packets_lost, 0, "{stack:?}");
        }

        let classical = run(
            StackKind::ClassicalQuic,
            0.0,
            StalenessProfile::fresh(10_000),
        );
        assert_eq!(classical.rounds, 1);
        assert_eq!(classical.amplification_stall_rounds, 0);
        assert_eq!(classical.pto_events, 0);

        let chronos = run(StackKind::ChronosMtc, 0.0, StalenessProfile::fresh(10_000));
        assert_eq!(chronos.rounds, 1);
        assert_eq!(chronos.layers.get(Layer::L3NetworkTransportAndRtt), 0);
    }

    #[test]
    fn oversized_flights_stall_and_cost_a_round_trip() {
        let naive = run(
            StackKind::NaivePqcQuic,
            0.0,
            StalenessProfile::fresh(10_000),
        );
        assert!(
            naive.amplification_stall_rounds > 0,
            "11,400 B cannot fit 3,600 B"
        );
        assert!(naive.rounds > 1);

        let draft = run(
            StackKind::DraftMtcQuic,
            0.0,
            StalenessProfile::fresh(10_000),
        );
        assert!(draft.amplification_stall_rounds > 0);
        assert!(
            draft.amplification_stall_rounds < naive.amplification_stall_rounds,
            "8,200 B stalls less than 11,400 B"
        );
    }

    #[test]
    fn fec_absorbs_losses_that_would_cost_a_pto() {
        // 3 % loss, 1,000 runs: ChronosMtc should need far fewer PTOs than DraftMtcQuic.
        let mut chronos_pto = 0u64;
        let mut draft_pto = 0u64;
        for run_index in 0..1_000u64 {
            let master = SimRng::new(DEFAULT_SEED ^ run_index);
            let mut rng = master.sub("fec-test");
            let mut channel = Channel::for_target_loss(0.03);
            let mut faults = FaultLog::new();

            let chronos = simulate_handshake(
                StackKind::ChronosMtc,
                &mut channel,
                &mut rng,
                StalenessProfile::stale(10_000, 1_000),
                LossProfile::new(0.03),
                &mut faults,
            );
            let draft = simulate_handshake(
                StackKind::DraftMtcQuic,
                &mut channel,
                &mut rng,
                StalenessProfile::stale(10_000, 1_000),
                LossProfile::new(0.03),
                &mut faults,
            );
            chronos_pto += u64::from(chronos.pto_events);
            draft_pto += u64::from(draft.pto_events);
        }
        assert!(
            chronos_pto < draft_pto,
            "FEC must cut PTOs: {chronos_pto} vs {draft_pto}"
        );
    }

    #[test]
    fn a_successful_handshake_never_exceeds_the_attempt_budget() {
        for stack in StackKind::ALL {
            let outcome = run(stack, 0.05, StalenessProfile::fresh(10_000));
            assert!(outcome.success, "{stack:?} at 5 % loss");
            assert!(outcome.pto_events <= MAX_PTO_ATTEMPTS, "{stack:?}");
        }
    }

    #[test]
    fn layer_costs_are_attributed_to_the_right_layer() {
        let outcome = run(
            StackKind::ChronosMtc,
            0.03,
            StalenessProfile::stale(10_000, 10_000),
        );
        assert_eq!(
            outcome.layers.get(Layer::L1InitAndKeyShare),
            costs::KEYGEN_HYBRID_NS + costs::TRUST_ANCHOR_ENCODE_NS
        );
        assert!(outcome.layers.get(Layer::L2ServerFlightAndFec) > costs::ENCAPSULATE_NS);
        assert!(
            outcome.layers.get(Layer::L4ClientFecDecodeAndMtcVerify) >= costs::ML_DSA_VERIFY_NS
        );
        assert!(outcome.layers.get(Layer::L5EbpfGuardAndAlert) > 0);
        assert_eq!(outcome.total_ns, outcome.layers.total());
    }

    #[test]
    fn simulation_is_reproducible_for_a_seed() {
        let master = SimRng::new(DEFAULT_SEED);
        let run_once = |stack: StackKind| {
            let mut rng = master.sub(&format!("replay::{stack:?}"));
            let mut channel = Channel::for_target_loss(0.05);
            let mut faults = FaultLog::new();
            simulate_handshake(
                stack,
                &mut channel,
                &mut rng,
                StalenessProfile::stale(1_000_000, 10_000),
                LossProfile::new(0.05),
                &mut faults,
            )
        };
        for stack in StackKind::ALL {
            assert_eq!(
                run_once(stack),
                run_once(stack),
                "{stack:?} must replay exactly"
            );
        }
    }
}
