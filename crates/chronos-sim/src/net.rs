//! The Gilbert-Elliott channel and the fault injectors layered on the same RNG stream.
//!
//! Isolated loss is the wrong model for wireless handshakes: losses arrive in bursts, and a burst
//! that swallows half a fragmented flight is exactly what a downgrade attack looks like. The model
//! is therefore two-state, `G ⇄ B`, with `P(G→B) = p`, `P(B→G) = r` and steady-state burst
//! probability `π_B = p / (p + r)` (`flow.md` §7.3.1).
//!
//! Targets map to parameters by choosing the burst depth first:
//! `π_B = min(target / (1 − h), 0.9)` with `h = 0.4`, `r = 0.25` (mean burst 4 packets) and
//! `p = π_B · r / (1 − π_B)`.

use crate::rng::SimRng;
use serde::{Deserialize, Serialize};

/// Drop probability inside a burst.
pub const BURST_DROP_PROBABILITY: f64 = 0.4;
/// Probability of leaving a burst (`P(B→G)`); 0.25 gives a mean burst length of 4 packets.
pub const BURST_EXIT_PROBABILITY: f64 = 0.25;
/// Largest burst probability the model will target (beyond this the channel is saturated).
pub const MAX_BURST_PROBABILITY: f64 = 0.9;

/// Channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    /// Good state: nothing drops (no isolated loss).
    Good,
    /// Bad state: packets drop with probability `1 − h`.
    Bad,
}

/// Gilbert-Elliott parameters derived from a target loss rate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GilbertElliott {
    /// Target overall loss rate.
    pub target_loss: f64,
    /// Steady-state burst probability `π_B`.
    pub burst_probability: f64,
    /// `P(G→B)`.
    pub enter_burst: f64,
    /// `P(B→G)`.
    pub exit_burst: f64,
    /// Drop probability inside a burst.
    pub burst_drop: f64,
}

impl GilbertElliott {
    /// Derives parameters for a target loss rate in `[0, 1)`.
    pub fn for_target_loss(target_loss: f64) -> Self {
        let target_loss = target_loss.clamp(0.0, 0.99);
        let burst_probability =
            (target_loss / (1.0 - BURST_DROP_PROBABILITY)).min(MAX_BURST_PROBABILITY);
        let enter_burst = burst_probability * BURST_EXIT_PROBABILITY
            / (1.0 - burst_probability).max(f64::EPSILON);
        Self {
            target_loss,
            burst_probability,
            enter_burst,
            exit_burst: BURST_EXIT_PROBABILITY,
            burst_drop: BURST_DROP_PROBABILITY,
        }
    }
}

/// Stateful channel: it remembers whether it is currently in a burst, because that is the whole
/// point of the model.
#[derive(Debug, Clone)]
pub struct Channel {
    parameters: GilbertElliott,
    state: ChannelState,
}

impl Channel {
    /// Creates a channel in the good state.
    pub fn new(parameters: GilbertElliott) -> Self {
        Self {
            parameters,
            state: ChannelState::Good,
        }
    }

    /// Creates a channel for a target loss rate.
    pub fn for_target_loss(target_loss: f64) -> Self {
        Self::new(GilbertElliott::for_target_loss(target_loss))
    }

    /// The parameters in use.
    pub fn parameters(&self) -> &GilbertElliott {
        &self.parameters
    }

    /// Current state.
    pub fn state(&self) -> ChannelState {
        self.state
    }

    /// Draws the state transition for the next packet.
    pub fn step(&mut self, rng: &mut SimRng) -> ChannelState {
        self.state = match self.state {
            ChannelState::Good => {
                if rng.chance(self.parameters.enter_burst) {
                    ChannelState::Bad
                } else {
                    ChannelState::Good
                }
            }
            ChannelState::Bad => {
                if rng.chance(self.parameters.exit_burst) {
                    ChannelState::Good
                } else {
                    ChannelState::Bad
                }
            }
        };
        self.state
    }

    /// Returns `true` when a packet sent in the current state is dropped.
    pub fn drops(&mut self, rng: &mut SimRng) -> bool {
        match self.step(rng) {
            ChannelState::Good => false,
            ChannelState::Bad => rng.chance(1.0 - self.parameters.burst_drop),
        }
    }
}

/// Fault injectors layered on the same RNG stream as the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// Burst loss from the Gilbert-Elliott state machine.
    BurstLoss,
    /// MTU blackhole: a datagram larger than the path MTU is dropped.
    MtuBlackhole,
    /// A CRC-detectable bit flip inside a payload byte.
    BitFlip,
    /// Two adjacent packets arrive swapped.
    Reorder,
    /// A cosigner emits a second, conflicting signature for the same subtree.
    SplitViewFork,
}

impl FaultKind {
    /// Stable label for reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::BurstLoss => "burst-loss",
            Self::MtuBlackhole => "mtu-blackhole",
            Self::BitFlip => "bit-flip",
            Self::Reorder => "reorder",
            Self::SplitViewFork => "split-view-fork",
        }
    }
}

/// A recorded fault injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRecord {
    /// What happened.
    pub kind: FaultKind,
    /// Index of the datagram it happened to.
    pub packet_index: u64,
    /// Byte offset it happened at, when meaningful.
    pub offset: usize,
}

/// Counts and records what the injectors did.
#[derive(Debug, Clone, Default)]
pub struct FaultLog {
    records: Vec<FaultRecord>,
}

impl FaultLog {
    /// Creates an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a fault.
    pub fn record(&mut self, kind: FaultKind, packet_index: u64, offset: usize) {
        self.records.push(FaultRecord {
            kind,
            packet_index,
            offset,
        });
    }

    /// Every recorded fault.
    pub fn records(&self) -> &[FaultRecord] {
        &self.records
    }

    /// How many faults of each kind occurred.
    pub fn count(&self, kind: FaultKind) -> usize {
        self.records
            .iter()
            .filter(|record| record.kind == kind)
            .count()
    }

    /// Total faults recorded.
    pub fn total(&self) -> usize {
        self.records.len()
    }
}

/// Decides whether a datagram of `size` bytes is lost to the path MTU.
///
/// A deterministic blackhole rather than a random one: a path that cannot carry 1,200 B loses *every*
/// oversized datagram, which is the failure mode of a middlebox silently capping QUIC.
pub fn mtu_blackhole(size: usize, path_mtu: usize, packet_index: u64, log: &mut FaultLog) -> bool {
    if size > path_mtu {
        log.record(FaultKind::MtuBlackhole, packet_index, size);
        return true;
    }
    false
}

/// Applies a single CRC-detectable bit flip to `payload` and reports the byte offset.
pub fn inject_bit_flip(
    rng: &mut SimRng,
    payload: &mut [u8],
    packet_index: u64,
    log: &mut FaultLog,
) -> Option<usize> {
    if payload.is_empty() {
        return None;
    }
    let offset = rng.below(payload.len());
    let bit = 1u8 << (7 - (offset % 8));
    payload[offset] ^= bit;
    log.record(FaultKind::BitFlip, packet_index, offset);
    Some(offset)
}

/// Decides whether two adjacent packets are swapped.
pub fn reorder_pair(
    rng: &mut SimRng,
    packet_index: u64,
    probability: f64,
    log: &mut FaultLog,
) -> bool {
    if rng.chance(probability) {
        log.record(FaultKind::Reorder, packet_index, 0);
        true
    } else {
        false
    }
}

/// Records a split-view fork attempt (a cosigner emitting a second, conflicting signature).
pub fn split_view_fork(rng: &mut SimRng, packet_index: u64, log: &mut FaultLog) -> u64 {
    let conflicting_signature = rng.next_signature_nonce();
    log.record(FaultKind::SplitViewFork, packet_index, 0);
    conflicting_signature
}

impl SimRng {
    /// A deterministic "second signature" marker for split-view tests.
    pub(crate) fn next_signature_nonce(&mut self) -> u64 {
        let mut buffer = [0u8; 8];
        self.fill_bytes(&mut buffer);
        u64::from_be_bytes(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SimRng;

    #[test]
    fn parameters_match_the_documented_table() {
        let one_percent = GilbertElliott::for_target_loss(0.01);
        assert!((one_percent.burst_probability - 0.016_667).abs() < 1e-5);
        assert!((one_percent.enter_burst - 0.004_232).abs() < 1e-5);

        let three_percent = GilbertElliott::for_target_loss(0.03);
        assert!((three_percent.burst_probability - 0.05).abs() < 1e-9);
        assert!((three_percent.enter_burst - 0.013_158).abs() < 1e-5);

        let five_percent = GilbertElliott::for_target_loss(0.05);
        assert!((five_percent.burst_probability - 0.083_333).abs() < 1e-5);
        assert!((five_percent.enter_burst - 0.022_727).abs() < 1e-5);

        assert_eq!(three_percent.exit_burst, 0.25);
        assert_eq!(three_percent.burst_drop, 0.4);
    }

    #[test]
    fn measured_loss_converges_to_the_target() {
        for target in [0.01, 0.03, 0.05, 0.10] {
            let mut rng = SimRng::new(0x9F4A_2C01);
            let mut channel = Channel::for_target_loss(target);
            let samples = 400_000;
            let mut losses = 0usize;
            let mut burst_packets = 0usize;
            for _ in 0..samples {
                if channel.drops(&mut rng) {
                    losses += 1;
                }
                if channel.state() == ChannelState::Bad {
                    burst_packets += 1;
                }
            }
            let measured = losses as f64 / samples as f64;
            assert!(
                (measured - target).abs() < 0.004,
                "target {target}: measured {measured}"
            );
            let burst_fraction = burst_packets as f64 / samples as f64;
            let expected = channel.parameters().burst_probability;
            assert!(
                (burst_fraction - expected).abs() < 0.01,
                "burst occupancy {burst_fraction} vs {expected}"
            );
        }
    }

    #[test]
    fn a_clean_channel_drops_nothing() {
        let mut rng = SimRng::new(1);
        let mut channel = Channel::for_target_loss(0.0);
        for _ in 0..10_000 {
            assert!(!channel.drops(&mut rng));
        }
    }

    #[test]
    fn channel_is_deterministic_for_a_seed() {
        let mut a_rng = SimRng::new(42);
        let mut b_rng = SimRng::new(42);
        let mut a = Channel::for_target_loss(0.05);
        let mut b = Channel::for_target_loss(0.05);
        for _ in 0..1_000 {
            assert_eq!(a.drops(&mut a_rng), b.drops(&mut b_rng));
            assert_eq!(a.state(), b.state());
        }
    }

    #[test]
    fn mtu_blackhole_only_takes_oversized_datagrams() {
        let mut log = FaultLog::new();
        assert!(!mtu_blackhole(1_200, 1_200, 0, &mut log));
        assert!(mtu_blackhole(1_500, 1_200, 1, &mut log));
        assert!(!mtu_blackhole(900, 1_200, 2, &mut log));
        assert_eq!(log.count(FaultKind::MtuBlackhole), 1);
    }

    #[test]
    fn bit_flips_are_detectable_by_a_crc() {
        let mut rng = SimRng::new(5);
        let mut log = FaultLog::new();
        let mut payload = vec![0u8; 128];
        let original = payload.clone();
        let offset = inject_bit_flip(&mut rng, &mut payload, 0, &mut log).expect("flip applied");

        assert_ne!(payload, original);
        assert!(original[offset] != payload[offset]);
        assert_eq!(
            payload
                .iter()
                .zip(original.iter())
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        assert_ne!(
            crc32fast::hash(&payload),
            crc32fast::hash(&original),
            "the CRC must catch the flip"
        );
        assert_eq!(log.count(FaultKind::BitFlip), 1);
    }

    #[test]
    fn reordering_fires_at_its_rate() {
        let mut rng = SimRng::new(9);
        let mut log = FaultLog::new();
        let trials = 100_000;
        let swaps = (0..trials)
            .filter(|index| reorder_pair(&mut rng, *index as u64, 0.01, &mut log))
            .count();
        let rate = swaps as f64 / trials as f64;
        assert!((rate - 0.01).abs() < 0.002, "rate {rate}");
        assert_eq!(log.count(FaultKind::Reorder), swaps);
    }

    #[test]
    fn split_view_forks_are_recorded_and_deterministic() {
        let mut rng = SimRng::new(13);
        let mut log = FaultLog::new();
        let first = split_view_fork(&mut rng, 1, &mut log);
        let second = split_view_fork(&mut rng, 2, &mut log);
        assert_ne!(first, second);
        assert_eq!(log.count(FaultKind::SplitViewFork), 2);

        let mut replay_rng = SimRng::new(13);
        let mut replay_log = FaultLog::new();
        assert_eq!(
            split_view_fork(&mut replay_rng, 1, &mut replay_log),
            first,
            "the fork must replay identically"
        );
    }
}
