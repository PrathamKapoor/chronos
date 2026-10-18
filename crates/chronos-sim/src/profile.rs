//! The five-layer deterministic cost model and the profiler that aggregates it.
//!
//! Wall-clock timing is deliberately excluded from the exported metrics: it is not bit-exact, so it
//! cannot be replayed. Each operation instead contributes a calibrated constant in nanoseconds
//! (`flow.md` §7.3.2), while the simulator still executes the *real* computation — real SHA-256, real
//! CRCs, real Reed-Solomon coding — for correctness. The constants are what the benchmark reports;
//! they are never used to decide whether something worked.

use crate::stats::SampleStats;
use serde::{Deserialize, Serialize};

/// Calibrated per-operation costs in nanoseconds.
pub mod costs {
    /// Client: hybrid key generation.
    pub const KEYGEN_HYBRID_NS: u64 = 37_000;
    /// Client: classical key generation (X25519 + ECDSA P-256).
    pub const KEYGEN_CLASSICAL_NS: u64 = 2_500;
    /// Client: base-128 trust-anchor extension encode.
    pub const TRUST_ANCHOR_ENCODE_NS: u64 = 700;

    /// Server: Flight 1 budget planning.
    pub const PLAN_NS: u64 = 1_200;
    /// Server: one skip-link hop lookup and proof derivation.
    pub const HOP_LOOKUP_NS: u64 = 3_000;
    /// Server: KEM encapsulation.
    pub const ENCAPSULATE_NS: u64 = 22_000;
    /// Server: MTC proof construction (including cosignature set).
    pub const PROOF_BUILD_NS: u64 = 1_800;
    /// Server: one Reed-Solomon encode shard.
    pub const RS_ENCODE_SHARD_NS: u64 = 3_200;

    /// Network: one round trip.
    pub const RTT_NS: u64 = 1_000_000;
    /// Network: the first probe timeout; each retry doubles it.
    pub const PTO_BASE_NS: u64 = 3_000_000;

    /// Client: one Reed-Solomon decode shard.
    pub const RS_DECODE_SHARD_NS: u64 = 3_800;
    /// Client: one skip-link consistency-hop verification.
    pub const HOP_VERIFY_NS: u64 = 4_000;
    /// Client: one ML-DSA-65 verification.
    pub const ML_DSA_VERIFY_NS: u64 = 42_000;

    /// Guard: bounded 256-byte classification of one datagram.
    pub const CLASSIFY_NS: u64 = 380;
    /// Guard: policy matrix evaluation for one datagram.
    pub const POLICY_NS: u64 = 500;
}

/// The five layers, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Layer {
    /// `InitAndKeyShare` — client key generation and trust-anchor encoding.
    L1InitAndKeyShare,
    /// `ServerFlightAndFec` — planning, encapsulation, proof build, RS encode.
    L2ServerFlightAndFec,
    /// `NetworkTransportAndRtt` — RTT, drops, PTO backoff, FEC recovery, amplification stalls.
    L3NetworkTransportAndRtt,
    /// `ClientFecDecodeAndMtcVerify` — RS decode, consistency chain, signature verification.
    L4ClientFecDecodeAndMtcVerify,
    /// `EbpfGuardAndAlert` — ingress classification and policy lookup.
    L5EbpfGuardAndAlert,
}

impl Layer {
    /// Every layer, in order.
    pub const ALL: [Layer; 5] = [
        Layer::L1InitAndKeyShare,
        Layer::L2ServerFlightAndFec,
        Layer::L3NetworkTransportAndRtt,
        Layer::L4ClientFecDecodeAndMtcVerify,
        Layer::L5EbpfGuardAndAlert,
    ];

    /// Short label used in reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::L1InitAndKeyShare => "L1_InitAndKeyShare",
            Self::L2ServerFlightAndFec => "L2_ServerFlightAndFec",
            Self::L3NetworkTransportAndRtt => "L3_NetworkTransportAndRtt",
            Self::L4ClientFecDecodeAndMtcVerify => "L4_ClientFecDecodeAndMtcVerify",
            Self::L5EbpfGuardAndAlert => "L5_EbpfGuardAndAlert",
        }
    }

    /// Index into a fixed-size cost vector.
    pub fn index(&self) -> usize {
        Layer::ALL
            .iter()
            .position(|layer| *layer == *self)
            .unwrap_or(0)
    }
}

/// Per-layer nanosecond totals for one handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LayerBreakdown {
    /// Cost per layer, indexed by [`Layer::index`].
    pub nanos: [u64; 5],
}

impl LayerBreakdown {
    /// Creates an empty breakdown.
    pub fn zero() -> Self {
        Self { nanos: [0; 5] }
    }

    /// Adds `nanos` to one layer.
    pub fn add(&mut self, layer: Layer, nanos: u64) {
        self.nanos[layer.index()] = self.nanos[layer.index()].saturating_add(nanos);
    }

    /// Adds a per-item cost `nanos × count`.
    pub fn add_repeated(&mut self, layer: Layer, nanos: u64, count: u64) {
        self.add(layer, nanos.saturating_mul(count));
    }

    /// Cost of one layer.
    pub fn get(&self, layer: Layer) -> u64 {
        self.nanos[layer.index()]
    }

    /// Total across all layers.
    pub fn total(&self) -> u64 {
        self.nanos.iter().copied().fold(0u64, u64::saturating_add)
    }

    /// Layer labels paired with their costs.
    pub fn labelled(&self) -> Vec<(&'static str, u64)> {
        Layer::ALL
            .iter()
            .map(|layer| (layer.label(), self.get(*layer)))
            .collect()
    }
}

/// Aggregated statistics for one layer across many handshakes.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LayerStats {
    /// Which layer this describes.
    pub layer: Layer,
    /// Total-nanosecond sample statistics.
    pub total: SampleStats,
    /// Mean share of the handshake this layer accounts for, in `[0, 1]`.
    pub mean_share: f64,
}

/// The profiler: one layer vector per handshake, aggregated on demand.
#[derive(Debug, Clone, Default)]
pub struct LatencyProfiler {
    breakdowns: Vec<LayerBreakdown>,
}

impl LatencyProfiler {
    /// Creates an empty profiler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one handshake.
    pub fn record(&mut self, breakdown: LayerBreakdown) {
        self.breakdowns.push(breakdown);
    }

    /// Number of recorded handshakes.
    pub fn len(&self) -> usize {
        self.breakdowns.len()
    }

    /// True when nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.breakdowns.is_empty()
    }

    /// Total-nanosecond statistics per layer.
    pub fn layer_stats(&self) -> Vec<LayerStats> {
        let totals: u64 = self
            .breakdowns
            .iter()
            .map(|breakdown| breakdown.total())
            .sum::<u64>();
        let denominator = totals.max(1) as f64;

        Layer::ALL
            .iter()
            .map(|layer| {
                let samples: Vec<u64> = self
                    .breakdowns
                    .iter()
                    .map(|breakdown| breakdown.get(*layer))
                    .collect();
                let stats = SampleStats::of(&samples);
                let share = samples.iter().map(|value| *value as f64).sum::<f64>() / denominator;
                LayerStats {
                    layer: *layer,
                    total: stats,
                    mean_share: share,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_indices_are_stable() {
        assert_eq!(Layer::L1InitAndKeyShare.index(), 0);
        assert_eq!(Layer::L5EbpfGuardAndAlert.index(), 4);
        assert_eq!(Layer::ALL.len(), 5);
        for (index, layer) in Layer::ALL.iter().enumerate() {
            assert_eq!(layer.index(), index);
            assert!(!layer.label().is_empty());
        }
    }

    #[test]
    fn breakdown_accumulates_and_totals() {
        let mut breakdown = LayerBreakdown::zero();
        breakdown.add(Layer::L1InitAndKeyShare, costs::KEYGEN_HYBRID_NS);
        breakdown.add_repeated(Layer::L2ServerFlightAndFec, costs::RS_ENCODE_SHARD_NS, 3);

        assert_eq!(breakdown.get(Layer::L1InitAndKeyShare), 37_000);
        assert_eq!(breakdown.get(Layer::L2ServerFlightAndFec), 9_600);
        assert_eq!(breakdown.get(Layer::L3NetworkTransportAndRtt), 0);
        assert_eq!(breakdown.total(), 46_600);
        assert_eq!(breakdown.labelled().len(), 5);
    }

    #[test]
    fn profiler_aggregates_percentiles_and_shares() {
        let mut profiler = LatencyProfiler::new();
        assert!(profiler.is_empty());

        for index in 0..100u64 {
            let mut breakdown = LayerBreakdown::zero();
            breakdown.add(Layer::L3NetworkTransportAndRtt, costs::RTT_NS + index);
            breakdown.add(
                Layer::L5EbpfGuardAndAlert,
                costs::CLASSIFY_NS + costs::POLICY_NS,
            );
            profiler.record(breakdown);
        }

        let stats = profiler.layer_stats();
        assert_eq!(stats.len(), 5);
        assert_eq!(stats[2].total.count, 100);
        assert_eq!(stats[2].total.p50, costs::RTT_NS + 49, "nearest rank");
        assert_eq!(stats[2].total.p99, costs::RTT_NS + 98);

        let share_sum: f64 = stats.iter().map(|entry| entry.mean_share).sum();
        assert!((share_sum - 1.0).abs() < 1e-9, "shares must sum to 1");
        assert_eq!(stats[4].total.mean, 880.0, "380 classify + 500 policy");
        assert!(
            stats[2].mean_share > 0.99,
            "the network dominates the handshake"
        );
    }

    #[test]
    fn an_empty_profiler_reports_zeroes() {
        let profiler = LatencyProfiler::new();
        for stats in profiler.layer_stats() {
            assert_eq!(stats.total.count, 0);
            assert_eq!(stats.mean_share, 0.0);
        }
    }
}
