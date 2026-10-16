//! QUIC 3× anti-amplification Flight 1 planner (RFC 9000 §8.1).
//!
//! Before the client's address is validated a QUIC server may send at most `3 · B_rx` bytes. That
//! single constraint decides the whole handshake design: an 11,400 B naive PQC chain and an 8,200 B
//! Standalone MTC both exceed it on first contact, so the bytes queue up until the client's ACK
//! validates the address — a full RTT of dead air exactly where fresh clients are.
//!
//! The planner therefore treats the credit as a hard design input and searches `(k, r)` for the
//! cheapest flight that fits:
//!
//! | Mode | When | Content |
//! |---|---|---|
//! | `FreshLandmarkRelative` | `client_landmark >= cert_landmark` | ServerHello + landmark-relative MTCProof |
//! | `InBandSkipLinkDelta` | client is stale and it fits | Mode A + O(log N) skip-links |
//! | `StatelessRetryThenStandalone` | no landmark, or nothing fits | 120 B Retry, then Standalone MTC |
//!
//! Parity is driven by the smoothed loss estimate: `r = 0` below 0.5 %, `1` below 2.5 %, else `2`.

use crate::fec_coder::{ShardLayout, MAX_DATA_SHARDS, MIN_DATA_SHARDS};
use chronos_mtc_core::skip_link::hop_count_for;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Minimum QUIC Initial datagram size (RFC 9000 §14.1).
pub const QUIC_MIN_INITIAL_BYTES: usize = 1_200;
/// Anti-amplification limit multiplier (RFC 9000 §8.1).
pub const AMPLIFICATION_FACTOR: usize = 3;
/// ServerHello carrying an X25519MLKEM768 ciphertext plus TLS headers.
pub const SERVER_HELLO_PQC_BYTES: usize = 1_240;
/// Landmark-relative MTCProof (23 sibling hashes).
pub const LANDMARK_MTC_PROOF_BYTES: usize = 736;
/// Full cosigned Standalone MTC.
pub const STANDALONE_MTC_PROOF_BYTES: usize = 8_200;
/// Stateless Retry token that validates the client address.
pub const RETRY_TOKEN_BYTES: usize = 120;
/// Loss sensitivity for parity sizing.
pub const PARITY_SENSITIVITY: f64 = 4.0;

/// Errors produced by the planner.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum BudgetError {
    /// A smoothed loss rate was negative, NaN, or above 1.
    #[error("smoothed loss rate {0} is outside [0, 1]")]
    IllegalLossRate(f64),

    /// The client RX byte count was smaller than a QUIC Initial datagram.
    #[error("client received {rx} bytes, below the {min}-byte QUIC Initial minimum")]
    TinyClientFlight {
        /// Bytes credited to the server.
        rx: usize,
        /// QUIC minimum.
        min: usize,
    },
}

/// Which authentication payload the server chose for Flight 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Flight1Mode {
    /// Landmark-relative proof only; the client already holds a new enough landmark.
    FreshLandmarkRelative,
    /// Landmark-relative proof plus the O(log N) skip-link delta.
    InBandSkipLinkDelta,
    /// Stateless Retry first, then the Standalone MTC once the address is validated.
    StatelessRetryThenStandalone,
}

impl Flight1Mode {
    /// Short label used in reports and the CLI scorecard.
    pub fn label(&self) -> &'static str {
        match self {
            Self::FreshLandmarkRelative => "FreshLandmarkRelative",
            Self::InBandSkipLinkDelta => "InBandSkipLinkDelta",
            Self::StatelessRetryThenStandalone => "StatelessRetryThenStandalone",
        }
    }
}

/// The planned shape of Server Flight 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flight1Plan {
    /// Selected authentication payload strategy.
    pub mode: Flight1Mode,
    /// Available anti-amplification credit in bytes.
    pub credit: usize,
    /// Payload bytes before sharding (`ServerHello` + proof [+ skip-links]).
    pub data_bytes: usize,
    /// Data shard count `k`.
    pub k: usize,
    /// Parity shard count `r`.
    pub r: usize,
    /// Aligned shard length in bytes.
    pub shard_len: usize,
    /// Wire bytes of the data shards.
    pub source_wire_bytes: usize,
    /// Wire bytes of the parity shards.
    pub repair_wire_bytes: usize,
    /// Number of skip-link hops carried inline (Mode B).
    pub skip_link_hops: usize,
    /// Total Flight 1 wire bytes, including the Retry token in Mode C.
    pub total_flight1_wire_bytes: usize,
    /// Parity the loss estimate asked for.
    pub required_parity: usize,
    /// True when the plan had to ship with less parity than the estimate wanted.
    pub parity_reduced: bool,
    /// True when the flight cannot fit the credit and the sender must expect an amplification stall.
    pub stall_expected: bool,
}

impl Flight1Plan {
    /// True when the planned flight fits inside the anti-amplification credit.
    pub fn fits_in_credit(&self) -> bool {
        !self.stall_expected
    }

    /// Datagram count the flight occupies (one datagram per FEC shard).
    pub fn packet_count(&self) -> usize {
        self.k + self.r
    }
}

/// Loss-adaptive Flight 1 planner.
#[derive(Debug, Clone, Copy, Default)]
pub struct AmplificationPlanner;

impl AmplificationPlanner {
    /// Creates a planner.
    pub fn new() -> Self {
        Self
    }

    /// Available anti-amplification credit: `3 · B_rx - B_tx` (RFC 9000 §8.1).
    pub fn available_credit(client_rx_bytes: usize, bytes_already_sent: usize) -> usize {
        client_rx_bytes
            .saturating_mul(AMPLIFICATION_FACTOR)
            .saturating_sub(bytes_already_sent)
    }

    /// Parity the smoothed loss estimate justifies: 0 below 0.5 %, 1 below 2.5 %, else 2.
    pub fn required_parity(smoothed_loss_rate: f64) -> Result<usize, BudgetError> {
        if !(0.0..=1.0).contains(&smoothed_loss_rate) || smoothed_loss_rate.is_nan() {
            return Err(BudgetError::IllegalLossRate(smoothed_loss_rate));
        }
        Ok(match smoothed_loss_rate {
            rate if rate < 0.005 => 0,
            rate if rate < 0.025 => 1,
            _ => 2,
        })
    }

    /// Chooses the authentication payload and shard geometry for Server Flight 1.
    ///
    /// `client_landmark` is the newest landmark the client claims (decoded from the
    /// `trust_anchors` extension); `None` means the client holds nothing for this CA.
    pub fn plan_flight1(
        &self,
        client_rx_bytes: usize,
        bytes_already_sent: usize,
        client_landmark: Option<u64>,
        cert_landmark: u64,
        current_landmark: u64,
        smoothed_loss_rate: f64,
    ) -> Result<Flight1Plan, BudgetError> {
        if client_rx_bytes < QUIC_MIN_INITIAL_BYTES {
            return Err(BudgetError::TinyClientFlight {
                rx: client_rx_bytes,
                min: QUIC_MIN_INITIAL_BYTES,
            });
        }
        let required_parity = Self::required_parity(smoothed_loss_rate)?;
        let credit = Self::available_credit(client_rx_bytes, bytes_already_sent);

        // Mode A payload: ServerHello + landmark-relative proof.
        let fresh_data = SERVER_HELLO_PQC_BYTES + LANDMARK_MTC_PROOF_BYTES;

        let (mode, data_bytes, skip_link_hops) = match client_landmark {
            Some(landmark) if landmark >= cert_landmark => {
                (Flight1Mode::FreshLandmarkRelative, fresh_data, 0)
            }
            Some(landmark) => {
                let delta = current_landmark.saturating_sub(landmark);
                let hops = hop_count_for(delta);
                (
                    Flight1Mode::InBandSkipLinkDelta,
                    fresh_data + hops * chronos_mtc_core::skip_link::SKIP_LINK_HOP_BYTES,
                    hops,
                )
            }
            None => (
                Flight1Mode::StatelessRetryThenStandalone,
                STANDALONE_MTC_PROOF_BYTES,
                0,
            ),
        };

        let mut chosen: Option<(ShardLayout, bool)> = None;
        for r in (0..=required_parity).rev() {
            if let Some(layout) = Self::cheapest_layout(data_bytes, r, credit) {
                chosen = Some((layout, r < required_parity));
                break;
            }
        }

        match chosen {
            Some((layout, parity_reduced)) => Ok(Flight1Plan {
                mode,
                credit,
                data_bytes,
                k: layout.k,
                r: layout.r,
                shard_len: layout.shard_len,
                source_wire_bytes: layout.source_wire_bytes(),
                repair_wire_bytes: layout.repair_wire_bytes(),
                skip_link_hops,
                total_flight1_wire_bytes: layout.total_wire_bytes(),
                required_parity,
                parity_reduced,
                stall_expected: false,
            }),
            None => {
                // Nothing fits inside the credit, so Mode C is the only way forward: a 120 B
                // Stateless Retry validates the client address, which lifts the 3x limit entirely,
                // and the Standalone MTC is streamed afterwards. The retry itself always fits,
                // because `client_rx_bytes >= 1200` guarantees at least 3,600 B of credit.
                Ok(Flight1Plan {
                    mode: Flight1Mode::StatelessRetryThenStandalone,
                    credit,
                    data_bytes: STANDALONE_MTC_PROOF_BYTES,
                    k: 0,
                    r: 0,
                    shard_len: 0,
                    source_wire_bytes: 0,
                    repair_wire_bytes: 0,
                    skip_link_hops: 0,
                    total_flight1_wire_bytes: RETRY_TOKEN_BYTES,
                    required_parity,
                    parity_reduced: false,
                    stall_expected: false,
                })
            }
        }
    }

    /// Cheapest `(k, r)` layout whose wire bytes fit the credit.
    fn cheapest_layout(data_bytes: usize, parity: usize, credit: usize) -> Option<ShardLayout> {
        let mut best: Option<ShardLayout> = None;
        for k in MIN_DATA_SHARDS..=MAX_DATA_SHARDS {
            let Ok(layout) = ShardLayout::new(data_bytes, k, parity) else {
                continue;
            };
            if layout.total_wire_bytes() > credit {
                continue;
            }
            let better = match best {
                None => true,
                Some(current) => layout.total_wire_bytes() < current.total_wire_bytes(),
            };
            if better {
                best = Some(layout);
            }
        }
        best
    }

    /// Sensitivity used when sizing parity from a raw loss estimate (`alpha = 4.0`).
    pub fn parity_sensitivity() -> f64 {
        PARITY_SENSITIVITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec_coder::ShardLayout;
    use crate::frames::{FEC_REPAIR_HEADER_BYTES, FEC_SOURCE_HEADER_BYTES};

    fn plan_with(
        client_rx: usize,
        client_landmark: Option<u64>,
        cert_landmark: u64,
        current_landmark: u64,
        loss: f64,
    ) -> Flight1Plan {
        AmplificationPlanner::new()
            .plan_flight1(
                client_rx,
                0,
                client_landmark,
                cert_landmark,
                current_landmark,
                loss,
            )
            .unwrap()
    }

    #[test]
    fn credit_is_three_times_the_client_flight() {
        assert_eq!(AmplificationPlanner::available_credit(1_200, 0), 3_600);
        assert_eq!(AmplificationPlanner::available_credit(1_200, 1_000), 2_600);
        assert_eq!(
            AmplificationPlanner::available_credit(0, 0),
            0,
            "no underflow"
        );
    }

    #[test]
    fn parity_follows_the_loss_estimate() {
        assert_eq!(AmplificationPlanner::required_parity(0.0).unwrap(), 0);
        assert_eq!(AmplificationPlanner::required_parity(0.0049).unwrap(), 0);
        assert_eq!(AmplificationPlanner::required_parity(0.005).unwrap(), 1);
        assert_eq!(AmplificationPlanner::required_parity(0.024).unwrap(), 1);
        assert_eq!(AmplificationPlanner::required_parity(0.025).unwrap(), 2);
        assert_eq!(AmplificationPlanner::required_parity(0.5).unwrap(), 2);
        assert!(AmplificationPlanner::required_parity(-0.1).is_err());
        assert!(AmplificationPlanner::required_parity(f64::NAN).is_err());
        assert!(AmplificationPlanner::required_parity(1.5).is_err());
    }

    #[test]
    fn fresh_landmark_flight_matches_the_documented_geometry() {
        let plan = plan_with(1_200, Some(500), 500, 500, 0.01);
        assert_eq!(plan.mode, Flight1Mode::FreshLandmarkRelative);
        assert_eq!(plan.data_bytes, 1_976);
        assert_eq!(plan.required_parity, 1);

        // 1,976 B over k = 8 gives 256-byte shards (247 B raw, rounded up), which is the cheapest
        // geometry inside the 3,600 B credit: 8 data + 1 parity frame of 269 B each.
        assert_eq!((plan.k, plan.r), (8, 1));
        assert_eq!(plan.shard_len, 256);
        assert_eq!(plan.source_wire_bytes, 8 * (256 + FEC_SOURCE_HEADER_BYTES));
        assert_eq!(plan.repair_wire_bytes, 256 + FEC_REPAIR_HEADER_BYTES);
        assert_eq!(
            plan.total_flight1_wire_bytes,
            9 * (256 + FEC_SOURCE_HEADER_BYTES)
        );
        assert_eq!(plan.total_flight1_wire_bytes, 2_421);
        assert!(
            plan.total_flight1_wire_bytes <= 3_600,
            "must fit the credit"
        );
        assert!(!plan.stall_expected);
        assert!(!plan.parity_reduced);
        assert_eq!(plan.packet_count(), 9);

        // No other (k, r) with the same parity is cheaper: that is what "cheapest" means.
        let cheapest = (MIN_DATA_SHARDS..=MAX_DATA_SHARDS)
            .filter_map(|k| ShardLayout::new(plan.data_bytes, k, 1).ok())
            .map(|layout| layout.total_wire_bytes())
            .min()
            .expect("at least one layout");
        assert_eq!(plan.total_flight1_wire_bytes, cheapest);
    }

    #[test]
    fn stale_landmark_carries_the_skip_link_delta() {
        let plan = plan_with(1_200, Some(436), 500, 500, 0.01);
        assert_eq!(plan.mode, Flight1Mode::InBandSkipLinkDelta);
        assert_eq!(plan.skip_link_hops, hop_count_for(64));
        assert_eq!(plan.skip_link_hops, 1, "64 is a single power-of-two hop");
        assert_eq!(plan.data_bytes, 1_976 + 40);
        assert!(plan.total_flight1_wire_bytes <= 3_600);

        // A 10,000-epoch catch-up still fits: 5 hops, 200 B of skip-links.
        let plan = plan_with(1_200, Some(0), 10_000, 10_000, 0.01);
        assert_eq!(plan.skip_link_hops, 5);
        assert_eq!(plan.data_bytes, 1_976 + 200);
        assert!(plan.total_flight1_wire_bytes <= 3_600);
        assert!(!plan.stall_expected);
    }

    #[test]
    fn heavier_loss_widens_the_shard_count_not_the_budget() {
        let low = plan_with(1_200, Some(500), 500, 500, 0.01);
        let high = plan_with(1_200, Some(500), 500, 500, 0.05);

        assert_eq!(high.required_parity, 2);
        assert!(high.k >= low.k, "more data shards amortize parity overhead");
        assert!(high.r > low.r);
        assert!(
            high.total_flight1_wire_bytes <= 3_600,
            "still inside the credit"
        );
        assert!(!high.stall_expected);
        assert!(!high.parity_reduced);
    }

    #[test]
    fn clean_path_ships_no_parity_at_all() {
        let plan = plan_with(1_200, Some(500), 500, 500, 0.0);
        assert_eq!(plan.r, 0);
        assert_eq!(plan.required_parity, 0);
        assert_eq!(
            plan.total_flight1_wire_bytes,
            plan.k * (plan.shard_len + crate::frames::FEC_SOURCE_HEADER_BYTES)
        );
        assert!(plan.total_flight1_wire_bytes < 3_600);
    }

    #[test]
    fn unknown_ca_falls_back_to_retry_then_standalone() {
        let plan = plan_with(1_200, None, 500, 500, 0.01);
        assert_eq!(plan.mode, Flight1Mode::StatelessRetryThenStandalone);
        assert_eq!(plan.total_flight1_wire_bytes, RETRY_TOKEN_BYTES);
        assert_eq!(plan.data_bytes, STANDALONE_MTC_PROOF_BYTES);
        assert!(!plan.stall_expected, "Retry validates the address first");
    }

    #[test]
    fn tiny_credit_degrades_to_retry_and_flags_the_reduced_parity() {
        // A client that already sent 2,400 B leaves only 1,200 B of credit.
        let planner = AmplificationPlanner::new();
        let plan = planner
            .plan_flight1(1_200, 2_400, Some(0), 500, 500, 0.05)
            .unwrap();
        assert_eq!(plan.credit, 1_200);
        assert_eq!(plan.mode, Flight1Mode::StatelessRetryThenStandalone);
        assert_eq!(plan.total_flight1_wire_bytes, RETRY_TOKEN_BYTES);
        assert!(plan.fits_in_credit());
    }

    #[test]
    fn undersized_client_flight_is_rejected() {
        let planner = AmplificationPlanner::new();
        assert!(matches!(
            planner.plan_flight1(600, 0, Some(1), 1, 1, 0.0),
            Err(BudgetError::TinyClientFlight {
                rx: 600,
                min: 1_200
            })
        ));
    }

    #[test]
    fn every_plan_never_exceeds_the_credit() {
        for client_rx in [1_200usize, 1_250, 1_400, 2_000, 4_000] {
            for already in [0usize, 500, 1_200] {
                for landmark in [None, Some(0u64), Some(499), Some(500), Some(600)] {
                    for loss in [0.0f64, 0.004, 0.01, 0.03, 0.2] {
                        let plan = AmplificationPlanner::new()
                            .plan_flight1(client_rx, already, landmark, 500, 600, loss)
                            .unwrap();
                        assert!(
                            plan.total_flight1_wire_bytes <= plan.credit,
                            "{plan:?} exceeds credit {}",
                            plan.credit
                        );
                        assert!(!plan.stall_expected);
                    }
                }
            }
        }
    }

    #[test]
    fn chosen_layouts_are_real_encodable_geometry() {
        let plan = plan_with(1_200, Some(0), 10_000, 10_000, 0.05);
        let layout = ShardLayout::new(plan.data_bytes, plan.k, plan.r).unwrap();
        assert_eq!(layout.k, plan.k);
        assert_eq!(layout.r, plan.r);
        assert_eq!(layout.shard_len, plan.shard_len);
        assert_eq!(layout.total_wire_bytes(), plan.total_flight1_wire_bytes);
    }
}
