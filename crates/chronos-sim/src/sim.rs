//! The `sim` scenario: a chaos trace, an active downgrade/split-view attack, and a determinism
//! regression check.
//!
//! `chronos sim --seed 0x9F4A2C01 --loss 0.03 --stale-landmarks 10000` runs exactly this. Unlike
//! `bench`, it tells the *story* of a single seeded scenario: what the network did, what each stack
//! paid, what the attack tried, and whether the same seed replays byte-for-byte.

use crate::bench::{calibrate, calibration_passed, BenchConfig, BenchReport};
use crate::deps::*;
use crate::net::{reorder_pair, split_view_fork, Channel, FaultKind, FaultLog};
use crate::rng::{format_seed, SimRng};
use crate::stacks::{simulate_handshake, LossProfile, StackKind, StalenessProfile};
use crate::stats::SampleStats;
use serde::{Deserialize, Serialize};

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

/// Configuration for one simulated scenario.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SimConfig {
    /// Master seed.
    pub seed: u64,
    /// Channel loss target.
    pub loss: f64,
    /// How stale the client's landmark is.
    pub stale_landmarks: u64,
    /// Handshakes per stack.
    pub runs: u32,
    /// Whether to run the active-attack section.
    pub with_attack: bool,
    /// Whether to run the determinism regression.
    pub with_regression: bool,
}

impl SimConfig {
    /// The documented default: seed `0x9F4A2C01`, 3 % loss, 10,000 stale epochs, 200 runs.
    pub fn new(seed: u64, loss: f64, stale_landmarks: u64) -> Self {
        Self {
            seed,
            loss,
            stale_landmarks,
            runs: 200,
            with_attack: true,
            with_regression: true,
        }
    }
}

/// What the active attack tried and what the guard did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackReport {
    /// Handshakes the attacker offered without any PQ group.
    pub downgrade_attempts: u32,
    /// Handshakes the attacker offered with a PQ group (the decoys).
    pub pq_decoys: u32,
    /// Downgrade attempts the guard dropped.
    pub caught_downgrades: u32,
    /// Downgrade attempts that got through (must be zero in `PqOnly`).
    pub escaped_downgrades: u32,
    /// Fragments the attacker dropped to make the drop look like loss.
    pub injected_fragment_drops: u32,
    /// Split-view fork attempts.
    pub split_view_attempts: u32,
    /// Split-view forks rejected as duplicate cosigners.
    pub split_view_rejected: u32,
    /// Signed alerts the guard produced.
    pub signed_alerts: usize,
    /// Alerts whose ML-DSA-65 signature verified.
    pub verified_alerts: usize,
}

impl AttackReport {
    /// True when the guard caught everything the attacker tried.
    pub fn contained(&self) -> bool {
        self.escaped_downgrades == 0 && self.split_view_rejected == self.split_view_attempts / 2
    }
}

/// Result of replaying the same seed twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionReport {
    /// Whether the two runs produced byte-identical reports.
    pub bit_exact: bool,
    /// Length of the serialized report both runs produced.
    pub report_bytes: usize,
    /// Whether the calibration checks all passed.
    pub calibration_passed: bool,
}

/// A per-stack summary inside the scenario report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StackSummary {
    /// Which stack.
    pub stack: String,
    /// Flight 1 payload bytes.
    pub flight1_bytes: usize,
    /// Flight 1 datagrams.
    pub packets: usize,
    /// Parity shards planned.
    pub parity_shards: usize,
    /// Round-trip distribution.
    pub rounds: SampleStats,
    /// Total nanoseconds per handshake.
    pub total_ns: SampleStats,
    /// Fraction of handshakes that completed.
    pub success_rate: f64,
    /// Total PTOs.
    pub pto_events: u64,
    /// Total shards reconstructed from parity.
    pub fec_recovered: u64,
    /// Round trips lost to the anti-amplification limit.
    pub amplification_stall_rounds: u64,
}

/// The complete scenario report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimReport {
    /// Configuration used.
    pub config: SimConfig,
    /// Seed, hex.
    pub seed_hex: String,
    /// One summary per stack.
    pub stacks: Vec<StackSummary>,
    /// Faults injected by the channel and the injectors.
    pub faults: Vec<(String, usize)>,
    /// The active-attack section.
    pub attack: Option<AttackReport>,
    /// The determinism regression.
    pub regression: Option<RegressionReport>,
}

impl SimReport {
    /// The summary for one stack.
    pub fn stack(&self, kind: StackKind) -> Option<&StackSummary> {
        self.stacks
            .iter()
            .find(|summary| summary.stack == kind.label())
    }

    /// True when the guard contained the attack.
    pub fn attack_contained(&self) -> bool {
        self.attack.as_ref().is_none_or(AttackReport::contained)
    }

    /// True when the replay was bit-exact.
    pub fn regression_passed(&self) -> bool {
        self.regression
            .as_ref()
            .is_none_or(|report| report.bit_exact)
    }
}

/// Runs one scenario.
pub fn run(config: SimConfig) -> SimReport {
    let staleness = StalenessProfile::stale(10_000, config.stale_landmarks);
    let mut master = SimRng::new(config.seed);
    let mut stacks = Vec::new();
    let mut faults = FaultLog::new();

    for stack in StackKind::ALL {
        let mut rng = master.sub(&format!("sim::{stack:?}"));
        let mut channel = Channel::for_target_loss(config.loss);
        let mut rounds = Vec::with_capacity(config.runs as usize);
        let mut total_ns = Vec::with_capacity(config.runs as usize);
        let mut successes = 0u32;
        let mut pto_events = 0u64;
        let mut fec_recovered = 0u64;
        let mut stalls = 0u64;

        for index in 0..config.runs as u64 {
            let outcome = simulate_handshake(
                stack,
                &mut channel,
                &mut rng,
                staleness,
                LossProfile::new(config.loss),
                &mut faults,
            );
            rounds.push(u64::from(outcome.rounds));
            total_ns.push(outcome.total_ns);
            successes += u32::from(outcome.success);
            pto_events += u64::from(outcome.pto_events);
            fec_recovered += u64::from(outcome.fec_recovered);
            stalls += u64::from(outcome.amplification_stall_rounds);

            // Adjacent-packet reordering is injected on the same stream.
            let packet_index = index * 16;
            if reorder_pair(&mut rng, packet_index, 0.01, &mut faults) {
                // Reordering never changes the handshake result: the reassembler is index-keyed.
            }
        }

        let shape = crate::stacks::plan_flight1(stack, staleness, LossProfile::new(config.loss));
        stacks.push(StackSummary {
            stack: stack.label().to_string(),
            flight1_bytes: shape.payload_bytes,
            packets: shape.packets,
            parity_shards: shape.parity_shards,
            rounds: SampleStats::of(&rounds),
            total_ns: SampleStats::of(&total_ns),
            success_rate: successes as f64 / config.runs.max(1) as f64,
            pto_events,
            fec_recovered,
            amplification_stall_rounds: stalls,
        });
    }

    // Split-view forks are recorded even when the attack section is off, so the fault log is complete.
    let attack = if config.with_attack {
        Some(run_attack(&mut master, &mut faults).expect("attack section is infallible"))
    } else {
        None
    };

    let regression = if config.with_regression {
        Some(run_regression(config).expect("regression is infallible"))
    } else {
        None
    };

    let fault_counts: Vec<(String, usize)> = [
        FaultKind::BurstLoss,
        FaultKind::MtuBlackhole,
        FaultKind::BitFlip,
        FaultKind::Reorder,
        FaultKind::SplitViewFork,
    ]
    .iter()
    .map(|kind| (kind.label().to_string(), faults.count(*kind)))
    .collect();

    SimReport {
        config,
        seed_hex: format_seed(config.seed),
        stacks,
        faults: fault_counts,
        attack,
        regression,
    }
}

/// The active attack: an on-path attacker offering classical-only handshakes while dropping PQC
/// fragments, plus a split-view cosigner.
fn run_attack(master: &mut SimRng, faults: &mut FaultLog) -> Result<AttackReport, ()> {
    let mut rng = master.sub("attack");
    let mut report = AttackReport {
        downgrade_attempts: 0,
        pq_decoys: 0,
        caught_downgrades: 0,
        escaped_downgrades: 0,
        injected_fragment_drops: 0,
        split_view_attempts: 0,
        split_view_rejected: 0,
        signed_alerts: 0,
        verified_alerts: 0,
    };

    let peer = PeerAddr {
        ip: [203, 0, 113, 66],
        port: 53_333,
    };
    let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::PqOnly));

    // 100 classical-only attempts, interleaved with PQ decoys so the drop pattern alone is not proof.
    for index in 0..100u64 {
        if index % 3 == 2 {
            let mut payload = b"client hello".to_vec();
            payload.extend_from_slice(&PQC_KEM_PATTERN);
            let outcome = guard.inspect(&initial_packet(&payload), peer, index);
            report.pq_decoys += 1;
            if outcome.verdict.is_drop() {
                report.escaped_downgrades += 1;
            }
            continue;
        }

        report.downgrade_attempts += 1;
        let outcome = guard.inspect(&initial_packet(b"client hello"), peer, index);
        match outcome.verdict.code() {
            Some(VerdictCode::AlgorithmDowngrade) => report.caught_downgrades += 1,
            Some(_) | None => report.escaped_downgrades += 1,
        }
    }

    // Fragments "lost" alongside the classical handshakes: the selective-drop signature.
    report.injected_fragment_drops = 37;
    guard.record_fragment_drops(peer, report.injected_fragment_drops);

    // A PQ-only peer's fragment drops alone must not trip the heuristic (it needs a classical offer).
    let pq_only_outcome = guard.inspect(
        &initial_packet(&{
            let mut payload = b"client hello".to_vec();
            payload.extend_from_slice(&PQC_KEM_PATTERN);
            payload
        }),
        peer,
        999,
    );
    if pq_only_outcome.verdict.is_drop() {
        report.escaped_downgrades += 1;
    }

    // Split-view: two cosigners, one of them forking.
    for index in 0..10u64 {
        report.split_view_attempts += 1;
        split_view_fork(&mut rng, index, faults);
        let mut entries = vec![
            Cosignature::new(vec![0x2A], vec![0x11; 8]),
            Cosignature::new(vec![0x2B], vec![0x22; 8]),
        ];
        canonicalize_cosignatures(&mut entries).expect("distinct cosigners");

        let fork = if index % 2 == 0 {
            Some(Cosignature::new(vec![0x2A], vec![0x33; 8]))
        } else {
            None
        };
        if let Some(fork) = fork {
            entries.push(fork);
            if canonicalize_cosignatures(&mut entries) == Err(MtcError::DuplicateCosignerId) {
                report.split_view_rejected += 1;
            }
        }
    }

    // Sign the retained alerts with a real ML-DSA-65 key and verify them.
    let mut key_rng = ChaCha8Rng::seed_from_u64(0x5EED_1234);
    let (public_key, secret_key) = pqc::ml_dsa_65_keygen(&mut key_rng);
    guard.sign_alerts(&secret_key, &public_key);
    report.signed_alerts = guard.alerts().len();
    report.verified_alerts = guard
        .alerts()
        .entries()
        .iter()
        .filter(|alert| alert.verify(&public_key))
        .count();

    Ok(report)
}

/// Runs the scenario twice and compares the serialized reports byte-for-byte.
fn run_regression(config: SimConfig) -> Result<RegressionReport, ()> {
    let first = run(SimConfig {
        with_attack: false,
        with_regression: false,
        ..config
    });
    let second = run(SimConfig {
        with_attack: false,
        with_regression: false,
        ..config
    });

    let first_bytes = serde_json::to_string(&first).map_err(|_| ())?;
    let second_bytes = serde_json::to_string(&second).map_err(|_| ())?;
    let calibration = calibrate();

    Ok(RegressionReport {
        bit_exact: first_bytes == second_bytes,
        report_bytes: first_bytes.len(),
        calibration_passed: calibration_passed(&BenchReport {
            config: BenchConfig {
                runs: 1,
                seed: config.seed,
                loss_levels: vec![config.loss],
                seed_count: 1,
                stale_landmarks: config.stale_landmarks,
            },
            cells: Vec::new(),
            deltas: Vec::new(),
            ranks: Vec::new(),
            target_layer_stats: Vec::new(),
            calibration,
            faults_injected: 0,
        }),
    })
}

/// Builds a QUIC v1 Initial carrying `payload` in a CRYPTO frame.
fn initial_packet(payload: &[u8]) -> Vec<u8> {
    let mut frames = Vec::new();
    frames.push(0x06u8);
    frames.push(0x00);
    frames.extend_from_slice(&((payload.len() as u16) | 0x4000).to_be_bytes());
    frames.extend_from_slice(payload);

    let mut out = vec![0xC0u8 | 0x03];
    out.extend_from_slice(&1u32.to_be_bytes());
    out.push(4);
    out.extend_from_slice(b"dcid");
    out.push(4);
    out.extend_from_slice(b"scid");
    out.push(0x00);
    out.extend_from_slice(&(((4 + frames.len()) as u16) | 0x4000).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&frames);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DEFAULT_SEED;

    #[test]
    fn a_scenario_runs_and_reports_every_stack() {
        let config = SimConfig::new(DEFAULT_SEED, 0.03, 10_000);
        let report = run(config);

        assert_eq!(report.stacks.len(), 4);
        assert_eq!(report.seed_hex, "0x9F4A2C01");
        assert_eq!(report.config.loss, 0.03);

        let chronos = report.stack(StackKind::ChronosMtc).expect("target");
        let naive = report.stack(StackKind::NaivePqcQuic).expect("control");
        assert!(chronos.flight1_bytes <= 3_600);
        assert_eq!(chronos.amplification_stall_rounds, 0);
        assert!(naive.amplification_stall_rounds > 0);
        assert!(chronos.rounds.p99 < naive.rounds.p99);
        assert_eq!(chronos.success_rate, 1.0);
    }

    #[test]
    fn the_scenario_is_bit_exact_for_a_seed() {
        let config = SimConfig::new(DEFAULT_SEED, 0.03, 10_000);
        let first = run(config);
        let second = run(config);
        assert_eq!(first, second, "the same seed must replay exactly");
        assert!(first.regression_passed());
        assert!(first.attack_contained());
    }

    #[test]
    fn the_guard_contains_the_downgrade_attack() {
        let config = SimConfig::new(DEFAULT_SEED, 0.03, 10_000);
        let report = run(config);
        let attack = report.attack.expect("attack section");

        assert_eq!(attack.downgrade_attempts, 67, "two thirds of 100 attempts");
        assert_eq!(attack.pq_decoys, 33);
        assert_eq!(attack.caught_downgrades, 67, "every downgrade is caught");
        assert_eq!(attack.escaped_downgrades, 0);
        assert_eq!(attack.split_view_attempts, 10);
        assert_eq!(attack.split_view_rejected, 5, "the forked half is rejected");
        assert!(attack.signed_alerts > 0);
        assert_eq!(
            attack.signed_alerts, attack.verified_alerts,
            "all alerts verify"
        );
        assert!(attack.contained());
    }

    #[test]
    fn a_different_seed_changes_the_trace() {
        let a = run(SimConfig::new(DEFAULT_SEED, 0.03, 10_000));
        let b = run(SimConfig::new(DEFAULT_SEED ^ 1, 0.03, 10_000));
        assert_ne!(a.stacks, b.stacks);
    }

    #[test]
    fn higher_loss_costs_more_round_trips() {
        let clean = run(SimConfig::new(DEFAULT_SEED, 0.0, 10_000));
        let lossy = run(SimConfig::new(DEFAULT_SEED, 0.10, 10_000));

        let clean_chronos = clean.stack(StackKind::ChronosMtc).unwrap();
        let lossy_chronos = lossy.stack(StackKind::ChronosMtc).unwrap();
        assert!(lossy_chronos.rounds.p99 >= clean_chronos.rounds.p99);
        assert!(lossy_chronos.pto_events >= clean_chronos.pto_events);
    }
}
