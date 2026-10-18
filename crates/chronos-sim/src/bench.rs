//! The benchmark driver: a seed × loss matrix over all four stacks, Glass's Δ, and the export.
//!
//! Determinism is the design constraint. Every export is byte-identical for a given seed: no
//! timestamps, no host names, no iteration over a hash map. A rerun of
//! `chronos bench --runs 1000 --seed 0x9F4A2C01` produces the same three files, which is what makes a
//! regression diff meaningful.

use crate::glass::{glass_delta, rank_analysis, EffectSize, GlassDelta, RankAnalysis};
use crate::net::{Channel, FaultLog};
use crate::profile::{costs, LatencyProfiler, LayerStats};
use crate::rng::{format_seed, SimRng, DEFAULT_SEED};
use crate::stacks::{
    credit_bytes, plan_flight1, simulate_handshake, LossProfile, StackKind, StalenessProfile,
};
use crate::stats::SampleStats;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// The workspace path dependencies are bound with 2018 `use ... as ...` aliases. Aliases keep the
// call sites short (`mtc::`, `guard::`, `fec::`, `pqc::`) and make the provenance explicit.
//
// These are deliberately *not* `extern crate ... as ...` bindings. `extern crate` resolves its
// argument through a different path than the extern prelude, and on this host it fails to resolve
// workspace path dependencies outright: `error[E0463]: can't find crate for chrono_mtc_core` is
// emitted even though cargo passes a correct, loadable `--extern` for it, and the same `--extern`
// works for every other consumer in the workspace. The 2018 form resolves through the extern
// prelude like any other import, which is the path that demonstrably works.
use chrono_ebpf_guard as guard;
use chrono_mtc_core as mtc;
use chrono_pqc_sys as pqc;
use chrono_quic_fec as fec;

use fec::{encode_block, FecBlockAssembler};
use guard::kernel::{GuardConfig, UserspaceGuard};
use guard::policy::{MigrationPhase, PeerAddr, VerdictCode};
use mtc::cosign::{canonicalize_cosignatures, Cosignature, MtcProof};
use mtc::skip_link::LandmarkGraph;
use mtc::subtrees::MerkleTreeLog;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

/// Loss targets the matrix sweeps.
pub const LOSS_LEVELS: [f64; 4] = [0.01, 0.03, 0.05, 0.10];
/// Number of derived seeds in the matrix.
pub const SEED_COUNT: usize = 4;
/// Number of landmarks published by the calibration pass with real ML-DSA-65 signing.
pub const CALIBRATION_LANDMARKS: u64 = 1_024;
/// Domain separator for the calibration's signatures.
const CALIBRATION_CONTEXT: &[u8] = b"chronos-calibration/v1";

/// Benchmark configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchConfig {
    /// Handshakes per (seed, loss, stack) cell.
    pub runs: u32,
    /// Master seed.
    pub seed: u64,
    /// Loss targets.
    pub loss_levels: Vec<f64>,
    /// Number of seeds derived from the master seed.
    pub seed_count: usize,
    /// How stale the client's landmark is.
    pub stale_landmarks: u64,
}

impl BenchConfig {
    /// The documented default: 1,000 runs, seed `0x9F4A2C01`, four loss levels, 10,000 stale epochs.
    pub fn default_runs() -> Self {
        Self {
            runs: 1_000,
            seed: DEFAULT_SEED,
            loss_levels: LOSS_LEVELS.to_vec(),
            seed_count: SEED_COUNT,
            stale_landmarks: 10_000,
        }
    }

    /// Derives the seeds of the matrix from the master seed.
    pub fn seeds(&self) -> Vec<u64> {
        (0..self.seed_count)
            .map(|index| {
                if index == 0 {
                    self.seed
                } else {
                    self.seed ^ (0x9E37_79B9_7F4A_7C15u64.wrapping_mul(index as u64))
                }
            })
            .collect()
    }
}

/// One (seed, loss, stack) cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CellReport {
    /// Derived seed, decimal.
    pub seed: u64,
    /// Derived seed, hex.
    pub seed_hex: String,
    /// Loss target.
    pub loss: f64,
    /// Which stack.
    pub stack: String,
    /// Handshakes executed.
    pub runs: u32,
    /// Fraction that completed inside the PTO budget.
    pub success_rate: f64,
    /// Round-trip distribution.
    pub rounds: SampleStats,
    /// Total nanoseconds per handshake.
    pub total_ns: SampleStats,
    /// Wire bytes per handshake.
    pub wire_bytes: SampleStats,
    /// Total PTOs charged across the cell.
    pub pto_events: u64,
    /// Total shards reconstructed from parity.
    pub fec_recovered: u64,
    /// Total round trips lost to the anti-amplification limit.
    pub amplification_stall_rounds: u64,
    /// Total datagrams lost.
    pub packets_lost: u64,
}

/// A real end-to-end run of the cryptographic path, executed once per benchmark.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationReport {
    /// Hybrid key agreement agreed.
    pub kem_agreed: bool,
    /// ML-DSA-65 signature verified over external μ.
    pub signature_verified: bool,
    /// Merkle inclusion proof verified.
    pub inclusion_verified: bool,
    /// A skip-link plan verified, every checkpoint signed and checked with ML-DSA-65.
    pub skip_link_verified: bool,
    /// One parity shard reconstructed from an erasure.
    pub fec_recovered: bool,
    /// Guard dropped a downgrade attempt in `PqOnly` mode.
    pub guard_caught_downgrade: bool,
    /// Split-view fork rejected as a duplicate cosigner.
    pub split_view_rejected: bool,
    /// Bytes the FEC block occupied on the wire.
    pub fec_wire_bytes: usize,
    /// Skip-link hops in the calibration plan.
    pub skip_link_hops: usize,
    /// Payload bytes a ChronosMTC Flight 1 carried at 3 % loss.
    pub chronos_flight1_bytes: usize,
    /// Anti-amplification credit those bytes had to fit in.
    pub credit_bytes: usize,
}

/// The complete benchmark report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchReport {
    /// Configuration used.
    pub config: BenchConfig,
    /// Every cell, in a fixed order.
    pub cells: Vec<CellReport>,
    /// Δ of the target against each control, per loss level.
    pub deltas: Vec<GlassDelta>,
    /// Paired rank analysis against each control, per loss level.
    pub ranks: Vec<RankAnalysis>,
    /// Per-layer statistics for the target stack.
    pub target_layer_stats: Vec<LayerStats>,
    /// The real-crypto calibration pass.
    pub calibration: CalibrationReport,
    /// Total faults recorded across the matrix.
    pub faults_injected: u64,
}

/// Runs the full benchmark matrix.
pub fn run_benchmark(config: BenchConfig) -> BenchReport {
    let calibration = calibrate();
    let staleness = StalenessProfile::stale(10_000, config.stale_landmarks);

    let mut cells = Vec::new();
    let mut faults_injected = 0u64;
    let mut target_profiler = LatencyProfiler::new();
    let mut rounds_samples: Vec<(f64, Vec<u64>)> = Vec::new();
    let mut control_samples: Vec<(f64, StackKind, Vec<u64>)> = Vec::new();

    for seed in config.seeds() {
        for loss in &config.loss_levels {
            for stack in StackKind::ALL {
                let master = SimRng::new(seed);
                let stream_name = format!("cell:{stack:?}:{loss:.4}:{}", config.stale_landmarks);
                let mut rng = master.sub(&stream_name);
                let mut channel = Channel::for_target_loss(*loss);
                let mut faults = FaultLog::new();

                let mut rounds = Vec::with_capacity(config.runs as usize);
                let mut total_ns = Vec::with_capacity(config.runs as usize);
                let mut wire_bytes = Vec::with_capacity(config.runs as usize);
                let mut successes = 0u32;
                let mut pto_events = 0u64;
                let mut fec_recovered = 0u64;
                let mut stalls = 0u64;
                let mut packets_lost = 0u64;

                for _ in 0..config.runs {
                    let outcome = simulate_handshake(
                        stack,
                        &mut channel,
                        &mut rng,
                        staleness,
                        LossProfile::new(*loss),
                        &mut faults,
                    );
                    rounds.push(u64::from(outcome.rounds));
                    total_ns.push(outcome.total_ns);
                    wire_bytes.push(outcome.wire_bytes);
                    successes += u32::from(outcome.success);
                    pto_events += u64::from(outcome.pto_events);
                    fec_recovered += u64::from(outcome.fec_recovered);
                    stalls += u64::from(outcome.amplification_stall_rounds);
                    packets_lost += u64::from(outcome.packets_lost);

                    if stack == StackKind::ChronosMtc {
                        target_profiler.record(outcome.layers);
                    }
                }

                faults_injected += faults.total() as u64;
                cells.push(CellReport {
                    seed,
                    seed_hex: format_seed(seed),
                    loss: *loss,
                    stack: stack.label().to_string(),
                    runs: config.runs,
                    success_rate: successes as f64 / config.runs.max(1) as f64,
                    rounds: SampleStats::of(&rounds),
                    total_ns: SampleStats::of(&total_ns),
                    wire_bytes: SampleStats::of(&wire_bytes),
                    pto_events,
                    fec_recovered,
                    amplification_stall_rounds: stalls,
                    packets_lost,
                });

                if stack == StackKind::ChronosMtc {
                    rounds_samples.push((*loss, rounds));
                } else {
                    control_samples.push((*loss, stack, rounds));
                }
            }
        }
    }

    let mut deltas = Vec::new();
    let mut ranks = Vec::new();
    for loss in &config.loss_levels {
        let Some((_, target_rounds)) = rounds_samples.iter().find(|(value, _)| value == loss)
        else {
            continue;
        };
        for (_, control, control_rounds) in
            control_samples.iter().filter(|(value, _, _)| value == loss)
        {
            let mut delta = glass_delta(
                StackKind::ChronosMtc.label(),
                control.label(),
                target_rounds,
                control_rounds,
            );
            delta.loss = Some(*loss);
            deltas.push(delta);
            ranks.push(rank_analysis(target_rounds, control_rounds));
        }
    }

    BenchReport {
        config,
        cells,
        deltas,
        ranks,
        target_layer_stats: target_profiler.layer_stats(),
        calibration,
        faults_injected,
    }
}

/// Executes the real cryptographic path once, so the constants in the model are anchored to code that
/// actually runs rather than to a description of code that might.
pub fn calibrate() -> CalibrationReport {
    let mut rng = ChaCha8Rng::seed_from_u64(DEFAULT_SEED);

    // 1. Hybrid key agreement, with implicit rejection on a tampered ciphertext.
    let (kem_pk, kem_sk) = pqc::x25519_mlkem768_keygen(&mut rng);
    let (kem_ct, client_secret) = pqc::x25519_mlkem768_encapsulate(&kem_pk, &mut rng);
    let server_secret = pqc::x25519_mlkem768_decapsulate(&kem_sk, &kem_ct);
    let kem_agreed = client_secret == server_secret;

    // 2. ML-DSA-65 over a streaming external μ. The same key signs the calibration checkpoints, so
    //    the skip-link verification below is a real signature check rather than a stub.
    let (sign_pk, sign_sk) = pqc::ml_dsa_65_keygen(&mut rng);
    let tr = sign_pk.key_hash();
    let mu = pqc::ExternalMuHasher::digest(&tr, CALIBRATION_CONTEXT, client_secret.as_bytes())
        .expect("the calibration context is short");
    let signature = pqc::ml_dsa_65_sign(&sign_sk, &mu);
    let signature_verified = pqc::ml_dsa_65_verify(&sign_pk, &mu, &signature);

    let checkpoint_mu = |message: &[u8]| {
        pqc::ExternalMuHasher::digest(&tr, CALIBRATION_CONTEXT, message)
            .expect("calibration context length")
    };
    let sign_checkpoint = |message: &[u8]| -> Vec<u8> {
        pqc::ml_dsa_65_sign(&sign_sk, &checkpoint_mu(message))
            .as_bytes()
            .to_vec()
    };
    let verify_checkpoint = |message: &[u8], signature: &[u8]| -> bool {
        let Ok(array) = <[u8; pqc::ML_DSA_65_SIGNATURE_LEN]>::try_from(signature) else {
            return false;
        };
        pqc::ml_dsa_65_verify(
            &sign_pk,
            &checkpoint_mu(message),
            &pqc::MlDsa65Signature::from_bytes(array),
        )
    };

    // 3. A real Merkle log, inclusion proof, and canonical MTCProof encoding.
    let mut log = MerkleTreeLog::new();
    for index in 0..64u32 {
        log.append_raw_entry(&index.to_be_bytes());
    }
    let leaf = log.leaf_hash_at(10).expect("leaf");
    let subtree = log.subtree_hash(0, 64).expect("subtree");
    let proof = log.inclusion_proof(10, 0, 64).expect("inclusion proof");
    let inclusion_verified =
        MerkleTreeLog::verify_inclusion(&leaf, 10, 0, 64, &proof, &subtree).is_ok();

    let mut cosignatures = vec![
        Cosignature::new(vec![0x0A, 0x0A], vec![0x00; 8]),
        Cosignature::new(vec![0xFF], vec![0x11; 8]),
        Cosignature::new(vec![0x01, 0x02], vec![0x22; 8]),
    ];
    canonicalize_cosignatures(&mut cosignatures).expect("distinct cosigners");
    let mtc_proof = MtcProof {
        extensions: vec![0x30, 0x00],
        start: 0,
        end: 64,
        inclusion_proof: proof.clone(),
        signatures: cosignatures,
    };
    let encoded = mtc_proof.encode().expect("canonical MTCProof");
    let round_trip = MtcProof::decode(&encoded).expect("decode");

    // A split-view fork: a cosigner emits a second signature for the same subtree.
    let mut forked = mtc_proof.clone();
    forked
        .signatures
        .push(Cosignature::new(vec![0xFF], vec![0x33; 8]));
    let split_view_rejected =
        forked.encode() == Err(MtcError::DuplicateCosignerId) && round_trip.encode() == Ok(encoded);

    // 4. A real skip-link plan, every checkpoint signed and verified with ML-DSA-65.
    let mut landmarks = LandmarkGraph::new();
    for landmark in 0..CALIBRATION_LANDMARKS {
        landmarks
            .publish_landmark(&log, landmark, &sign_checkpoint)
            .expect("publish");
    }
    let client_root = landmarks.landmark(0).expect("landmark 0").root_hash;
    let plan = landmarks
        .plan_skip_link_sync(&log, 0, CALIBRATION_LANDMARKS - 1)
        .expect("plan");
    let skip_link_verified =
        LandmarkGraph::verify_skip_link_sync(&plan, &client_root, &verify_checkpoint).is_ok();

    // 5. A real erasure-coded block losing one data shard.
    let payload: Vec<u8> = (0..2_000u32).map(|value| (value % 251) as u8).collect();
    let block = encode_block(1, &payload, 8, 1).expect("encode");
    let mut assembler = FecBlockAssembler::new(
        block.block_id,
        8,
        1,
        block.layout.shard_len,
        block.layout.payload_len,
    )
    .expect("assembler");
    for frame in &block.repair_frames {
        assembler.add_repair(frame).expect("repair");
    }
    for (index, frame) in block.source_frames.iter().enumerate() {
        if index != 3 {
            assembler.add_source(frame).expect("source");
        }
    }
    let outcome = assembler.assemble().expect("assemble");
    let fec_recovered = outcome.payload == payload && outcome.recovered_shard_indices == vec![3];
    let fec_wire_bytes = block.total_wire_bytes();

    // 6. The real guard, on a real Initial packet, in `PqOnly` mode.
    let mut guard = UserspaceGuard::new(GuardConfig::new(MigrationPhase::PqOnly));
    let outcome = guard.inspect(
        &build_initial(b"client hello without pq"),
        PeerAddr {
            ip: [192, 0, 2, 1],
            port: 4433,
        },
        1_700_000_000_000_000_000,
    );
    let guard_caught_downgrade = outcome.verdict.code() == Some(VerdictCode::AlgorithmDowngrade);

    let shape = plan_flight1(
        StackKind::ChronosMtc,
        StalenessProfile::stale(10_000, 10_000),
        LossProfile::new(0.03),
    );

    CalibrationReport {
        kem_agreed,
        signature_verified,
        inclusion_verified,
        skip_link_verified,
        fec_recovered,
        guard_caught_downgrade,
        split_view_rejected,
        fec_wire_bytes,
        skip_link_hops: plan.hop_count(),
        chronos_flight1_bytes: shape.payload_bytes,
        credit_bytes: credit_bytes(),
    }
}

/// Builds a QUIC v1 Initial carrying `payload` in a CRYPTO frame.
fn build_initial(payload: &[u8]) -> Vec<u8> {
    let mut frames = Vec::new();
    frames.push(0x06u8); // CRYPTO
    frames.push(0x00); // offset 0
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

/// The markdown scorecard.
pub fn render_scorecard(report: &BenchReport) -> String {
    let mut out = String::new();
    out.push_str("# ChronosMTC benchmark scorecard\n\n");
    out.push_str(&format!(
        "- Seed: `{}` (matrix of {} seeds)\n- Runs per cell: {}\n- Loss targets: {}\n- Client staleness: {} epochs\n- Anti-amplification credit: {} B\n\n",
        format_seed(report.config.seed),
        report.config.seed_count,
        report.config.runs,
        report
            .config
            .loss_levels
            .iter()
            .map(|loss| format!("{:.0}%", loss * 100.0))
            .collect::<Vec<_>>()
            .join(", "),
        report.config.stale_landmarks,
        credit_bytes(),
    ));

    out.push_str("## Handshake round trips (p50 / p95 / p99)\n\n");
    out.push_str(
        "| Loss | Stack | p50 | p95 | p99 | PTOs | FEC recoveries | Amplification stalls |\n",
    );
    out.push_str("|---|---|---|---|---|---|---|---|\n");
    for cell in &report.cells {
        out.push_str(&format!(
            "| {:.0}% | {} | {} | {} | {} | {} | {} | {} |\n",
            cell.loss * 100.0,
            cell.stack,
            cell.rounds.p50,
            cell.rounds.p95,
            cell.rounds.p99,
            cell.pto_events,
            cell.fec_recovered,
            cell.amplification_stall_rounds,
        ));
    }

    out.push_str("\n## Glass's delta of ChronosMtc against each control\n\n");
    out.push_str(
        "| Loss | Control | delta (p99 rounds) | Relative p99 change | Effect size | Rank status |\n",
    );
    out.push_str("|---|---|---|---|---|---|\n");
    for (index, delta) in report.deltas.iter().enumerate() {
        let rank = report.ranks.get(index);
        let loss_text = delta
            .loss
            .map_or_else(|| "—".to_string(), |loss| format!("{:.0}%", loss * 100.0));
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            loss_text,
            delta.control,
            delta.delta_text(),
            delta.relative_change_text(),
            delta.effect_size.label(),
            rank.map_or("n/a", RankAnalysis::status),
        ));
    }

    out.push_str("\n## Five-layer cost model (ChronosMtc)\n\n");
    out.push_str("| Layer | mean ns | p99 ns | share |\n|---|---|---|---|\n");
    for stats in &report.target_layer_stats {
        out.push_str(&format!(
            "| {} | {} | {} | {:.1}% |\n",
            stats.layer.label(),
            stats.total.mean,
            stats.total.p99,
            stats.mean_share * 100.0,
        ));
    }

    let calibration = &report.calibration;
    out.push_str("\n## Calibration (real cryptography, executed)\n\n");
    out.push_str(&format!(
        "| Check | Result |\n|---|---|\n\
         | Hybrid key agreement | {} |\n\
         | ML-DSA-65 over external mu | {} |\n\
         | Merkle inclusion proof | {} |\n\
         | Skip-link plan over {} landmarks | {} ({} hops) |\n\
         | FEC reconstruction after 1 loss | {} ({} B block) |\n\
         | Guard caught downgrade in PqOnly | {} |\n\
         | Split-view fork rejected | {} |\n\
         | ChronosMTC Flight 1 at 3% loss | {} B of {} B credit |\n",
        calibration.kem_agreed,
        calibration.signature_verified,
        calibration.inclusion_verified,
        CALIBRATION_LANDMARKS,
        calibration.skip_link_verified,
        calibration.skip_link_hops,
        calibration.fec_recovered,
        calibration.fec_wire_bytes,
        calibration.guard_caught_downgrade,
        calibration.split_view_rejected,
        calibration.chronos_flight1_bytes,
        calibration.credit_bytes,
    ));
    out.push_str("\nCalibrated constants: ");
    out.push_str(&format!(
        "keygen {} ns, encaps {} ns, DSA verify {} ns, RS encode {} ns/shard, RTT {} ns, PTO {} ns.\n",
        costs::KEYGEN_HYBRID_NS,
        costs::ENCAPSULATE_NS,
        costs::ML_DSA_VERIFY_NS,
        costs::RS_ENCODE_SHARD_NS,
        costs::RTT_NS,
        costs::PTO_BASE_NS,
    ));
    out
}

/// The CSV matrix.
pub fn render_csv(report: &BenchReport) -> String {
    let mut out = String::from(
        "seed,seed_hex,loss,stack,runs,success_rate,rounds_p50,rounds_p95,rounds_p99,total_ns_p50,total_ns_p99,wire_bytes_p50,pto_events,fec_recovered,amplification_stall_rounds,packets_lost\n",
    );
    for cell in &report.cells {
        out.push_str(&format!(
            "{},{},{:.4},{},{},{:.4},{},{},{},{},{},{},{},{},{},{}\n",
            cell.seed,
            cell.seed_hex,
            cell.loss,
            cell.stack,
            cell.runs,
            cell.success_rate,
            cell.rounds.p50,
            cell.rounds.p95,
            cell.rounds.p99,
            cell.total_ns.p50,
            cell.total_ns.p99,
            cell.wire_bytes.p50,
            cell.pto_events,
            cell.fec_recovered,
            cell.amplification_stall_rounds,
            cell.packets_lost,
        ));
    }
    out
}

/// Writes `benchmark_summary.json`, `benchmark_matrix.csv` and `benchmark_scorecard.md`.
///
/// The output is a pure function of the report: no timestamps, no host details.
pub fn export(report: &BenchReport, directory: &Path) -> std::io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(directory)?;

    let json_path = directory.join("benchmark_summary.json");
    let csv_path = directory.join("benchmark_matrix.csv");
    let scorecard_path = directory.join("benchmark_scorecard.md");

    let json = serde_json::to_string_pretty(report)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    std::fs::write(&json_path, json)?;
    std::fs::write(&csv_path, render_csv(report))?;
    std::fs::write(&scorecard_path, render_scorecard(report))?;

    Ok(vec![json_path, csv_path, scorecard_path])
}

/// True when every calibration check passed.
pub fn calibration_passed(report: &BenchReport) -> bool {
    let calibration = &report.calibration;
    calibration.kem_agreed
        && calibration.signature_verified
        && calibration.inclusion_verified
        && calibration.skip_link_verified
        && calibration.fec_recovered
        && calibration.guard_caught_downgrade
        && calibration.split_view_rejected
        && calibration.chronos_flight1_bytes <= calibration.credit_bytes
}

/// A compact human-readable summary of one cell, for the CLI.
pub fn cell_summary(cell: &CellReport) -> String {
    format!(
        "{:<14} loss {:>4.0}%  rounds p50={} p95={} p99={}  PTOs={}  FEC={}  stalls={}",
        cell.stack,
        cell.loss * 100.0,
        cell.rounds.p50,
        cell.rounds.p95,
        cell.rounds.p99,
        cell.pto_events,
        cell.fec_recovered,
        cell.amplification_stall_rounds,
    )
}

/// Effect size of a Δ record, for the CLI summary.
pub fn effect_size(delta: &GlassDelta) -> EffectSize {
    delta.effect_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_are_derived_deterministically() {
        let config = BenchConfig::default_runs();
        let seeds = config.seeds();
        assert_eq!(seeds.len(), SEED_COUNT);
        assert_eq!(seeds[0], DEFAULT_SEED);
        assert_eq!(seeds, config.seeds());
        assert_ne!(seeds[0], seeds[1]);
    }

    #[test]
    fn calibration_runs_the_real_cryptography() {
        let calibration = calibrate();
        assert!(calibration.kem_agreed, "hybrid key agreement must agree");
        assert!(calibration.signature_verified);
        assert!(calibration.inclusion_verified);
        assert!(calibration.skip_link_verified);
        assert!(calibration.fec_recovered);
        assert!(calibration.guard_caught_downgrade);
        assert!(calibration.split_view_rejected);
        assert!(
            calibration.chronos_flight1_bytes <= calibration.credit_bytes,
            "Flight 1 must fit the credit"
        );
        assert_eq!(calibration.skip_link_hops, 10, "popcount(1023)");
        assert_eq!(calibration.credit_bytes, 3_600);
    }

    #[test]
    fn a_small_benchmark_is_bit_exact() {
        let config = BenchConfig {
            runs: 12,
            seed: DEFAULT_SEED,
            loss_levels: vec![0.03],
            seed_count: 2,
            stale_landmarks: 10_000,
        };
        let first = run_benchmark(config);
        let second = run_benchmark(config);
        assert_eq!(first, second, "the same seed must replay exactly");

        assert_eq!(first.cells.len(), 2 * 1 * 4);
        assert_eq!(first.deltas.len(), 3, "target against three controls");
        assert_eq!(first.ranks.len(), 3);
        assert!(calibration_passed(&first));
    }

    #[test]
    fn chronos_beats_the_controls_on_round_trips() {
        let config = BenchConfig {
            runs: 200,
            seed: DEFAULT_SEED,
            loss_levels: vec![0.03],
            seed_count: 1,
            stale_landmarks: 10_000,
        };
        let report = run_benchmark(config);

        let p99_of = |stack: &str| {
            report
                .cells
                .iter()
                .find(|cell| cell.stack == stack)
                .expect("cell")
                .rounds
                .p99
        };
        assert!(
            p99_of("ChronosMtc") < p99_of("NaivePqcQuic"),
            "ChronosMtc p99 {} vs NaivePqcQuic p99 {}",
            p99_of("ChronosMtc"),
            p99_of("NaivePqcQuic")
        );
        assert!(p99_of("ChronosMtc") < p99_of("DraftMtcQuic"));
    }

    #[test]
    fn export_writes_three_deterministic_files() {
        let config = BenchConfig {
            runs: 8,
            seed: DEFAULT_SEED,
            loss_levels: vec![0.01],
            seed_count: 1,
            stale_landmarks: 1_000,
        };
        let report = run_benchmark(config);
        let directory = PathBuf::from("target/test-export-chronos-sim");
        let _ = std::fs::remove_dir_all(&directory);

        let paths = export(&report, &directory).expect("export");
        assert_eq!(paths.len(), 3);
        for path in &paths {
            assert!(path.exists(), "{} missing", path.display());
        }

        let first_csv = std::fs::read_to_string(&directory.join("benchmark_matrix.csv")).unwrap();
        assert_eq!(
            first_csv,
            render_csv(&report),
            "CSV must be a pure function"
        );

        let scorecard = std::fs::read_to_string(&directory.join("benchmark_scorecard.md")).unwrap();
        assert!(scorecard.contains("# ChronosMTC benchmark scorecard"));
        assert!(scorecard.contains("ChronosMtc"));
        assert!(!scorecard.contains("T00:00"), "no timestamps in exports");

        std::fs::remove_dir_all(&directory).expect("cleanup");
    }
}
