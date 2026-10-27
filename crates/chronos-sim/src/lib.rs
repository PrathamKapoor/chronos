//! # chronos-sim
//!
//! The deterministic chaos harness, the five-layer latency profiler, Glass's Δ calculator and the
//! `chronos` CLI.
//!
//! One 64-bit seed drives everything — every drop, burst transition, bit flip, reorder and split-view
//! fork — so a failure is replayable in milliseconds and identical across machines. Nothing in the
//! harness reads the clock, the OS entropy pool or the thread scheduler; wall-clock timing is
//! excluded from the exported metrics on purpose, because it is not bit-exact and therefore cannot be
//! diffed against a previous run.
//!
//! ```text
//! chronos verify-vectors
//! chronos sim --seed 0x9F4A2C01 --loss 0.03 --stale-landmarks 10000
//! chronos bench --runs 1000 --seed 0x9F4A2C01 --export-dir artifacts
//! ```
//!
//! ## What is real and what is modelled
//!
//! * **Real, executed every run**: SHA-256, CRC32c, Reed-Solomon coding, the Merkle tree and its
//!   proofs, the budget planner, the QUIC frame codecs, the guard's parser and policy, and the
//!   reference PQ backend (hybrid key agreement with implicit rejection, ML-DSA-65 over external μ).
//!   `bench::calibrate()` runs that whole path once and reports what it proved.
//! * **Modelled, with calibrated constants**: per-packet timing. The simulator charges the documented
//!   nanosecond constants ([`profile::costs`]) instead of measuring, because a measurement is not
//!   reproducible. The constants only ever enter the *reported* metrics; every correctness decision in
//!   the harness is made by code that actually ran.

#![allow(unexpected_cfgs)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// The four lower layers are compiled into this crate from source rather than linked as `--extern`
// path dependencies.
//
// Why: on this build host rustc intermittently fails to place workspace path dependencies into the
// extern prelude for this package. Cargo passes correct, loadable `--extern` entries for all four and
// each artifact loads fine in isolation, yet the compile still fails with
// `error[E0433]: use of unresolved module or unlinked crate chrono_mtc_core`. Mounting the sources
// removes cross-crate metadata loading from the picture entirely: `chronos-sim` declares no path
// dependencies, so Cargo passes no `--extern chronos_*` at all and every layer resolves as an
// ordinary module.
//
// The lower layers still build standalone and keep their own 155 unit tests. Each is dual-mode:
// intra-crate paths are relative (`super::`), file-backed modules carry explicit `#[path]`, and the
// two files that reach for the MTC core or PQ layer import them through a `cfg(chronos_bundled)`
// alias that is off when they are built on their own. See decisions.md ADR-013.

/// Layer 5: the 256-byte QUIC Initial sensor, downgrade policy and batch verification rings.
#[path = "../../chronos-mtc-core/src/lib.rs"]
pub mod chronos_mtc_core;
pub use self::chronos_mtc_core as chrono_mtc_core;

#[path = "../../chronos-pqc-sys/src/lib.rs"]
pub mod chronos_pqc_sys;
pub use self::chronos_pqc_sys as chrono_pqc_sys;

#[path = "../../chronos-quic-fec/src/lib.rs"]
pub mod chronos_quic_fec;
pub use self::chronos_quic_fec as chrono_quic_fec;

#[path = "../../chronos-ebpf-guard/src/lib.rs"]
pub mod chronos_ebpf_guard;
pub use self::chronos_ebpf_guard as chrono_ebpf_guard;

pub mod bench;
pub mod deps;
pub mod glass;
pub mod net;
pub mod profile;
pub mod rng;
pub mod sim;
pub mod stacks;
pub mod stats;
pub mod vectors;

pub use bench::{
    calibration_passed, export, render_csv, render_scorecard, run_benchmark, BenchConfig,
    BenchReport, CalibrationReport, CellReport,
};
pub use glass::{glass_delta, rank_analysis, EffectSize, GlassDelta, RankAnalysis};
pub use net::{Channel, FaultKind, FaultLog, GilbertElliott};
pub use profile::{costs, LatencyProfiler, Layer, LayerBreakdown, LayerStats};
pub use rng::{format_seed, parse_seed, SimRng, DEFAULT_SEED};
pub use sim::{run as run_sim, SimConfig, SimReport};
pub use stacks::{
    plan_flight1, simulate_handshake, HandshakeOutcome, LossProfile, StackKind, StalenessProfile,
};
pub use stats::SampleStats;
pub use vectors::{verify_file, VerifyReport, VECTOR_PATH};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_surface_is_what_the_cli_needs() {
        assert_eq!(DEFAULT_SEED, 0x9F4A_2C01);
        assert_eq!(StackKind::ALL.len(), 4);
        assert_eq!(Layer::ALL.len(), 5);
        assert_eq!(VECTOR_PATH, "vectors/ietf_mtc_appendix_c.json");
        assert!(parse_seed("0x9F4A2C01").is_ok());
        assert_eq!(format_seed(DEFAULT_SEED), "0x9F4A2C01");
    }

    #[test]
    fn bench_config_defaults_match_the_documented_invocation() {
        let config = BenchConfig::default_runs();
        assert_eq!(config.runs, 1_000);
        assert_eq!(config.seed, DEFAULT_SEED);
        assert_eq!(config.loss_levels, vec![0.01, 0.03, 0.05, 0.10]);
        assert_eq!(config.stale_landmarks, 10_000);
    }

    #[test]
    fn sim_config_defaults_match_the_documented_invocation() {
        let config = SimConfig::new(DEFAULT_SEED, 0.03, 10_000);
        assert_eq!(config.seed, DEFAULT_SEED);
        assert_eq!(config.loss, 0.03);
        assert_eq!(config.stale_landmarks, 10_000);
        assert!(config.with_attack);
        assert!(config.with_regression);
    }
}

/// The command-line front end, mounted rather than compiled as a second binary target.
#[path = "bin/chronos.rs"]
pub mod cli_bin;

fn main() -> std::process::ExitCode {
    cli_bin::main()
}
