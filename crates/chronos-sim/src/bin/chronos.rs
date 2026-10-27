//! The `chronos` command-line interface.
//!
//! Three subcommands, each deterministic given its seed:
//!
//! ```text
//! chronos verify-vectors
//! chronos sim --seed 0x9F4A2C01 --loss 0.03 --stale-landmarks 10000
//! chronos bench --runs 1000 --seed 0x9F4A2C01 --export-dir artifacts
//! ```
//!
//! Everything the tool prints is a pure function of the inputs. No wall-clock timestamps, no host
//! names, no iteration over a hash map — so two runs of the same command produce byte-identical
//! output and a regression diff means something.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::bench::BenchConfig;
use crate::bench::{calibration_passed, export, render_csv, render_scorecard, run_benchmark};
use crate::rng::{format_seed, parse_seed, DEFAULT_SEED};
use crate::sim::{run as run_sim, SimConfig};
use crate::vectors::{verify_file, VECTOR_PATH};

/// Loss-resilient post-quantum QUIC with Merkle Tree Certificates.
#[derive(Parser, Debug)]
#[command(name = "chronos", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Replay the IETF PLANTS golden vectors against the implementation.
    VerifyVectors {
        /// Path to the vector file.
        #[arg(long, default_value = VECTOR_PATH)]
        vectors: PathBuf,
    },
    /// Replay one deterministic chaos scenario and print the trace.
    Sim {
        /// Master 64-bit seed.
        #[arg(long, default_value_t = DEFAULT_SEED, value_parser = parse_seed)]
        seed: u64,
        /// Channel loss target, 0.0 - 1.0.
        #[arg(long, default_value_t = 0.03)]
        loss: f64,
        /// How many epochs the client's landmark is stale by.
        #[arg(long, default_value_t = 10_000)]
        stale_landmarks: u64,
        /// Handshakes per stack.
        #[arg(long, default_value_t = 64)]
        runs: u32,
    },
    /// Run the comparative benchmark matrix and export it.
    Bench {
        /// Handshakes per (seed, loss, stack) cell.
        #[arg(long, default_value_t = 1_000)]
        runs: u32,
        /// Master 64-bit seed.
        #[arg(long, default_value_t = DEFAULT_SEED, value_parser = parse_seed)]
        seed: u64,
        /// Directory to write the export into.
        #[arg(long, default_value = "artifacts")]
        export_dir: PathBuf,
        /// Print the CSV matrix as well as the scorecard.
        #[arg(long)]
        csv: bool,
    },
}

/// Entry point for the `chronos` binary.
pub fn main() -> ExitCode {
    match Cli::parse().command {
        Command::VerifyVectors { vectors } => verify_vectors(&vectors),
        Command::Sim {
            seed,
            loss,
            stale_landmarks,
            runs,
        } => sim(seed, loss, stale_landmarks, runs),
        Command::Bench {
            runs,
            seed,
            export_dir,
            csv,
        } => bench(runs, seed, &export_dir, csv),
    }
}

fn verify_vectors(path: &std::path::Path) -> ExitCode {
    let report = match verify_file(path) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("vector replay failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("IETF PLANTS vector replay - {}", report.path);
    println!("{:<40} {:>8}", "case group", "replayed");
    println!("{:-<40} {:>8}", "-", "-");
    for (label, count) in [
        ("subtree hashes (draft 4.1)", report.subtree_hashes),
        ("two-subtree covers (draft 4.5.1)", report.subtree_covers),
        ("inclusion proofs", report.inclusion_proofs),
        ("consistency proofs", report.consistency_proofs),
        ("DER malleability guard (draft 12.6)", report.der_cases),
        ("streaming TBS leaf hashes (draft 7.2)", report.tbs_cases),
        ("C2SP cosignature encodings", report.cosign_cases),
        ("base-128 trust-anchor ranges", report.base128_cases),
    ] {
        println!("{label:<40} {count:>8}");
    }
    println!("{:-<40} {:>8}", "-", "-");
    println!("{:<40} {:>8}", "total", report.total());

    println!();
    println!("draft accumulated digests");
    for (name, expected) in &report.draft_accumulated {
        println!("  {name:<40} {expected}");
    }

    if report.accumulated_match {
        println!();
        println!("all four accumulated digests match the draft");
        ExitCode::SUCCESS
    } else {
        println!();
        println!("accumulated digests DID NOT match the draft");
        ExitCode::FAILURE
    }
}

fn sim(seed: u64, loss: f64, stale_landmarks: u64, runs: u32) -> ExitCode {
    let base = SimConfig::new(seed, loss, stale_landmarks);
    let report = run_sim(SimConfig { runs, ..base });

    println!("ChronosMTC deterministic chaos replay");
    println!("  seed              {}", report.seed_hex);
    println!("  loss target       {:.3}", report.config.loss);
    println!("  stale landmarks   {}", report.config.stale_landmarks);
    println!("  handshakes/stack  {}", report.config.runs);
    println!();

    println!(
        "{:<16} {:>9} {:>6} {:>7} {:>9} {:>9} {:>9} {:>8}",
        "stack", "flight1 B", "pkts", "parity", "p50 rtt", "p95 rtt", "p99 rtt", "success"
    );
    println!(
        "{:-<16} {:>9} {:>6} {:>7} {:>9} {:>9} {:>9} {:>8}",
        "-", "-", "-", "-", "-", "-", "-", "-"
    );
    for summary in &report.stacks {
        println!(
            "{:<16} {:>9} {:>6} {:>7} {:>9} {:>9} {:>9} {:>7.1}%",
            summary.stack,
            summary.flight1_bytes,
            summary.packets,
            summary.parity_shards,
            summary.rounds.p50,
            summary.rounds.p95,
            summary.rounds.p99,
            summary.success_rate * 100.0
        );
    }

    if !report.faults.is_empty() {
        println!();
        println!("faults injected");
        for (kind, count) in &report.faults {
            println!("  {kind:<40} {count:>8}");
        }
    }

    let mut ok = true;

    if let Some(attack) = &report.attack {
        println!();
        println!("active downgrade attack");
        println!("  downgrade attempts        {}", attack.downgrade_attempts);
        println!("  PQ decoy handshakes      {}", attack.pq_decoys);
        println!("  caught by the guard      {}", attack.caught_downgrades);
        println!("  escaped the guard        {}", attack.escaped_downgrades);
        println!(
            "  injected fragment drops  {}",
            attack.injected_fragment_drops
        );
        println!("  split-view fork attempts {}", attack.split_view_attempts);
        println!("  rejected as duplicates   {}", attack.split_view_rejected);
        ok &= report.attack_contained();
    }

    if let Some(regression) = &report.regression {
        println!();
        println!("determinism regression");
        println!("  byte-exact across runs   {}", regression.bit_exact);
        println!("  report bytes             {}", regression.report_bytes);
        println!(
            "  calibration passed       {}",
            regression.calibration_passed
        );
        ok &= report.regression_passed();
    }

    println!();
    if ok {
        println!("scenario passed");
        ExitCode::SUCCESS
    } else {
        println!("scenario FAILED");
        ExitCode::FAILURE
    }
}

fn bench(runs: u32, seed: u64, export_dir: &std::path::Path, csv: bool) -> ExitCode {
    let config = BenchConfig {
        runs,
        seed,
        ..BenchConfig::default_runs()
    };
    let report = run_benchmark(config);

    print!("{}", render_scorecard(&report));

    if csv {
        println!();
        print!("{}", render_csv(&report));
    }

    let calibration_ok = calibration_passed(&report);

    match export(&report, export_dir) {
        Ok(written) => {
            println!();
            println!("exported");
            for path in written {
                println!("  {}", path.display());
            }
        }
        Err(error) => {
            eprintln!("export failed: {error}");
            return ExitCode::FAILURE;
        }
    }

    println!();
    println!("seed {}", format_seed(seed));
    if calibration_ok {
        println!("calibration passed");
        ExitCode::SUCCESS
    } else {
        println!("calibration FAILED");
        ExitCode::FAILURE
    }
}
