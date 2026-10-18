//! Seed handling and the deterministic random stream.
//!
//! One 64-bit seed drives everything: every drop, burst transition, bit flip, reordering decision and
//! split-view fork. Nothing consults the clock, the OS entropy pool or the thread scheduler, so two
//! runs of the same scenario on two machines produce byte-identical reports.

use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The default seed, as documented in `flow.md` §7.3.5.
pub const DEFAULT_SEED: u64 = 0x9F4A_2C01;

/// Errors produced while parsing a seed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SeedError {
    /// The string was empty.
    #[error("empty seed")]
    Empty,
    /// The string was neither decimal nor `0x`-prefixed hexadecimal.
    #[error("seed {value:?} is neither decimal nor 0x-prefixed hex")]
    NotANumber {
        /// The rejected input.
        value: String,
    },
}

/// Parses a seed given in decimal (`2678338561`) or hexadecimal (`0x9F4A2C01`).
pub fn parse_seed(text: &str) -> Result<u64, SeedError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(SeedError::Empty);
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).map_err(|_| SeedError::NotANumber {
            value: text.to_string(),
        });
    }
    trimmed.parse::<u64>().map_err(|_| SeedError::NotANumber {
        value: text.to_string(),
    })
}

/// Renders a seed the way the CLI prints it.
pub fn format_seed(seed: u64) -> String {
    format!("0x{seed:08X}")
}

/// A named, reproducible sub-stream of the master seed.
///
/// Named streams matter: adding a fault injector to the network model must not shift the draws that
/// the stacks consume, or every previously-recorded scenario would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimRng {
    master_seed: u64,
    stream: String,
    inner: ChaCha8Rng,
    draws: u64,
}

impl SimRng {
    /// Creates the master stream.
    pub fn new(seed: u64) -> Self {
        Self {
            master_seed: seed,
            stream: "master".to_string(),
            inner: ChaCha8Rng::seed_from_u64(seed),
            draws: 0,
        }
    }

    /// Creates a named sub-stream. The name is folded into the seed with FNV-1a, so
    /// `sub("net")` and `sub("pqc")` are independent and stable across runs.
    pub fn sub(&self, stream: &str) -> Self {
        Self {
            master_seed: self.master_seed,
            stream: stream.to_string(),
            inner: ChaCha8Rng::seed_from_u64(self.master_seed ^ fnv1a(stream)),
            draws: 0,
        }
    }

    /// The master seed this stream derives from.
    pub fn master_seed(&self) -> u64 {
        self.master_seed
    }

    /// The stream name.
    pub fn stream_name(&self) -> &str {
        &self.stream
    }

    /// Number of draws taken so far (used to prove two replays consumed the same stream).
    pub fn draws(&self) -> u64 {
        self.draws
    }

    /// Uniform `f64` in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        self.draws += 1;
        // 53 bits of mantissa from two u32 draws keeps the mapping exact and platform independent.
        let hi = self.next_u32();
        let lo = self.next_u32();
        ((u64::from(hi) << 21 | (u64::from(lo) >> 11)) as f64) / ((1u64 << 53) as f64)
    }

    /// Uniform `f64` in `[low, high)`.
    pub fn range_f64(&mut self, low: f64, high: f64) -> f64 {
        low + self.unit() * (high - low)
    }

    /// Uniform `usize` in `[0, bound)`; returns 0 when `bound == 0`.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        self.draws += 1;
        (self.next_u64() % bound as u64) as usize
    }

    /// Bernoulli draw with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    /// Fills a byte buffer.
    pub fn fill_bytes(&mut self, buffer: &mut [u8]) {
        self.draws += 1;
        self.inner.fill_bytes(buffer);
    }

    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }
}

/// FNV-1a over the stream name.
fn fnv1a(text: &str) -> u64 {
    let mut hash = 0xCBF2_9CE4_8422_2325u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01B3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex_seeds() {
        assert_eq!(parse_seed("0x9F4A2C01").unwrap(), DEFAULT_SEED);
        assert_eq!(parse_seed("0X9f4a2c01").unwrap(), DEFAULT_SEED);
        assert_eq!(parse_seed(" 0x9F4A2C01 ").unwrap(), DEFAULT_SEED);
        assert_eq!(parse_seed("2678338561").unwrap(), DEFAULT_SEED);
        assert_eq!(parse_seed("0").unwrap(), 0);
        assert_eq!(parse_seed(&u64::MAX.to_string()).unwrap(), u64::MAX);
    }

    #[test]
    fn rejects_bad_seeds() {
        assert_eq!(parse_seed(""), Err(SeedError::Empty));
        assert_eq!(parse_seed("   "), Err(SeedError::Empty));
        assert!(matches!(
            parse_seed("0xZZ"),
            Err(SeedError::NotANumber { .. })
        ));
        assert!(matches!(
            parse_seed("-1"),
            Err(SeedError::NotANumber { .. })
        ));
        assert!(matches!(
            parse_seed("0x10000000000000000"),
            Err(SeedError::NotANumber { .. })
        ));
    }

    #[test]
    fn formats_the_way_the_cli_prints() {
        assert_eq!(format_seed(DEFAULT_SEED), "0x9F4A2C01");
        assert_eq!(format_seed(0), "0x00000000");
    }

    #[test]
    fn the_same_seed_replays_the_same_stream() {
        let mut a = SimRng::new(DEFAULT_SEED).sub("net");
        let mut b = SimRng::new(DEFAULT_SEED).sub("net");
        for _ in 0..1_000 {
            assert_eq!(a.unit(), b.unit());
            assert_eq!(a.below(37), b.below(37));
        }
        assert_eq!(a.draws(), b.draws());
    }

    #[test]
    fn named_streams_are_independent() {
        let master = SimRng::new(DEFAULT_SEED);
        let mut net = master.sub("net");
        let mut pqc = master.sub("pqc");

        let net_draws: Vec<f64> = (0..16).map(|_| net.unit()).collect();
        let pqc_draws: Vec<f64> = (0..16).map(|_| pqc.unit()).collect();
        assert_ne!(net_draws, pqc_draws);

        // A different seed changes everything.
        let mut other = SimRng::new(DEFAULT_SEED ^ 1).sub("net");
        assert_ne!(net_draws[0], other.unit());
    }

    #[test]
    fn unit_is_always_in_range() {
        let mut rng = SimRng::new(7);
        let mut min = 1.0f64;
        let mut max = 0.0f64;
        for _ in 0..100_000 {
            let value = rng.unit();
            assert!((0.0..1.0).contains(&value));
            min = min.min(value);
            max = max.max(value);
        }
        assert!(min < 0.01, "samples reach the low end");
        assert!(max > 0.99, "samples reach the high end");
    }

    #[test]
    fn below_respects_its_bound() {
        let mut rng = SimRng::new(11);
        assert_eq!(rng.below(0), 0);
        for _ in 0..10_000 {
            assert!(rng.below(7) < 7);
        }
    }
}
