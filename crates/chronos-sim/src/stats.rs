//! Sample statistics with the definitions fixed in `flow.md` §7.3.4.
//!
//! Percentiles use the **nearest-rank** definition on the ascending sample, `p(q) = x[ceil(q·n) − 1]`
//! clamped to `[1, n]`, so every reported percentile is an observed sample rather than an
//! interpolation. The standard deviation is the sample form (denominator `n − 1`).

use serde::{Deserialize, Serialize};

/// Summary of a sample of non-negative integers.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SampleStats {
    /// Number of observations.
    pub count: usize,
    /// Arithmetic mean.
    pub mean: f64,
    /// Smallest observation.
    pub min: u64,
    /// Nearest-rank 50th percentile (the median).
    pub p50: u64,
    /// Nearest-rank 95th percentile.
    pub p95: u64,
    /// Nearest-rank 99th percentile.
    pub p99: u64,
    /// Largest observation.
    pub max: u64,
    /// Sample standard deviation (denominator `n − 1`); 0 for fewer than two observations.
    pub stddev: f64,
}

impl SampleStats {
    /// Computes the summary of `samples`, ascending order irrelevant.
    pub fn of(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self {
                count: 0,
                mean: 0.0,
                min: 0,
                p50: 0,
                p95: 0,
                p99: 0,
                max: 0,
                stddev: 0.0,
            };
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();

        let count = sorted.len();
        let sum: u128 = sorted.iter().map(|value| u128::from(*value)).sum();
        let mean = sum as f64 / count as f64;
        let variance = if count > 1 {
            let squared: f64 = sorted
                .iter()
                .map(|value| {
                    let delta = *value as f64 - mean;
                    delta * delta
                })
                .sum();
            squared / (count - 1) as f64
        } else {
            0.0
        };

        Self {
            count,
            mean,
            min: sorted[0],
            p50: nearest_rank(&sorted, 0.50),
            p95: nearest_rank(&sorted, 0.95),
            p99: nearest_rank(&sorted, 0.99),
            max: sorted[count - 1],
            stddev: variance.sqrt(),
        }
    }

    /// Nearest-rank percentile of an already sorted slice.
    pub fn percentile(sorted: &[u64], quantile: f64) -> u64 {
        nearest_rank(sorted, quantile)
    }
}

/// Nearest-rank percentile `p(q) = x[ceil(q·n) − 1]`, clamped to `[1, n]`.
fn nearest_rank(sorted: &[u64], quantile: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (quantile * sorted.len() as f64).ceil() as usize;
    let index = rank.clamp(1, sorted.len()) - 1;
    sorted[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_samples_report_zeroes() {
        let stats = SampleStats::of(&[]);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.mean, 0.0);
        assert_eq!(stats.p99, 0);
        assert_eq!(stats.stddev, 0.0);
    }

    #[test]
    fn percentiles_are_observed_samples() {
        let samples: Vec<u64> = (1..=100).collect();
        let stats = SampleStats::of(&samples);

        assert_eq!(stats.count, 100);
        assert_eq!(stats.min, 1);
        assert_eq!(stats.max, 100);
        assert_eq!(stats.p50, 50, "ceil(0.50 · 100) = 50");
        assert_eq!(stats.p95, 95, "ceil(0.95 · 100) = 95");
        assert_eq!(stats.p99, 99, "ceil(0.99 · 100) = 99");
        assert!((stats.mean - 50.5).abs() < 1e-9);
        assert!(stats.stddev > 28.7 && stats.stddev < 29.1);
        assert!(
            samples.contains(&stats.p99),
            "percentiles must be observations"
        );
    }

    #[test]
    fn small_samples_never_underflow_the_rank() {
        let stats = SampleStats::of(&[7]);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.p50, 7);
        assert_eq!(stats.p95, 7);
        assert_eq!(stats.p99, 7);
        assert_eq!(stats.stddev, 0.0, "a single sample has no dispersion");

        let stats = SampleStats::of(&[1, 2]);
        assert_eq!(stats.p50, 1, "ceil(0.50 · 2) = 1");
        assert_eq!(stats.p95, 2);
        assert_eq!(stats.p99, 2);
    }

    #[test]
    fn stddev_is_the_sample_form() {
        // Sample variance of [2, 4, 4, 4, 5, 5, 7, 9] is 32/7, so sigma = sqrt(32/7).
        let stats = SampleStats::of(&[2, 4, 4, 4, 5, 5, 7, 9]);
        let expected = (32.0f64 / 7.0).sqrt();
        assert!((stats.stddev - expected).abs() < 1e-12);
        assert!((stats.mean - 5.0).abs() < 1e-12);
    }

    #[test]
    fn input_order_does_not_matter() {
        let ascending: Vec<u64> = (0..64).collect();
        let descending: Vec<u64> = (0..64).rev().collect();
        assert_eq!(SampleStats::of(&ascending), SampleStats::of(&descending));
    }

    #[test]
    fn large_samples_do_not_overflow_the_sum() {
        let samples = vec![u64::MAX / 2; 1_000];
        let stats = SampleStats::of(&samples);
        assert!(stats.mean > 0.0);
        assert_eq!(stats.min, samples[0]);
        assert_eq!(stats.p99, samples[0]);
    }
}
