//! Glass's Δ (delta) calculator — N-version programming effect size.
//!
//! $$\Delta = \frac{\mu_{target} - \mu_{control}}{\sigma_{control}}$$
//!
//! Glass's thresholds: `Δ < 0.8` small, `≈ 1.0` medium, `≈ 1.8` large. When the control has zero
//! dispersion the ratio is undefined, so the effect size is reported as [`EffectSize::None`] rather
//! than as an infinity — an infinite effect size is a statement about the denominator, not about the
//! effect.
//!
//! The companion [`rank_analysis`] is the part of Glass's method that is usually skipped: across many
//! runs of two versions, *how consistently* does the target win? A large mean difference driven by a
//! handful of outliers is a weaker result than a smaller but rank-stable one.

use crate::stats::SampleStats;
use serde::{Deserialize, Serialize};

/// Glass's effect-size band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectSize {
    /// `|Δ| < 0.8`.
    Small,
    /// `0.8 ≤ |Δ| < 1.8`.
    Medium,
    /// `|Δ| ≥ 1.8`.
    Large,
    /// The control has no dispersion, so Δ is undefined.
    None,
}

impl EffectSize {
    /// Classifies a Δ value.
    pub fn classify(delta: f64) -> Self {
        let magnitude = delta.abs();
        if magnitude < 0.8 {
            Self::Small
        } else if magnitude < 1.8 {
            Self::Medium
        } else {
            Self::Large
        }
    }

    /// Lower-case label for reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::None => "none",
        }
    }
}

/// The result of comparing one stack against a control.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlassDelta {
    /// Which stack was measured.
    pub target: String,
    /// Which stack it was compared against.
    pub control: String,
    /// Loss level of the cell this Δ was computed for, when the caller supplies one.
    pub loss: Option<f64>,
    /// Mean of the target metric.
    pub target_mean: f64,
    /// Mean of the control metric.
    pub control_mean: f64,
    /// Sample standard deviation of the control.
    pub control_stddev: f64,
    /// The Δ value, when defined.
    pub delta: Option<f64>,
    /// Glass's band for `delta`.
    pub effect_size: EffectSize,
    /// Relative change `(target − control) / control`, when the control mean is non-zero.
    pub relative_change: Option<f64>,
}

impl GlassDelta {
    /// Δ as a displayable string, `n/a` when undefined.
    pub fn delta_text(&self) -> String {
        match self.delta {
            Some(value) => format!("{value:+.3}"),
            None => "n/a".to_string(),
        }
    }

    /// Relative change as a percentage string.
    pub fn relative_change_text(&self) -> String {
        match self.relative_change {
            Some(value) => format!("{:+.1}%", value * 100.0),
            None => "n/a".to_string(),
        }
    }
}

/// Computes Δ for two samples of the same metric.
pub fn glass_delta(
    target_name: &str,
    control_name: &str,
    target: &[u64],
    control: &[u64],
) -> GlassDelta {
    let target_stats = SampleStats::of(target);
    let control_stats = SampleStats::of(control);

    let delta = if control_stats.stddev > f64::EPSILON {
        Some((target_stats.mean - control_stats.mean) / control_stats.stddev)
    } else {
        None
    };
    let effect_size = delta.map_or(EffectSize::None, EffectSize::classify);
    let relative_change = if control_stats.mean.abs() > f64::EPSILON {
        Some((target_stats.mean - control_stats.mean) / control_stats.mean)
    } else {
        None
    };

    GlassDelta {
        target: target_name.to_string(),
        control: control_name.to_string(),
        loss: None,
        target_mean: target_stats.mean,
        control_mean: control_stats.mean,
        control_stddev: control_stats.stddev,
        delta,
        effect_size,
        relative_change,
    }
}

/// How consistently one version's metric is lower than another's across paired runs.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RankAnalysis {
    /// Paired runs where the target was strictly lower.
    pub target_wins: usize,
    /// Paired runs where both were equal.
    pub ties: usize,
    /// Paired runs where the control was lower.
    pub control_wins: usize,
    /// The modal rank of the target, as `wins / (wins + ties + losses)`.
    pub target_rank_fraction: f64,
    /// The most frequent per-pair difference.
    pub most_frequent_delta: i64,
    /// Smallest per-pair difference observed.
    pub delta_range_low: i64,
    /// Largest per-pair difference observed.
    pub delta_range_high: i64,
}

impl RankAnalysis {
    /// The classic interpretation.
    pub fn status(&self) -> &'static str {
        match self.target_rank_fraction {
            fraction if fraction >= 0.9 => "consistent win",
            fraction if fraction >= 0.75 => "mostly consistent",
            fraction if fraction >= 0.5 => "mixed",
            _ => "consistent loss",
        }
    }
}

/// Compares paired per-run samples of the same metric.
pub fn rank_analysis(target: &[u64], control: &[u64]) -> RankAnalysis {
    let pairs = target.len().min(control.len());
    let mut target_wins = 0usize;
    let mut ties = 0usize;
    let mut control_wins = 0usize;
    let mut deltas: Vec<i64> = Vec::with_capacity(pairs);
    let mut low = 0i64;
    let mut high = 0i64;

    for index in 0..pairs {
        let difference = target[index] as i64 - control[index] as i64;
        match difference.cmp(&0) {
            std::cmp::Ordering::Less => target_wins += 1,
            std::cmp::Ordering::Equal => ties += 1,
            std::cmp::Ordering::Greater => control_wins += 1,
        }
        deltas.push(difference);
        if index == 0 || difference < low {
            low = difference;
        }
        if index == 0 || difference > high {
            high = difference;
        }
    }

    let mut counts: Vec<(i64, usize)> = Vec::new();
    for difference in &deltas {
        match counts.iter_mut().find(|(value, _)| value == difference) {
            Some(entry) => entry.1 += 1,
            None => counts.push((*difference, 1)),
        }
    }
    counts.sort_by_key(|a| std::cmp::Reverse(a.1));
    let most_frequent_delta = counts.first().map_or(0, |(value, _)| *value);

    RankAnalysis {
        target_wins,
        ties,
        control_wins,
        target_rank_fraction: target_wins as f64 / pairs.max(1) as f64,
        most_frequent_delta,
        delta_range_low: low,
        delta_range_high: high,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uniformly_better_sample_has_a_large_effect() {
        let control: Vec<u64> = (0..100).map(|index| 100 + index % 10).collect();
        let target: Vec<u64> = control.iter().map(|value| value - 20).collect();

        let result = glass_delta("ChronosMtc", "NaivePqcQuic", &target, &control);
        let delta = result.delta.expect("the control has dispersion");
        assert!(delta < -1.0, "delta {delta}");
        assert_eq!(result.effect_size, EffectSize::Large);
        assert!(result.relative_change.unwrap() < -0.1);
        assert!(result.delta_text().starts_with('-'));
    }

    #[test]
    fn a_zero_variance_control_reports_none_not_infinity() {
        let control = vec![5u64; 50];
        let target = vec![9u64; 50];
        let result = glass_delta("ChronosMtc", "ClassicalQuic", &target, &control);

        assert_eq!(result.delta, None);
        assert_eq!(result.effect_size, EffectSize::None);
        assert_eq!(result.delta_text(), "n/a");
        assert_eq!(result.relative_change_text(), "+80.0%");
    }

    #[test]
    fn effect_bands_follow_glass() {
        assert_eq!(EffectSize::classify(0.0), EffectSize::Small);
        assert_eq!(EffectSize::classify(0.79), EffectSize::Small);
        assert_eq!(EffectSize::classify(0.8), EffectSize::Medium);
        assert_eq!(EffectSize::classify(1.79), EffectSize::Medium);
        assert_eq!(EffectSize::classify(1.8), EffectSize::Large);
        assert_eq!(EffectSize::classify(-2.5), EffectSize::Large);
        assert_eq!(EffectSize::Small.label(), "small");
    }

    #[test]
    fn rank_analysis_counts_paired_wins() {
        let control = vec![10u64, 12, 14, 16];
        let target = vec![8u64, 12, 15, 9];
        let ranks = rank_analysis(&target, &control);

        assert_eq!(ranks.target_wins, 2);
        assert_eq!(ranks.ties, 1);
        assert_eq!(ranks.control_wins, 1);
        assert_eq!(ranks.delta_range_low, -7);
        assert_eq!(ranks.delta_range_high, 1);
        assert_eq!(ranks.most_frequent_delta, -2, "the modal difference is -2");
        assert_eq!(ranks.status(), "mixed");
    }

    #[test]
    fn a_consistent_win_is_reported_as_such() {
        let control: Vec<u64> = (100..200).collect();
        let target: Vec<u64> = (50..150).collect();
        let ranks = rank_analysis(&target, &control);

        assert_eq!(ranks.target_wins, 100);
        assert_eq!(ranks.status(), "consistent win");
        assert_eq!(ranks.target_rank_fraction, 1.0);
        assert_eq!(ranks.delta_range_low, -50);
        assert_eq!(ranks.delta_range_high, -50);
    }

    #[test]
    fn empty_samples_do_not_panic() {
        let result = glass_delta("a", "b", &[], &[]);
        assert_eq!(result.delta, None);
        assert_eq!(result.relative_change, None);

        let ranks = rank_analysis(&[], &[1, 2, 3]);
        assert_eq!(ranks.target_wins, 0);
        assert_eq!(ranks.status(), "consistent loss");
        assert_eq!(ranks.delta_range_low, 0);
    }
}
