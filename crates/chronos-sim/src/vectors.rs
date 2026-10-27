//! Golden-vector replay: `chronos verify-vectors`.
//!
//! `vectors/ietf_mtc_appendix_c.json` is produced by `tools/gen_vectors.py`, an *independent* Python
//! implementation of the draft algorithms. Replaying it here means the Rust code is checked against a
//! second implementation and against the draft's own accumulated digests — not merely against
//! itself.

use crate::deps::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

/// Path of the vector file relative to the workspace root.
pub const VECTOR_PATH: &str = "vectors/ietf_mtc_appendix_c.json";

/// Errors produced while replaying vectors.
#[derive(Debug, Error)]
pub enum VectorError {
    /// The vector file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path that failed.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The file is not valid JSON in the expected shape.
    #[error("cannot parse {path}: {source}")]
    Parse {
        /// Path that failed.
        path: String,
        /// Underlying error.
        source: serde_json::Error,
    },
    /// A vector did not match the implementation.
    #[error("{section}: {detail}")]
    Mismatch {
        /// Which section failed.
        section: String,
        /// What differed.
        detail: String,
    },
}

/// The subset of the vector file this replay understands.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VectorFile {
    merkle: MerkleVectors,
    der_guard: Vec<DerCase>,
    #[serde(default)]
    tbs_leaf_hashes: Vec<TbsCase>,
    #[serde(default)]
    cosign: Vec<HexCase>,
    #[serde(default)]
    base128_patterns: Vec<Base128Case>,
}

/// Merkle section.
#[derive(Debug, Clone, Deserialize)]
struct MerkleVectors {
    draft_accumulated: BTreeMap<String, String>,
    subtree_cases: Vec<SubtreeCase>,
    subtree_hashes: Vec<SubtreeHashCase>,
    inclusion_cases: Vec<InclusionCase>,
    #[serde(default)]
    consistency_cases: Vec<ConsistencyCase>,
    #[serde(default)]
    tree_roots: Vec<TreeRootCase>,
}

#[derive(Debug, Clone, Deserialize)]
struct SubtreeCase {
    start: u64,
    end: u64,
    left: [u64; 2],
    right: [u64; 2],
}

#[derive(Debug, Clone, Deserialize)]
struct SubtreeHashCase {
    start: u64,
    end: u64,
    hash: String,
}

#[derive(Debug, Clone, Deserialize)]
struct InclusionCase {
    index: u64,
    start: u64,
    end: u64,
    subtree_hash: String,
    proof: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConsistencyCase {
    start: u64,
    end: u64,
    tree_size: u64,
    subtree_hash: String,
    tree_root: String,
    proof: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TreeRootCase {
    size: u64,
    root: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DerCase {
    hex: String,
    accept: bool,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TbsCase {
    case: String,
    fields: TbsFieldsJson,
    expected_leaf_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TbsFieldsJson {
    version_raw: String,
    serial_number: u64,
    log_number: u64,
    signature_alg_oid: String,
    issuer_dn: String,
    not_before: u64,
    not_after: u64,
    subject_dn: String,
    subject_public_key_info: String,
    extensions_der: String,
}

#[derive(Debug, Clone, Deserialize)]
struct HexCase {
    case: String,
    #[serde(default)]
    hex: String,
    #[serde(default)]
    start: u64,
    #[serde(default)]
    end: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct Base128Case {
    arcs: Vec<u64>,
    unbounded: bool,
    hex: String,
}

/// The outcome of a replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Path that was replayed.
    pub path: String,
    /// Draft accumulated digests, as recorded in the file.
    pub draft_accumulated: BTreeMap<String, String>,
    /// Subtree-hash cases replayed.
    pub subtree_hashes: usize,
    /// Cover cases replayed.
    pub subtree_covers: usize,
    /// Inclusion proofs replayed.
    pub inclusion_proofs: usize,
    /// Consistency proofs replayed.
    pub consistency_proofs: usize,
    /// DER guard cases replayed.
    pub der_cases: usize,
    /// TBS leaf-hash cases replayed.
    pub tbs_cases: usize,
    /// Cosignature encodings replayed.
    pub cosign_cases: usize,
    /// Trust-anchor pattern cases replayed.
    pub base128_cases: usize,
    /// All four draft accumulated digests matched.
    pub accumulated_match: bool,
}

impl VerifyReport {
    /// Total number of vector cases replayed.
    pub fn total(&self) -> usize {
        self.subtree_hashes
            + self.subtree_covers
            + self.inclusion_proofs
            + self.consistency_proofs
            + self.der_cases
            + self.tbs_cases
            + self.cosign_cases
            + self.base128_cases
    }
}

/// Replays the vector file against the implementation.
pub fn verify_file(path: &Path) -> Result<VerifyReport, VectorError> {
    let text = std::fs::read_to_string(path).map_err(|source| VectorError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let vectors: VectorFile = serde_json::from_str(&text).map_err(|source| VectorError::Parse {
        path: path.display().to_string(),
        source,
    })?;
    verify(&vectors, &path.display().to_string())
}

/// Replays already-parsed vectors.
pub(crate) fn verify(vectors: &VectorFile, path: &str) -> Result<VerifyReport, VectorError> {
    let mut log = MerkleTreeLog::new();
    for index in 0..130u32 {
        log.append_raw_entry(&[index as u8]);
    }

    // Draft accumulated digests, recomputed the way the draft accumulates them.
    let mut accumulated = BTreeMap::new();
    accumulated.insert(
        "subtree_hashes".to_string(),
        accumulate_subtree_hashes(&log),
    );
    accumulated.insert(
        "inclusion_proofs".to_string(),
        accumulate_inclusion_proofs(&log),
    );
    accumulated.insert(
        "consistency_proofs".to_string(),
        accumulate_consistency_proofs(&log),
    );
    accumulated.insert(
        "covering_subtrees".to_string(),
        accumulate_covering_subtrees(),
    );

    let accumulated_match = vectors
        .merkle
        .draft_accumulated
        .iter()
        .all(|(key, expected)| accumulated.get(key) == Some(expected));
    if !accumulated_match {
        return Err(VectorError::Mismatch {
            section: "Appendix C accumulated".to_string(),
            detail: format!(
                "expected {:?}, recomputed {:?}",
                vectors.merkle.draft_accumulated, accumulated
            ),
        });
    }

    // Two-subtree covers.
    for case in &vectors.merkle.subtree_cases {
        let found = find_subtrees(case.start, case.end).map_err(|error| VectorError::Mismatch {
            section: "find_subtrees".to_string(),
            detail: format!("{}..{}: {error}", case.start, case.end),
        })?;
        let expected = vec![case.left, case.right];
        let observed: Vec<[u64; 2]> = found.iter().map(|range| [range.start, range.end]).collect();
        if observed != expected {
            return Err(VectorError::Mismatch {
                section: "find_subtrees".to_string(),
                detail: format!("{}..{}: {found:?} != {expected:?}", case.start, case.end),
            });
        }
    }

    // Subtree hashes.
    for case in &vectors.merkle.subtree_hashes {
        if !is_valid_subtree(case.start, case.end) {
            return Err(VectorError::Mismatch {
                section: "is_valid_subtree".to_string(),
                detail: format!("{}..{} should be valid", case.start, case.end),
            });
        }
        let computed = hex::encode(log.subtree_hash(case.start, case.end).map_err(|error| {
            VectorError::Mismatch {
                section: "subtree_hash".to_string(),
                detail: format!("{}..{}: {error}", case.start, case.end),
            }
        })?);
        if computed != case.hash {
            return Err(VectorError::Mismatch {
                section: "subtree_hash".to_string(),
                detail: format!("{}..{}: {computed} != {}", case.start, case.end, case.hash),
            });
        }
    }

    // Empty subtree.
    if hex::encode(empty_tree_hash()) != hex::encode(log.subtree_hash(0, 0).unwrap_or_default())
        && !vectors.merkle.subtree_hashes.is_empty()
    {
        return Err(VectorError::Mismatch {
            section: "empty subtree".to_string(),
            detail: "SHA256(\"\") mismatch".to_string(),
        });
    }

    // Inclusion proofs.
    for case in &vectors.merkle.inclusion_cases {
        let proof = log
            .inclusion_proof(case.index, case.start, case.end)
            .map_err(|error| VectorError::Mismatch {
                section: "inclusion_proof".to_string(),
                detail: format!("{} in {}..{}: {error}", case.index, case.start, case.end),
            })?;
        let expected: Vec<[u8; 32]> = case
            .proof
            .iter()
            .map(|value| {
                <[u8; 32]>::try_from(hex::decode(value).unwrap_or_default()).unwrap_or_default()
            })
            .collect();
        if proof != expected {
            return Err(VectorError::Mismatch {
                section: "inclusion_proof".to_string(),
                detail: format!("{} in {}..{}", case.index, case.start, case.end),
            });
        }

        let leaf = log
            .leaf_hash_at(case.index)
            .map_err(|error| VectorError::Mismatch {
                section: "leaf_hash".to_string(),
                detail: format!("{}: {error}", case.index),
            })?;
        let subtree = hex::decode(&case.subtree_hash).unwrap_or_default();
        let subtree: [u8; 32] = subtree.try_into().map_err(|_| VectorError::Mismatch {
            section: "inclusion_proof".to_string(),
            detail: "subtree hash is not 32 bytes".to_string(),
        })?;
        MerkleTreeLog::verify_inclusion(&leaf, case.index, case.start, case.end, &proof, &subtree)
            .map_err(|error| VectorError::Mismatch {
                section: "verify_inclusion".to_string(),
                detail: format!("{} in {}..{}: {error}", case.index, case.start, case.end),
            })?;
    }

    // Consistency proofs.
    for case in &vectors.merkle.consistency_cases {
        let proof = log
            .consistency_proof(case.start, case.end, case.tree_size)
            .map_err(|error| VectorError::Mismatch {
                section: "consistency_proof".to_string(),
                detail: format!("{}..{} @ {}: {error}", case.start, case.end, case.tree_size),
            })?;
        let expected: Vec<[u8; 32]> = case
            .proof
            .iter()
            .map(|value| {
                <[u8; 32]>::try_from(hex::decode(value).unwrap_or_default()).unwrap_or_default()
            })
            .collect();
        if proof.proof != expected {
            return Err(VectorError::Mismatch {
                section: "consistency_proof".to_string(),
                detail: format!("{}..{} @ {}", case.start, case.end, case.tree_size),
            });
        }

        let root = <[u8; 32]>::try_from(hex::decode(&case.tree_root).unwrap_or_default()).map_err(
            |_| VectorError::Mismatch {
                section: "consistency_proof".to_string(),
                detail: "tree root is not 32 bytes".to_string(),
            },
        )?;
        let subtree = <[u8; 32]>::try_from(hex::decode(&case.subtree_hash).unwrap_or_default())
            .map_err(|_| VectorError::Mismatch {
                section: "consistency_proof".to_string(),
                detail: "subtree hash is not 32 bytes".to_string(),
            })?;
        MerkleTreeLog::verify_prefix_consistency(&subtree, &root, &proof).map_err(|error| {
            VectorError::Mismatch {
                section: "verify_prefix_consistency".to_string(),
                detail: format!("{}..{} @ {}: {error}", case.start, case.end, case.tree_size),
            }
        })?;
    }

    // Tree roots.
    for case in &vectors.merkle.tree_roots {
        let computed =
            hex::encode(
                log.subtree_hash(0, case.size)
                    .map_err(|error| VectorError::Mismatch {
                        section: "tree_root".to_string(),
                        detail: format!("size {}: {error}", case.size),
                    })?,
            );
        if computed != case.root {
            return Err(VectorError::Mismatch {
                section: "tree_root".to_string(),
                detail: format!("size {}: {computed} != {}", case.size, case.root),
            });
        }
    }

    // DER guard.
    for case in &vectors.der_guard {
        let bytes = hex::decode(&case.hex).map_err(|_| VectorError::Mismatch {
            section: "der_guard".to_string(),
            detail: format!("{}: not hex", case.hex),
        })?;
        let accepted = validate_canonical_der_tlv(&bytes).is_ok();
        if accepted != case.accept {
            return Err(VectorError::Mismatch {
                section: "der_guard".to_string(),
                detail: format!(
                    "{} ({}): expected accept={}",
                    case.hex,
                    case.note.clone().unwrap_or_default(),
                    case.accept
                ),
            });
        }
    }

    // TBS leaf hashes.
    for case in &vectors.tbs_leaf_hashes {
        let version_raw = hex::decode(&case.fields.version_raw).unwrap_or_default();
        let signature_alg_oid = hex::decode(&case.fields.signature_alg_oid).unwrap_or_default();
        let issuer_dn = hex::decode(&case.fields.issuer_dn).unwrap_or_default();
        let subject_dn = hex::decode(&case.fields.subject_dn).unwrap_or_default();
        let subject_public_key_info =
            hex::decode(&case.fields.subject_public_key_info).unwrap_or_default();
        let extensions_der = hex::decode(&case.fields.extensions_der).unwrap_or_default();
        let fields = TbsCertFields {
            version_raw: &version_raw,
            signature_alg_oid: &signature_alg_oid,
            issuer_dn: &issuer_dn,
            not_before: case.fields.not_before,
            not_after: case.fields.not_after,
            subject_dn: &subject_dn,
            subject_public_key_info: &subject_public_key_info,
            extensions_der: &extensions_der,
            log_number: case.fields.log_number as u16,
            serial_number: case.fields.serial_number,
        };
        let computed = hex::encode(hash_tbs_certificate_streaming(&fields).map_err(|error| {
            VectorError::Mismatch {
                section: format!("tbs_leaf_hashes[{}]", case.case),
                detail: error.to_string(),
            }
        })?);
        if computed != case.expected_leaf_hash {
            return Err(VectorError::Mismatch {
                section: format!("tbs_leaf_hashes[{}]", case.case),
                detail: format!("{computed} != {}", case.expected_leaf_hash),
            });
        }
    }

    // Cosignature encodings.
    for case in &vectors.cosign {
        let expected = hex::decode(&case.hex).map_err(|_| VectorError::Mismatch {
            section: format!("cosign[{}]", case.case),
            detail: "not hex".to_string(),
        })?;
        let computed = match case.case.as_str() {
            name if name.starts_with("cosigned_subtree") => {
                let timestamp = if name.ends_with("timestamped") {
                    1_700_000_000
                } else {
                    0
                };
                let start = if case.start == 0 && case.end == 0 {
                    4
                } else {
                    case.start
                };
                let end = if case.start == 0 && case.end == 0 {
                    12
                } else {
                    case.end
                };
                let root = log.subtree_hash(start, end).unwrap_or([0x42; 32]);
                CosignedSubtree::new("32473.1", "32473.2", timestamp, start, end, root)
                    .to_bytes()
                    .map_err(|error| VectorError::Mismatch {
                        section: format!("cosign[{name}]"),
                        detail: error.to_string(),
                    })?
            }
            _ => {
                let mut signatures = vec![
                    Cosignature::new(vec![0xFF], vec![0xA5; 64]),
                    Cosignature::new(vec![0x01, 0x02], vec![0x5A; 64]),
                    Cosignature::new(vec![0x0A, 0x0A], vec![0x00]),
                ];
                canonicalize_cosignatures(&mut signatures).map_err(|error| {
                    VectorError::Mismatch {
                        section: format!("cosign[{}]", case.case),
                        detail: error.to_string(),
                    }
                })?;
                MtcProof {
                    extensions: vec![0x30, 0x00],
                    start: case.start,
                    end: case.end,
                    inclusion_proof: log.inclusion_proof(5, 4, 12).unwrap_or_default(),
                    signatures,
                }
                .encode()
                .map_err(|error| VectorError::Mismatch {
                    section: format!("cosign[{}]", case.case),
                    detail: error.to_string(),
                })?
            }
        };
        if computed != expected {
            return Err(VectorError::Mismatch {
                section: format!("cosign[{}]", case.case),
                detail: format!(
                    "computed {} bytes, expected {} bytes",
                    hex::encode(&computed),
                    case.hex
                ),
            });
        }
    }

    // Trust-anchor patterns: only the closed forms are replayed, plus the id-string prefix.
    for case in &vectors.base128_patterns {
        if !case.unbounded {
            let mut encoded = Vec::new();
            for arc in &case.arcs {
                encoded.extend_from_slice(&encode_base128(*arc));
            }
            if hex::encode(&encoded) != case.hex {
                return Err(VectorError::Mismatch {
                    section: "base128_patterns".to_string(),
                    detail: format!("{:?}: {} != {}", case.arcs, hex::encode(&encoded), case.hex),
                });
            }
        }
    }

    // The trust-anchor id prefix is used by the cosignature cases above.
    if trust_anchor_id_string("32473.1") != b"oid/1.3.6.1.4.1.32473.1" {
        return Err(VectorError::Mismatch {
            section: "trust_anchor_id".to_string(),
            detail: "prefix mismatch".to_string(),
        });
    }

    Ok(VerifyReport {
        path: path.to_string(),
        draft_accumulated: vectors.merkle.draft_accumulated.clone(),
        subtree_hashes: vectors.merkle.subtree_hashes.len(),
        subtree_covers: vectors.merkle.subtree_cases.len(),
        inclusion_proofs: vectors.merkle.inclusion_cases.len(),
        consistency_proofs: vectors.merkle.consistency_cases.len(),
        der_cases: vectors.der_guard.len(),
        tbs_cases: vectors.tbs_leaf_hashes.len(),
        cosign_cases: vectors.cosign.len(),
        base128_cases: vectors.base128_patterns.len(),
        accumulated_match,
    })
}

/// Base-128 encoding used by trust-anchor ID patterns.
fn encode_base128(mut value: u64) -> Vec<u8> {
    let mut digits = Vec::new();
    loop {
        digits.push((value & 0x7F) as u8);
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    digits.reverse();
    let last = digits.len() - 1;
    for digit in digits.iter_mut().take(last) {
        *digit |= 0x80;
    }
    digits
}

/// Recomputes the draft's C.1.1 accumulated subtree-hash digest.
fn accumulate_subtree_hashes(log: &MerkleTreeLog) -> String {
    let mut rolling = <sha2::Sha256 as sha2::Digest>::new();
    for end in 0..=130u64 {
        for start in 0..=end {
            if !is_valid_subtree(start, end) {
                continue;
            }
            let hash = hex::encode(log.subtree_hash(start, end).unwrap_or_default());
            sha2::Digest::update(
                &mut rolling,
                format!("[{start}, {end}) {hash}\n").as_bytes(),
            );
        }
    }
    hex::encode(sha2::Digest::finalize(rolling))
}

/// Recomputes the draft's C.1.2 accumulated inclusion-proof digest.
fn accumulate_inclusion_proofs(log: &MerkleTreeLog) -> String {
    let mut rolling = <sha2::Sha256 as sha2::Digest>::new();
    for end in 0..=130u64 {
        for start in 0..=end {
            if !is_valid_subtree(start, end) {
                continue;
            }
            for index in start..end {
                let mut line = format!("{index} [{start}, {end})");
                for proof in log.inclusion_proof(index, start, end).unwrap_or_default() {
                    line.push_str(&format!(" {}", hex::encode(proof)));
                }
                sha2::Digest::update(&mut rolling, format!("{line}\n").as_bytes());
            }
        }
    }
    hex::encode(sha2::Digest::finalize(rolling))
}

/// Recomputes the draft's C.1.3 accumulated consistency-proof digest.
fn accumulate_consistency_proofs(log: &MerkleTreeLog) -> String {
    let mut rolling = <sha2::Sha256 as sha2::Digest>::new();
    for size in 0..=130u64 {
        for end in 0..=size {
            for start in 0..=end {
                if !is_valid_subtree(start, end) {
                    continue;
                }
                let mut line = format!("[{start}, {end}) {size}");
                for proof in log
                    .consistency_proof(start, end, size)
                    .map(|p| p.proof)
                    .unwrap_or_default()
                {
                    line.push_str(&format!(" {}", hex::encode(proof)));
                }
                sha2::Digest::update(&mut rolling, format!("{line}\n").as_bytes());
            }
        }
    }
    hex::encode(sha2::Digest::finalize(rolling))
}

/// Recomputes the draft's C.1.4 accumulated covering-subtree digest.
fn accumulate_covering_subtrees() -> String {
    let mut rolling = <sha2::Sha256 as sha2::Digest>::new();
    for end in 0..=130u64 {
        for start in 0..=end {
            if let Ok(found) = find_subtrees(start, end) {
                let line = format!(
                    "[{}, {}) [{}, {})\n",
                    found[0].start, found[0].end, found[1].start, found[1].end
                );
                sha2::Digest::update(&mut rolling, line.as_bytes());
            }
        }
    }
    hex::encode(sha2::Digest::finalize(rolling))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        // CARGO_MANIFEST_DIR points at crates/chronos-sim during `cargo test`.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|parent| parent.parent())
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    #[test]
    fn the_shipped_vectors_replay_clean() {
        let path = workspace_root().join(VECTOR_PATH);
        if !path.exists() {
            panic!("{} is missing; run tools/gen_vectors.py", path.display());
        }
        let report = verify_file(&path).expect("vectors must replay");

        assert!(report.accumulated_match);
        assert!(
            report.total() > 1_000,
            "only {} cases replayed",
            report.total()
        );
        assert_eq!(report.der_cases, 12);
        assert_eq!(report.tbs_cases, 4);
        assert!(report.inclusion_proofs > 200);
        assert!(report.consistency_proofs > 600);
        assert!(report.subtree_covers > 300);
    }

    #[test]
    fn a_corrupted_vector_is_reported_not_ignored() {
        let path = workspace_root().join(VECTOR_PATH);
        let text = std::fs::read_to_string(&path).expect("vectors");

        // Flip one character of the first subtree hash and confirm the replay fails loudly.
        let mut broken = text.clone();
        let section = broken.find("\"subtree_hashes\"").expect("subtree_hashes");
        let needle = "\"hash\": \"";
        let position = section + broken[section..].find(needle).expect("hash field");
        let value_start = position + needle.len();
        broken.replace_range(value_start..value_start + 2, "00");
        assert_ne!(broken, text);

        let directory = std::env::temp_dir().join("chronos-vectors-test");
        std::fs::create_dir_all(&directory).expect("temp dir");
        let broken_path = directory.join("broken.json");
        std::fs::write(&broken_path, &broken).expect("write");
        assert!(verify_file(&broken_path).is_err());
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn base128_encoding_matches_the_draft_arcs() {
        assert_eq!(encode_base128(0), vec![0x00]);
        assert_eq!(encode_base128(1), vec![0x01]);
        assert_eq!(encode_base128(127), vec![0x7F]);
        assert_eq!(encode_base128(128), vec![0x81, 0x00]);
        assert_eq!(encode_base128(16_384), vec![0x81, 0x80, 0x00]);
    }
}
