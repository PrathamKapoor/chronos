//! Merkle tree state and the normative subtree algorithms of IETF
//! `draft-ietf-plants-merkle-tree-certs-07`.
//!
//! Implemented directly from the draft text (and cross-checked against the draft's own Appendix C
//! "accumulated" test vectors in this module's tests):
//!
//! * §4.1 — subtree validity: `start` is a multiple of `BIT_CEIL(end - start)`.
//! * §4.3 — subtree inclusion proofs (RFC 9162 §2.1.3.1 `PATH` over `D[start:end]`).
//! * §4.3.2 — proof *evaluation* by the `fn`/`sn` bit walk (evaluation, not recomputation, is what a
//!   relying party runs).
//! * §4.4 — subtree consistency proofs (`SUBTREE_PROOF` / `SUBTREE_SUBPROOF`).
//! * §4.4.3 — dual-hash (`fr`/`sr`) consistency verification, which is what proves the tree hash
//!   *contains* the subtree hash.
//! * §4.5.1 — covering an arbitrary interval with two valid subtrees.
//!
//! The log is stored level-indexed: `levels[l][i]` is the hash of leaves `[i·2^l, (i+1)·2^l)` and
//! exists whenever `(i+1)·2^l <= size`. Every window the algorithms touch is a subtree of the log,
//! so the hot paths are array lookups instead of re-hashing, and no traversal allocates beyond the
//! proof it is asked to return.

use super::error::{MtcError, MtcResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for a single-leaf Merkle tree hash: `MTH({d}) = SHA256(0x00 || d)`.
pub const MTC_LEAF_PREFIX: u8 = 0x00;

/// Domain separator for an interior node: `MTH(D[a:b]) = SHA256(0x01 || MTH(D[a:k]) || MTH(D[k:b]))`.
pub const MTC_NODE_PREFIX: u8 = 0x01;

/// Largest legal log index / serial value (uint48).
pub const MAX_UINT48: u64 = (1u64 << 48) - 1;

/// Largest Merkle tree the MTC proof format can express (`2^48 - 1`, draft §C.2).
pub const MAX_LOG_SIZE: u64 = MAX_UINT48;

/// Leaf hash of one log entry: `SHA256(0x00 || entry)`.
pub fn hash_leaf(entry: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([MTC_LEAF_PREFIX]);
    hasher.update(entry);
    hasher.finalize().into()
}

/// Interior node hash from two 32-byte child hashes.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([MTC_NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// `HASH()`, the hash of the empty string: the subtree hash of an empty subtree (draft §4.4.3).
pub fn empty_tree_hash() -> [u8; 32] {
    Sha256::new().finalize().into()
}

/// Largest power of two strictly smaller than `n` (requires `n >= 2`).
#[inline]
fn largest_power_of_two_below(n: u64) -> u64 {
    debug_assert!(n >= 2, "largest_power_of_two_below requires n >= 2");
    1u64 << (63 - (n - 1).leading_zeros())
}

/// `BIT_CEIL(x)`: smallest power of two greater than or equal to `x` (`BIT_CEIL(0) = 1`).
#[inline]
fn bit_ceil(x: u64) -> u64 {
    x.max(1).next_power_of_two()
}

/// Subtree validity per draft §4.1: `0 <= start <= end` and `start % BIT_CEIL(end - start) == 0`.
///
/// The overflow guard follows the draft's C++ reference: when `end - start > 2^63`,
/// `bit_ceil` would overflow, and the answer is `start == 0`.
pub fn is_valid_subtree(start: u64, end: u64) -> bool {
    if start > end {
        return false;
    }
    let size = end - start;
    if size > (1u64 << 63) {
        return start == 0;
    }
    (start & (bit_ceil(size) - 1)) == 0
}

/// Alias for [`is_valid_subtree`] using the terminology of §4.1/B.2 ("aligned" subtree).
pub fn is_aligned_subtree(start: u64, end: u64) -> bool {
    is_valid_subtree(start, end)
}

/// A half-open log index interval `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubtreeRange {
    /// Inclusive first leaf index.
    pub start: u64,
    /// Exclusive last leaf index.
    pub end: u64,
}

impl SubtreeRange {
    /// Builds a range, validating the uint48 index space.
    pub fn new(start: u64, end: u64) -> MtcResult<Self> {
        validate_range(start, end)?;
        Ok(Self { start, end })
    }

    /// Number of leaves covered.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// True only for an empty range.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// True when the range is a valid subtree (§4.1).
    pub fn is_valid(&self) -> bool {
        is_valid_subtree(self.start, self.end)
    }
}

fn validate_range(start: u64, end: u64) -> MtcResult<()> {
    if start > end || end > MAX_LOG_SIZE {
        return Err(MtcError::InvalidRange { start, end });
    }
    Ok(())
}

/// Selects the two subtrees that efficiently cover `[start, end)` (draft §4.5.1).
///
/// The returned pair `[left, right]` satisfies the draft's contract:
///
/// ```text
/// left.start <= start <= left.end == right.start <= end == right.end
/// ```
///
/// `left` may extend below `start` (it is the lowest common ancestor of the elements in
/// `[start, mid)`), while `right` never extends past `end`. For `end - start <= 1` the draft
/// returns `[start, end)` and the empty range `[end, end)`.
///
/// ```text
/// last       = end - 1
/// split      = index of the most significant bit where start and last differ
/// mid        = last with its least significant `split` bits cleared
/// left_split = (index of the most significant zero bit among start's low `split` bits) + 1, or 0
/// left_start = start with its least significant `left_split` bits cleared
/// ```
pub fn find_subtrees(start: u64, end: u64) -> MtcResult<Vec<SubtreeRange>> {
    validate_range(start, end)?;

    if end - start <= 1 {
        return Ok(vec![
            SubtreeRange { start, end },
            SubtreeRange { start: end, end },
        ]);
    }

    let last = end - 1;
    let split = 63 - (start ^ last).leading_zeros();
    let mid = last & !((1u64 << split) - 1);

    // Most significant zero bit within start's least significant `split` bits.
    let mut left_split = 0u32;
    for bit in 0..split {
        if start >> bit & 1 == 0 {
            left_split = bit + 1;
        }
    }
    let left_start = start & !((1u64 << left_split) - 1);

    let left = SubtreeRange {
        start: left_start,
        end: mid,
    };
    let right = SubtreeRange { start: mid, end };

    debug_assert!(left.is_valid() && right.is_valid());
    Ok(vec![left, right])
}

/// A subtree consistency proof between a subtree `[start, end)` and a tree of `tree_size` elements
/// (draft §4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubtreeConsistencyProof {
    /// Subtree start index.
    pub start: u64,
    /// Subtree end index.
    pub end: u64,
    /// Size of the overall tree the proof is against.
    pub tree_size: u64,
    /// Hashes in the order the draft's verifier consumes them.
    pub proof: Vec<[u8; 32]>,
}

impl SubtreeConsistencyProof {
    /// Number of hashes in the proof.
    pub fn len(&self) -> usize {
        self.proof.len()
    }

    /// True when the proof carries no hashes.
    pub fn is_empty(&self) -> bool {
        self.proof.is_empty()
    }
}

/// Append-only Merkle log with level-indexed node storage.
#[derive(Debug, Clone, Default)]
pub struct MerkleTreeLog {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTreeLog {
    /// Creates an empty log.
    pub fn new() -> Self {
        Self { levels: Vec::new() }
    }

    /// Number of leaves currently in the log.
    pub fn len(&self) -> u64 {
        self.levels.first().map_or(0, |level| level.len() as u64)
    }

    /// True when the log holds no leaves.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends a pre-computed leaf hash and returns its log index.
    pub fn append_entry(&mut self, leaf_hash: [u8; 32]) -> u64 {
        let index = self.len();
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        self.levels[0].push(leaf_hash);

        let mut level = 0usize;
        loop {
            let count = self.levels[level].len();
            if !count.is_multiple_of(2) {
                break;
            }
            let right = self.levels[level][count - 1];
            let left = self.levels[level][count - 2];
            let parent = node_hash(&left, &right);
            level += 1;
            while self.levels.len() <= level {
                self.levels.push(Vec::new());
            }
            self.levels[level].push(parent);
        }

        index
    }

    /// Appends a raw entry, hashing it as `SHA256(0x00 || entry)` first.
    pub fn append_raw_entry(&mut self, entry: &[u8]) -> u64 {
        let leaf = hash_leaf(entry);
        self.append_entry(leaf)
    }

    /// Reads the stored leaf hash at `index`.
    pub fn leaf_hash_at(&self, index: u64) -> MtcResult<[u8; 32]> {
        if index >= self.len() {
            return Err(MtcError::IndexOutOfBounds {
                index,
                size: self.len(),
            });
        }
        Ok(self.levels[0][index as usize])
    }

    /// Root hash of the whole log (`MTH(D[0:size])`).
    pub fn root_hash(&self) -> MtcResult<[u8; 32]> {
        self.subtree_hash(0, self.len())
    }

    /// `MTH(D[start:end])`.
    ///
    /// An empty range hashes the empty string (draft §4.4.3). Aligned power-of-two ranges are a
    /// single lookup; other ranges split at the largest power of two below their size, exactly as
    /// RFC 9162 §2.1.1 prescribes. No allocation.
    pub fn subtree_hash(&self, start: u64, end: u64) -> MtcResult<[u8; 32]> {
        if start > end {
            return Err(MtcError::InvalidRange { start, end });
        }
        if start == end {
            return Ok(empty_tree_hash());
        }
        if end > self.len() {
            return Err(MtcError::IndexOutOfBounds {
                index: end,
                size: self.len(),
            });
        }
        self.hash_window(start, end)
    }

    /// Root of the window `[start, end)`, which the callers keep inside the populated log.
    fn hash_window(&self, start: u64, end: u64) -> MtcResult<[u8; 32]> {
        let size = end - start;
        if size == 1 {
            return Ok(self.levels[0][start as usize]);
        }
        if size.is_power_of_two() && start.is_multiple_of(size) {
            let level = size.trailing_zeros() as usize;
            return Ok(self.levels[level][(start / size) as usize]);
        }
        let k = largest_power_of_two_below(size);
        let left = self.hash_window(start, start + k)?;
        let right = self.hash_window(start + k, end)?;
        Ok(node_hash(&left, &right))
    }

    /// Subtree inclusion proof for `index` inside `[start, end)` (draft §4.3).
    ///
    /// Hashes are emitted bottom-up, sibling first — RFC 9162 §2.1.3.1 `PATH(m, D[n])` with
    /// `m = index - start` and `n = end - start`. A subtree of size `n` carries at most
    /// `BIT_WIDTH(n - 1)` hashes.
    pub fn inclusion_proof(&self, index: u64, start: u64, end: u64) -> MtcResult<Vec<[u8; 32]>> {
        if start > end {
            return Err(MtcError::UnalignedSubtree { start, end });
        }
        if end > self.len() {
            return Err(MtcError::IndexOutOfBounds {
                index: end,
                size: self.len(),
            });
        }
        if index < start || index >= end {
            return Err(MtcError::IndexOutOfBounds { index, size: end });
        }

        let mut proof = Vec::new();
        self.inclusion_rec(start, end - start, index - start, &mut proof)?;
        Ok(proof)
    }

    /// `PATH(m, D[a:a+n])`, bottom-up.
    fn inclusion_rec(&self, a: u64, n: u64, m: u64, out: &mut Vec<[u8; 32]>) -> MtcResult<()> {
        if n == 1 {
            return Ok(());
        }
        let k = largest_power_of_two_below(n);
        if m < k {
            self.inclusion_rec(a, k, m, out)?;
            out.push(self.hash_window(a + k, a + n)?);
        } else {
            self.inclusion_rec(a + k, n - k, m - k, out)?;
            out.push(self.hash_window(a, a + k)?);
        }
        Ok(())
    }

    /// Evaluates a subtree inclusion proof to the expected subtree hash (draft §4.3.2).
    ///
    /// This is the relying-party path: it hashes the proof into `r` following the `fn`/`sn` paths
    /// and returns `r`, which the caller compares against the trusted subtree hash. Because every
    /// fold direction comes from index arithmetic, a reordered or duplicated proof element can only
    /// produce a wrong `r`, never a wrong-sided hash.
    pub fn evaluate_inclusion_proof(
        entry_hash: &[u8; 32],
        index: u64,
        start: u64,
        end: u64,
        proof: &[[u8; 32]],
    ) -> MtcResult<[u8; 32]> {
        if start > end {
            return Err(MtcError::UnalignedSubtree { start, end });
        }
        if index < start || index >= end {
            return Err(MtcError::IndexOutOfBounds { index, size: end });
        }

        let mut fn_index = index - start;
        let mut sn = end - start - 1;
        let mut r = *entry_hash;

        for (position, p) in proof.iter().enumerate() {
            if sn == 0 {
                return Err(MtcError::ProofLengthMismatch {
                    expected: position,
                    got: proof.len(),
                });
            }
            if fn_index & 1 == 1 || fn_index == sn {
                r = node_hash(p, &r);
                while fn_index & 1 == 0 {
                    fn_index >>= 1;
                    sn >>= 1;
                }
            } else {
                r = node_hash(&r, p);
            }
            fn_index >>= 1;
            sn >>= 1;
        }

        if sn != 0 {
            return Err(MtcError::ProofLengthMismatch {
                expected: proof.len() + 1,
                got: proof.len(),
            });
        }

        Ok(r)
    }

    /// Verifies a subtree inclusion proof against a trusted subtree hash (draft §4.3.3).
    pub fn verify_inclusion(
        entry_hash: &[u8; 32],
        index: u64,
        start: u64,
        end: u64,
        proof: &[[u8; 32]],
        expected_subtree_hash: &[u8; 32],
    ) -> MtcResult<()> {
        let evaluated = Self::evaluate_inclusion_proof(entry_hash, index, start, end, proof)?;
        if &evaluated != expected_subtree_hash {
            return Err(MtcError::RootMismatch {
                computed: hex::encode(evaluated),
                expected: hex::encode(expected_subtree_hash),
            });
        }
        Ok(())
    }

    /// Generates `SUBTREE_PROOF(start, end, D_n)` (draft §4.4.1).
    pub fn consistency_proof(
        &self,
        start: u64,
        end: u64,
        tree_size: u64,
    ) -> MtcResult<SubtreeConsistencyProof> {
        if start > end {
            return Err(MtcError::InvalidRange { start, end });
        }
        if end > tree_size {
            return Err(MtcError::InvalidRange {
                start: end,
                end: tree_size,
            });
        }
        if !is_valid_subtree(start, end) {
            return Err(MtcError::UnalignedSubtree { start, end });
        }
        if tree_size > self.len() {
            return Err(MtcError::IndexOutOfBounds {
                index: tree_size,
                size: self.len(),
            });
        }

        let mut proof = Vec::new();
        if start != end {
            self.subtree_subproof(0, start, end, tree_size, true, &mut proof)?;
        }

        Ok(SubtreeConsistencyProof {
            start,
            end,
            tree_size,
            proof,
        })
    }

    /// `SUBTREE_SUBPROOF(start, end, D[a:a+n], b)`.
    ///
    /// `omit_first` tracks whether the starting node hash is elided because the verifier already
    /// knows it — the case where the subtree root itself is a node of the tree.
    fn subtree_subproof(
        &self,
        a: u64,
        start: u64,
        end: u64,
        n: u64,
        omit_first: bool,
        out: &mut Vec<[u8; 32]>,
    ) -> MtcResult<()> {
        if start == 0 && end == n {
            if !omit_first {
                out.push(self.hash_window(a, a + n)?);
            }
            return Ok(());
        }

        let k = largest_power_of_two_below(n);
        if end <= k {
            self.subtree_subproof(a, start, end, k, omit_first, out)?;
            out.push(self.hash_window(a + k, a + n)?);
        } else if k <= start {
            self.subtree_subproof(a + k, start - k, end - k, n - k, omit_first, out)?;
            out.push(self.hash_window(a, a + k)?);
        } else {
            debug_assert_eq!(start, 0, "start < k < end implies start == 0");
            self.subtree_subproof(a + k, 0, end - k, n - k, false, out)?;
            out.push(self.hash_window(a, a + k)?);
        }
        Ok(())
    }

    /// Verifies a subtree consistency proof (draft §4.4.3).
    ///
    /// Rebuilds `fr` (the subtree hash) and `sr` (the tree hash) in one pass; because everything
    /// folded into `fr` is also folded into `sr`, success is what demonstrates that the tree hash
    /// *contains* the subtree hash, rather than the two hashes merely being consistent.
    pub fn verify_consistency(
        start: u64,
        end: u64,
        tree_size: u64,
        subtree_root: &[u8; 32],
        tree_root: &[u8; 32],
        proof: &[[u8; 32]],
    ) -> MtcResult<()> {
        if start > end || end > tree_size {
            return Err(MtcError::InvalidRange {
                start: end,
                end: tree_size,
            });
        }
        if !is_valid_subtree(start, end) {
            return Err(MtcError::UnalignedSubtree { start, end });
        }

        if start == end {
            if !proof.is_empty() {
                return Err(MtcError::ProofLengthMismatch {
                    expected: 0,
                    got: proof.len(),
                });
            }
            if subtree_root != &empty_tree_hash() {
                return Err(MtcError::RootMismatch {
                    computed: hex::encode(subtree_root),
                    expected: hex::encode(empty_tree_hash()),
                });
            }
            return Ok(());
        }

        let mut fn_index = start;
        let mut sn = end - 1;
        let mut tn = tree_size - 1;

        if sn == tn {
            while fn_index != sn {
                fn_index >>= 1;
                sn >>= 1;
                tn >>= 1;
            }
        } else {
            while fn_index != sn && sn & 1 == 1 {
                fn_index >>= 1;
                sn >>= 1;
                tn >>= 1;
            }
        }

        let (mut fr, mut sr, position) = if fn_index == sn {
            (*subtree_root, *subtree_root, 0usize)
        } else {
            match proof.first() {
                Some(first) => (*first, *first, 1usize),
                None => {
                    return Err(MtcError::ProofLengthMismatch {
                        expected: 1,
                        got: 0,
                    })
                }
            }
        };

        for (offset, c) in proof[position..].iter().enumerate() {
            if tn == 0 {
                return Err(MtcError::ProofLengthMismatch {
                    expected: position + offset,
                    got: proof.len(),
                });
            }
            if sn & 1 == 1 || sn == tn {
                if fn_index < sn {
                    fr = node_hash(c, &fr);
                }
                sr = node_hash(c, &sr);
                while sn & 1 == 0 {
                    fn_index >>= 1;
                    sn >>= 1;
                    tn >>= 1;
                }
            } else {
                sr = node_hash(&sr, c);
            }
            fn_index >>= 1;
            sn >>= 1;
            tn >>= 1;
        }

        if tn != 0 {
            return Err(MtcError::ProofLengthMismatch {
                expected: proof.len() + 1,
                got: proof.len(),
            });
        }
        if fr != *subtree_root {
            return Err(MtcError::RootMismatch {
                computed: hex::encode(fr),
                expected: hex::encode(subtree_root),
            });
        }
        if sr != *tree_root {
            return Err(MtcError::RootMismatch {
                computed: hex::encode(sr),
                expected: hex::encode(tree_root),
            });
        }
        Ok(())
    }

    /// Convenience wrapper: consistency proof for the prefix subtree `[0, from_size)` against a
    /// tree of `to_size` elements (this is the landmark-sync case).
    pub fn prefix_consistency_proof(
        &self,
        from_size: u64,
        to_size: u64,
    ) -> MtcResult<SubtreeConsistencyProof> {
        self.consistency_proof(0, from_size, to_size)
    }

    /// Convenience wrapper: verify a proof produced by [`Self::prefix_consistency_proof`].
    pub fn verify_prefix_consistency(
        from_root: &[u8; 32],
        to_root: &[u8; 32],
        proof: &SubtreeConsistencyProof,
    ) -> MtcResult<()> {
        Self::verify_consistency(
            proof.start,
            proof.end,
            proof.tree_size,
            from_root,
            to_root,
            &proof.proof,
        )
    }
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::*;

    /// Builds the draft's Appendix C tree: `d[i] = i` as a single byte.
    fn draft_tree(size: u64) -> MerkleTreeLog {
        let mut log = MerkleTreeLog::new();
        for i in 0..size {
            log.append_raw_entry(&[i as u8]);
        }
        log
    }

    fn sample_log(n: u64) -> MerkleTreeLog {
        let mut log = MerkleTreeLog::new();
        for i in 0..n {
            log.append_raw_entry(&[i as u8; 32]);
        }
        log
    }

    // ---------------------------------------------------------------- Appendix C conformance

    /// Draft §C.1.1: accumulated subtree hashes for every valid subtree of trees up to size 130.
    #[test]
    fn appendix_c_1_1_subtree_hashes() {
        let log = draft_tree(130);
        let mut rolling = Sha256::new();
        for end in 0..=130u64 {
            for start in 0..=end {
                if is_valid_subtree(start, end) {
                    let hash = log.subtree_hash(start, end).unwrap();
                    rolling.update(format!("[{start}, {end}) {}\n", hex::encode(hash)));
                }
            }
        }
        assert_eq!(
            hex::encode(rolling.finalize()),
            "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"
        );
    }

    /// Draft §C.1.2: accumulated subtree inclusion proofs.
    #[test]
    fn appendix_c_1_2_inclusion_proofs() {
        let log = draft_tree(130);
        let mut rolling = Sha256::new();
        for end in 0..=130u64 {
            for start in 0..=end {
                if !is_valid_subtree(start, end) {
                    continue;
                }
                for index in start..end {
                    let proof = log.inclusion_proof(index, start, end).unwrap();
                    let mut line = format!("{index} [{start}, {end})");
                    for p in &proof {
                        line.push(' ');
                        line.push_str(&hex::encode(p));
                    }
                    line.push('\n');
                    rolling.update(line);
                }
            }
        }
        assert_eq!(
            hex::encode(rolling.finalize()),
            "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
        );
    }

    /// Draft §C.1.3: accumulated subtree consistency proofs.
    #[test]
    fn appendix_c_1_3_consistency_proofs() {
        let log = draft_tree(130);
        let mut rolling = Sha256::new();
        for n in 0..=130u64 {
            for end in 0..=n {
                for start in 0..=end {
                    if !is_valid_subtree(start, end) {
                        continue;
                    }
                    let proof = log.consistency_proof(start, end, n).unwrap();
                    let mut line = format!("[{start}, {end}) {n}");
                    for p in &proof.proof {
                        line.push(' ');
                        line.push_str(&hex::encode(p));
                    }
                    line.push('\n');
                    rolling.update(line);
                }
            }
        }
        assert_eq!(
            hex::encode(rolling.finalize()),
            "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74"
        );
    }

    /// Draft §C.1.4: accumulated covering-subtree selections.
    #[test]
    fn appendix_c_1_4_efficient_covering_subtrees() {
        let mut rolling = Sha256::new();
        for end in 0..=130u64 {
            for start in 0..=end {
                let covering = find_subtrees(start, end).unwrap();
                rolling.update(format!(
                    "[{}, {}) [{}, {})\n",
                    covering[0].start, covering[0].end, covering[1].start, covering[1].end
                ));
            }
        }
        assert_eq!(
            hex::encode(rolling.finalize()),
            "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0"
        );
    }

    /// Draft §C.2.1 and §C.2.4: large-value subtree validity and covering examples.
    #[test]
    fn appendix_c_2_large_values() {
        for end in [
            (1u64 << 47) + 1,
            (1u64 << 48) - 1,
            (1u64 << 62) + 1,
            (1u64 << 63) - 1,
            (1u64 << 63) + 1,
            u64::MAX,
        ] {
            assert!(is_valid_subtree(0, end), "[0, {end:#x}) must be valid");
        }
        for (start, end) in [
            (1u64 << 46, (1u64 << 47) + 1),
            (1u64 << 46, (1u64 << 48) - 1),
            (1u64 << 61, (1u64 << 62) + 1),
            (1u64 << 61, (1u64 << 63) - 1),
            (1u64 << 62, (1u64 << 63) + 1),
            (1u64 << 62, u64::MAX),
        ] {
            assert!(
                !is_valid_subtree(start, end),
                "[{start:#x}, {end:#x}) must be invalid"
            );
        }

        let covering = find_subtrees(0x0, 0x8000_0000_0000).unwrap();
        assert_eq!(
            covering[0],
            SubtreeRange {
                start: 0,
                end: 0x4000_0000_0000
            }
        );
        assert_eq!(
            covering[1],
            SubtreeRange {
                start: 0x4000_0000_0000,
                end: 0x8000_0000_0000
            }
        );

        let covering = find_subtrees(0x5000_0000_0000, 0xd000_0000_0000).unwrap();
        assert_eq!(
            covering[0],
            SubtreeRange {
                start: 0x4000_0000_0000,
                end: 0x8000_0000_0000
            }
        );
        assert_eq!(
            covering[1],
            SubtreeRange {
                start: 0x8000_0000_0000,
                end: 0xd000_0000_0000
            }
        );
    }

    // ---------------------------------------------------------------- local invariants

    #[test]
    fn covering_subtrees_satisfy_the_draft_contract() {
        for end in 0..=130u64 {
            for start in 0..=end {
                let covering = find_subtrees(start, end).unwrap();
                let (left, right) = (covering[0], covering[1]);
                assert!(left.is_valid(), "left {left:?} must be a valid subtree");
                assert!(right.is_valid(), "right {right:?} must be a valid subtree");
                assert!(
                    left.start <= start,
                    "left must not start after [start, end)"
                );
                assert!(start <= left.end, "left must reach start");
                assert_eq!(left.end, right.start, "left and right must be adjacent");
                assert!(right.end >= end, "right must reach end");
                assert_eq!(right.end, end, "right must not extend past end");
                assert!(left.len() <= bit_ceil(end - start) || end - start == 0);
                assert!(right.len() <= bit_ceil(end - start));
            }
        }
    }

    #[test]
    fn inclusion_proofs_evaluate_to_the_subtree_hash() {
        let log = draft_tree(40);
        for end in 0..=40u64 {
            for start in 0..=end {
                if !is_valid_subtree(start, end) {
                    continue;
                }
                let subtree_hash = log.subtree_hash(start, end).unwrap();
                for index in start..end {
                    let proof = log.inclusion_proof(index, start, end).unwrap();
                    let leaf = log.leaf_hash_at(index).unwrap();
                    MerkleTreeLog::verify_inclusion(
                        &leaf,
                        index,
                        start,
                        end,
                        &proof,
                        &subtree_hash,
                    )
                    .unwrap_or_else(|e| panic!("index {index} in [{start}, {end}): {e}"));
                }
            }
        }
    }

    #[test]
    fn inclusion_proof_evaluation_rejects_truncation_and_extension() {
        let log = draft_tree(24);
        let start = 8;
        let end = 13;
        let index = 10;
        let leaf = log.leaf_hash_at(index).unwrap();
        let subtree_hash = log.subtree_hash(start, end).unwrap();
        let proof = log.inclusion_proof(index, start, end).unwrap();
        assert_eq!(proof.len(), 3, "draft §4.3.1 example proof length");

        MerkleTreeLog::verify_inclusion(&leaf, index, start, end, &proof, &subtree_hash).unwrap();

        // Truncated and extended proofs must fail (draft Appendix C.1.2 steps 3 and 4).
        assert!(MerkleTreeLog::verify_inclusion(
            &leaf,
            index,
            start,
            end,
            &proof[..proof.len() - 1],
            &subtree_hash
        )
        .is_err());
        let mut extended = proof.clone();
        extended.push([0xAA; 32]);
        assert!(MerkleTreeLog::verify_inclusion(
            &leaf,
            index,
            start,
            end,
            &extended,
            &subtree_hash
        )
        .is_err());
    }

    #[test]
    fn inclusion_proof_example_matches_the_draft() {
        // Draft §4.3.1: proof for entry 10 of subtree [8, 13) is
        // [MTH({d[11]}), MTH(D[8:10]), MTH({d[12]})].
        let log = draft_tree(13);
        let proof = log.inclusion_proof(10, 8, 13).unwrap();
        assert_eq!(proof.len(), 3);
        assert_eq!(proof[0], hash_leaf(&[11]));
        assert_eq!(proof[1], log.subtree_hash(8, 10).unwrap());
        assert_eq!(proof[2], hash_leaf(&[12]));
    }

    #[test]
    fn consistency_proofs_verify_exhaustively() {
        let log = draft_tree(40);
        for n in 0..=40u64 {
            for end in 0..=n {
                for start in 0..=end {
                    if !is_valid_subtree(start, end) {
                        continue;
                    }
                    let subtree_root = log.subtree_hash(start, end).unwrap();
                    let tree_root = log.subtree_hash(0, n).unwrap();
                    let proof = log.consistency_proof(start, end, n).unwrap();
                    MerkleTreeLog::verify_consistency(
                        start,
                        end,
                        n,
                        &subtree_root,
                        &tree_root,
                        &proof.proof,
                    )
                    .unwrap_or_else(|e| panic!("consistency [{start}, {end}) vs n={n}: {e}"));
                }
            }
        }
    }

    #[test]
    fn consistency_verification_detects_every_tamper() {
        let log = draft_tree(24);
        let start = 0;
        let end = 6;
        let n = 24;
        let subtree_root = log.subtree_hash(start, end).unwrap();
        let tree_root = log.subtree_hash(0, n).unwrap();
        let proof = log.consistency_proof(start, end, n).unwrap();
        assert!(!proof.is_empty());
        MerkleTreeLog::verify_consistency(start, end, n, &subtree_root, &tree_root, &proof.proof)
            .unwrap();

        // Flipping a bit in any proof hash fails.
        for i in 0..proof.proof.len() {
            let mut bad = proof.proof.clone();
            bad[i][7] ^= 0x01;
            assert!(
                MerkleTreeLog::verify_consistency(start, end, n, &subtree_root, &tree_root, &bad)
                    .is_err(),
                "mutated proof element {i} was accepted"
            );
        }

        // Flipping a bit in the input subtree hash fails.
        let mut bad_subtree = subtree_root;
        bad_subtree[0] ^= 0x01;
        assert!(MerkleTreeLog::verify_consistency(
            start,
            end,
            n,
            &bad_subtree,
            &tree_root,
            &proof.proof
        )
        .is_err());

        // Flipping a bit in the input tree hash fails.
        let mut bad_tree = tree_root;
        bad_tree[0] ^= 0x01;
        assert!(MerkleTreeLog::verify_consistency(
            start,
            end,
            n,
            &subtree_root,
            &bad_tree,
            &proof.proof
        )
        .is_err());

        // Truncation and extension fail.
        assert!(MerkleTreeLog::verify_consistency(
            start,
            end,
            n,
            &subtree_root,
            &tree_root,
            &proof.proof[..proof.proof.len() - 1]
        )
        .is_err());
        let mut extended = proof.proof.clone();
        extended.push([0x11; 32]);
        assert!(MerkleTreeLog::verify_consistency(
            start,
            end,
            n,
            &subtree_root,
            &tree_root,
            &extended
        )
        .is_err());
    }

    #[test]
    fn empty_subtree_consistency_has_a_dedicated_shape() {
        let log = draft_tree(8);
        let proof = log.consistency_proof(3, 3, 8).unwrap();
        assert!(proof.is_empty());
        MerkleTreeLog::verify_consistency(
            3,
            3,
            8,
            &empty_tree_hash(),
            &log.root_hash().unwrap(),
            &[],
        )
        .unwrap();
        assert!(MerkleTreeLog::verify_consistency(
            3,
            3,
            8,
            &[0u8; 32],
            &log.root_hash().unwrap(),
            &[]
        )
        .is_err());
    }

    #[test]
    fn append_is_consistent_with_recomputation() {
        let mut log = MerkleTreeLog::new();
        for i in 0..=200u64 {
            log.append_raw_entry(&i.to_be_bytes());
            let mut fresh = MerkleTreeLog::new();
            for j in 0..=i {
                fresh.append_raw_entry(&j.to_be_bytes());
            }
            assert_eq!(log.root_hash().unwrap(), fresh.root_hash().unwrap());
        }
    }

    #[test]
    fn subtree_hash_matches_naive_recursion() {
        let log = sample_log(23);
        let leaves: Vec<[u8; 32]> = (0..23u64).map(|i| hash_leaf(&[i as u8; 32])).collect();

        fn naive(leaves: &[[u8; 32]], start: usize, end: usize) -> [u8; 32] {
            let size = end - start;
            if size == 1 {
                return leaves[start];
            }
            let k = 1usize << (usize::BITS - 1 - (size as u64 - 1).leading_zeros()) as usize;
            node_hash(
                &naive(leaves, start, start + k),
                &naive(leaves, start + k, end),
            )
        }

        for start in 0..23usize {
            for end in (start + 1)..=23usize {
                assert_eq!(
                    log.subtree_hash(start as u64, end as u64).unwrap(),
                    naive(&leaves, start, end),
                    "subtree_hash mismatch for [{start},{end})"
                );
            }
        }
        assert_eq!(log.subtree_hash(5, 5).unwrap(), empty_tree_hash());
        assert!(log.subtree_hash(9, 4).is_err());
        assert!(log.subtree_hash(0, 24).is_err());
    }

    #[test]
    fn non_canonical_ranges_are_rejected() {
        let log = draft_tree(16);
        assert!(
            log.inclusion_proof(0, 1, 5).is_err(),
            "[1,5) is not a valid subtree"
        );
        assert!(log.consistency_proof(1, 5, 16).is_err());
        assert!(find_subtrees(0, MAX_LOG_SIZE + 1).is_err());
    }
}
