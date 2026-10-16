//! O(log N) power-of-two skip-link landmark graph (`draft-gray-plants-mtc-deploy-use-cases-01`
//! §3.1.6) and landmark checkpoint payloads.
//!
//! At landmark `N` the LDP registers edges `L_{N-2^k} → L_N` for every `k` with `2^k <= N`. A stale
//! client resolves catch-up with greedy binary jumps, so the hop count is
//! `popcount(target - client) <= ceil(log2(delta))` and only the *final* checkpoint needs an
//! ML-DSA-65 verification (ADR-003).

use crate::error::{MtcError, MtcResult};
use crate::subtrees::{MerkleTreeLog, SubtreeConsistencyProof};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

/// Domain separator of a landmark checkpoint statement: `"checkpoint/v1\n\0"`.
pub const CHECKPOINT_CONTEXT_HEADER: [u8; 15] = *b"checkpoint/v1\n\0";

/// Length of the landmark checkpoint statement: 15 + 8 + 8 + 8 + 32.
pub const CHECKPOINT_PAYLOAD_LEN: usize = 71;

/// One published landmark (checkpoint) of the transparency log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandmarkNode {
    /// Monotonic landmark index `N`.
    pub landmark_id: u64,
    /// Log size `S_N` at publication time.
    pub tree_size: u64,
    /// Publication time, unix seconds.
    pub timestamp: u64,
    /// Root hash of the log at `tree_size`.
    pub root_hash: [u8; 32],
    /// Checkpoint signature over [`checkpoint_payload`] (ML-DSA-65 in production wiring).
    pub checkpoint_signature: Vec<u8>,
}

/// A published skip link between two landmarks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipLinkEdge {
    /// Origin landmark id.
    pub from_landmark: u64,
    /// Landmark id at the origin.
    pub from_tree_size: u64,
    /// Destination landmark id.
    pub to_landmark: u64,
    /// Log size at the destination.
    pub to_tree_size: u64,
    /// Root hash committed to by this edge.
    pub to_root_hash: [u8; 32],
    /// Consistency proof binding the origin root to the destination root.
    pub consistency_proof: SubtreeConsistencyProof,
}

/// The hop plan a stale client executes to reach a target landmark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandmarkSubtreeProofSet {
    /// Landmark the client already trusts.
    pub client_landmark: u64,
    /// Target landmark.
    pub target_landmark: u64,
    /// Log size at the target.
    pub target_tree_size: u64,
    /// Publication timestamp of the target landmark.
    pub target_timestamp: u64,
    /// Root hash the client ends up trusting.
    pub target_root_hash: [u8; 32],
    /// Ordered skip-link edges; hop count is `popcount(target - client)`.
    pub hops: Vec<SkipLinkEdge>,
    /// The single signature the client must verify, on the target landmark.
    pub target_checkpoint_signature: Vec<u8>,
}

impl LandmarkSubtreeProofSet {
    /// Number of hops (edges) in the plan.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Total wire cost of the skip-link portion of the plan (40 B per hop, `flow.md` §4.3.2).
    pub fn wire_bytes(&self) -> usize {
        self.hops.len() * SKIP_LINK_HOP_BYTES
    }

    /// The exact 71-byte message the target checkpoint signature covers.
    pub fn target_checkpoint_payload(&self) -> [u8; CHECKPOINT_PAYLOAD_LEN] {
        checkpoint_payload(
            self.target_landmark,
            self.target_tree_size,
            self.target_timestamp,
            &self.target_root_hash,
        )
    }
}

/// Wire cost of one skip-link hop inside a Flight 1 budget.
pub const SKIP_LINK_HOP_BYTES: usize = 40;

/// Number of greedy binary-jump hops needed to travel `delta` landmarks.
pub fn hop_count_for(delta: u64) -> usize {
    delta.count_ones() as usize
}

/// Canonical 71-byte landmark checkpoint statement handed to the injected signer.
pub fn checkpoint_payload(
    landmark_id: u64,
    tree_size: u64,
    timestamp: u64,
    root_hash: &[u8; 32],
) -> [u8; CHECKPOINT_PAYLOAD_LEN] {
    let mut out = [0u8; CHECKPOINT_PAYLOAD_LEN];
    out[0..15].copy_from_slice(&CHECKPOINT_CONTEXT_HEADER);
    out[15..23].copy_from_slice(&landmark_id.to_be_bytes());
    out[23..31].copy_from_slice(&tree_size.to_be_bytes());
    out[31..39].copy_from_slice(&timestamp.to_be_bytes());
    out[39..71].copy_from_slice(root_hash);
    out
}

/// The published skip-link graph, backed by a level-indexed log for O(log²) proof derivation.
///
/// Edge existence and sizes are registered at publication time; the consistency proof *bytes* are
/// derived on demand from the log and memoized in an insertion-ordered cache, which keeps LDP memory
/// at O(N) instead of O(N log²) while preserving the O(log N) client hop count (ADR-003).
#[derive(Debug, Default)]
pub struct LandmarkGraph {
    landmarks: Vec<LandmarkNode>,
    /// Published edges keyed by `(from_landmark, to_landmark)` → `(from_tree_size, to_tree_size)`.
    edges: HashMap<(u64, u64), (u64, u64)>,
    /// Insertion-ordered memoization of materialized consistency proofs.
    proof_cache: RefCell<ProofCache>,
}

/// Maximum number of materialized consistency proofs retained by the LDP cache.
pub const PROOF_CACHE_CAPACITY: usize = 4_096;

/// Insertion-ordered proof memoization with a hard capacity bound.
#[derive(Debug, Default)]
struct ProofCache {
    entries: HashMap<(u64, u64), SubtreeConsistencyProof>,
    order: VecDeque<(u64, u64)>,
}

impl ProofCache {
    fn get(&self, key: &(u64, u64)) -> Option<SubtreeConsistencyProof> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: (u64, u64), proof: SubtreeConsistencyProof) {
        if self.entries.insert(key, proof).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > PROOF_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl LandmarkGraph {
    /// Creates an empty graph.
    pub fn new() -> Self {
        Self {
            landmarks: Vec::new(),
            edges: HashMap::new(),
            proof_cache: RefCell::new(ProofCache::default()),
        }
    }

    /// Number of published landmarks.
    pub fn len(&self) -> usize {
        self.landmarks.len()
    }

    /// True when no landmark has been published.
    pub fn is_empty(&self) -> bool {
        self.landmarks.is_empty()
    }

    /// Borrows the landmark log.
    pub fn landmarks(&self) -> &[LandmarkNode] {
        &self.landmarks
    }

    /// Looks up a published landmark.
    pub fn landmark(&self, landmark_id: u64) -> MtcResult<&LandmarkNode> {
        self.landmarks
            .get(landmark_id as usize)
            .filter(|node| node.landmark_id == landmark_id)
            .ok_or(MtcError::SkipLinkEdgeMissing {
                from: landmark_id,
                to: landmark_id,
            })
    }

    /// Publishes landmark `N` for the current state of `tree` and registers the edges
    /// `L_{N-2^k} → L_N` for every `k` with `2^k <= N`.
    ///
    /// `sign_fn` is injected so this crate stays free of a signature dependency: production wiring
    /// passes an ML-DSA-65 signer, tests pass a deterministic seeded signer.
    pub fn publish_landmark<F>(
        &mut self,
        tree: &MerkleTreeLog,
        timestamp: u64,
        sign_fn: F,
    ) -> MtcResult<u64>
    where
        F: Fn(&[u8]) -> Vec<u8>,
    {
        let landmark_id = self.landmarks.len() as u64;
        let tree_size = tree.len();
        let root_hash = tree.root_hash()?;
        let payload = checkpoint_payload(landmark_id, tree_size, timestamp, &root_hash);

        self.landmarks.push(LandmarkNode {
            landmark_id,
            tree_size,
            timestamp,
            root_hash,
            checkpoint_signature: sign_fn(&payload),
        });

        let mut step = 1u64;
        while step <= landmark_id {
            let from = landmark_id - step;
            let from_tree_size = self.landmarks[from as usize].tree_size;
            self.edges
                .insert((from, landmark_id), (from_tree_size, tree_size));
            step <<= 1;
        }

        Ok(landmark_id)
    }

    /// True when the power-of-two edge `from → to` was published.
    pub fn has_edge(&self, from: u64, to: u64) -> bool {
        self.edges.contains_key(&(from, to))
    }

    /// Number of published edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Materializes the edge `from → to`, deriving the consistency proof from the log on first use.
    pub fn edge(&self, tree: &MerkleTreeLog, from: u64, to: u64) -> MtcResult<SkipLinkEdge> {
        let (from_tree_size, to_tree_size) = self
            .edges
            .get(&(from, to))
            .copied()
            .ok_or(MtcError::SkipLinkEdgeMissing { from, to })?;
        let to_node = self.landmark(to)?;

        let key = (from_tree_size, to_tree_size);
        // The borrow guard is released at the end of this statement so the `borrow_mut` below
        // cannot collide with a live `borrow()`.
        let cached = self.proof_cache.borrow().get(&key);
        let proof = match cached {
            Some(proof) => proof,
            None => {
                let derived = tree.prefix_consistency_proof(from_tree_size, to_tree_size)?;
                self.proof_cache.borrow_mut().insert(key, derived.clone());
                derived
            }
        };

        Ok(SkipLinkEdge {
            from_landmark: from,
            from_tree_size,
            to_landmark: to,
            to_tree_size,
            to_root_hash: to_node.root_hash,
            consistency_proof: proof,
        })
    }

    /// Number of consistency proofs currently materialized (memory accounting for ADR-003).
    pub fn cached_proof_count(&self) -> usize {
        self.proof_cache.borrow().len()
    }

    /// Builds the greedy binary-jump plan from `client_landmark` to `target_landmark`.
    ///
    /// Each step jumps by the highest power of two that still fits, so the plan contains
    /// `popcount(target - client)` hops — never a linear walk through intermediate landmarks.
    pub fn plan_skip_link_sync(
        &self,
        tree: &MerkleTreeLog,
        client_landmark: u64,
        target_landmark: u64,
    ) -> MtcResult<LandmarkSubtreeProofSet> {
        if target_landmark < client_landmark {
            return Err(MtcError::InvalidLandmarkDelta {
                from: client_landmark,
                to: target_landmark,
            });
        }
        // Validates that both endpoints are actually published.
        self.landmark(client_landmark)?;
        let target_node = self.landmark(target_landmark)?;

        let mut hops = Vec::with_capacity(hop_count_for(target_landmark - client_landmark));
        let mut current = client_landmark;
        while current < target_landmark {
            let remaining = target_landmark - current;
            let step = 1u64 << (63 - remaining.leading_zeros());
            let next = current + step;
            if !self.has_edge(current, next) {
                return Err(MtcError::SkipLinkEdgeMissing {
                    from: current,
                    to: next,
                });
            }
            hops.push(self.edge(tree, current, next)?);
            current = next;
        }

        Ok(LandmarkSubtreeProofSet {
            client_landmark,
            target_landmark,
            target_tree_size: target_node.tree_size,
            target_timestamp: target_node.timestamp,
            target_root_hash: target_node.root_hash,
            hops,
            target_checkpoint_signature: target_node.checkpoint_signature.clone(),
        })
    }

    /// Verifies a hop plan: chains every consistency proof and checks the one target checkpoint.
    ///
    /// `verify_signature` receives `(checkpoint_payload, signature)` — the signed *message*, not
    /// just the root, because that is what a real signature verification API (ML-DSA-65 here)
    /// needs. Intermediate hops are bound by collision-resistant consistency hashes and are
    /// therefore never signature-checked.
    pub fn verify_skip_link_sync<S>(
        plan: &LandmarkSubtreeProofSet,
        client_root_hash: &[u8; 32],
        verify_signature: S,
    ) -> MtcResult<()>
    where
        S: FnOnce(&[u8], &[u8]) -> bool,
    {
        let mut root = *client_root_hash;
        let mut expected_from_size: Option<u64> = None;

        for hop in &plan.hops {
            if let Some(size) = expected_from_size {
                if hop.from_tree_size != size {
                    return Err(MtcError::InvalidRange {
                        start: size,
                        end: hop.from_tree_size,
                    });
                }
            }
            MerkleTreeLog::verify_prefix_consistency(
                &root,
                &hop.to_root_hash,
                &hop.consistency_proof,
            )?;
            root = hop.to_root_hash;
            expected_from_size = Some(hop.to_tree_size);
        }

        if root != plan.target_root_hash {
            return Err(MtcError::RootMismatch {
                computed: hex::encode(root),
                expected: hex::encode(plan.target_root_hash),
            });
        }

        if !verify_signature(
            &plan.target_checkpoint_payload(),
            &plan.target_checkpoint_signature,
        ) {
            return Err(MtcError::CheckpointSignatureInvalid {
                landmark: plan.target_landmark,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Deterministic stand-in for an ML-DSA-65 checkpoint signer: keyed SHA-256 over the payload.
    /// The verification contract (one signature, bound to the root) is what is under test here.
    fn signer() -> impl Fn(&[u8]) -> Vec<u8> {
        move |payload: &[u8]| {
            let mut hasher = Sha256::new();
            hasher.update(b"chronos-test-checkpoint-key");
            hasher.update(payload);
            hasher.finalize().to_vec()
        }
    }

    fn verifier() -> impl Fn(&[u8], &[u8]) -> bool {
        move |message: &[u8], signature: &[u8]| signer()(message) == signature
    }

    fn build(landmarks: u64, leaves_per_epoch: u64) -> (MerkleTreeLog, LandmarkGraph) {
        let mut tree = MerkleTreeLog::new();
        let mut graph = LandmarkGraph::new();
        let sign = signer();
        for epoch in 0..landmarks {
            for leaf in 0..leaves_per_epoch {
                tree.append_raw_entry(&[epoch as u8, leaf as u8]);
            }
            graph
                .publish_landmark(&tree, 1_700_000_000 + epoch, &sign)
                .unwrap();
        }
        (tree, graph)
    }

    #[test]
    fn checkpoint_payload_layout() {
        let root = [0x5A; 32];
        let payload = checkpoint_payload(7, 640_000, 1_700_000_000, &root);
        assert_eq!(payload.len(), CHECKPOINT_PAYLOAD_LEN);
        assert_eq!(&payload[0..15], b"checkpoint/v1\n\0");
        assert_eq!(&payload[15..23], &7u64.to_be_bytes());
        assert_eq!(&payload[23..31], &640_000u64.to_be_bytes());
        assert_eq!(&payload[31..39], &1_700_000_000u64.to_be_bytes());
        assert_eq!(&payload[39..71], &root);
    }

    #[test]
    fn edges_are_published_for_every_power_of_two() {
        let (_tree, graph) = build(20, 4);
        assert_eq!(graph.len(), 20);

        // Landmark N has exactly floor(log2(N)) + 1 outgoing edges.
        for n in 0..20u64 {
            let expected = if n == 0 {
                0
            } else {
                64 - (n.leading_zeros() as usize)
            };
            let mut k = 0u32;
            while (1u64 << k) <= n {
                assert!(
                    graph.has_edge(n - (1u64 << k), n),
                    "edge {}-{}->{}",
                    n - (1u64 << k),
                    n,
                    k
                );
                k += 1;
            }
            let mut edges = 0u32;
            let mut k = 0u32;
            while (1u64 << k) <= n {
                edges += 1;
                k += 1;
            }
            assert_eq!(edges as usize, expected, "landmark {n} edge count");
        }

        // Non-power-of-two gaps are not edges.
        assert!(!graph.has_edge(0, 3));
        assert!(!graph.has_edge(6, 15), "step 9 is not a power of two");
        assert!(!graph.has_edge(4, 3), "edges point forward");
    }

    #[test]
    fn hop_count_equals_popcount_of_delta() {
        let (tree, graph) = build(600, 2);
        let target = (graph.len() - 1) as u64;
        for delta in 1..=target {
            let client = target - delta;
            let plan = graph.plan_skip_link_sync(&tree, client, target).unwrap();
            assert_eq!(
                plan.hop_count(),
                hop_count_for(delta),
                "delta {delta} hop count"
            );
            assert!(plan.hop_count() <= 64 - delta.leading_zeros() as usize);
        }
    }

    #[test]
    fn large_deltas_stay_logarithmic() {
        // Ten years of hourly landmarks: 87,600 epochs, 7 hops (bound 17).
        assert_eq!(hop_count_for(87_600), 7);
        assert!(hop_count_for(87_600) <= 17);
        // Ten thousand missed epochs: 5 hops, 200 B of skip-links.
        assert_eq!(hop_count_for(10_000), 5);
        assert_eq!(hop_count_for(10_000) * SKIP_LINK_HOP_BYTES, 200);
    }

    #[test]
    fn plan_verifies_end_to_end() {
        let (tree, graph) = build(300, 3);
        let target = (graph.len() - 1) as u64;
        let client_root = graph.landmark(37).unwrap().root_hash;

        let plan = graph.plan_skip_link_sync(&tree, 37, target).unwrap();
        assert!(plan.hop_count() > 1, "plan should take multiple hops");
        LandmarkGraph::verify_skip_link_sync(&plan, &client_root, verifier()).unwrap();

        // A single hop still works.
        let one_hop_from = target - 4;
        let one_hop = graph
            .plan_skip_link_sync(&tree, one_hop_from, target)
            .unwrap();
        assert_eq!(one_hop.hop_count(), 1);
        let root_before = graph.landmark(one_hop_from).unwrap().root_hash;
        LandmarkGraph::verify_skip_link_sync(&one_hop, &root_before, verifier()).unwrap();
    }

    #[test]
    fn plan_detects_tampered_hops_and_bad_signatures() {
        let (tree, graph) = build(64, 2);
        let target = (graph.len() - 1) as u64;
        let client_root = graph.landmark(3).unwrap().root_hash;
        let plan = graph.plan_skip_link_sync(&tree, 3, target).unwrap();

        // Tampered intermediate proof hash.
        let mut bad_hop = plan.clone();
        bad_hop.hops[0].consistency_proof.proof[0][0] ^= 0xFF;
        assert!(LandmarkGraph::verify_skip_link_sync(&bad_hop, &client_root, verifier()).is_err());

        // Tampered edge root.
        let mut bad_root = plan.clone();
        bad_root.hops[0].to_root_hash[5] ^= 0x01;
        assert!(LandmarkGraph::verify_skip_link_sync(&bad_root, &client_root, verifier()).is_err());

        // Wrong client root: the chain cannot reach the target.
        assert!(LandmarkGraph::verify_skip_link_sync(&plan, &[0u8; 32], verifier()).is_err());

        // Valid structure, invalid checkpoint signature.
        assert!(matches!(
            LandmarkGraph::verify_skip_link_sync(&plan, &client_root, |_, _| false),
            Err(MtcError::CheckpointSignatureInvalid { .. })
        ));
    }

    #[test]
    fn plan_rejects_backwards_targets_and_unknown_landmarks() {
        let (tree, graph) = build(16, 2);
        assert!(matches!(
            graph.plan_skip_link_sync(&tree, 10, 4),
            Err(MtcError::InvalidLandmarkDelta { .. })
        ));
        assert!(graph.plan_skip_link_sync(&tree, 0, 99).is_err());
        assert!(graph.landmark(99).is_err());
    }

    #[test]
    fn proof_materialization_is_cached() {
        let (tree, graph) = build(41, 2);
        let before = graph.cached_proof_count();
        let first = graph.edge(&tree, 32, 40).unwrap();
        let after_first = graph.cached_proof_count();
        let second = graph.edge(&tree, 32, 40).unwrap();
        assert_eq!(first, second);
        assert_eq!(after_first, before + 1);
        assert_eq!(graph.cached_proof_count(), after_first, "cache is reused");
    }

    #[test]
    fn edge_metadata_is_registered_at_publication() {
        let (_tree, graph) = build(16, 2);
        assert!(graph.edge_count() > 0);
        // Landmark 15 publishes edges from 14, 13, 11 and 7 (steps 1, 2, 4, 8).
        assert!(graph.has_edge(14, 15));
        assert!(graph.has_edge(13, 15));
        assert!(graph.has_edge(11, 15));
        assert!(graph.has_edge(7, 15));
        assert!(!graph.has_edge(6, 15), "step 9 is not a power of two");
        assert!(!graph.has_edge(15, 15), "self loops are not edges");
        assert!(!graph.has_edge(0, 0));
    }
}
