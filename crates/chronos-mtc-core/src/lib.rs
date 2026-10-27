#![allow(unexpected_cfgs)]
//! # chronos-mtc-core
//!
//! IETF PLANTS Merkle Tree Certificate engine: canonical subtree decomposition
//! (`draft-ietf-plants-merkle-tree-certs-07` §4.5.1), a single-pass streaming `TBSCertificate`
//! leaf hasher with a strict DER guard (§7.2, §12.6), the O(log N) power-of-two skip-link landmark
//! graph (`draft-gray-plants-mtc-deploy-use-cases-01` §3.1.6), canonical C2SP cosignatures, C2SP
//! `tlog-tiles` rendering and base-128 relative-OID trust anchor negotiation
//! (`draft-ietf-tls-trust-anchor-ids-06` §5.3.1).
//!
//! The crate contains no signature implementation on purpose: checkpoint signing is injected as a
//! closure, so `chronos-pqc-sys` (ML-DSA-65) and the deterministic test vectors share one code path.
//! Every module is `#![forbid(unsafe_code)]` and allocation-free on the hashing hot path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[path = "cosign.rs"]
pub mod cosign;
#[path = "error.rs"]
pub mod error;
#[path = "skip_link.rs"]
pub mod skip_link;
#[path = "subtrees.rs"]
pub mod subtrees;
#[path = "tbs_hasher.rs"]
pub mod tbs_hasher;
#[path = "tiles.rs"]
pub mod tiles;
#[path = "trust_anchor.rs"]
pub mod trust_anchor;

pub use cosign::{
    canonicalize_cosignatures, count_quorum, is_canonical_cosigner_order, is_grease_cosigner_id,
    trust_anchor_id_string, Cosignature, CosignedSubtree, MtcProof, TimestampedSignature,
    COSIGN_CONTEXT_HEADER, ID_ALG_MTC_PROOF, OID_MTC_PROOF,
};
pub use error::{MtcError, MtcResult};
pub use skip_link::{
    checkpoint_payload, hop_count_for, LandmarkGraph, LandmarkNode, LandmarkSubtreeProofSet,
    SkipLinkEdge, CHECKPOINT_CONTEXT_HEADER, SKIP_LINK_HOP_BYTES,
};
pub use subtrees::{
    empty_tree_hash, find_subtrees, hash_leaf, is_aligned_subtree, is_valid_subtree, node_hash,
    MerkleTreeLog, SubtreeConsistencyProof, SubtreeRange, MAX_LOG_SIZE, MAX_UINT48,
    MTC_LEAF_PREFIX, MTC_NODE_PREFIX,
};
pub use tbs_hasher::{
    compressed_serial, hash_tbs_certificate_streaming, strip_volatile_extensions,
    validate_canonical_der_tlv, TbsCertFields,
};
pub use tiles::{
    render_tile, render_tile_bytes, serial_for, LandmarkStateGuard, RenderedTile, TileCoord,
    TILE_BYTES, TILE_WIDTH, TLOG_TILE_HEIGHT,
};
pub use trust_anchor::{
    decode_base128_arc, encode_base128_arc, encode_landmark_pattern, LandmarkRange,
    TrustAnchorPattern, BASE128_INFINITY_MARKER, TRUST_ANCHORS_EXTENSION_TYPE,
};
