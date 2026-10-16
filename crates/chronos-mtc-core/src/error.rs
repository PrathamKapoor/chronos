//! Typed error surface for the Merkle Tree Certificate core.
//!
//! Every failure mode that a peer could use to create two different byte strings with the same
//! trust meaning has its own variant, so callers can fail closed with a precise reason instead of a
//! generic "verification failed".

use thiserror::Error;

/// Result alias used across `chronos-mtc-core`.
pub type MtcResult<T> = Result<T, MtcError>;

/// All errors produced by subtree decomposition, leaf hashing, landmark graphs and cosignatures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MtcError {
    /// `start >= end`, or `end` escaped the 48-bit log index space.
    #[error("invalid log range [{start}, {end})")]
    InvalidRange {
        /// Inclusive range start.
        start: u64,
        /// Exclusive range end.
        end: u64,
    },

    /// A range was used as a Merkle subtree although it is not power-of-two aligned.
    #[error("subtree range [{start}, {end}) is not power-of-two aligned")]
    UnalignedSubtree {
        /// Inclusive range start.
        start: u64,
        /// Exclusive range end.
        end: u64,
    },

    /// The DER encoding is parseable but not the canonical minimal-length form.
    #[error("non-canonical DER: {0}")]
    NonCanonicalDer(String),

    /// A TLV was shorter than its own header/content declares, or carried trailing bytes.
    #[error("DER TLV truncated or with trailing bytes")]
    DerTruncated,

    /// The certificate serial escaped the 48-bit serial space of the compressed log serial.
    #[error("certificate serial {serial} exceeds the 48-bit log serial space")]
    SerialOutOfBounds {
        /// Offending serial.
        serial: u64,
    },

    /// A leaf index or tree size fell outside the populated part of the log.
    #[error("index {index} out of bounds for log of size {size}")]
    IndexOutOfBounds {
        /// Offending index or size.
        index: u64,
        /// Populated log size.
        size: u64,
    },

    /// The proof carried a different number of elements than the traversal consumes.
    #[error("proof length mismatch: traversal consumed {expected}, proof carried {got}")]
    ProofLengthMismatch {
        /// Elements required by the canonical traversal.
        expected: usize,
        /// Elements supplied by the peer.
        got: usize,
    },

    /// A reconstructed root did not equal the expected (signed) root.
    #[error("root mismatch: computed {computed}, expected {expected}")]
    RootMismatch {
        /// Reconstructed root, hex encoded.
        computed: String,
        /// Expected root, hex encoded.
        expected: String,
    },

    /// Two cosigner entries carried the same `cosigner_id` (split-view witness fork).
    #[error("duplicate cosigner_id in MTCProof")]
    DuplicateCosignerId,

    /// Cosigner entries were serialized without the length-first canonical ordering.
    #[error("cosigner entries are not in canonical (length, lexicographic) order")]
    CosignersOutOfOrder,

    /// A landmark update moved backwards in landmark id or tree size.
    #[error("landmark rollback rejected: {new_landmark}/{new_tree_size} below {current_landmark}/{current_tree_size}")]
    RollbackRejected {
        /// Current (trusted) landmark id.
        current_landmark: u64,
        /// Current (trusted) tree size.
        current_tree_size: u64,
        /// Rejected landmark id.
        new_landmark: u64,
        /// Rejected tree size.
        new_tree_size: u64,
    },

    /// The requested power-of-two skip link does not exist in the published graph.
    #[error("skip-link edge {from} -> {to} is not published")]
    SkipLinkEdgeMissing {
        /// Origin landmark.
        from: u64,
        /// Destination landmark.
        to: u64,
    },

    /// A landmark transition was requested with a non-positive delta.
    #[error("invalid landmark delta from {from} to {to}")]
    InvalidLandmarkDelta {
        /// Origin landmark.
        from: u64,
        /// Destination landmark.
        to: u64,
    },

    /// The single target checkpoint signature did not verify.
    #[error("checkpoint signature verification failed for landmark {landmark}")]
    CheckpointSignatureInvalid {
        /// Landmark whose checkpoint was rejected.
        landmark: u64,
    },

    /// A base-128 relative-OID arc was truncated, over-long, or ended with a dangling flag bit.
    #[error("malformed base-128 arc at offset {offset}")]
    MalformedBase128 {
        /// Byte offset inside the extension body.
        offset: usize,
    },

    /// A base-128 arc did not fit the 64-bit value space.
    #[error("base-128 arc overflows the 64-bit value space")]
    Base128Overflow,

    /// The relative-OID landmark pattern did not match the `caID.2.N.{L-}` shape.
    #[error("invalid trust anchor pattern: {0}")]
    InvalidTrustAnchorPattern(String),

    /// A tile coordinate addressed nodes that are not (yet) in the log.
    #[error("tile coordinate out of bounds: level {level}, index {index}")]
    TileOutOfBounds {
        /// Requested tile level.
        level: u8,
        /// Requested tile index.
        index: u64,
    },

    /// A canonical wire encoding could not be produced or parsed.
    #[error("wire encoding error: {0}")]
    WireEncoding(String),
}
