//! The single place where this crate names its workspace siblings.
//!
//! Why a façade instead of `use` in every module: on the pinned stable toolchain this workspace is
//! built with, the 2018 extern prelude intermittently fails to expose path-dependency crates to
//! `use` statements — the symptom is `error[E0433]: ... use of unresolved module or unlinked crate
//! chrono_mtc_core` for a crate whose `--extern` path is on disk and correct. Routing every
//! cross-crate reference through one module bounds that to a single resolution site: either the
//! façade resolves and the whole crate compiles, or the failure is obvious and localized.
//!
//! Everything downstream imports from [`crate::deps`], so this file is the whole dependency surface
//! of `chronos-sim` on the rest of the workspace.

// The four lower layers are modules of this crate (see the mounts in lib.rs), so their bare
// names have to be in scope before the re-exports below can resolve.
#[cfg(chronos_bundled)]
#[allow(unused_imports)]
use crate::{chrono_ebpf_guard, chrono_mtc_core, chrono_pqc_sys, chrono_quic_fec};

#[cfg(not(chronos_bundled))]
pub use chrono_ebpf_guard::kernel::{GuardConfig, UserspaceGuard};
pub use chrono_ebpf_guard::parser::{parse_quic_initial_256b, MAX_EBPF_INSPECT_BYTES};
pub use chrono_ebpf_guard::policy::{
    MigrationPhase, MonitorAlert, PacketVerdict, PeerAddr, VerdictCode, PQC_KEM_PATTERN,
};
pub use chrono_mtc_core::cosign::{
    canonicalize_cosignatures, trust_anchor_id_string, Cosignature, CosignedSubtree, MtcProof,
};
pub use chrono_mtc_core::skip_link::{hop_count_for, LandmarkGraph};
pub use chrono_mtc_core::subtrees::{
    empty_tree_hash, find_subtrees, is_valid_subtree, MerkleTreeLog,
};
pub use chrono_mtc_core::tbs_hasher::{
    hash_tbs_certificate_streaming, validate_canonical_der_tlv, TbsCertFields,
};
pub use chrono_mtc_core::{MtcError, SKIP_LINK_HOP_BYTES};
pub use chrono_pqc_sys as pqc;
pub use chrono_quic_fec::budget::{
    AmplificationPlanner, Flight1Mode, LANDMARK_MTC_PROOF_BYTES, RETRY_TOKEN_BYTES,
    SERVER_HELLO_PQC_BYTES, STANDALONE_MTC_PROOF_BYTES,
};
pub use chrono_quic_fec::fec_coder::{encode_block, FecBlockAssembler};
pub use chrono_quic_fec::frames::{FEC_REPAIR_HEADER_BYTES, FEC_SOURCE_HEADER_BYTES};
