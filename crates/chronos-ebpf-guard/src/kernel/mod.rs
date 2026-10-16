//! Kernel-plane split.
//!
//! * [`program`] — the eBPF/TC source, its verifier budget and the exact compile/load/attach
//!   sequence. Pure data, so it is reviewable and tested on any host.
//! * [`userspace`] — the same policy running over a userspace ring, which is what the deterministic
//!   chaos harness drives on every platform.
//!
//! A live loader is deliberately absent: loading BPF requires privileges and a BPF-capable kernel,
//! neither of which belongs in a test harness. What *is* tested is that the two planes agree on the
//! same bounded window, the same signals and the same integer policy thresholds.

pub mod program;
pub mod userspace;

pub use program::{
    load_sequence, ProgramSpec, EBPF_C_SOURCE, INSPECT_BYTES, MAX_LOOP_ITERATIONS,
    VERDICT_RING_BYTES, VERIFIER_MAX_INSTRUCTIONS, VERIFIER_MAX_STACK_BYTES,
};
pub use userspace::{GuardConfig, PeerState, PipelineOutcome, UserspaceGuard};
