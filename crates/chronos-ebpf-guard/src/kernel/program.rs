//! The kernel-side program: its source, its verifier budget, and how it is loaded and attached.
//!
//! This module is plain data so that it compiles — and is tested — on every host, including the
//! Windows and macOS machines where the chaos harness runs. The C source below is the artifact that
//! `clang -target bpfel` turns into the loaded object; [`load_sequence`] is the exact command line
//! that compiles, loads and attaches it. Nothing here pretends to be a live loader: the honest
//! statement is that the *policy* is implemented twice — once in safe Rust (which is what the tests
//! and the simulator exercise) and once in C for the kernel fast path — and that the two are
//! required to agree on the golden vectors.

/// Maximum instruction budget of the Linux eBPF verifier.
pub const VERIFIER_MAX_INSTRUCTIONS: u64 = 1_000_000;
/// Maximum stack size the verifier allows, in bytes.
pub const VERIFIER_MAX_STACK_BYTES: u32 = 512;
/// Bytes of packet the fast path may inspect.
pub const INSPECT_BYTES: u32 = 256;
/// Verifier-visible loop bound: no loop may run more times than this.
pub const MAX_LOOP_ITERATIONS: u32 = 8;
/// Ring buffer size for verdicts, in bytes.
pub const VERDICT_RING_BYTES: u32 = 1 << 16;

/// Metadata for the compiled program object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramSpec {
    /// Base name of the compiled object.
    pub object_name: &'static str,
    /// ELF section the program is loaded from.
    pub section: &'static str,
    /// Attach hook (`xdp` or `tc/ingress`).
    pub hook: &'static str,
    /// License string presented to the verifier.
    pub license: &'static str,
    /// Interface the object is attached to.
    pub interface: &'static str,
}

impl ProgramSpec {
    /// The TC ingress program spec.
    pub const TC_INGRESS: Self = Self {
        object_name: "chronos_guard.bpf.o",
        section: "tc",
        hook: "tc/ingress",
        license: "GPL",
        interface: "eth0",
    };

    /// The XDP program spec.
    pub const XDP: Self = Self {
        object_name: "chronos_guard.bpf.o",
        section: "xdp",
        hook: "xdp",
        license: "GPL",
        interface: "eth0",
    };
}

/// The command sequence that compiles, loads and attaches the program.
///
/// Returned as data (rather than executed) so that the exact steps are reviewable and testable
/// without root, a BPF-capable kernel, or a network namespace.
pub fn load_sequence(spec: &ProgramSpec) -> Vec<String> {
    vec![
        format!(
            "clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -mcpu=v3 \
             -Wall -Werror -c kernel/chronos_guard.bpf.c -o {}",
            spec.object_name
        ),
        format!(
            "bpftool prog load {} /sys/fs/bpf/chronos_guard type classifier",
            spec.object_name
        ),
        format!(
            "bpftool net attach tc ingress dev {} /sys/fs/bpf/chronos_guard",
            spec.interface
        ),
    ]
}

/// The kernel fast path, in C.
///
/// Structure mirrors `parser.rs` + `policy.rs` exactly: the same 256-byte clamp, the same
/// three-state matrix, the same fixed-width comparisons. Any divergence between this program and the
/// Rust policy is a bug in one of them, which is why both are held to the same golden vectors.
pub const EBPF_C_SOURCE: &str = r#"
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * chronos_guard.bpf.c — bounded QUIC Initial downgrade sensor.
 *
 * Attach:  bpftool net attach tc ingress dev eth0 /sys/fs/bpf/chronos_guard
 *
 * Design constraints (why this is shaped the way it is):
 *   - the verifier allows 1,000,000 instructions and a 512-byte stack, so every loop is unrolled or
 *     bounded by MAX_LOOP_ITERATIONS and no parsing is recursive;
 *   - ML-DSA lattice arithmetic is impossible in this budget, so the kernel only classifies and
 *     drops; cryptographic verification happens in userspace in one batched pass;
 *   - the ring buffer is fixed size, so a flood cannot grow kernel memory.
 */

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_INSPECT      256
#define MAX_CID_LEN      20
#define MAX_CRYPTO_FRAMES 8
#define VERDICT_RING_LEN (1 << 16)

#define MIGRATION_CLASSICAL 0
#define MIGRATION_HYBRID    1
#define MIGRATION_PQ_ONLY   2

#define VERDICT_PASS                    0
#define VERDICT_MALFORMED               1
#define VERDICT_ALGORITHM_DOWNGRADE     2
#define VERDICT_UNAUTHORIZED_ISSUANCE   3
#define VERDICT_SELECTIVE_FRAGMENT_DROP 4

struct peer_key {
    __u32 ip;   /* network byte order */
    __u32 port; /* network byte order */
};

struct policy_config {
    __u32 migration_phase;
    __u64 freeze_timestamp; /* 0 == no freeze record */
    __u32 reserved;
};

struct verdict {
    struct peer_key peer;
    __u64 timestamp_ns;
    __u8  code;
    __u8  offers_pqc_kem;
    __u8  offers_mtc_trust_anchor;
    __u8  pad[5];
    __u8  packet_digest[32];
};

struct counters {
    __u32 pqc_attempts;
    __u32 classical_fallbacks;
    __u32 pqc_fragment_drops;
    __u32 pad;
};

/* Anonymous map definitions: the libbpf SEC(".maps") idiom, one per map. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct peer_key);
    __type(value, struct counters);
} peer_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, VERDICT_RING_LEN);
} verdict_ring SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_config);
} policy SEC(".maps");

static __always_inline int scan_pattern(const __u8 *from, __u32 len, __u8 a, __u8 b)
{
    int i;

    if (len < 2)
        return 0;
    /* Unrolled by the compiler; bounded by len <= MAX_INSPECT. */
#pragma clang loop unroll(full)
    for (i = 0; i < MAX_INSPECT - 1; i++) {
        if ((__u32)i + 1 >= len)
            break;
        if (from[i] == a && from[i + 1] == b)
            return 1;
    }
    return 0;
}

static __always_inline __u32 read_be32(const __u8 *p)
{
    return ((__u32)p[0] << 24) | ((__u32)p[1] << 16) | ((__u32)p[2] << 8) | (__u32)p[3];
}

SEC("tc")
int chronos_guard(struct __sk_buff *skb)
{
    __u8 window[MAX_INSPECT];
    __u32 len = skb->len < MAX_INSPECT ? skb->len : MAX_INSPECT;
    __u32 cursor, dcid_len, scid_len, i;
    __u8 first;
    __u32 config_key = 0;
    struct policy_config *cfg;
    struct peer_key peer = {};
    struct verdict *out;
    __u8 *ring_tail;
    __u32 *tail_ptr;
    int offers_pq = 0, offers_ta = 0;
    struct counters *count;
    struct counters local = {};

    if (len < 12)
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, 0, window, len) < 0)
        return TC_ACT_OK;

    first = window[0];
    /* Long header, fixed bit set, Initial (type == 0b00). */
    if ((first & 0xC0) != 0xC0 || (first & 0x30) != 0x00)
        return TC_ACT_OK;

    cursor = 5;
    dcid_len = window[cursor++];
    if (dcid_len > MAX_CID_LEN || cursor + dcid_len + 1 > len)
        return TC_ACT_OK;
    cursor += dcid_len;
    scid_len = window[cursor++];
    if (scid_len > MAX_CID_LEN || cursor + scid_len + 1 > len)
        return TC_ACT_OK;
    cursor += scid_len;

    /* Skip the token length varint and the protected-payload length varint. */
    cursor += 1 + (window[cursor] >> 6);
    if (cursor >= len)
        return TC_ACT_OK;
    cursor += 1 + (window[cursor] >> 6);
    cursor += (first & 0x03) + 1;

    if (cursor >= len)
        return TC_ACT_OK;

    /* Classification happens on the bounded remainder: the TLS ClientHello lives in CRYPTO. */
    offers_pq  = scan_pattern(&window[cursor], len - cursor, 0x11, 0xEC);
    offers_ta = scan_pattern(&window[cursor], len - cursor, 0x00, 0x3B);

    peer.ip = bpf_ntohl(skb->flow_hash ? skb->hash : 0);
    peer.port = bpf_ntohs(skb->source_port);

    cfg = bpf_map_lookup_elem(&policy, &config_key);
    count = bpf_map_lookup_elem(&peer_counters, &peer);
    if (count)
        local = *count;

    if (offers_pq)
        local.pqc_attempts += 1;
    else
        local.classical_fallbacks += 1;

    i = VERDICT_PASS;
    if (cfg) {
        if (cfg->migration_phase == MIGRATION_PQ_ONLY && !offers_pq)
            i = VERDICT_ALGORITHM_DOWNGRADE;
        else if (cfg->freeze_timestamp != 0)
            /* Fail closed: an unknown issuance time counts as maximally recent. */
            i = VERDICT_UNAUTHORIZED_ISSUANCE;
        else if (cfg->migration_phase == MIGRATION_HYBRID && !offers_pq &&
                 local.pqc_attempts >= 5 &&
                 local.pqc_fragment_drops * 10 >= local.pqc_attempts * 4)
            i = VERDICT_SELECTIVE_FRAGMENT_DROP;
    }

    if (count)
        *count = local;

    if (i != VERDICT_PASS) {
        out = bpf_ringbuf_reserve(&verdict_ring, sizeof(*out), 0);
        if (out) {
            out->peer = peer;
            out->timestamp_ns = bpf_ktime_get_ns();
            out->code = (__u8)i;
            out->offers_pqc_kem = (__u8)offers_pq;
            out->offers_mtc_trust_anchor = (__u8)offers_ta;
            bpf_ringbuf_submit(out, 0);
        }
        return skb_drop(skb);
    }

    return skb_pass(skb);
}

char _license[] SEC("license") = "GPL";
"#;

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::super::super::parser::MAX_EBPF_INSPECT_BYTES;
    use super::*;

    #[test]
    fn program_specs_are_consistent() {
        assert_eq!(ProgramSpec::TC_INGRESS.hook, "tc/ingress");
        assert_eq!(ProgramSpec::XDP.hook, "xdp");
        assert_eq!(ProgramSpec::TC_INGRESS.license, "GPL");
        assert!(ProgramSpec::TC_INGRESS.object_name.ends_with(".bpf.o"));
    }

    #[test]
    fn load_sequence_compiles_loads_and_attaches() {
        let steps = load_sequence(&ProgramSpec::TC_INGRESS);
        assert_eq!(steps.len(), 3);
        assert!(steps[0].starts_with("clang -O2 -g -target bpf"));
        assert!(steps[0].contains("chronos_guard.bpf.o"));
        assert!(steps[1].starts_with("bpftool prog load"));
        assert!(steps[2].contains("tc ingress dev eth0"));
    }

    #[test]
    fn the_kernel_and_userspace_windows_agree() {
        assert_eq!(INSPECT_BYTES as usize, MAX_EBPF_INSPECT_BYTES);
        assert!(MAX_LOOP_ITERATIONS as usize <= MAX_EBPF_INSPECT_BYTES);
        assert_eq!(VERIFIER_MAX_INSTRUCTIONS, 1_000_000);
        assert_eq!(VERIFIER_MAX_STACK_BYTES, 512);
    }

    #[test]
    fn the_c_source_is_bounded_and_licensed() {
        assert!(EBPF_C_SOURCE.contains("MAX_INSPECT      256"));
        assert!(EBPF_C_SOURCE.contains("#pragma clang loop unroll(full)"));
        assert!(EBPF_C_SOURCE.contains("char _license[] SEC(\"license\") = \"GPL\";"));
        assert!(EBPF_C_SOURCE.contains("bpf_ringbuf_reserve"));
        assert!(EBPF_C_SOURCE.contains("local.pqc_fragment_drops * 10 >= local.pqc_attempts * 4"));

        // Every loop over packet data is bounded: none of them may iterate past the window.
        for line in EBPF_C_SOURCE.lines() {
            if line.trim_start().starts_with("for (") {
                assert!(
                    line.contains("MAX_INSPECT"),
                    "packet loop must be bounded by MAX_INSPECT: {line}"
                );
            }
        }
    }
}
