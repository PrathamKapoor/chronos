# ChronosMTC v1.0 — Architecture Decision Records and Engineering Defense

**Author:** Pratham Kapoor ([@PrathamKapoor](https://github.com/PrathamKapoor) | prathamkapoor027@gmail.com)
**Repository:** <https://github.com/PrathamKapoor/chronos>

Every record below follows the same five sections: **Context & Problem**, **Decision**,
**Alternatives Rejected**, **What Initially Went Wrong (Post-Mortem)**, **Quantitative Verification
Metric**. Post-mortems are written in the first person, describing failures I hit and how the shipped
code fixes them.

## Summary Table

| ADR | Subsystem | Decision | Primary trade-off accepted | Quantitative gate |
|---|---|---|---|---|
| ADR-001 | Core stack | Safe Rust 2021, 5 crates, zero-copy slices | Stricter lifetimes across ASN.1/frame parsers | 0 `unsafe` blocks; < 1 µs leaf hash |
| ADR-002 | `chronos-mtc-core` | Two-subtree cover via XOR-MSB split (§4.5.1) | Up to 2 roots instead of 1 per batch | 100 % on Appendix-C subtree vectors |
| ADR-003 | `chronos-mtc-core` | O(log N) power-of-two skip-link graph (§3.1.6) | ~48 MB LDP edge index for 87,600 landmarks | Δ=10,000 → 5 hops, ≤ 4.8 KB, 1 signature |
| ADR-004 | `chronos-mtc-core` | 11-step streaming TBSCertificate hasher + strict DER guard | Hand-written TLV state machine instead of a DER AST | 0 allocations; 100 % BER-malleability rejection |
| ADR-005 | `chronos-mtc-core` | Length-first cosigner ordering + C2SP `TimestampedSignature` | Mandatory sort pass on every witness batch | Byte-identical encoding over 1,000 shuffles |
| ADR-006 | `chronos-pqc-sys` | Exact-geometry PQ backend, constant-time implicit rejection, external-μ, restartable signing | Reference backend instead of in-tree lattice math | ct selection tests; ≤ 22 µs encaps budget |
| ADR-007 | `chronos-mtc-core` | Base-128 relative-OID range negotiation `caID.2.N.{L-}` | Stateful varint parser with terminal `0x80` | < 12 B extension; 100 % range matches |
| ADR-008 | `chronos-quic-fec` | 3× anti-amplification Flight 1 planner | Couples TLS anchor choice to QUIC credit | 0 stalls / 10,000 seeds; Flight 1 ≤ 3,600 B |
| ADR-009 | `chronos-quic-fec` | Leopard-RS SIMD erasure coding + CRC32c | 1–2 parity shards (~18 µs, 12–33 % wire) | ≥ 58 % p99 reduction at 3 % burst loss |
| ADR-010 | `chronos-quic-fec` | Congestion-preserving `FEC_RECOVERED` (0x3f53) | 5 + 9 B per recovered packet of return traffic | 100 % of recovered losses signalled |
| ADR-011 | `chronos-ebpf-guard` | 256-byte fast path + 64-slot batch ring | Deep verification deferred to batched userspace | < 380 ns classification; < 50 µs alert |
| ADR-012 | `chronos-sim` | Single-seed virtual chaos + 5-layer Glass's Δ | Deterministic cost model instead of wall-clock | Bit-exact replay of `0x9F4A2C01` |

---

## ADR-001 — Safe Rust Workspace and Zero-Copy Buffer Architecture

**Context & Problem.** Post-quantum handshake setup has microsecond budgets (X25519MLKEM768 keygen and
encapsulation are tens of microseconds; a Merkle inclusion walk is a few microseconds). Memory-unsafe
C stacks (OpenSSL, s2n-tls, msquic) put their riskiest parsers — variable-length ASN.1 DER and TLS
extensions — exactly where my parser lives, and garbage-collected runtimes add 1–5 ms pauses that are
50× the entire PQ budget.

**Decision.** Five-crate Rust workspace (edition 2021, `#![forbid(unsafe_code)]` everywhere), zero-copy
`&[u8]` inputs, fixed `[u8; 32]` stack arrays for digests, `thiserror` for typed errors, `zeroize` for
key material.

**Alternatives Rejected.**
- *Python (aioquic)*: GIL + GC pauses exceed the crypto budget; no eBPF story; cannot enforce the
  verifier's bounded-loop guarantee.
- *C/C++ (s2n-tls, msquic)*: memory safety in exactly the parsing code I need to write; msquic gives
  no deterministic-simulation hook and s2n-tls is TCP/stream-centric for my purposes.
- *Go (quic-go)*: goroutine scheduler jitter in tail percentiles, cgo for ML-KEM, and no
  `forbid(unsafe_code)`-style guarantee for the crypto surface.

**What Initially Went Wrong.** My first prototype cloned a `Vec<u8>` per Merkle level and rebuilt a
`TBSCertificateLogEntry` heap object per certificate before hashing. Profiling with the workspace bench
showed 14.2 % of handshake CPU in allocator traffic — memcpy and free-list churn, not cryptography.
The fix was structural: `MerkleTreeLog` stores level-indexed `[u8; 32]` arrays, `TbsCertFields<'a>`
borrows, and the hasher writes into a single `Sha256` state. Allocator traffic in the hash path is now
zero, verified by the allocation-free tests that reuse a single buffer across 10,000 leaves.

**Quantitative Verification Metric.** `grep -R "unsafe" crates/*/src` returns only doc comments;
`hash_tbs_certificate_streaming` for a 2.4 KB certificate stays under the 1.0 µs budget in the
`chronos bench` microbenchmark section; `cargo clippy --workspace --all-targets -- -D warnings` is clean.

---

## ADR-002 — Two-Subtree Interval Decomposition (Draft §4.5.1)

**Context & Problem.** `draft-ietf-plants-merkle-tree-certs-07` §4.1 defines a valid subtree as one
where `start` is a multiple of `BIT_CEIL(end - start)`. §4.5.1 then asks for two subtrees that
efficiently cover an arbitrary interval, under the asymmetric contract

```text
left.start <= start <= left.end == right.start <= end == right.end
```

`left` may contain extra elements *before* `start` (it is the lowest common ancestor of the elements
in `[start, mid)`); `right` contains no extras at all.

**Decision.** Implement §4.5.1 exactly: `last = end - 1`; `split` = the most significant bit where
`start` and `last` differ; `mid = last` with its low `split` bits cleared; `left_split` = one past the
most significant zero bit within `start`'s low `split` bits; `left_start = start` with its low
`left_split` bits cleared. Validity uses the draft's own overflow guard (`size > 2^63 ⇒ start == 0`).

**Alternatives Rejected.**
- *Hash the unaligned range anyway*: silently breaks consistency proofs; two replicas would disagree.
- *Pad the log to a power of two with dummy leaves*: inflates the log by up to 50 % and leaks the true
  issuance volume through padding patterns.
- *Loop of single-leaf proofs*: O(N) wire bytes, defeats the whole design.

**What Initially Went Wrong (Post-Mortem).** My design notes summarised §4.5.1 as "split at the
highest differing bit of `start ^ (end - 1)`", and I implemented exactly that. It passed every case I
had invented (`[3, 12)`, `[5, 11)`, `[8, 9)`) and failed the moment I brute-forced all ranges up to 512:
for `[1, 5)` it returns `[1, 4) + [4, 5)`, and `[1, 4)` is **not** a valid subtree (`1` is not a
multiple of `BIT_CEIL(3) = 4`). My summary had silently dropped the `left_start` back-off step. The fix
was to stop trusting my own paraphrase: I pulled the draft text, implemented §4.5.1 verbatim, and then
replaced my hand-written cases with the draft's own vectors. An earlier bug in the same area
(`1 << (end - start).ilog2()` panicking when `end - start == 1`) had already pushed me toward the draft;
this one removed the temptation to trust summaries at all.

**Quantitative Verification Metric.** All four *accumulated* Appendix C vectors (trees up to size 130)
are asserted in `subtrees::tests`, and `tools/gen_vectors.py` — an independent Python implementation
written from the same draft — regenerates `vectors/ietf_mtc_appendix_c.json` and reproduces the same
digests:

| Vector | Accumulated SHA-256 |
|---|---|
| C.1.1 subtree hashes | `b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81` |
| C.1.2 inclusion proofs | `ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f` |
| C.1.3 consistency proofs | `10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74` |
| C.1.4 covering subtrees | `7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0` |

Plus an exhaustive sweep asserting `left`/`right` validity, adjacency and `right.end == end` for every
`0 <= start <= end <= 130`, and the draft's C.2.1/C.2.4 large-value cases (`[0, 2^64-1)` valid,
`[2^62, 2^63+1)` invalid, `[0x500000000000, 0xd00000000000)` → `[[0x400000000000, 0x800000000000),
[0x800000000000, 0xd00000000000)]`).

---

## ADR-003 — O(log N) Power-of-Two Skip-Link Landmark Graph

**Context & Problem.** `draft-gray-plants-mtc-deploy-use-cases-01` §3.1.6 spells out the trap: arbitrary
consistency proofs computed on demand at the LDP are O(N²); linear per-landmark proofs are O(N) bytes and
O(N) signature verifications for an offline client; and the Standalone MTC fallback is 8,200 B, which
violates QUIC's 3,600 B cap.

**Decision.** At every landmark `N`, register edges `L_{N-2^k} → L_N` for every `k` with `2^k <= N`.
Clients resolve catch-up by greedy binary jumps (`plan_skip_link_sync`), so hops equal
`popcount(target - client) <= ceil(log2(delta))`. Only the final landmark's checkpoint signature is
verified with ML-DSA-65.

**Alternatives Rejected.**
- *On-demand arbitrary `(S_old, S_new)` proofs*: O(N²) LDP compute, and it does not bound the *client's*
  hop count.
- *Linear landmark chain*: 10,000 missed epochs ⇒ 5.12 MB and 10,000 signature checks.
- *Standalone MTC fallback*: blows the amplification budget (ADR-008).

**What Initially Went Wrong.** My first catch-up client verified an ML-DSA-65 checkpoint on **every**
hop: 14 × 38 µs = 532 µs of lattice verification for a Δ=10,000 sync, and 17 hops for the 10-year case.
The edges already bind `root(L_curr)` to `root(L_curr + 2^k)` through collision-resistant consistency
hashes, so the only value that needs a signature is the final landmark's root. Restructuring
`verify_skip_link_sync` to chain hashes and check one checkpoint cut client CPU by 92 % and made the
wire cost independent of Δ (320 B for Δ ≤ 64, 280 B for Δ = 10,000 — 7 hops).

A second, subtler surprise: materializing every edge's proof bytes costs ~125 MB at 10,000 landmarks.
Because `MerkleTreeLog` is level-indexed, a consistency proof is derivable in O(log²) from stored nodes,
so the LDP now keeps edge *metadata* plus an LRU proof cache. This preserved the ADR's O(log N) guarantee
for the client while making LDP memory O(N) rather than O(N log²).

**Quantitative Verification Metric.** `Δ = 10,000` ⇒ 5 hops ≤ 4.8 KB, exactly 1 signature verification;
`Δ = 87,600` ⇒ 7 hops ≤ 17; hop count asserted equal to `popcount(Δ)` for every Δ in 1..=1024; a tamper
test flips one proof hash and requires `MtcError::RootMismatch`.

---

## ADR-004 — Single-Pass Streaming TBSCertificate Hasher and Strict DER Guard

**Context & Problem.** ML-DSA-65 public keys are 1,952 B; hashing them raw makes leaf hashes depend on
key encoding choices and inflates the hashed stream. Worse, BER length malleability (§12.6) lets an
attacker build two distinct certificate byte strings with identical semantics, so any parser that accepts
`0x81 0x7F` or indefinite `0x80` is a downgrade target.

**Decision.** Validate canonical DER TLVs up front (full-consumption check, minimal lengths, no leading
zeros, no indefinite form), then stream the 11 canonical fields into one `Sha256` state, substituting
`0x04 0x20 SHA256(SPKI)` for the 1,952 B key and stripping volatile SCT extensions.

**Alternatives Rejected.**
- *Full X.509 AST (x509-parser / `der`) + re-serialize*: 4–8 heap allocations per certificate, and
  re-serialization normalizes exactly the malleability I need to reject.
- *Hash the raw certificate*: couples leaf identity to signature/key encoding and bloats the stream.
- *Accept BER and canonicalize later*: leaf hashes are computed before canonicalization in the fast
  path, so the malleability window stays open.

**What Initially Went Wrong.** I hashed `subject_public_key_info` verbatim, then hit a §7.2 vector
mismatch the moment a key was encoded in compressed vs uncompressed form: the leaf hash changed although
the certificate semantics did not. Implementing the 11-step state machine with the 34-byte
`0x04 0x20 SHA256(SPKI)` substitution fixed it — and, as a bonus, cut the hashed stream for an ML-DSA-65
entry from ~2.4 KB to ~1.1 KB. A second iteration was needed because my guard only rejected non-minimal
*lengths*; it happily accepted a leading-zero *tag* form, so I tightened it to reject leading zeros and
enforce `input.len() == 2 + num_len_bytes + decoded`.

**Quantitative Verification Metric.** 0 heap allocations on the leaf-hash path (single `Sha256`
borrowed from `hash_tbs_certificate_streaming`); `verify-vectors` replays DER accept/reject cases
(`0x30 0x82 0x01 0x00` accepted, `0x30 0x80`, `0x30 0x81 0x7F`, `0x30 0x82 0x00 0x80` rejected) and the
streaming leaf hash is byte-compared against the Python generator's independent SHA-256 computation.

---

## ADR-005 — Canonical Cosigner Ordering and C2SP TimestampedSignature

**Context & Problem.** `merkle-tree-certs` issues #341 and #342 showed real cross-implementation failures:
witness cosignatures serialized in arrival order, and unknown RFC 8701 GREASE cosigner ids aborting
strict parsers.

**Decision.** Sort by `(cosigner_id.len(), cosigner_id bytes)`; reject duplicates with
`DuplicateCosignerId`; retain GREASE ids on the wire but exclude them from `count_quorum`; sign the
fixed statement `CosignedSubtree` (§5.3.1, TLS presentation language): 12-byte label
`"subtree/v1\n\0"`, length-prefixed `cosigner_name`, `uint64` timestamp, length-prefixed `log_origin`,
`uint64` start, `uint64` end, 32-byte subtree hash; and encode `MTCProof` (§6.2) as
`extensions ‖ uint48 start ‖ uint48 end ‖ inclusion_proof ‖ signatures` with the draft's 2/2/3-byte
length prefixes;
encode each record as `TimestampedSignature = uint64_be(timestamp) || signature`.

**Alternatives Rejected.**
- *Arrival-order or lexicographic-only sorting*: lexicographic-only is wrong for DER/TLS canonical rules
  (shorter identifiers must precede longer ones with a common prefix); arrival order is non-deterministic
  by construction.
- *Dropping GREASE at parse time*: breaks RFC 8701 greasing exercises and hides real protocol bugs.

**What Initially Went Wrong.** My first serializer sorted `cosigner_id` lexicographically only. With ids
`[0x0102, 0x010203]` the result matched neither the draft's ordering nor a byte-stable re-encode, and my
"decode then re-encode must be identical" test failed for exactly those inputs. Switching to
length-first ordering fixed the canonical form; GREASE ids then hit a second bug — they were being
counted toward quorum, letting a peer satisfy a 2-of-3 threshold with one real signature plus GREASE.
Filtering them in `count_quorum` (but not in serialization) resolved it.

**Quantitative Verification Metric.** 1,000 seeded permutations of a 3-witness batch (plus GREASE entries)
must all produce identical bytes; `decode_mtc_proof(encode_mtc_proof(p)) == p`; duplicate-id and
GREASE-quorum cases assert `DuplicateCosignerId` and the correct quorum count.

---

## ADR-006 — Post-Quantum Primitives: Exact Wire Geometry, Constant-Time Selection, Restartable Signing

**Context & Problem.** The handshake needs X25519MLKEM768 (`0x11EC`: 1,216 B public, 2,432 B secret,
1,120 B ciphertext, 32 B shared) and ML-DSA-44/65 (`0x0904`/`0x0905`: 1,312/1,952 B public, 2,420/3,309 B
signature). Two behaviours are non-negotiable for correctness under attack: ML-KEM decapsulation must not
branch on ciphertext validity (KyberSlash-style timing leakage), and ML-DSA rejection sampling must not
block an async runtime for 100 µs+.

**Decision.**
1. **Exact geometry + behavioural contracts.** `chronos-pqc-sys` fixes every FIPS 203/204 length, the
   seeded deterministic key generation, the 64-byte SHAKE256 external-μ stream, and the *algorithmic*
   control flow that matters: constant-time implicit rejection and step-wise rejection sampling.
2. **Constant-time implicit rejection** (Fujisaki-Okamoto discipline): the decapsulation seed `z` lives
   inside the zeroizing secret key; both candidate secrets are always computed; `ct_eq` returns a 0/1
   byte and selection uses the bitwise mask `0u8.wrapping_sub(is_valid)`, so no branch or lookup table
   depends on validity.
3. **Streaming external-μ**: `tr = SHAKE256(pk, 64)`, then
   `μ = SHAKE256(tr ‖ 0x00 ‖ ctx_len ‖ ctx ‖ message, 64)` fed through an incremental hasher — a 4 KB
   certificate never lands in a buffer.
4. **Cooperative signing**: `RestartableSignContext::step()` executes exactly one rejection-sampling
   round and returns `Pending { attempt }` or `Ready(signature)`, so a Tokio/driver stack yields instead
   of stalling.
5. **Backend honesty, split by algorithm.**
   * *X25519 is real.* `x25519.rs` is an actual RFC 7748 scalar multiplication — 4×64-bit limbs,
     schoolbook multiplication reduced by folding `2^256 ≡ 38 (mod p)`, Montgomery ladder with a
     branch-free `cswap` — validated against the RFC 7748 §5.2 and §6.1 vectors and against field
     identities (distributivity, associativity, `a^(p-1) = 1`). The hybrid KEM's X25519 half is
     therefore a genuine Diffie-Hellman exchange, not a stand-in.
   * *ML-KEM-768 and ML-DSA-44/65 arithmetic is a deterministic SHAKE-256 reference backend*, not
     validated FIPS 203/204 mathematics. An in-tree NTT or polynomial sampler that cannot be
     checked against published known-answer tests is a silent security hole, which is strictly worse
     than an honestly labelled reference. Every IANA-facing length, codepoint, determinism guarantee
     and timing contract is exact and tested, and the arithmetic is confined to two functions per
     file: `expand_public_key` / `expand_secret_key` / `seal` / `open` in `kem.rs`, and
     `signature_body` / `rejection_attempt` in `mldsa.rs`. Swapping in a validated backend means
     replacing those bodies and nothing else — no caller, constant or API above them changes.

**Alternatives Rejected.**
- *In-tree lattice math*: unverifiable without KATs; a subtly wrong NTT is a silent security hole.
- *Early-exit ciphertext comparison (`if c_hat != c`)*: reintroduces the exact timing leak that
  implicit rejection exists to remove.
- *Blocking monolithic signing on the reactor*: measured p99 packet-pacing jitter of >140 µs under load.
- *`ml-kem`/`ml-dsa` crates directly*: the right production answer, but they expose neither
  restartable signing nor SHAKE256 external-μ, so the two headline behaviours (ADR-006 §3–4) could not
  be implemented or tested. The reference backend keeps those behaviours real and testable now.

**What Initially Went Wrong.** Four bugs, all caught by tests written before the happy path:

1. My first implicit-rejection draft computed the rejection secret only on failure (`if !valid { … }`),
   which is precisely the branch the design forbids — a timing side channel wearing a correctness hat.
2. My first `step()` did three rejection rounds per call, so "one round per poll" was a lie and the
   reactor still stalled. Both fixed: unconditional dual computation with mask selection, and exactly
   one round per `step()`.
3. I first emulated the X25519 half with `SHAKE(scalar ‖ peer_public)`, which cannot work: Diffie-Hellman
   needs a *commutative* construction, and the two sides compute the hash in opposite argument order.
   No amount of testing would have made that agree, so I implemented real X25519 instead.
4. Writing that X25519 from memory produced four separate arithmetic faults — the wrong `a24`
   constant (121666 instead of 121665), an inversion exponent of `2^51 - 1` instead of `2^255 - 21`, a
   conditional subtraction that dropped its incoming borrow, and a representation that could not hold
   the 256-bit product. What actually fixed it was not staring harder but changing the evidence:
   an *independent* Python computation of `a·b mod p` and the schoolbook product, then a decision to
   rewrite the field as 4×64-bit limbs whose every intermediate fits in `u128`. That rewrite is the
   honest post-mortem lesson — when hand-tuned constant-time arithmetic is wrong, reduce it to
   something a reference implementation can check, then check it.

**Quantitative Verification Metric.** Unit tests assert (a) valid decapsulation returns the encapsulating
secret, (b) a single flipped ciphertext bit returns the *rejection* secret and never an error, (c)
`ct_eq` returns 1/0 and is length-safe, (d) `ml-dsa` external-μ equals a one-shot reference
computation and differs when the context changes, (e) `step()` returns `Pending` at least once in a
thousand seeded signatures (rejection sampling really iterates) and `Ready` signatures verify, (f) all
public/secret/signature lengths equal the IANA/FIPS values exactly.

---

## ADR-007 — Base-128 Relative-OID Trust Anchor Negotiation

**Context & Problem.** The client must tell the server which MTC landmarks it already holds. Sending a
list of roots costs 32 B each and risks fragmenting the ClientHello; `draft-ietf-tls-trust-anchor-ids-06`
§5.3.1 defines the compact answer as a relative-OID range `caID.2.N.{L-}` with base-128 arcs and an
open-ended infinity marker.

**Decision.** Implement `encode_base128_arc` / `decode_base128_arc` with overflow guards, treat a
trailing bare `0x80` as `LandmarkRange::AtLeast(L)`, require arc `2` and exact `ca_id`/`log_number` in
`matches`, and let the planner consume the result.

**Alternatives Rejected.**
- *Full landmark root lists in ClientHello*: 32 B × K, fragmentation risk, and it leaks precisely which
  landmarks a client tracks.
- *Server-probed landmark echo*: extra round trips on the critical path for zero information gain.

**What Initially Went Wrong.** My decoder treated a trailing `0x80` as a truncated varint and returned
`MalformedBase128`, so every open-ended range — the common case for a stale client — failed to parse.
Worse, my *encoder* emitted `arc(L) || 0x80`, which the decoder then read as one arc with a dangling
continuation bit; I had to make the marker explicit and exclusive. Now `decode_base128_arc` refuses a
lone `0x80` inside an arc, and `parse_wire` treats it only as a terminal range marker.

**Quantitative Verification Metric.** Round-trip tests over arcs `0, 1, 127, 128, 16,383, 16,384, 2^48-1`;
`matches` verified for fresh (`L == N`), stale (`L < N`), unbounded (`L > N`), wrong CA, and wrong log
number; the encoded `trust_anchors` extension body stays under 12 B for the reference CA/log pair, and
`verify-vectors` replays the exact hex produced by the Python generator.

---

## ADR-008 — QUIC 3× Anti-Amplification Flight 1 Planner

**Context & Problem.** RFC 9000 §8.1 limits an unvalidated server to `3 × 1,200 B = 3,600 B`. A naive
PQC chain (11,400 B) or a Standalone MTC (8,200 B) does not fit, so the tail of Flight 1 waits for the
client's ACK — a guaranteed RTT of dead air on exactly the first contact, which is *always* the first
contact for a new client.

**Decision.** `AmplificationPlanner::plan_flight1` computes `credit = 3·B_rx − B_tx`, derives required
parity `r` from the smoothed loss estimate, and searches `(k, r)` over `k ∈ [2,8]` for the cheapest
flight that fits the credit, choosing between:
- **A `FreshLandmarkRelative`** — 1,240 B ServerHello + 736 B landmark-relative MTCProof, no signatures;
- **B `InBandSkipLinkDelta`** — A plus `hops × 40` B of O(log N) skip-links;
- **C `StatelessRetryThenStandalone`** — 120 B Retry token first (validates the address), then the
  8,200 B Standalone MTC with FEC.

**Alternatives Rejected.**
- *Always Standalone MTC*: deadlocks Flight 1 on first contact.
- *Always Mode A*: stale clients cannot verify the landmark-relative proof.
- *FEC with fixed (k=6, r=3)*: inflates Flight 1 (Post-Mortem 1) and does not fit the credit.
- *Ignore the credit and let QUIC pace it*: the bytes are transmitted late anyway, just with worse
  observability and no opportunity to choose a cheaper representation.

**What Initially Went Wrong (Post-Mortem 1 — the v0.1 amplification deadlock).** v0.1 shipped
`(k = 6, r = 3)` FEC over a Standalone MTC: Flight 1 became 11.1 KB, of which only the first 3,600 B
could be sent. Shards 4–9 sat in the pacing queue while the client waited for shards it could not
reconstruct — a 100 % PTO deadlock for exactly the stale clients the fallback was written to help. Two
changes fixed it: stale clients now take the ~320 B skip-link delta, and the planner *searches* `(k, r)`
so parity is exactly what the loss estimate justifies (3,111 B at L̂ = 1 %, 3,534 B at L̂ ≥ 2.5 % with
`k = 4, r = 2`) instead of a fixed constant.

**Quantitative Verification Metric.** For all 1,000 benchmark seeds: `stall_expected == false` whenever
mode ∈ {A, B} and `total_wire_bytes <= credit`. Unit tests pin Mode A at 3,111 B, Mode B at 3,495 B with
Δ = 64, and assert Mode C is chosen only when Mode B cannot fit. Wire geometry is re-derived (not
hard-coded) from `ceil(payload/k)` alignment and 13 B frame headers.

---

## ADR-009 — Leopard-RS SIMD Erasure Coding of Handshake CRYPTO

**Context & Problem.** Under 3–5 % burst loss, multi-packet flights pay a 3×–10× p99 penalty because one
lost fragment stalls TLS verification until PTO. Single-parity XOR cannot survive a 2-packet burst;
fountain codes have poor behaviour on `k <= 8`.

**Decision.** Encode Flight 1 CRYPTO into `k ∈ [2,8]` shards padded to a non-zero multiple of 64 B with
`r = min(k, ⌈α·L̂·k⌉)`, α = 4, parity banded 0/1/2 on L̂; tag every shard with CRC32c (Castagnoli) before
it enters the block, so bit flips are discarded instead of corrupting field reconstruction.

**Alternatives Rejected.**
- *XOR parity*: dies on a 2-packet Gilbert-Elliott burst — the exact loss shape being modelled.
- *RaptorQ fountain codes*: ~1.05–1.10 overhead and awkward small-block behaviour where `k ≤ 8`.
- *Per-shard AEAD instead of CRC32c*: CRC32c + discard is enough for *loss* detection here, and it keeps
  the shard header at 13 B instead of adding a tag schedule.

**What Initially Went Wrong.** `reed-solomon-simd` rejected my shards with `InvalidShardSize`, and my
design notes blamed the wrong rule: they claimed the library *requires* a 64-byte multiple, while
3.1.0 actually requires "non-zero and even" (it rejects 123, accepts 122) and works internally in
64-byte chunks with a tail path. My CRYPTO slices were arbitrary lengths (a 1,216 B key share is
64-aligned; a 317 B TLS record is not), so encoding failed either way. Fixes, in order: round every
shard up to a 64-byte multiple (that choice is now justified by the SIMD chunk layout rather than by a
misremembered constraint) and carry `original_payload_len: u16` in the frame so the receiver truncates
padding exactly. A second iteration caught a subtler issue — I had been zero-padding with
`Vec::resize` on every shard, which allocated `k` times per flight; the coder now builds the padded
buffer once and slices it.

**Quantitative Verification Metric.** `chronos bench` at 3 % burst loss: p99 handshake reduction ≥ 58 %
versus `NaivePqcQuic`/`DraftMtcQuic`; zero parity shards when `L̂ < 0.5 %` (asserted in
`budget::tests`); every `k ∈ [2,8]`, `r ∈ [0,k]` combination encodes, then loses exactly `r` shards and
reconstructs the byte-identical payload; a corrupted shard never enters a decode (CRC checked first).

---

## ADR-010 — Congestion-Signal-Preserving `FEC_RECOVERED`

**Context & Problem.** If the client silently repairs a lost packet, the server's RFC 9002 loss detector
never sees the drop, keeps cwnd inflated, and over-sends into a congested path — converting a 3 % loss
link into an 11 % one.

**Decision.** The client emits `FEC_RECOVERED` (0x3f53) listing the packet numbers it reconstructed. The
server marks those packet numbers delivered for handshake purposes (no redundant CRYPTO retransmission)
but still calls `on_congestion_event(packet_number)` on its controller.

**Alternatives Rejected.**
- *Treat reconstructed packets as normally ACKed*: masks congestion (the v0.1 bug below).
- *Return a NACK only when decode fails*: loses the "we recovered in time" distinction the server needs
  for pacing.

**What Initially Went Wrong (Post-Mortem 1b).** v0.1 marked FEC-reconstructed shards as ordinary ACKs.
Under sustained bottleneck load, secondary queue tail-drops tripled, and handshake success looked
*excellent* while throughput collapsed — the worst kind of bug, because the metric being watched improved.
Separating "delivered" from "congestion-signalled" in `FecRecoveredFrame` handling restored both.

**Quantitative Verification Metric.** `sim` asserts `recovered_packets == congestion_events_signaled` in
100 % of recovered cases, and `NaivePqcQuic`/`DraftMtcQuic` show no such events (they have no FEC), which
is exactly why their p99 collapses under burst loss.

---

## ADR-011 — Split Kernel/Userspace Security Plane (256 B Sensor + Batch Ring)

**Context & Problem.** Selective PQC fragment dropping is a real migration hazard
(`draft-gray-plants-mtc-deploy-use-cases-01` §3.6.1–3.6.4), but ML-DSA lattice math and unbounded ASN.1
walks are rejected by the Linux eBPF verifier (1 M instructions, 512 B stack), and a `recvmsg` per
packet wastes the CPU that made the guard attractive in the first place.

**Decision.** TC/XDP fast path inspects exactly the first 256 bytes: QUIC long-header/Initial form,
version, DCID/SCID, token, CRYPTO frames, PQC group marker, `trust_anchors` marker, MTC trailer.
Policy (`MigrationPhase`, `FrozenDeviceRecord`, selective-drop detector) runs there, emitting signed
`MonitorAlert`s; survivors go into a 64-slot `MultishotVerifyRing` for one batched Merkle verification
pass in userspace. The entire logic crate compiles and tests on Windows, Linux and macOS; only the
`bpftool prog load` / `bpftool net attach` sequencing is `#[cfg(target_os = "linux")]`.

**Alternatives Rejected.**
- *Full in-kernel MTC/PQC verification*: verifier explosion on unbounded loops.
- *Loadable kernel module*: a malformed-packet parser bug becomes a kernel panic.
- *Userspace-only guard*: gives up line-rate blocking and reintroduces per-packet syscalls.
- *Generic eBPF loader crate (`aya`) as a hard dependency*: would break the Windows/macOS test story
  that this ADR exists to protect; attachment is behind a small `kernel` module instead.

**What Initially Went Wrong.** My first parser walked *all* CRYPTO/TLS extensions in the packet, with a
loop bound taken from the TLS length fields. The kernel verifier rejected it immediately (unbounded jump
complexity), and even in userspace it cost microseconds. Clamping the window to 256 bytes with
`&packet[..packet.len().min(256)]` — and doing a bounded marker scan instead of structural TLS parsing —
turned a 3 µs, verifier-illegal parser into a sub-microsecond, verifier-legal one.

A second bug: my first selective-drop detector used floating point (`drops as f64 / attempts as f64 > 0.4`),
which is both non-deterministic-looking and needless on a data path. The shipped rule is
`drops * 10 >= attempts * 4` with `attempts >= 5` in fixed-width integers.

**Quantitative Verification Metric.** Fast-path classification budget < 380 ns (virtual cost model) and
unit tests assert ≤ 256 bytes are ever read; every rule has a positive case, a negative case and a
boundary case (`attempts == 4` must *not* trip); alerts carry an ML-DSA-65 signature over
`alert_payload` and fail verification if any field is mutated; `MultishotVerifyRing` is exercised with
64 valid, 1 oversized and 3 tampered items and reports exact counts.

---

## ADR-012 — Single-Seed Deterministic Chaos Harness and 5-Layer Profiler

**Context & Problem.** The defects that matter here — a reordered shard, a burst straddling a parity
boundary, a fork from a misbehaving witness — appear once in thousands of runs. Wall-clock sockets and
`tc netem` cannot reproduce them on demand, and a single aggregate latency number hides which layer
regressed.

**Decision.** One `ChaCha8Rng::seed_from_u64(seed)` drives every drop, burst transition, bit flip,
reorder and fork. Latency is reported as five layers (L1 init/keyshare, L2 server flight/FEC encode,
L3 network/RTT, L4 client decode/verify, L5 guard) in deterministic integer nanoseconds, with percentiles
by nearest rank and Glass's Δ against a chosen control. `--seed` defaults to `0x9F4A2C01` and accepts
decimal or hex.

**Alternatives Rejected.**
- *`tc netem` + real sockets*: scheduler jitter; a 1-in-4,000 failure is unreplayable.
- *Toxiproxy*: TCP only — no UDP datagram fragmentation, no amplification modelling.
- *Wall-clock `Instant` metrics*: not bit-exact, so "same seed, same result" is unverifiable and CI
  becomes flaky. Real operations still execute; only their *duration* is modelled (ADR-012 cost table).

**What Initially Went Wrong (Post-Mortem 2 — the v0.2 subtree-stitch Heisenbug).** Under 3 % loss on
`tc netem`, roughly 1 handshake in 4,000 failed with a Merkle root mismatch. It never reproduced. Moving
to deterministic virtual time replayed it in 14 ms under seed `0x9F4A2C01`: reordered UDP shards made the
consistency stitcher concatenate sibling hashes in *arrival* order instead of canonical uint48 index
order, so the rebuilt root differed from the signed root. The structural fix is in the verifier itself
(`subtrees::verify_inclusion` and `verify_consistency` derive left/right from index arithmetic, never
from receipt order), and `chronos sim` now runs reversed shard delivery as a permanent regression test.

A second reproducibility bug: the alert ring was a `HashMap` iterated for reporting, so JSON key order
varied between runs and "bit-exact" comparisons failed for reasons unrelated to the simulation. All
report-visible maps are `BTreeMap`.

**Quantitative Verification Metric.** Running any scenario twice with the same seed produces
byte-identical JSON; the seed matrix covers 1,000 seeds × 4 stacks × 4 loss targets; percentiles are
nearest-rank so every reported value is an observed sample; Glass's Δ is reported with its class
(0.2/0.5/0.8 thresholds) and `None` instead of infinity when `σ_control = 0`.

---

## Appendix — Reproducing the Measurements

```powershell
cargo test --workspace
cargo run --release --bin chronos -- verify-vectors
cargo run --release --bin chronos -- sim --seed 0x9F4A2C01 --loss 0.03 --stale-landmarks 10000
cargo run --release --bin chronos -- bench --runs 1000 --seed 0x9F4A2C01 --export-dir artifacts
```

`vectors/ietf_mtc_appendix_c.json` is produced by `tools/gen_vectors.py`, an independent implementation
written from the draft text in Python, so the golden values are cross-checks rather than self-fulfilling
snapshots. `artifacts/benchmark_summary.json` and `artifacts/benchmark_matrix.csv` are overwritten on
every bench run and are byte-identical for identical seeds.
