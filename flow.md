# ChronosMTC v1.0 — End-to-End System Execution Flow Specification

**Author:** Pratham Kapoor ([@PrathamKapoor](https://github.com/PrathamKapoor) | prathamkapoor027@gmail.com)
**Repository:** <https://github.com/PrathamKapoor/chronos-mtc>
**Standards baseline:** IETF `draft-ietf-plants-merkle-tree-certs-07`, IETF `draft-gray-plants-mtc-deploy-use-cases-01`, IETF `draft-ietf-tls-trust-anchor-ids-06`, C2SP `tlog-tiles` / `tlog-cosignature`, RFC 9000 (QUIC), RFC 9002 (QUIC Congestion Control), RFC 9162 (Certificate Transparency v2), NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA)

This document is the normative execution contract for the workspace. Every byte offset, wire constant,
state transition and formula stated here is implemented literally in the corresponding crate; the unit
test suites in each crate assert these values, and `chronos verify-vectors` replays them from
`vectors/ietf_mtc_appendix_c.json`.

---

## 1. System Topology and the 5-Crate Execution Pipeline

ChronosMTC is a five-crate Rust workspace (2021 edition, `#![forbid(unsafe_code)]` in every crate) that
moves a QUIC handshake from *certificate bytes* to *trust anchor roots* across six deterministic stages.

| Stage | Crate | Primary input | Primary output | Budget / target |
|---|---|---|---|---|
| Flow 1 | `chronos-mtc-core` | Raw DER `TBSCertificate` slice + validity window `[start, end)` | 32-byte streaming leaf hash `MTH({entry})` and ≤ 2 aligned `SubtreeRange` descriptors | < 1.0 µs per leaf, 0 heap allocations |
| Flow 2 | `chronos-mtc-core` | Landmarked tree size `S_N` + witness cosignatures | Power-of-two skip-link edge set `L_{N-2^k} → L_N` and canonical `MTCProof` | ≤ 17 edges across 87,600 landmarks (10 years hourly) |
| Flow 3 | `chronos-quic-fec` | Client Initial datagram (1,200 B) carrying base-128 `trust_anchors` (`0x003b`) | `Flight1Plan` ∈ {`FreshLandmarkRelative`, `InBandSkipLinkDelta`, `StatelessRetryThenStandalone`} | Server Flight 1 ≤ 3,600 B cap |
| Flow 4 | `chronos-quic-fec` | Serialized Flight 1 CRYPTO payload + smoothed loss `L̂` | `k` `FEC_SOURCE` (0x3f51) + `r` `FEC_REPAIR` (0x3f52) frames, client `FEC_RECOVERED` (0x3f53) | 1-RTT loss recovery; `k ∈ [2,8]`, `r ≤ 2` |
| Flow 5 | `chronos-ebpf-guard` | First 256 B of ingress QUIC Initial | `PacketVerdict` + signed `MonitorAlert` + batched verification | < 380 ns fast path |
| Flow 6 | `chronos-sim` | 64-bit seed (`0x9F4A2C01`), Gilbert-Elliott `(p, r, k, h)` | 5-layer p50/p90/p95/p99 and Glass's Δ across 4 stacks | 100 % bit-exact replay |

### 1.1 Crate dependency graph

```text
chronos-sim ──┬─▶ chronos-quic-fec ─┬─▶ chronos-mtc-core ─▶ (sha2, thiserror, serde, hex, bytes)
              │                     └─▶ chronos-pqc-sys ──▶ (sha2, sha3, zeroize, rand_chacha)
              ├─▶ chronos-ebpf-guard ─┬─▶ chronos-mtc-core
              │                       └─▶ chronos-pqc-sys
              └─▶ chronos-pqc-sys / chronos-mtc-core / rand_chacha / serde_json / clap
```

`chronos-mtc-core` never depends on a signature implementation: checkpoint signing is injected as a
closure `Fn(&[u8]) -> Vec<u8>`. That is what lets `chronos-pqc-sys` (ML-DSA-65) and the test vectors
(keys derived from a deterministic seed) share one code path.

### 1.2 Global wire constants (authoritative)

| Constant | Value | Location |
|---|---|---|
| `MTC_LEAF_PREFIX` | `0x00` | `chronos-mtc-core::subtrees` |
| `MTC_NODE_PREFIX` | `0x01` | `chronos-mtc-core::subtrees` |
| `OID_MTC_PROOF` | `06 09 2B 06 01 05 05 07 06 43` (1.3.6.1.5.5.7.6.67) | `chronos-mtc-core::cosign` |
| `COSIGN_CONTEXT_HEADER` | `"subtree/v1\n\0"` (12 B) | `chronos-mtc-core::cosign` |
| `TLOG_TILE_HEIGHT` / `TILE_WIDTH` / `TILE_BYTES` | 8 / 256 / 8,192 | `chronos-mtc-core::tiles` |
| `MAX_UINT48` | `(1 << 48) - 1` | `chronos-mtc-core::subtrees` |
| `X25519MLKEM768` / `ML_DSA_44` / `ML_DSA_65` codepoints | `0x11EC` / `0x0904` / `0x0905` | `chronos-pqc-sys` |
| `FEC_SOURCE` / `FEC_REPAIR` / `FEC_RECOVERED` | `0x3f51` / `0x3f52` / `0x3f53` | `chronos-quic-fec::frames` |
| `TRUST_ANCHORS` extension type | `0x003b` | `chronos-mtc-core::trust_anchor` |
| `MAX_EBPF_INSPECT_BYTES` | 256 | `chronos-ebpf-guard` |

---

## 2. Flow 1 — Certificate Authority Ingestion, Streaming TBSCertificate Hashing, Two-Subtree Cover

### 2.1 WHAT happens

The Certificate Authority (CA) ingests a batch of certificates spanning log indices `[start, end)`.
`chronos-mtc-core` (a) rejects any non-canonical DER, (b) streams the canonical leaf representation of
each `TBSCertificate` through a single SHA-256 state with **zero heap allocation**, and (c) decomposes
`[start, end)` into **at most two** power-of-two aligned Merkle subtrees.

### 2.2 WHY it happens

1. **The post-quantum signature tax.** A conventional TLS 1.3 chain carrying ML-DSA-65
   (3,309 B signature + 1,952 B public key per entry) adds 9,927 B to the handshake
   (`draft-ietf-plants-merkle-tree-certs-07` §1). Merkle Tree Certificates replace per-leaf signatures
   with an inclusion proof over the canonical `TBSCertificate` projection, so the certificate never
   carries its own signature on the wire.
2. **Allocator pressure at verification throughput.** Materializing a `TBSCertificateLogEntry` buffer
   per certificate produces one heap object per certificate; at 10^5 cert/s that is sustained
   allocator traffic on the handshake hot path. The hasher consumes `&[u8]` slices and writes into a
   single `Sha256` state, so the leaf hash costs zero allocations.
3. **RFC 9162 alignment.** `[start, end)` is representable as *one* subtree root only when
   `start mod 2^ceil(log2(end - start)) == 0`. Arbitrary validity windows straddle power-of-two
   boundaries, and an unaligned "subtree root" would break consistency proofs.
4. **BER length malleability (§12.6).** If the parser accepts `0x81 0x7F` (127) or indefinite `0x80`,
   an attacker can produce two distinct byte strings that canonicalize to the same certificate,
   defeating leaf-hash-based cache pinning.

### 2.3 HOW it happens — byte-exact execution

#### 2.3.1 Strict DER guard (`validate_canonical_der_tlv`)

Input: one complete TLV (`tag || length || value`). The function *requires full consumption*:
`input.len() == 2 + num_len_bytes + decoded_len`.

| Step | Check | Rejection |
|---|---|---|
| 0 | `input.len() >= 2` | `MtcError::DerTruncated` |
| 1 | `b0 = input[1]`; if `b0 == 0x80` → indefinite length | `NonCanonicalDer("Indefinite length 0x80 forbidden in DER")` |
| 2 | if `b0 & 0x80 == 0` → short form, value length is `b0` | — |
| 3 | else `num_len_bytes = (b0 & 0x7F)`; reject `0` or `> 4`; reject `input.len() < 2 + num_len_bytes` | `NonCanonicalDer` |
| 4 | reject `input[2] == 0x00` (leading zero padding) | `NonCanonicalDer` |
| 5 | decode big-endian length; reject `decoded < 128` (fits in one short-form byte) | `NonCanonicalDer("Non-minimal multi-byte DER length")` |
| 6 | reject `input.len() != 2 + num_len_bytes + decoded` | `DerTruncated` |

Accepted: `30 82 01 00 …`, `04 20 …`, `02 01 05`. Rejected: `30 80 …`, `30 81 7F …`, `30 82 00 80 …`.

#### 2.3.2 11-step streaming leaf hasher (`hash_tbs_certificate_streaming`)

`TbsCertFields<'a>` holds zero-copy slices:

```text
version_raw          : &'a [u8]   raw DER of the [0] EXPLICIT version (absent => [0x02 0x01 0x02])
serial_number        : u64        ≤ MAX_UINT48
log_number           : u16
signature_alg_oid    : &'a [u8]   raw OID *contents* (no tag/length)
issuer_dn            : &'a [u8]   complete DER Name TLV
not_before / not_after : u64      unix seconds
subject_dn           : &'a [u8]   complete DER Name TLV
subject_public_key_info : &'a [u8]  complete DER SubjectPublicKeyInfo TLV
extensions_der       : &'a [u8]   complete DER Extensions SEQUENCE TLV (may be empty)
```

Byte stream fed to SHA-256, in order:

```text
0x00                                        (MTC_LEAF_PREFIX)
version_raw
uint64_be((log_number << 48) | serial_number) (compressed serial, §12.3)
signature_alg_oid
issuer_dn
uint64_be(not_before)
uint64_be(not_after)
subject_dn
0x04 0x20 SHA256(subject_public_key_info)   (34-byte OCTET STRING replacing the 1,952 B ML-DSA key)
canonical_extensions_der                    (volatile SCT extensions removed, §2.3.3)
```

Formally:

$$\mathrm{MTH}(\{entry\}) = \mathrm{SHA256}\Big( \mathtt{0x00} \parallel \mathrm{Version} \parallel \mathrm{CompressedSerial}_{8B} \parallel \mathrm{SigAlgOID} \parallel \mathrm{IssuerDN} \parallel \mathrm{NotBefore}_{8B} \parallel \mathrm{NotAfter}_{8B} \parallel \mathrm{SubjectDN} \parallel \mathtt{0x0420} \parallel \mathrm{SHA256}(\mathrm{SPKI}) \parallel \mathrm{Extensions}_{\mathrm{canonical}} \Big)$$

Constraints: `serial_number > MAX_UINT48` ⇒ `MtcError::SerialOutOfBounds`; `ctx`/serial truncation never
happens silently. `extensions_der` and `subject_public_key_info` are validated by the guard before use.

#### 2.3.3 Volatile SCT stripping (`strip_volatile_extensions`)

Input is the `Extensions` SEQUENCE TLV. The function parses each child `Extension` TLV (guarded),
removes any extension whose `extnID` is the signed-certificate-timestamp OID
`1.3.6.1.4.1.11129.2.4.2` (`06 0A 2B 06 01 04 01 D6 79 02 04 02`), and re-encodes the remaining
children with a minimal-length SEQUENCE header. Empty input yields empty output; an empty result is
hashed as zero bytes.

#### 2.3.4 Two-subtree interval cover (`find_subtrees`)

```text
MAX_UINT48 = (1 << 48) - 1
is_aligned_subtree(s, e):  size = e - s;  ceil_pow2 = size.next_power_of_two();  (s & (ceil_pow2 - 1)) == 0
```

Preconditions: `0 <= start < end` and `end <= MAX_UINT48`, else `MtcError::InvalidRange { start, end }`.

* If `is_aligned_subtree(start, end)`: return `[{ start, end }]` (1 subtree).
* Otherwise split at the most significant differing bit:

$$\text{diff} = \text{start} \oplus (\text{end}-1), \qquad \text{split\_bit} = 63 - \text{diff.leading\_zeros}()$$
$$\text{mid} = (\text{end}-1) \mathbin{\&} \neg\!\left(2^{\text{split\_bit}} - 1\right)$$

Return `[{ start, mid }, { mid, end }]`. Both halves are provably aligned: `start` and `mid` are both
multiples of `2^split_bit`, and `end - mid <= 2^split_bit`.

Worked example: `[3, 12)` → not aligned (`size=9`, `ceil_pow2=16`, `3 & 15 = 3 ≠ 0`) → `diff = 3^11 = 8`,
`split_bit = 3` → `mid = 11 & !7 = 8` → `[{3,8), {8,12})`. Both aligned, sizes 8 and 4.

#### 2.3.5 Merkle tree state machine (`MerkleTreeLog`)

Node storage is level-indexed: `levels[l][i]` is the hash of leaves `[i·2^l, (i+1)·2^l)`, present iff
`(i+1)·2^l <= size`. `append_entry` pushes into `levels[0]` and merges upward while both children exist
— `O(log N)` hashes per append, `O(N)` total storage.

```text
node(l, r)   = SHA256(0x01 || MTH(leaves[l:r_left]) || MTH(leaves[r_left:r]))
subtree_hash(a, b):
    if b - a == 1 -> levels[0][a]                         (the leaf hash is MTH({entry}))
    k = 1 << (63 - (b - a - 1).leading_zeros())           (largest power of two < size)
    if is_aligned_subtree(a, b) && (b - a).is_power_of_two() -> single stored node lookup
    else -> node_hash(subtree_hash(a, a+k), subtree_hash(a+k, b))
```

Every window reached by this recursion is an *aligned* subtree, so the common case is a single stored
node: `subtree_hash` is `O(log N)` with no allocation and no hashing of untouched levels.

`inclusion_proof(index, start, end)` emits sibling hashes **top-down** (outermost split first). Left/right
position is decided by `uint48` index arithmetic, never by arrival order:

```text
rel = index - a
rel <  k -> sibling is the RIGHT subtree [a+k, b): push hash(a+k, b); a, b = a, a+k
rel >= k -> sibling is the LEFT  subtree [a, a+k): push hash(a, a+k);   a, b = a+k, b
```

`verify_inclusion` mirrors the walk, folding with `node(cur, sib)` or `node(sib, cur)` as dictated by the
index, then requiring `cur == expected_root` and full proof consumption. This is the structural fix for
Post-Mortem 2 (`decisions.md`, ADR-012): UDP reordering cannot invert a hash concatenation because
order is derived from indices, never from the wire.

---

## 3. Flow 2 — Hourly Landmark Issuance, O(log N) Skip-Link Graph, C2SP Cosigning

### 3.1 WHAT happens

At every epoch `N` the Landmark Distribution Point (LDP) registers `LandmarkNode { landmark_id, tree_size,
timestamp, root_hash, checkpoint_signature }` and publishes the power-of-two skip-link edges
`L_{N-2^k} → L_N` for all `k` with `2^k <= N`. Witnesses cosign the subtree root with canonical C2SP
`TimestampedSignature` envelopes.

### 3.2 WHY it happens

* `draft-gray-plants-mtc-deploy-use-cases-01` §3.1.6: on-demand arbitrary `(S_old, S_new)` proofs at the
  LDP are `O(N²)`; a client that downloads one linear proof per missed landmark pays `O(N)` bandwidth
  and `O(N)` signature verifications; and the "just send a standalone MTC" fallback is 8,200 B, which
  cannot fit QUIC's 3,600 B anti-amplification window. Power-of-two edges make both sides `O(log N)`.
* `merkle-tree-certs` issues #341/#342: out-of-order cosigner arrays and mismatched signature envelopes
  caused deterministic cross-implementation verification failures. Hence length-first canonical
  ordering and a fixed 64-byte signed statement.

### 3.3 HOW it happens

#### 3.3.1 Edge generation and proof derivation

At publish time the LDP records which edges *exist* (metadata only):
`edges[(N - 2^k, N)] = { from_tree_size, to_tree_size }`. Consistency proof bytes are derived on demand
from the level-indexed node storage in `O(log² N)` (`k <= 64` recursion levels, `O(log N)` per emitted
element) and memoized in an LRU-bounded cache. This replaces `O(N²)` *stored* proofs with `O(N)` edge
metadata; the hop *plan* — the part that makes the client fast — is unchanged.

Subtree consistency proof, RFC 9162 §2.1.4.2 `SUBPROOF`, on window `[a, a+n)` holding `m` old leaves:

```text
subproof(a, n, m, is_top):
    if m == n:  push hash(a, a+n) unless is_top;  return
    k = largest power of two < n
    if m <= k:  subproof(a,     k,     m,     false);  push hash(a + k, a + n)     # right sibling
    else:       subproof(a + k, n - k, m - k, false);  push hash(a,     a + k)     # left sibling
```

Verification is the structural mirror that rebuilds **both** roots from one proof, which is why a
tampered element cannot be laundered into the new root:

```text
consume(n, m):                       # returns (new_window_root, old_prefix_root)
    if m == n: h = next_proof(); return (h, h)
    k = largest power of two < n
    if m <= k: (nl, ol) = consume(k, m);       hr = next_proof(); return (node(nl, hr), ol)
    else:       (nr, or) = consume(n - k, m - k); hl = next_proof(); return (node(hl, nr), node(hl, or))
```

Top level: `m == 0` ⇒ proof must be empty (nothing to bind); `m == n` ⇒ proof must be empty and the
roots must be equal; otherwise require `old_prefix_root == from_root`, `new_window_root == to_root`, and
exact proof consumption.

#### 3.3.2 Greedy binary-jump catch-up (`plan_skip_link_sync`)

With `delta = target - client`, hops jump by the highest set bit of the remaining distance:

```text
while curr < target:
    rem   = target - curr
    step  = 1 << (63 - rem.leading_zeros())
    edge  = graph.edge(curr, curr + step)      # must exist
    hops.push(edge)
    curr += step
```

`hops = popcount(delta) <= ceil(log2(delta))`. Checkpoints: `Δ = 10,000 → 5 hops`, `Δ = 87,600 → 7 hops`
(bound 17). Verification chains the roots across hops and performs **exactly one** ML-DSA-65 check, on
the final target landmark: intermediate edges are bound by collision-resistant consistency hashes.

#### 3.3.3 Canonical C2SP cosignature envelope

Signed statement (64 B, `build_cosigned_subtree_payload`):

| Offset | Length | Content |
|---|---|---|
| 0 | 12 | `"subtree/v1\n\0"` = `73 75 62 74 72 65 65 2F 76 31 0A 00` |
| 12 | 8 | `uint64_be(timestamp)` |
| 20 | 6 | `uint48_be(start)` |
| 26 | 6 | `uint48_be(end)` |
| 32 | 32 | `root_hash` |

Checkpoint statement (68 B, `checkpoint_payload`), the input to the injected signer:

```text
"checkpoint/v1\n\0" (12 B) || uint64_be(landmark_id) || uint64_be(tree_size) || uint64_be(timestamp) || root_hash[32]
```

Each witness record is a `TimestampedSignature`: `uint64_be(timestamp) || signature_bytes`.

**Canonicalization** (`canonicalize_cosignatures`): sort by `(cosigner_id.len(), cosigner_id bytes)`,
reject adjacent duplicates with `MtcError::DuplicateCosignerId`, never reorder by arrival. RFC 8701
GREASE ids (`len == 2 && id[0] & 0x0F == 0x0A && id[1] & 0x0F == 0x0A`) are retained on the wire for
protocol hygiene but excluded from `count_quorum`.

**`MTCProof` canonical encoding** (`encode_mtc_proof` / `decode_mtc_proof`):

```text
OID_MTC_PROOF (10 B) || 0x01 (version)
  || uint48_be(start) || uint48_be(end) || root_hash[32]
  || uint16_be(proof_len) || proof hashes (32 B each, top-down canonical order)
  || uint16_be(cosigner_count)
  || per cosigner: uint8(id_len) || id || uint64_be(timestamp) || uint16_be(sig_len) || signature
```

Decoding re-canonicalizes and re-encodes; a byte-identical round trip is a test invariant (ADR-005).

---

## 4. Flow 3 — Base-128 Trust Anchor Negotiation and the 3× Anti-Amplification Budget

### 4.1 WHAT happens

The client sends a 1,200 B QUIC Initial with an X25519MLKEM768 (`0x11EC`) key share and a
`trust_anchors` (`0x003b`) extension encoding its newest landmark as a relative OID range
`caID.2.N.{L-}`. The server decodes the client's landmark and plans Server Flight 1 so it always fits
the unvalidated credit `3 · B_rx`.

### 4.2 WHY it happens

* RFC 9000 §8.1 caps an unvalidated server at `3 × 1,200 B = 3,600 B`. Exceeding it parks bytes in the
  send queue until the client's ACK validates the address — a full RTT + PTO of dead air.
* Post-Mortem 1: a naive PQC chain (11,400 B) or a Standalone MTC (8,200 B) both exceed the cap on
  first contact, which is precisely why stale clients must be served the ~320 B skip-link delta instead
  of a fallback certificate bundle.

### 4.3 HOW it happens

#### 4.3.1 Base-128 relative-OID range (`TrustAnchorPattern`)

Arcs are big-endian base-128: bits 6..0 carry value, bit 7 (`0x80`) is the continuation flag and is set
on every byte except the last of an arc. Wire form of `caID.2.N.{L-}` is
`arc(caID) || arc(2) || arc(N) || arc(L) || 0x80`, where the trailing bare `0x80` is the §5.3.1
open-ended ("at least") marker, decoded as `LandmarkRange::AtLeast(L)`, never as a truncated varint.

```text
encode_base128_arc(16384) -> [0x81, 0x00]      (continuation + 7-bit groups, MSB first)
decode_base128_arc([0x81, 0x00]) -> (16384, 2)
terminal [.., 0x80]          -> AtLeast(previous arc)
```

`matches(ca_id, log_number, landmark_id)` requires exact `ca_id`, exact `log_number`, arc `2` present,
and `landmark_id >= L` (or `== L` for a closed range).

#### 4.3.2 Budget arithmetic (`AmplificationPlanner::plan_flight1`)

```text
credit       = saturating_mul_3(client_rx_bytes) - bytes_already_sent        # 3,600 B on first contact
required_r   = 0                      if L̂ < 0.005
             = 1                      if 0.005 <= L̂ < 0.025
             = 2                      if L̂ >= 0.025
data_bytes   = SERVER_HELLO_PQC_BYTES (1240)
             + LANDMARK_MTC_PROOF_BYTES (736)                  [Mode A]
             + skip_link_hops * SKIP_LINK_HOP_BYTES (40)        [Mode B]
aligned      = 64 * ceil(max(ceil(data_bytes / k), 64) / 64)
total(k, r)  = (k + r) * (aligned + 13)                        # 13 B FEC_SOURCE/FEC_REPAIR header
```

Selection is an exhaustive search over `k ∈ [2, 8]` and `r ∈ [required_r ..= 0]` (descending): the first
`(k, r)` whose `total <= credit` wins, minimizing wire bytes and maximizing parity.

| Mode | Condition | Flight 1 content | Worked example (credit 3,600 B, L̂ = 1 %) |
|---|---|---|---|
| A `FreshLandmarkRelative` | `client_landmark >= cert_landmark` | 1,240 + 736 = 1,976 B | `k = 2, r = 1`, aligned 1,024 ⇒ 3 × 1,037 = **3,111 B** |
| B `InBandSkipLinkDelta` | `client_landmark < cert_landmark` and it fits | + `hops × 40` B skip-links | `Δ = 64` ⇒ 6 hops ⇒ data 2,216 B ⇒ `k = 2, r = 1` ⇒ **3,495 B** |
| C `StatelessRetryThenStandalone` | no landmark, or nothing fits | Retry token (120 B) + Standalone MTC (8,200 B) after address validation | 120 B now, unblocked afterwards |

The planner reports `stall_expected` whenever the chosen parity is below `required_r`, so the caller can
act on a lossy-but-legal plan rather than discovering it at the wire.

---

## 5. Flow 4 — SIMD Reed-Solomon CRYPTO Coding, Reconstruction, FEC_RECOVERED

### 5.1 WHAT happens

Flight 1 CRYPTO is split into `k` 64-byte-aligned data shards, `r` recovery shards are computed with
Leopard-RS SIMD, every shard carries a CRC32c tag, and shards travel as `FEC_SOURCE` (0x3f51) /
`FEC_REPAIR` (0x3f52). The client reconstructs up to `r` losses in the same RTT and reports them with
`FEC_RECOVERED` (0x3f53).

### 5.2 WHY it happens

* One lost fragment of a multi-packet flight stalls TLS transcript verification until the PTO fires —
  the source of the 3×–10× p99 spike under 3–5 % burst loss.
* *But* silent receiver-side recovery hides congestion from the sender. ADR-010: without
  `FEC_RECOVERED`, secondary loss on a bottleneck link rose from 3 % to 11 %.

### 5.3 HOW it happens — wire formats

QUIC varints: minimal-length big-endian, top two bits select width. `0x3f51 → 0x7F 0x51`,
`0x3f52 → 0x7F 0x52`, `0x3f53 → 0x7F 0x53` (2-byte form).

```text
FEC_SOURCE    (0x3f51): varint type || block_id u32 || k u8 || r u8 || shard_index u8
                         || original_payload_len u16 || crc32c u32 || shard bytes      [13 B header]
FEC_REPAIR    (0x3f52): varint type || block_id u32 || k u8 || r u8 || parity_index u8
                         || shard_len u16 || crc32c u32 || parity bytes                  [13 B header]
FEC_RECOVERED (0x3f53): varint type || block_id u32 || recovered_count u8
                         || recovered_packet_numbers: varint-prefixed u64 list        [5 B + 9 B per pn]
```

```text
raw_shard        = ceil(payload_len / k)
aligned_shard_len = 64 * ceil(max(raw_shard, 64) / 64)          # reed-solomon-simd shard rule
data shards      = payload[0..k-1], final shard zero-padded to aligned_shard_len
crc32c           = crc32fast::hash(shard)                       # Castagnoli
encoder          = ReedSolomonEncoder::new(k, r, aligned_shard_len)
```

Receiver (`FecBlockAssembler`): every shard's CRC32c is checked *before* it enters the block, so a
Byzantine bit flip is discarded rather than poisoning Galois-field reconstruction. As soon as
`valid_sources + valid_repairs >= k`:

* `valid_sources == k` → concatenate sources, truncate to `original_payload_len`;
* otherwise `ReedSolomonDecoder::new(k, r, aligned_shard_len)` reconstructs the missing indices,
  which are reported through `FecRecoveredFrame { block_id, recovered_count, recovered_packet_numbers }`.

`FecBlockAssembler::assemble` returns `AssemblyOutcome { payload, recovered_shard_indices }`; the
integration layer maps shard indices to packet numbers via the frame schedule.

---

## 6. Flow 5 — Bounded Sensor, Downgrade Policy, Signed Alerts, Batch Ring

### 6.1 WHAT happens

On ingress, a bounded parser inspects the **first 256 bytes** of each QUIC Initial, classifies the
negotiated groups/extensions, enforces `MigrationPhase` (ClassicalOnly / Hybrid / PqOnly) and
`FrozenDeviceRecord` policy, emits ML-DSA-65-signed `MonitorAlert`s, and queues survivors into a
64-slot `MultishotVerifyRing` for one batched Merkle verification pass.

### 6.2 WHY it happens

* During hybrid migration an on-path attacker drops fragmented PQC flights while letting single-packet
  classical handshakes through, silently downgrading peers (`draft-gray-plants-mtc-deploy-use-cases-01`
  §3.6.1–3.6.4).
* Full ML-DSA lattice arithmetic and unbounded ASN.1 loops are rejected by the Linux eBPF verifier
  (1 M instruction budget, 512 B stack). Hence a 256-byte fast path plus userspace batching.

### 6.3 HOW it happens

#### 6.3.1 `parse_quic_initial_256b`

```text
window = &packet[..min(256, packet.len())]          # hard clamp: no loop can read past byte 255
b0     = window[0]
header_form_long = (b0 & 0x80) != 0
is_initial      = ((b0 & 0x30) >> 4) == 0x00         # only meaningful when header_form_long
version         = u32::from_be_bytes(window[1..5])
dcid_len/dcid, scid_len/scid, varint token_len, token, varint length, packet number (pn_len = (b0 & 3) + 1)
frames          -> CRYPTO (0x06) payloads are collected as bounded (offset, len, bytes) windows
```

Classification inside the collected CRYPTO window:

| Signal | Test |
|---|---|
| `offers_pqc_kem` | bytes `11 EC` present (X25519MLKEM768 `0x11EC`) |
| `offers_mtc_trust_anchor` | bytes `00 3B` present (`trust_anchors`) |
| `cert_serial_hint` | trailer magic `M T C 0x01` then `uint48_be` serial |
| `cert_issuance_timestamp` | the 6 bytes following the serial |

The trailer is the plaintext MTC checkpoint hint a ChronosMTC client appends inside its Initial CRYPTO
frame so the fast path can reason about issuance age without TLS decryption. Absence ⇒ `None`.

#### 6.3.2 Three-state policy matrix (`evaluate_packet`)

```text
Rule 1  phase == PqOnly  && !offers_pqc_kem
            -> Drop(AlgorithmDowngrade) + signed alert
Rule 2  phase == Frozen { freeze_timestamp }
            && cert_issuance_timestamp.unwrap_or(u64::MAX) > freeze_timestamp
            -> Drop(UnauthorizedIssuanceAfterFreeze) + signed alert
Rule 3  phase == Hybrid  && !offers_pqc_kem
            && pqc_attempts >= 5 && pqc_fragment_drops * 10 >= pqc_attempts * 4
            -> Drop(SelectiveFragmentDropAttack) + signed alert
otherwise -> PassToBatchRing
```

Rule 3's integer form is deliberate: `drops × 10 >= attempts × 4` is "≥ 40 % of this peer's PQC
fragments vanished while at least one classical fallback appeared" — the selective-fragment-drop
signature, evaluated in fixed-width integers with no floating point on the hot path. `Frozen` treats a
missing timestamp as maximally recent, because "issued after the freeze" must fail closed.

#### 6.3.3 Signed alerts and the batch ring

`MonitorAlert` fields: `code`, `peer` (IPv4 + port), `timestamp_ns`, `packet_digest` (SHA-256 of the
inspected window), `signature` (ML-DSA-65 over `alert_payload(...)`: domain string
`"monitor/v1\n\0"`, code, peer, timestamp, digest). Alerts go into a fixed-capacity
`MonitorAlertRing` (`VecDeque`, capacity 64) that counts and exposes drops instead of growing.

`MultishotVerifyRing` is a 64-slot slab of `MAX_PACKET_BYTES = 1500`. `submit_burst` copies and
length-checks datagrams; `flush_and_verify_batch` runs `verify_inclusion` for every queued item against
the tree root and returns `BatchVerifyStats { submitted, verified, failed, first_failure_index }`.

#### 6.3.4 Platform split

`parse_quic_initial_256b`, the policy engine, the ring and the batch verifier compile and test on every
host (Windows, Linux, macOS) — that is where 100 % of the unit tests and chaos runs execute.
`kernel::linux` (TC/XDP program metadata plus `bpftool prog load` / `bpftool net attach` sequencing)
is gated behind `#[cfg(target_os = "linux")]`; `kernel::userspace_emulator` runs the identical
policy pipeline over a userspace ring everywhere else, so the simulator exercises production logic
rather than a re-implementation.

---

## 7. Flow 6 — Seed-Deterministic Virtual Chaos and 5-Layer Profiling

### 7.1 WHAT happens

`chronos-sim` seeds one `ChaCha8Rng` and runs four protocol stacks — `ClassicalQuic`, `NaivePqcQuic`,
`DraftMtcQuic`, `ChronosMtc` — across an identical Gilbert-Elliott burst-loss trajectory, recording
five latency layers and exporting percentiles plus Glass's Δ.

### 7.2 WHY it happens

Wall-clock sockets and `tc netem` make a 1-in-4,000 reordering defect unreproducible (Post-Mortem 2).
A single 64-bit seed drives every drop, burst transition, bit flip, reorder and fork, so any failure is
replayable in milliseconds and identical across machines.

### 7.3 HOW it happens

#### 7.3.1 Gilbert-Elliott channel

State `G ⇄ B` with `P(G→B) = p`, `P(B→G) = r`; steady-state burst probability
`π_B = p / (p + r)`. Packets drop with probability `1 - k` in `G` (`k = 1.0`, no isolated loss) and
`1 - h` in `B`. Targets map to parameters as `π_B = min(target / (1 - h), 0.9)`,
`p = π_B · r / (1 - π_B)`, with `r = 0.25` (mean burst 4 packets) and `h = 0.4`:

| Target loss | `π_B` | `p` |
|---|---|---|
| 1 % | 0.016667 | 0.004232 |
| 3 % | 0.050000 | 0.013158 |
| 5 % | 0.083333 | 0.022727 |

Fault injectors layered on the same RNG stream: MTU blackhole (datagram > 1,200 B ⇒ dropped),
CRC-detectable bit flips, seeded adjacent-pair reordering, and split-view witness forks (a cosigner
emitting a second, conflicting signature for the same subtree ⇒ `DuplicateCosignerId`).

#### 7.3.2 Deterministic virtual cost model

Wall-clock timing is deliberately excluded from the exported metrics (it is not bit-exact); each
operation contributes a calibrated constant in nanoseconds, and the simulator *still* executes the real
computation (real SHA-256, real CRCs, real RS coding) for correctness:

| Layer | Contents | Constants (ns) |
|---|---|---|
| L1 `InitAndKeyShare` | X25519MLKEM768 keygen, trust-anchor encode | keygen 37,000; TA encode 700 |
| L2 `ServerFlightAndFec` | budget plan, skip-link lookup, encaps, MTC build, RS encode | plan 1,200; hop 3,000; encaps 22,000; proof build 1,800; RS 3,200/shard |
| L3 `NetworkTransportAndRtt` | RTT/2 per direction, drops, PTO backoff, FEC recovery, amp stalls | RTT 1,000,000; PTO 3,000,000 (doubling) |
| L4 `ClientFecDecodeAndMtcVerify` | RS decode, consistency chain, 1 × ML-DSA-65 verify | RS decode 3,800/shard; hop verify 4,000; DSA verify 42,000 |
| L5 `EbpfGuardAndAlert` | per-packet 256-byte classification + policy lookup | classify 380; policy 500 |

#### 7.3.3 Stack geometry

| Stack | Server Flight 1 | Packets | FEC | Skip-links |
|---|---|---|---|---|
| `ClassicalQuic` | 1,850 B (X25519 + ECDSA P-256 chain) | 2 | none | none |
| `NaivePqcQuic` | 11,400 B (full ML-DSA-65 chain + 2 SCTs) | 10 | none | none |
| `DraftMtcQuic` | 8,200 B Standalone MTC | 7 | none | none |
| `ChronosMtc` | `1240 + 736 + hops·40`, ≤ 3,600 B | `k + r` | RS `(k, r)` | yes |

`NaivePqcQuic` and `DraftMtcQuic` exceed the 3,600 B cap on first contact: only the first 3 datagrams
leave before the client ACKs and the address is validated — the amplification stall the benchmark is
built to expose. With FEC stacks, `losses <= r` costs zero extra RTT (recovered in place) and emits a
`FEC_RECOVERED` signal; otherwise a PTO with exponential backoff is charged.

#### 7.3.4 Statistics

Percentiles use the **nearest-rank** definition on the ascending sample: `p(q) = x[ceil(q·n) - 1]`
(clamped to `[1, n]`), so every reported value is an observed sample. Standard deviation is the sample
form (denominator `n - 1`). Glass's Δ:

$$\Delta = \frac{\mu_{target} - \mu_{control}}{\sigma_{control}}, \qquad \sigma_{control} = \sqrt{\frac{1}{N-1}\sum_{i=1}^{N}(x_{i,control} - \mu_{control})^2}$$

`Δ < 0.8` small, `≈ 1.0` medium, `≈ 1.8` large. With `σ_control = 0` the effect size is reported as
`None` rather than an infinity.

#### 7.3.5 CLI surface

```text
chronos verify-vectors                                            # replay vectors/ietf_mtc_appendix_c.json
chronos sim --seed 0x9F4A2C01 --loss 0.03 --stale-landmarks 10000 # chaos trace + attack + regression
chronos bench --runs 1000 --seed 0x9F4A2C01 --export-dir artifacts # 4x4 seed matrix, JSON + CSV + scorecard
```

`--seed` accepts decimal or `0x`-prefixed hex and defaults to `0x9F4A2C01`. `bench` writes
`artifacts/benchmark_summary.json`, `artifacts/benchmark_matrix.csv` and a Markdown scorecard; reruns
with the same seed produce byte-identical files.

---

## 8. Cross-Subsystem Invariants

1. **Zero allocation on the hash path.** `hash_tbs_certificate_streaming`, `subtree_hash`,
   `find_subtrees`, `inclusion_proof`, `verify_inclusion` and every varint/TLV parser operate on
   borrowed slices and fixed `[u8; 32]` arrays.
2. **Canonical ordering everywhere.** Cosigners sort by `(len, bytes)`; Merkle siblings are placed by
   uint48 index; proof sets are consumed hop-by-hop in ascending landmark order. Nothing depends on
   arrival order.
3. **Fails closed.** Unaligned ranges, BER malleability, duplicate cosigners, landmark rollback,
   non-monotonic trees, serial overflow, CRC mismatch, stale/mismatched trust anchors and unverified
   downgrades are all hard errors or drops — never fallbacks.
4. **Budgets are enforced, not assumed.** `Flight1Plan::fits_in_credit()` is asserted by tests for
   every mode and every loss band.
5. **Determinism is testable.** `chaos::replay_is_bit_exact` re-runs a seeded scenario twice and compares
   serialized reports byte-for-byte.
