#!/usr/bin/env python3
"""Generate ChronosMTC golden test vectors.

This is an *independent* implementation of the normative algorithms, written from
IETF draft-ietf-plants-merkle-tree-certs-07 (and draft-ietf-tls-trust-anchor-ids-06 for the
base-128 pattern encoding). It exists so that `vectors/ietf_mtc_appendix_c.json` is a
cross-implementation check of the Rust code rather than a snapshot of the Rust code's own output.

Usage:  python tools/gen_vectors.py > vectors/ietf_mtc_appendix_c.json

Algorithms implemented here (draft sections in brackets):
  * MTH / subtree validity            [4.1]
  * subtree inclusion proofs          [4.3]
  * subtree consistency proofs        [4.4]
  * two-subtree covering of intervals [4.5.1]
  * CosignedSubtree / MTCProof TLS encodings  [5.3.1, 6.2]
  * trust anchor ID patterns (base-128 min/max pairs)  [trust-anchor-ids 5.3.1]
  * canonical DER guard + streaming TBSCertificate leaf hash  [12.6]
"""

import hashlib
import json
import sys

# --------------------------------------------------------------------------------------
# Merkle tree primitives [4.1]
# --------------------------------------------------------------------------------------

MTC_LEAF_PREFIX = 0x00
MTC_NODE_PREFIX = 0x01


def sha256(*chunks: bytes) -> bytes:
    hasher = hashlib.sha256()
    for chunk in chunks:
        hasher.update(chunk)
    return hasher.digest()


def leaf_hash(entry: bytes) -> bytes:
    return sha256(bytes([MTC_LEAF_PREFIX]), entry)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(bytes([MTC_NODE_PREFIX]), left, right)


def bit_ceil(x: int) -> int:
    return 1 << max(0, (x - 1)).bit_length() if x > 1 else 1


def is_valid_subtree(start: int, end: int) -> bool:
    """[4.1] start must be a multiple of BIT_CEIL(end - start)."""
    if start > end:
        return False
    size = end - start
    if size > (1 << 63):
        return start == 0
    return (start & (bit_ceil(size) - 1)) == 0


def build_tree(size: int) -> list[bytes]:
    """Draft Appendix C tree: d[i] = i as a single byte."""
    return [leaf_hash(bytes([i])) for i in range(size)]


def subtree_hash(leaves: list[bytes], start: int, end: int) -> bytes:
    """MTH(D[start:end]); the empty subtree hashes the empty string [4.4.3]."""
    if start == end:
        return hashlib.sha256().digest()
    size = end - start
    if size == 1:
        return leaves[start]
    k = 1 << ((size - 1).bit_length() - 1)
    return node_hash(
        subtree_hash(leaves, start, start + k), subtree_hash(leaves, start + k, end)
    )


def inclusion_proof(leaves: list[bytes], start: int, end: int, index: int) -> list[bytes]:
    """PATH(index - start, D[start:end]) [4.3]; sibling hashes bottom-up."""

    def path(a: int, n: int, m: int, out: list[bytes]) -> None:
        if n == 1:
            return
        k = 1 << ((n - 1).bit_length() - 1)
        if m < k:
            path(a, k, m, out)
            out.append(subtree_hash(leaves, a + k, a + n))
        else:
            path(a + k, n - k, m - k, out)
            out.append(subtree_hash(leaves, a, a + k))

    proof: list[bytes] = []
    path(start, end - start, index - start, proof)
    return proof


def consistency_proof(leaves: list[bytes], start: int, end: int, n: int) -> list[bytes]:
    """SUBTREE_PROOF(start, end, D_n) [4.4.1]."""
    if start == end:
        return []
    proof: list[bytes] = []
    _subproof(leaves, 0, start, end, n, True, proof)
    return proof


def _subproof(
    leaves: list[bytes], a: int, start: int, end: int, n: int, omit_first: bool, out: list[bytes]
) -> None:
    if start == 0 and end == n:
        if not omit_first:
            out.append(subtree_hash(leaves, a, a + n))
        return
    k = 1 << ((n - 1).bit_length() - 1)
    if end <= k:
        _subproof(leaves, a, start, end, k, omit_first, out)
        out.append(subtree_hash(leaves, a + k, a + n))
    elif k <= start:
        _subproof(leaves, a + k, start - k, end - k, n - k, omit_first, out)
        out.append(subtree_hash(leaves, a, a + k))
    else:
        _subproof(leaves, a + k, 0, end - k, n - k, False, out)
        out.append(subtree_hash(leaves, a, a + k))


def covering_subtrees(start: int, end: int) -> tuple[int, int, int, int]:
    """Two subtrees covering [start, end) [4.5.1]."""
    if end - start <= 1:
        return start, end, end, end
    last = end - 1
    split = (start ^ last).bit_length() - 1
    mid = last & ~((1 << split) - 1)
    left_split = 0
    for bit in range(split):
        if (start >> bit) & 1 == 0:
            left_split = bit + 1
    left_start = start & ~((1 << left_split) - 1)
    return left_start, mid, mid, end


# --------------------------------------------------------------------------------------
# Draft Appendix C accumulated vectors (published values, for cross-checking)
# --------------------------------------------------------------------------------------

APPENDIX_C_ACCUMULATED = {
    "subtree_hashes": "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81",
    "inclusion_proofs": "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f",
    "consistency_proofs": "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74",
    "covering_subtrees": "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0",
}


def verify_accumulated() -> None:
    """Recompute the draft's own accumulated hashes to prove this generator agrees."""
    size = 130
    leaves = build_tree(size)

    rolling = hashlib.sha256()
    for end in range(0, size + 1):
        for start in range(end + 1):
            if is_valid_subtree(start, end):
                h = subtree_hash(leaves, start, end).hex()
                rolling.update(f"[{start}, {end}) {h}\n".encode())
    assert rolling.hexdigest() == APPENDIX_C_ACCUMULATED["subtree_hashes"], "C.1.1"

    rolling = hashlib.sha256()
    for end in range(0, size + 1):
        for start in range(end + 1):
            if not is_valid_subtree(start, end):
                continue
            for index in range(start, end):
                line = f"{index} [{start}, {end})"
                for p in inclusion_proof(leaves, start, end, index):
                    line += f" {p.hex()}"
                rolling.update(f"{line}\n".encode())
    assert rolling.hexdigest() == APPENDIX_C_ACCUMULATED["inclusion_proofs"], "C.1.2"

    rolling = hashlib.sha256()
    for n in range(0, size + 1):
        for end in range(0, n + 1):
            for start in range(end + 1):
                if not is_valid_subtree(start, end):
                    continue
                line = f"[{start}, {end}) {n}"
                for p in consistency_proof(leaves, start, end, n):
                    line += f" {p.hex()}"
                rolling.update(f"{line}\n".encode())
    assert rolling.hexdigest() == APPENDIX_C_ACCUMULATED["consistency_proofs"], "C.1.3"

    rolling = hashlib.sha256()
    for end in range(0, size + 1):
        for start in range(end + 1):
            ls, le, rs, re = covering_subtrees(start, end)
            rolling.update(f"[{ls}, {le}) [{rs}, {re})\n".encode())
    assert rolling.hexdigest() == APPENDIX_C_ACCUMULATED["covering_subtrees"], "C.1.4"


# --------------------------------------------------------------------------------------
# DER guard and streaming TBSCertificate leaf hash [7.2, 12.6]
# --------------------------------------------------------------------------------------

SCT_OID = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02])


def encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_der_length(len(content)) + content


def der_header_canonical(raw: bytes) -> bool:
    """Header rules only: the declared content length must fit inside `raw`."""
    if len(raw) < 2:
        return False
    length_byte = raw[1]
    if length_byte == 0x80:
        return False
    if length_byte & 0x80 == 0:
        return len(raw) >= 2 + length_byte
    count = length_byte & 0x7F
    if count == 0 or count > 4 or len(raw) < 2 + count:
        return False
    if raw[2] == 0x00:
        return False
    value = int.from_bytes(raw[2 : 2 + count], "big")
    if value < 128:
        return False
    return len(raw) >= 2 + count + value


def der_is_canonical(raw: bytes) -> bool:
    if not der_header_canonical(raw):
        return False
    header = _header_len(raw)
    length = raw[1] if raw[1] < 0x80 else int.from_bytes(raw[2:header], "big")
    return len(raw) == header + length


def der_extension(oid: bytes, critical: bool, value: bytes) -> bytes:
    content = der_tlv(0x06, oid)
    if critical:
        content += der_tlv(0x01, b"\xff")
    content += der_tlv(0x04, value)
    return der_tlv(0x30, content)


def der_extensions(extensions: list[bytes]) -> bytes:
    return der_tlv(0x30, b"".join(extensions))


def strip_volatile_extensions(extensions_der: bytes) -> bytes:
    """Drop Signed Certificate Timestamp extensions, re-encoding minimally."""
    if not extensions_der:
        return b""
    assert der_is_canonical(extensions_der)
    header = _header_len(extensions_der)
    body = extensions_der[header:]
    kept = b""
    cursor = 0
    while cursor < len(body):
        child, consumed = _take_tlv(body[cursor:])
        if not _is_sct(child):
            kept += body[cursor : cursor + consumed]
        cursor += consumed
    return der_tlv(0x30, kept) if kept else b""


def _header_len(raw: bytes) -> int:
    length_byte = raw[1]
    if length_byte & 0x80 == 0:
        return 2
    return 2 + (length_byte & 0x7F)


def _content(raw: bytes) -> bytes:
    header = _header_len(raw)
    length = raw[1] if raw[1] < 0x80 else int.from_bytes(raw[2:header], "big")
    return raw[header : header + length]


def _take_tlv(raw: bytes) -> tuple[bytes, int]:
    assert der_header_canonical(raw)
    header = _header_len(raw)
    length = raw[1] if raw[1] < 0x80 else int.from_bytes(raw[2:header], "big")
    return raw[: header + length], header + length


def _is_sct(tlv: bytes) -> bool:
    if tlv[0] != 0x30:
        return False
    content = _content(tlv)
    if not content:
        return False
    inner, _ = _take_tlv(content)
    return inner[0] == 0x06 and _content(inner) == SCT_OID


def tbs_leaf_hash(fields: dict) -> bytes:
    """Streams the canonical leaf representation into SHA-256 [7.2]."""
    spki_digest = hashlib.sha256(fields["subject_public_key_info"]).digest()
    compressed_serial = ((fields["log_number"] << 48) | fields["serial_number"]).to_bytes(8, "big")
    extensions = strip_volatile_extensions(fields["extensions_der"])
    stream = (
        bytes([MTC_LEAF_PREFIX])
        + fields["version_raw"]
        + compressed_serial
        + fields["signature_alg_oid"]
        + fields["issuer_dn"]
        + fields["not_before"].to_bytes(8, "big")
        + fields["not_after"].to_bytes(8, "big")
        + fields["subject_dn"]
        + bytes([0x04, 0x20])
        + spki_digest
        + extensions
    )
    return hashlib.sha256(stream).digest()


# --------------------------------------------------------------------------------------
# CosignedSubtree / MTCProof TLS presentation language [5.3.1, 6.2]
# --------------------------------------------------------------------------------------

COSIGN_LABEL = b"subtree/v1\n\0"
TRUST_ANCHOR_PREFIX = b"oid/1.3.6.1.4.1."


def trust_anchor_id_string(trust_anchor_id: str) -> bytes:
    return TRUST_ANCHOR_PREFIX + trust_anchor_id.encode()


def opaque_u8(payload: bytes) -> bytes:
    assert 1 <= len(payload) <= 255
    return bytes([len(payload)]) + payload


def opaque_u16(payload: bytes) -> bytes:
    assert len(payload) <= 0xFFFF
    return len(payload).to_bytes(2, "big") + payload


def opaque_u24(payload: bytes) -> bytes:
    assert len(payload) <= 0xFFFFFF
    return len(payload).to_bytes(3, "big") + payload


def cosigned_subtree_bytes(
    ca_id: str, log_id: str, timestamp: int, start: int, end: int, subtree_hash: bytes
) -> bytes:
    return (
        COSIGN_LABEL
        + opaque_u8(trust_anchor_id_string(ca_id))
        + timestamp.to_bytes(8, "big")
        + opaque_u8(trust_anchor_id_string(log_id))
        + start.to_bytes(8, "big")
        + end.to_bytes(8, "big")
        + subtree_hash
    )


def mtc_proof_bytes(
    extensions: bytes, start: int, end: int, inclusion_proof_hashes: list[bytes], signatures: list[tuple[bytes, bytes]]
) -> bytes:
    signature_block = b""
    for cosigner_id, signature in signatures:
        assert 1 <= len(cosigner_id) <= 255 and len(signature) <= 0xFFFF
        signature_block += opaque_u8(cosigner_id) + opaque_u16(signature)
    return (
        opaque_u16(extensions)
        + start.to_bytes(8, "big")[2:]
        + end.to_bytes(8, "big")[2:]
        + opaque_u16(b"".join(inclusion_proof_hashes))
        + opaque_u24(signature_block)
    )


# --------------------------------------------------------------------------------------
# Trust anchor ID patterns (base-128 min/max pairs) [draft-ietf-tls-trust-anchor-ids-06 5.3.1]
# --------------------------------------------------------------------------------------


def encode_base128(value: int) -> bytes:
    digits = []
    remaining = value
    while True:
        digits.append(remaining & 0x7F)
        remaining >>= 7
        if remaining == 0:
            break
    digits.reverse()
    out = bytearray()
    for index, digit in enumerate(digits):
        out.append(digit if index + 1 == len(digits) else digit | 0x80)
    return bytes(out)


def encode_pattern(pairs: list[tuple[int, int | None]]) -> bytes:
    """A closed pair (min == max) encodes as a single integer; `None` max is infinity (0x80)."""
    out = b""
    for minimum, maximum in pairs:
        out += encode_base128(minimum)
        if maximum == minimum:
            continue
        out += b"\x80" if maximum is None else encode_base128(maximum)
    return out


# --------------------------------------------------------------------------------------
# Vector generation
# --------------------------------------------------------------------------------------


def hx(data: bytes) -> str:
    return data.hex()


def gen_merkle_vectors() -> dict:
    size = 130
    leaves = build_tree(size)

    subtree_cases = []
    subtree_hashes = []
    inclusion_cases = []
    consistency_cases = []

    for end in range(0, 25):
        for start in range(end + 1):
            ls, le, rs, re = covering_subtrees(start, end)
            subtree_cases.append(
                {"start": start, "end": end, "left": [ls, le], "right": [rs, re]}
            )
            if is_valid_subtree(start, end):
                subtree_hashes.append(
                    {"start": start, "end": end, "hash": hx(subtree_hash(leaves, start, end))}
                )
            if end <= 17 and is_valid_subtree(start, end):
                for index in range(start, end):
                    proof = inclusion_proof(leaves, start, end, index)
                    inclusion_cases.append(
                        {
                            "index": index,
                            "start": start,
                            "end": end,
                            "subtree_hash": hx(subtree_hash(leaves, start, end)),
                            "proof": [hx(p) for p in proof],
                        }
                    )

    for n in range(0, 19):
        for end in range(0, n + 1):
            for start in range(end + 1):
                if not is_valid_subtree(start, end):
                    continue
                consistency_cases.append(
                    {
                        "start": start,
                        "end": end,
                        "tree_size": n,
                        "subtree_hash": hx(subtree_hash(leaves, start, end)),
                        "tree_root": hx(subtree_hash(leaves, 0, n)),
                        "proof": [hx(p) for p in consistency_proof(leaves, start, end, n)],
                    }
                )

    # Larger spot checks straight out of the draft's examples.
    inclusion_cases.append(
        {
            "index": 10,
            "start": 8,
            "end": 13,
            "subtree_hash": hx(subtree_hash(leaves, 8, 13)),
            "proof": [hx(p) for p in inclusion_proof(leaves, 8, 13, 10)],
            "note": "draft section 4.3.1 worked example",
        }
    )
    consistency_cases.append(
        {
            "start": 4,
            "end": 8,
            "tree_size": 14,
            "subtree_hash": hx(subtree_hash(leaves, 4, 8)),
            "tree_root": hx(subtree_hash(leaves, 0, 14)),
            "proof": [hx(p) for p in consistency_proof(leaves, 4, 8, 14)],
            "note": "draft section 4.4.2 worked example",
        }
    )

    return {
        "draft_accumulated": APPENDIX_C_ACCUMULATED,
        "subtree_cases": subtree_cases,
        "subtree_hashes": subtree_hashes,
        "inclusion_cases": inclusion_cases,
        "consistency_cases": consistency_cases,
        "tree_roots": [
            {"size": n, "root": hx(subtree_hash(leaves, 0, n))} for n in (0, 1, 2, 8, 16, 64, 130)
        ],
    }


def gen_der_vectors() -> list:
    long_form_128 = b"\x04\x81\x80" + b"\x00" * 128
    long_form_256 = b"\x04\x82\x01\x00" + b"\x00" * 256
    return [
        {"hex": hx(b"\x04\x00"), "accept": True, "note": "empty OCTET STRING, short form"},
        {"hex": hx(b"\x04\x20" + b"\xab" * 32), "accept": True, "note": "32-byte OCTET STRING"},
        {"hex": hx(b"\x02\x01\x05"), "accept": True, "note": "INTEGER 5"},
        {"hex": hx(long_form_128), "accept": True, "note": "minimal long form for 128 bytes"},
        {"hex": hx(long_form_256), "accept": True, "note": "minimal long form for 256 bytes"},
        {"hex": hx(b"\x30\x80\x00\x00"), "accept": False, "note": "indefinite length"},
        {"hex": hx(b"\x30\x81\x7f" + b"\x00" * 127), "accept": False, "note": "non-minimal long form"},
        {"hex": hx(b"\x30\x82\x00\x80" + b"\x00" * 128), "accept": False, "note": "leading zero length"},
        {"hex": hx(b"\x30\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), "accept": False, "note": "reserved width"},
        {"hex": hx(b"\x04"), "accept": False, "note": "truncated header"},
        {"hex": hx(b"\x04\x04\x01"), "accept": False, "note": "truncated content"},
        {"hex": hx(b"\x04\x01\x01\x02"), "accept": False, "note": "trailing bytes"},
    ]


def gen_tbs_vectors() -> list:
    spki = der_tlv(0x30, der_tlv(0x03, b"\x00" + b"\x5a" * 1952))
    base_fields = {
        "version_raw": "a003020102",
        "serial_number": 42,
        "log_number": 7,
        "signature_alg_oid": "2b6570",
        "issuer_dn": "3003130141",
        "not_before": 1_700_000_000,
        "not_after": 1_900_000_000,
        "subject_dn": "3003130142",
        "subject_public_key_info": hx(spki),
        "extensions_der": "",
    }
    with_sct = dict(base_fields)
    with_sct["extensions_der"] = hx(
        der_extensions([der_extension(SCT_OID, False, b"\x04\x02\xaa\xbb")])
    )
    with_constraints = dict(base_fields)
    with_constraints["extensions_der"] = hx(
        der_extensions(
            [
                der_extension(bytes([0x55, 0x1D, 0x13]), True, b"\x30\x00"),
                der_extension(SCT_OID, False, b"\x04\x02\xaa\xbb"),
            ]
        )
    )
    different_key = dict(base_fields)
    different_key["subject_public_key_info"] = hx(der_tlv(0x30, der_tlv(0x03, b"\x00" + b"\x5b" * 1952)))

    cases = []
    for name, fields in (
        ("baseline", base_fields),
        ("with_volatile_sct", with_sct),
        ("with_sct_and_constraints", with_constraints),
        ("different_key", different_key),
    ):
        parsed = {
            **fields,
            "version_raw": bytes.fromhex(fields["version_raw"]),
            "signature_alg_oid": bytes.fromhex(fields["signature_alg_oid"]),
            "issuer_dn": bytes.fromhex(fields["issuer_dn"]),
            "subject_dn": bytes.fromhex(fields["subject_dn"]),
            "subject_public_key_info": bytes.fromhex(fields["subject_public_key_info"]),
            "extensions_der": bytes.fromhex(fields["extensions_der"]),
        }
        cases.append(
            {
                "case": name,
                "fields": fields,
                "expected_leaf_hash": hx(tbs_leaf_hash(parsed)),
            }
        )
    return cases


def gen_cosign_vectors(leaves: list[bytes]) -> list:
    root = subtree_hash(leaves, 4, 12)
    cases = [
        {
            "case": "cosigned_subtree_reference",
            "hex": hx(cosigned_subtree_bytes("32473.1", "32473.2", 0, 4, 12, root)),
        },
        {
            "case": "cosigned_subtree_timestamped",
            "hex": hx(
                cosigned_subtree_bytes("32473.1", "32473.2", 1_700_000_000, 4, 12, root)
            ),
        },
    ]
    proof_hashes = inclusion_proof(leaves, 4, 12, 5)
    signatures = [
        (bytes([0xFF]), b"\xa5" * 64),
        (bytes([0x01, 0x02]), b"\x5a" * 64),
        (bytes([0x0A, 0x0A]), b"\x00"),
    ]
    cases.append(
        {
            "case": "mtc_proof_canonical",
            "start": 4,
            "end": 12,
            "hex": hx(
                mtc_proof_bytes(
                    b"\x30\x00", 4, 12, proof_hashes, signatures
                )
            ),
        }
    )
    return cases


def gen_base128_vectors() -> list:
    cases = []
    for arcs, unbounded in (
        ([1, 2, 45, 4500], False),
        ([1, 2, 45, 4500], True),
        ([0x7FFFFFFF, 2, 1 << 40], True),
        ([32473, 1], False),
    ):
        if unbounded:
            encoded = encode_pattern([(arcs[0], None), (arcs[1], arcs[1]), (arcs[2], None)])
        else:
            encoded = encode_pattern([(arc, arc) for arc in arcs])
        cases.append({"arcs": arcs, "unbounded": unbounded, "hex": hx(encoded)})
    return cases


def main() -> None:
    verify_accumulated()
    leaves = build_tree(130)

    vectors = {
        "meta": {
            "generator": "tools/gen_vectors.py",
            "draft": "draft-ietf-plants-merkle-tree-certs-07",
            "trust_anchor_draft": "draft-ietf-tls-trust-anchor-ids-06",
            "hash": "SHA-256",
            "tree_leaf_values": "d[i] = i (single byte), per draft Appendix C",
            "note": (
                "Generated by an independent Python implementation of the draft algorithms; "
                "regenerate with: python tools/gen_vectors.py > vectors/ietf_mtc_appendix_c.json"
            ),
        },
        "merkle": gen_merkle_vectors(),
        "der_guard": gen_der_vectors(),
        "tbs_leaf_hashes": gen_tbs_vectors(),
        "cosign": gen_cosign_vectors(leaves),
        "base128_patterns": gen_base128_vectors(),
    }

    json.dump(vectors, sys.stdout, indent=1, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
