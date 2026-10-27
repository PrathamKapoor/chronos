//! Base-128 relative-OID trust anchor negotiation (`draft-ietf-tls-trust-anchor-ids-06` §5.3.1).
//!
//! A client advertises the newest landmark it already trusts as a compact range
//! `caID.2.N.{L-}` inside the `trust_anchors` (`0x003b`) ClientHello extension. Arcs are base-128
//! with a continuation bit, and a trailing bare `0x80` is the *open-ended* infinity marker — not a
//! truncated varint, which is exactly what my first decoder got wrong (ADR-007).

use super::error::{MtcError, MtcResult};
use serde::{Deserialize, Serialize};

/// `trust_anchors` ClientHello extension type.
pub const TRUST_ANCHORS_EXTENSION_TYPE: u16 = 0x003b;

/// Arc that marks an MTC landmark assertion (`caID.2.N.{L-}`).
pub const TRUST_ANCHOR_LANDMARK_ARC: u64 = 2;

/// Bare trailing `0x80` that turns a closed range into `{L-}` (at least L).
pub const BASE128_INFINITY_MARKER: u8 = 0x80;

/// Encodes one arc as big-endian base-128 (bits 6..0 value, bit 7 continuation).
pub fn encode_base128_arc(value: u64, out: &mut Vec<u8>) {
    let mut septets = [0u8; 10];
    let mut count = 0usize;
    let mut remaining = value;
    loop {
        septets[count] = (remaining & 0x7F) as u8;
        count += 1;
        remaining >>= 7;
        if remaining == 0 {
            break;
        }
    }
    for (index, septet) in septets[..count].iter().rev().enumerate() {
        let last = index + 1 == count;
        out.push(if last { *septet } else { septet | 0x80 });
    }
}

/// Decodes one arc, returning `(value, bytes_consumed)`.
///
/// A lone `0x80`, or any arc whose continuation bit is set at the end of the slice, is malformed
/// here; [`TrustAnchorPattern::parse_wire`] is the layer that recognises the infinity marker.
pub fn decode_base128_arc(slice: &[u8]) -> MtcResult<(u64, usize)> {
    let mut value = 0u64;
    let mut consumed = 0usize;

    for byte in slice {
        if consumed >= 10 {
            return Err(MtcError::Base128Overflow);
        }
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add((*byte & 0x7F) as u64))
            .ok_or(MtcError::Base128Overflow)?;
        consumed += 1;
        if byte & 0x80 == 0 {
            return Ok((value, consumed));
        }
    }

    Err(MtcError::MalformedBase128 { offset: 0 })
}

/// Whether the range is closed or open-ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LandmarkRange {
    /// Exactly landmark `L`.
    Exact(u64),
    /// Landmark `L` or newer (`{L-}`).
    AtLeast(u64),
}

impl LandmarkRange {
    /// Tests a candidate landmark id against this range.
    pub fn matches(&self, landmark_id: u64) -> bool {
        match self {
            Self::Exact(l) => landmark_id == *l,
            Self::AtLeast(l) => landmark_id >= *l,
        }
    }
}

/// A parsed `caID.2.N.{L-}` trust anchor landmark assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchorPattern {
    /// Trust anchor identifier (first relative arc).
    pub ca_id: u64,
    /// Log number (third relative arc).
    pub log_number: u64,
    /// Landmark range (fourth relative arc, plus optional infinity marker).
    pub landmark: LandmarkRange,
}

impl TrustAnchorPattern {
    /// Parses the relative-OID body of a `trust_anchors` extension entry.
    pub fn parse_wire(bytes: &[u8]) -> MtcResult<Self> {
        let mut arcs: Vec<u64> = Vec::new();
        let mut pos = 0usize;
        let mut unbounded = false;

        while pos < bytes.len() {
            if bytes.len() - pos == 1 && bytes[pos] == BASE128_INFINITY_MARKER {
                unbounded = true;
                break;
            }
            let (value, consumed) = match decode_base128_arc(&bytes[pos..]) {
                Ok(pair) => pair,
                Err(MtcError::MalformedBase128 { .. }) => {
                    return Err(MtcError::MalformedBase128 { offset: pos })
                }
                Err(other) => return Err(other),
            };
            arcs.push(value);
            pos += consumed;
        }

        if unbounded && bytes.last() != Some(&BASE128_INFINITY_MARKER) {
            return Err(MtcError::InvalidTrustAnchorPattern(
                "infinity marker must terminate the encoding".into(),
            ));
        }
        if arcs.len() != 4 {
            return Err(MtcError::InvalidTrustAnchorPattern(format!(
                "expected caID.2.N.{{L-}} (4 arcs), found {}",
                arcs.len()
            )));
        }
        if arcs[1] != TRUST_ANCHOR_LANDMARK_ARC {
            return Err(MtcError::InvalidTrustAnchorPattern(format!(
                "arc 2 must be {TRUST_ANCHOR_LANDMARK_ARC}, found {}",
                arcs[1]
            )));
        }

        let landmark = if unbounded {
            LandmarkRange::AtLeast(arcs[3])
        } else {
            LandmarkRange::Exact(arcs[3])
        };

        Ok(Self {
            ca_id: arcs[0],
            log_number: arcs[2],
            landmark,
        })
    }

    /// Canonical encoding of this pattern.
    pub fn encode(&self) -> Vec<u8> {
        let landmark = match self.landmark {
            LandmarkRange::Exact(l) | LandmarkRange::AtLeast(l) => l,
        };
        let unbounded = matches!(self.landmark, LandmarkRange::AtLeast(_));

        let mut out = Vec::with_capacity(8);
        encode_base128_arc(self.ca_id, &mut out);
        encode_base128_arc(TRUST_ANCHOR_LANDMARK_ARC, &mut out);
        encode_base128_arc(self.log_number, &mut out);
        encode_base128_arc(landmark, &mut out);
        if unbounded {
            out.push(BASE128_INFINITY_MARKER);
        }
        out
    }

    /// Size of the encoded extension body in bytes.
    pub fn body_len(&self) -> usize {
        self.encode().len()
    }

    /// Matches a candidate `(ca_id, log_number, landmark)` triple.
    ///
    /// `ca_id` arrives as the sequence of relative arcs the peer presented; this pattern only
    /// speaks for a single-arc identifier, so anything else is a deliberate mismatch.
    pub fn matches(&self, ca_id: &[u64], log_number: u64, landmark_id: u64) -> bool {
        ca_id.len() == 1
            && ca_id[0] == self.ca_id
            && log_number == self.log_number
            && self.landmark.matches(landmark_id)
    }
}

/// Encodes `caID.2.N.{L-}` directly, optionally open-ended.
pub fn encode_landmark_pattern(
    ca_id: u64,
    log_number: u64,
    landmark: u64,
    unbounded: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_base128_arc(ca_id, &mut out);
    encode_base128_arc(TRUST_ANCHOR_LANDMARK_ARC, &mut out);
    encode_base128_arc(log_number, &mut out);
    encode_base128_arc(landmark, &mut out);
    if unbounded {
        out.push(BASE128_INFINITY_MARKER);
    }
    out
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::*;

    #[test]
    fn arc_encoding_is_big_endian_base_128() {
        let mut out = Vec::new();
        encode_base128_arc(0, &mut out);
        assert_eq!(out, vec![0x00]);

        out.clear();
        encode_base128_arc(127, &mut out);
        assert_eq!(out, vec![0x7F]);

        out.clear();
        encode_base128_arc(128, &mut out);
        assert_eq!(out, vec![0x81, 0x00]);

        out.clear();
        encode_base128_arc(16_383, &mut out);
        assert_eq!(out, vec![0xFF, 0x7F]);

        out.clear();
        encode_base128_arc(16_384, &mut out);
        assert_eq!(out, vec![0x81, 0x80, 0x00]);
    }

    #[test]
    fn arc_decoding_roundtrips_and_rejects_dangling_flags() {
        for value in [
            0u64,
            1,
            127,
            128,
            255,
            16_383,
            16_384,
            65_535,
            1 << 40,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            encode_base128_arc(value, &mut buf);
            let (decoded, consumed) = decode_base128_arc(&buf).unwrap();
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(consumed, buf.len());
        }

        // Dangling continuation bit.
        assert!(matches!(
            decode_base128_arc(&[0x81]),
            Err(MtcError::MalformedBase128 { .. })
        ));
        // Bare infinity marker is not an arc.
        assert!(matches!(
            decode_base128_arc(&[0x80]),
            Err(MtcError::MalformedBase128 { .. })
        ));
        // 11 continuation bytes overflow the 64-bit space.
        assert_eq!(
            decode_base128_arc(&[0xFF; 11]),
            Err(MtcError::Base128Overflow)
        );
    }

    #[test]
    fn pattern_roundtrip_closed_and_open_ended() {
        let closed = encode_landmark_pattern(9, 4_500, 4_500, false);
        let parsed = TrustAnchorPattern::parse_wire(&closed).unwrap();
        assert_eq!(parsed.ca_id, 9);
        assert_eq!(parsed.log_number, 4_500);
        assert_eq!(parsed.landmark, LandmarkRange::Exact(4_500));
        assert_eq!(parsed.encode(), closed);

        let open = encode_landmark_pattern(9, 4_500, 4_500, true);
        let parsed_open = TrustAnchorPattern::parse_wire(&open).unwrap();
        assert_eq!(parsed_open.landmark, LandmarkRange::AtLeast(4_500));
        assert_eq!(parsed_open.encode(), open);
        assert_eq!(*open.last().unwrap(), BASE128_INFINITY_MARKER);
    }

    #[test]
    fn clienthello_overhead_stays_under_twelve_bytes() {
        let body = encode_landmark_pattern(1, 45, 4_500, true);
        assert!(
            body.len() <= 12,
            "trust anchor body grew to {} bytes",
            body.len()
        );
    }

    #[test]
    fn matching_semantics() {
        let fresh = TrustAnchorPattern {
            ca_id: 7,
            log_number: 45,
            landmark: LandmarkRange::Exact(4_500),
        };
        assert!(fresh.matches(&[7], 45, 4_500));
        assert!(!fresh.matches(&[7], 45, 4_501));
        assert!(!fresh.matches(&[8], 45, 4_500), "wrong CA must not match");
        assert!(!fresh.matches(&[7], 46, 4_500), "wrong log must not match");
        assert!(
            !fresh.matches(&[7, 1], 45, 4_500),
            "multi-arc CA must not match"
        );

        let stale = TrustAnchorPattern {
            ca_id: 7,
            log_number: 45,
            landmark: LandmarkRange::AtLeast(4_500),
        };
        assert!(stale.matches(&[7], 45, 4_500));
        assert!(stale.matches(&[7], 45, 87_600));
        assert!(!stale.matches(&[7], 45, 4_499));
    }

    #[test]
    fn parse_rejects_wrong_shapes() {
        // Too few arcs.
        assert!(matches!(
            TrustAnchorPattern::parse_wire(&encode_base128_arc_and(&[1, 2, 3])),
            Err(MtcError::InvalidTrustAnchorPattern(_))
        ));
        // Wrong landmark arc.
        let mut body = Vec::new();
        encode_base128_arc(1, &mut body);
        encode_base128_arc(3, &mut body);
        encode_base128_arc(45, &mut body);
        encode_base128_arc(4_500, &mut body);
        assert!(matches!(
            TrustAnchorPattern::parse_wire(&body),
            Err(MtcError::InvalidTrustAnchorPattern(_))
        ));
        // Truncated arc.
        assert!(matches!(
            TrustAnchorPattern::parse_wire(&[0x01, 0x02, 0x81]),
            Err(MtcError::MalformedBase128 { .. })
        ));
        // Empty body.
        assert!(TrustAnchorPattern::parse_wire(&[]).is_err());
    }

    fn encode_base128_arc_and(values: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        for value in values {
            encode_base128_arc(*value, &mut out);
        }
        out
    }
}
