//! Bounded QUIC Initial parser: the first [`MAX_EBPF_INSPECT_BYTES`] bytes, nothing more.
//!
//! The clamp is the whole point. An eBPF program cannot loop over an attacker-controlled buffer, so
//! this parser never indexes past byte 255, never allocates proportionally to packet length, and
//! never follows a length field beyond the window it was given. Everything it returns is a *bounded
//! window* — offsets and lengths into the inspected slice — so the classification stage reads the
//! same bytes without copying them again.

use serde::{Deserialize, Serialize};

/// Hard ceiling on how many bytes the fast path may inspect.
pub const MAX_EBPF_INSPECT_BYTES: usize = 256;
/// Maximum number of CRYPTO frames recorded from one datagram.
pub const MAX_CRYPTO_WINDOWS: usize = 8;
/// Largest DCID or SCID length a QUIC connection ID may have (RFC 9000 §17.2).
pub const MAX_CONNECTION_ID_LEN: usize = 20;
/// Magic bytes of the plaintext MTC checkpoint hint (`MTC0`).
pub const MTC_HINT_MAGIC: [u8; 4] = *b"MTC0";
/// Version byte of the MTC checkpoint hint.
pub const MTC_HINT_VERSION: u8 = 0x01;
/// Size of the hint trailer appended inside the Initial CRYPTO frame.
pub const MTC_HINT_LEN: usize = 4 + 1 + 6 + 6;

/// Errors produced by the bounded parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Fewer bytes than a QUIC long header can occupy.
    #[error("datagram shorter than a QUIC long header")]
    ShortDatagram,
    /// The first byte does not have the long-header form bit set.
    #[error("not a long-header packet")]
    NotLongHeader,
    /// The fixed bit is clear.
    #[error("QUIC fixed bit is not set")]
    FixedBitClear,
    /// The packet type field is not `Initial` (`0x00`).
    #[error("packet type {0:#04x} is not Initial")]
    NotInitial(u8),
    /// A connection ID length field exceeds [`MAX_CONNECTION_ID_LEN`].
    #[error("connection ID length {0} exceeds the RFC 9000 maximum")]
    ConnectionIdTooLong(usize),
    /// A varint or field ran past the inspected window.
    #[error("field at offset {offset} runs past the inspected window")]
    OutOfWindow {
        /// Offset where the field started.
        offset: usize,
    },
    /// The Initial packet type carries a version the guard refuses to reason about.
    #[error("unsupported QUIC version {0:#010x}")]
    UnsupportedVersion(u32),
}

/// QUIC version 1 (RFC 9000).
pub const QUIC_VERSION_1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369).
pub const QUIC_VERSION_2: u32 = 0x6B33_43CF;
/// QUIC version with the IETF codepoint (RFC 8999 / draft-ietf-quic-version-negotiation).
pub const QUIC_VERSION_IETF: u32 = 0xFF00_0001;

/// Header form and packet-type field values that identify an Initial packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicInitialHeader<'a> {
    /// Negotiated (or attempted) version.
    pub version: u32,
    /// Destination connection ID, borrowed from the window.
    pub dcid: &'a [u8],
    /// Source connection ID, borrowed from the window.
    pub scid: &'a [u8],
    /// Retry token (always empty in a first-contact Initial).
    pub token: &'a [u8],
    /// Encoded packet-number length in bytes (`(first_byte & 0x03) + 1`).
    pub packet_number_len: usize,
    /// Offset of the first frame byte inside the window.
    pub frames_offset: usize,
    /// Number of bytes actually available in the window.
    pub inspected_len: usize,
    /// True when the packet was longer than the inspected window.
    pub truncated: bool,
}

/// A bounded CRYPTO frame window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoWindow {
    /// Offset of the CRYPTO payload inside the inspected window.
    pub offset: usize,
    /// Length of the CRYPTO payload that is actually present.
    pub len: usize,
    /// Offset declared by the CRYPTO frame (may point past the window).
    pub declared_offset: u64,
    /// Length declared by the CRYPTO frame (may exceed the window).
    pub declared_len: u64,
}

/// What the bounded parser produced for one datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicInitialSummary {
    /// Negotiated (or attempted) version.
    pub version: u32,
    /// Destination connection ID.
    pub dcid: Vec<u8>,
    /// Source connection ID.
    pub scid: Vec<u8>,
    /// Encoded packet-number length.
    pub packet_number_len: usize,
    /// Bounded CRYPTO frame windows.
    pub crypto_windows: Vec<CryptoWindow>,
    /// True when the datagram was longer than the inspected window.
    pub truncated: bool,
}

impl QuicInitialSummary {
    /// The plaintext MTC checkpoint hint trailer, when the client appended one.
    ///
    /// The hint is deliberately *plaintext* inside the Initial CRYPTO frame: the fast path needs to
    /// reason about certificate issuance age without decrypting TLS. Absence means "unknown", which
    /// the policy stage treats as maximally recent.
    pub fn checkpoint_hint(&self, inspected: &[u8]) -> Option<MtcCheckpointHint> {
        for window in &self.crypto_windows {
            let end = (window.offset + window.len).min(inspected.len());
            let bytes = &inspected[window.offset.min(end)..end];
            if bytes.len() < MTC_HINT_LEN {
                continue;
            }
            let tail = &bytes[bytes.len() - MTC_HINT_LEN..];
            if tail[..4] != MTC_HINT_MAGIC || tail[4] != MTC_HINT_VERSION {
                continue;
            }
            return Some(MtcCheckpointHint {
                serial: read_uint48(&tail[5..11]),
                issuance_timestamp: read_uint48(&tail[11..17]),
            });
        }
        None
    }
}

/// The plaintext checkpoint hint a ChronosMTC client appends to its Initial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtcCheckpointHint {
    /// 48-bit compressed serial (`(log_number << 48) | index`).
    pub serial: u64,
    /// 48-bit issuance timestamp in microseconds since the Unix epoch.
    pub issuance_timestamp: u64,
}

/// Reads a 6-byte big-endian integer (RFC 8999 `uint48`).
pub fn read_uint48(bytes: &[u8]) -> u64 {
    let mut buffer = [0u8; 8];
    buffer[2..].copy_from_slice(&bytes[..6]);
    u64::from_be_bytes(buffer)
}

/// Parses a QUIC varint from the window, returning `(value, bytes_consumed)`.
///
/// `limit` is the hard boundary; a varint that would cross it is an error rather than a read.
fn read_varint(
    window: &[u8],
    cursor: &mut usize,
    limit: usize,
) -> Result<(u64, usize), ParseError> {
    let first = *window
        .get(*cursor)
        .ok_or(ParseError::OutOfWindow { offset: *cursor })?;
    let width = 1usize << (first >> 6);
    if *cursor + width > limit || *cursor + width > window.len() {
        return Err(ParseError::OutOfWindow { offset: *cursor });
    }
    let mut value = u64::from(first & 0x3F);
    for byte in &window[*cursor + 1..*cursor + width] {
        value = (value << 8) | u64::from(*byte);
    }
    *cursor += width;
    Ok((value, width))
}

/// Parses the bounded view of a QUIC Initial datagram.
///
/// Only the first [`MAX_EBPF_INSPECT_BYTES`] bytes are read. Frames are walked until the window ends
/// or [`MAX_CRYPTO_WINDOWS`] CRYPTO windows have been recorded; unknown frame types are skipped
/// using their type-specific length rules, so one exotic frame cannot desynchronize the walk.
pub fn parse_quic_initial_256b(datagram: &[u8]) -> Result<QuicInitialSummary, ParseError> {
    if datagram.len() < 7 {
        return Err(ParseError::ShortDatagram);
    }
    let limit = datagram.len().min(MAX_EBPF_INSPECT_BYTES);
    let window = &datagram[..limit];
    let first = window[0];
    if first & 0x80 == 0 {
        return Err(ParseError::NotLongHeader);
    }
    if first & 0x40 == 0 {
        return Err(ParseError::FixedBitClear);
    }
    let packet_type = (first & 0x30) >> 4;
    if packet_type != 0x00 {
        return Err(ParseError::NotInitial(packet_type));
    }

    let version = u32::from_be_bytes([window[1], window[2], window[3], window[4]]);
    let mut cursor = 5usize;

    let dcid_len = *window
        .get(cursor)
        .ok_or(ParseError::OutOfWindow { offset: cursor })? as usize;
    cursor += 1;
    if dcid_len > MAX_CONNECTION_ID_LEN {
        return Err(ParseError::ConnectionIdTooLong(dcid_len));
    }
    let dcid_end = cursor + dcid_len;
    let dcid = window
        .get(cursor..dcid_end)
        .ok_or(ParseError::OutOfWindow { offset: cursor })?;
    cursor = dcid_end;

    let scid_len = *window
        .get(cursor)
        .ok_or(ParseError::OutOfWindow { offset: cursor })? as usize;
    cursor += 1;
    if scid_len > MAX_CONNECTION_ID_LEN {
        return Err(ParseError::ConnectionIdTooLong(scid_len));
    }
    let scid_end = cursor + scid_len;
    let scid = window
        .get(cursor..scid_end)
        .ok_or(ParseError::OutOfWindow { offset: cursor })?;
    cursor = scid_end;

    // Initial packets carry a token before the length field (RFC 9000 §17.2.2). The token bytes are
    // skipped rather than copied: the fast path never inspects them, and a Retry token can be up to
    // 1,500 bytes, which a 256-byte window could not contain anyway.
    let (token_len, _) = read_varint(window, &mut cursor, limit)?;
    let token_end = cursor
        .checked_add(token_len as usize)
        .ok_or(ParseError::OutOfWindow { offset: cursor })?;
    if token_end > limit {
        return Err(ParseError::OutOfWindow { offset: cursor });
    }
    cursor = token_end;

    // The Length field covers packet number + payload; skip it and decode the packet number.
    let (_protected_len, _) = read_varint(window, &mut cursor, limit)?;
    let packet_number_len = (first & 0x03) as usize + 1;
    cursor = cursor.saturating_add(packet_number_len).min(limit);

    let mut crypto_windows = Vec::new();
    while cursor < limit && crypto_windows.len() < MAX_CRYPTO_WINDOWS {
        match walk_frame(window, &mut cursor, limit, &mut crypto_windows)? {
            FrameWalk::Continue => {}
            FrameWalk::Stop => break,
        }
    }

    Ok(QuicInitialSummary {
        version,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        packet_number_len,
        crypto_windows,
        truncated: datagram.len() > limit,
    })
}

/// Whether the frame walk should continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameWalk {
    /// The cursor advanced and the walk may continue.
    Continue,
    /// The window ended or padding was reached.
    Stop,
}

/// Advances one frame, recording CRYPTO windows as bounded `(offset, len)` pairs.
fn walk_frame(
    window: &[u8],
    cursor: &mut usize,
    limit: usize,
    crypto_windows: &mut Vec<CryptoWindow>,
) -> Result<FrameWalk, ParseError> {
    let frame_start = *cursor;
    let frame_type = *window.get(frame_start).ok_or(ParseError::OutOfWindow {
        offset: frame_start,
    })?;
    *cursor += 1;

    match frame_type {
        0x00 => {
            // PADDING: a run of zero bytes; stop the walk, the rest is padding.
            Ok(FrameWalk::Stop)
        }
        0x06 => {
            // CRYPTO: offset, length, payload.
            let (declared_offset, _) = read_varint(window, cursor, limit)?;
            let (declared_len, _) = read_varint(window, cursor, limit)?;
            let payload_start = *cursor;
            let available = limit.saturating_sub(payload_start);
            let len = (declared_len as usize).min(available);
            *cursor = payload_start + len;
            crypto_windows.push(CryptoWindow {
                offset: payload_start,
                len,
                declared_offset,
                declared_len,
            });
            Ok(FrameWalk::Continue)
        }
        0x01..=0x03 => {
            // PING / ACK / RESET_STREAM / STOP_SENDING: consume the remaining window; the fast path
            // does not need their contents, and guessing a wrong length could desynchronize the
            // walk, so the conservative choice is to stop.
            Ok(FrameWalk::Stop)
        }
        _ => {
            let (length, _) = read_varint(window, cursor, limit)?;
            let end = (*cursor as u64)
                .checked_add(length)
                .ok_or(ParseError::OutOfWindow { offset: *cursor })?;
            if end > limit as u64 {
                return Ok(FrameWalk::Stop);
            }
            *cursor = end as usize;
            Ok(FrameWalk::Continue)
        }
    }
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::*;

    /// Builds a QUIC v1 Initial whose payload area holds the given CRYPTO frames.
    fn initial_with_crypto_frames(frames: &[&[u8]]) -> Vec<u8> {
        let mut payload_area = Vec::new();
        for payload in frames {
            payload_area.push(0x06); // CRYPTO
            payload_area.push(0x00); // offset 0
            payload_area.extend_from_slice(&((payload.len() as u16) | 0x4000).to_be_bytes());
            payload_area.extend_from_slice(payload);
        }

        let mut out = Vec::new();
        out.push(0xC0 | 0x03); // long header, Initial, 4-byte packet number
        out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        out.push(4);
        out.extend_from_slice(b"dcid");
        out.push(4);
        out.extend_from_slice(b"scid");
        out.push(0x00); // zero-length token
        let length = 4 + payload_area.len(); // packet number + frames
        out.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // packet number
        out.extend_from_slice(&payload_area);
        out
    }

    /// Builds a QUIC v1 Initial with one CRYPTO frame carrying `payload`.
    fn initial_with_crypto(payload: &[u8]) -> Vec<u8> {
        initial_with_crypto_frames(&[payload])
    }

    #[test]
    fn parses_a_well_formed_initial() {
        let datagram = initial_with_crypto(b"hello mtc");
        let summary = parse_quic_initial_256b(&datagram).unwrap();

        assert_eq!(summary.version, QUIC_VERSION_1);
        assert_eq!(summary.dcid, b"dcid");
        assert_eq!(summary.scid, b"scid");
        assert_eq!(summary.packet_number_len, 4);
        assert!(!summary.truncated);
        assert_eq!(summary.crypto_windows.len(), 1);

        let window = summary.crypto_windows[0];
        let payload = &datagram[window.offset..window.offset + window.len];
        assert_eq!(payload, b"hello mtc");
    }

    #[test]
    fn rejects_every_malformed_header_shape() {
        assert_eq!(parse_quic_initial_256b(&[]), Err(ParseError::ShortDatagram));
        assert_eq!(
            parse_quic_initial_256b(&[0x40; 8]),
            Err(ParseError::NotLongHeader)
        );
        assert_eq!(
            parse_quic_initial_256b(&[0x80, 0, 0, 0, 1, 0, 0, 0]),
            Err(ParseError::FixedBitClear)
        );
        // Packet type 0b01 = 0-RTT.
        assert_eq!(
            parse_quic_initial_256b(&[0xD0, 0, 0, 0, 1, 0, 0, 0]),
            Err(ParseError::NotInitial(1))
        );
        // DCID length 21 exceeds the RFC maximum.
        let mut datagram = vec![0xC0, 0, 0, 0, 1, 21];
        datagram.extend_from_slice(&[0u8; 21]);
        assert_eq!(
            parse_quic_initial_256b(&datagram),
            Err(ParseError::ConnectionIdTooLong(21))
        );
    }

    #[test]
    fn never_reads_past_the_256_byte_window() {
        // A CRYPTO frame that declares 4,000 bytes inside a 300-byte datagram.
        let mut datagram = initial_with_crypto(&[0x11; 8]);
        datagram.push(0x06); // CRYPTO
        datagram.push(0x00); // offset 0
        datagram.extend_from_slice(&(4_000u32 | 0x8000_0000).to_be_bytes());
        datagram.extend(std::iter::repeat_n(0x5Au8, 300));

        let summary = parse_quic_initial_256b(&datagram).expect("bounded parse");
        assert!(
            summary.truncated,
            "the datagram exceeds the 256-byte window"
        );
        assert_eq!(summary.crypto_windows.len(), 2);

        let window = summary.crypto_windows[1];
        assert_eq!(window.declared_len, 4_000);
        assert!(
            (window.len as u64) < window.declared_len,
            "the window clamps the read"
        );
        assert!(
            window.offset + window.len <= MAX_EBPF_INSPECT_BYTES,
            "no read may cross byte 255"
        );
        assert_eq!(window.len, MAX_EBPF_INSPECT_BYTES - window.offset);
        assert!(window.declared_len as usize > window.len);
    }

    #[test]
    fn extracts_the_plaintext_checkpoint_hint() {
        let mut payload = b"client hello payload".to_vec();
        let mut hint = Vec::new();
        hint.extend_from_slice(&MTC_HINT_MAGIC);
        hint.push(MTC_HINT_VERSION);
        hint.extend_from_slice(&(0x0000_0700_0000_002Au64).to_be_bytes()[2..]);
        hint.extend_from_slice(&(1_700_000_000_000u64).to_be_bytes()[2..]);
        assert_eq!(hint.len(), MTC_HINT_LEN);
        payload.extend_from_slice(&hint);

        let datagram = initial_with_crypto(&payload);
        let summary = parse_quic_initial_256b(&datagram).unwrap();
        let parsed = summary.checkpoint_hint(&datagram).expect("hint present");

        assert_eq!(parsed.serial, 0x0000_0700_0000_002A);
        assert_eq!(parsed.issuance_timestamp, 1_700_000_000_000);
    }

    #[test]
    fn a_missing_hint_is_absent_not_guessed() {
        let datagram = initial_with_crypto(b"no hint here");
        let summary = parse_quic_initial_256b(&datagram).unwrap();
        assert_eq!(summary.checkpoint_hint(&datagram), None);
    }

    #[test]
    fn stops_the_frame_walk_at_padding() {
        let mut datagram = initial_with_crypto(b"first");
        datagram.push(0x00); // PADDING
        datagram.push(0x06); // a CRYPTO frame after padding must be ignored
        datagram.push(0x00);
        datagram.push(0x02);
        datagram.extend_from_slice(b"zz");

        let summary = parse_quic_initial_256b(&datagram).unwrap();
        assert_eq!(summary.crypto_windows.len(), 1);
    }

    #[test]
    fn records_at_most_the_window_cap() {
        let frames: Vec<Vec<u8>> = (0..(MAX_CRYPTO_WINDOWS + 4))
            .map(|_| b"x".to_vec())
            .collect();
        let borrowed: Vec<&[u8]> = frames.iter().map(|frame| frame.as_slice()).collect();
        let datagram = initial_with_crypto_frames(&borrowed);
        let summary = parse_quic_initial_256b(&datagram).expect("bounded parse");
        assert_eq!(summary.crypto_windows.len(), MAX_CRYPTO_WINDOWS);
    }

    #[test]
    fn accepts_version_2_and_reports_it() {
        let mut datagram = initial_with_crypto(b"v2");
        datagram[1..5].copy_from_slice(&QUIC_VERSION_2.to_be_bytes());
        let summary = parse_quic_initial_256b(&datagram).unwrap();
        assert_eq!(summary.version, QUIC_VERSION_2);
    }
}
