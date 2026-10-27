//! Fixed-capacity rings: signed alerts and the multishot Merkle verification batch.
//!
//! Neither ring grows. Under a flood, the alert ring keeps its newest 64 entries and counts what it
//! dropped; the verification ring keeps 64 datagrams of at most 1,500 bytes each and refuses
//! anything longer. An attacker must therefore be unable to turn a monitoring decision into unbounded
//! memory growth, which is exactly the property the kernel plane does not get for free.

use super::policy::MonitorAlert;
#[cfg(chronos_bundled)]
use crate::chronos_mtc_core::subtrees::MerkleTreeLog;
#[cfg(chronos_bundled)]
use crate::chronos_pqc_sys;
#[cfg(not(chronos_bundled))]
use chronos_mtc_core::subtrees::MerkleTreeLog;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Capacity of the alert ring.
pub const ALERT_RING_CAPACITY: usize = 64;
/// Capacity of the multishot verification ring.
pub const VERIFY_RING_SLOTS: usize = 64;
/// Maximum datagram size the verification ring accepts.
pub const MAX_PACKET_BYTES: usize = 1_500;

/// Errors produced by the rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RingError {
    /// The datagram was larger than [`MAX_PACKET_BYTES`].
    #[error("datagram of {len} bytes exceeds the {max}-byte limit")]
    OversizedDatagram {
        /// Length offered.
        len: usize,
        /// Limit.
        max: usize,
    },
    /// The verification ring is full; the caller must flush first.
    #[error("verification ring is full ({capacity} slots)")]
    RingFull {
        /// Ring capacity.
        capacity: usize,
    },
}

/// A fixed-capacity ring of signed alerts.
#[derive(Debug, Clone)]
pub struct MonitorAlertRing {
    entries: VecDeque<MonitorAlert>,
    total_pushed: u64,
    total_dropped: u64,
}

impl MonitorAlertRing {
    /// Creates an empty ring.
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(ALERT_RING_CAPACITY),
            total_pushed: 0,
            total_dropped: 0,
        }
    }

    /// Pushes an alert, evicting the oldest entry when the ring is already full.
    ///
    /// Returns `true` when the alert was stored into free space, and `false` when it took the place
    /// of an evicted alert (the ring keeps its newest [`ALERT_RING_CAPACITY`] entries either way, and
    /// counts the eviction in [`Self::total_dropped`]).
    pub fn push(&mut self, alert: MonitorAlert) -> bool {
        self.total_pushed += 1;
        if self.entries.len() == ALERT_RING_CAPACITY {
            self.entries.pop_front();
            self.total_dropped += 1;
            self.entries.push_back(alert);
            return false;
        }
        self.entries.push_back(alert);
        true
    }

    /// Signs every retained alert in place, without disturbing the ring's bookkeeping.
    pub fn sign_all(
        &mut self,
        secret_key: &chronos_pqc_sys::MlDsa65SecretKey,
        public_key: &chronos_pqc_sys::MlDsa65PublicKey,
    ) {
        for alert in &mut self.entries {
            alert.sign(secret_key, public_key);
        }
    }

    /// Alerts currently retained, oldest first.
    pub fn entries(&self) -> &VecDeque<MonitorAlert> {
        &self.entries
    }

    /// Number of retained alerts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the ring holds no alerts.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total alerts ever pushed.
    pub fn total_pushed(&self) -> u64 {
        self.total_pushed
    }

    /// Total alerts evicted because the ring was full.
    pub fn total_dropped(&self) -> u64 {
        self.total_dropped
    }

    /// Removes and returns every retained alert.
    pub fn drain(&mut self) -> Vec<MonitorAlert> {
        self.entries.drain(..).collect()
    }
}

impl Default for MonitorAlertRing {
    fn default() -> Self {
        Self::new()
    }
}

/// The Merkle inputs needed to verify one datagram's inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionInputs {
    /// Leaf hash of the certificate's log entry.
    pub entry_hash: [u8; 32],
    /// Index of the entry in the log.
    pub index: u64,
    /// Subtree start index.
    pub start: u64,
    /// Subtree end index.
    pub end: u64,
    /// Sibling hashes, bottom-up.
    pub proof: Vec<[u8; 32]>,
    /// Expected subtree hash the proof must evaluate to.
    pub expected_subtree_hash: [u8; 32],
}

/// One datagram queued for batched verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedPacket {
    /// The datagram as received (already length-checked).
    pub datagram: Vec<u8>,
    /// The inclusion inputs extracted from it.
    pub inclusion: InclusionInputs,
}

/// Outcome of one batch verification pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchVerifyStats {
    /// Packets accepted into the ring.
    pub submitted: usize,
    /// Packets whose inclusion proof verified.
    pub verified: usize,
    /// Packets whose proof failed or could not be evaluated.
    pub failed: usize,
    /// Index of the first failure, when any.
    pub first_failure_index: Option<usize>,
}

/// A fixed-size slab of datagrams awaiting batched Merkle verification.
///
/// The datagram payload is stored inline in a `[u8; MAX_PACKET_BYTES]` slab per slot so the ring's
/// footprint is a compile-time constant rather than a function of traffic.
#[derive(Clone)]
pub struct MultishotVerifyRing {
    slots: [Option<QueuedPacket>; VERIFY_RING_SLOTS],
    submitted: usize,
}

impl std::fmt::Debug for MultishotVerifyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultishotVerifyRing")
            .field("used", &self.used())
            .field("capacity", &VERIFY_RING_SLOTS)
            .finish()
    }
}

impl MultishotVerifyRing {
    /// Creates an empty ring.
    ///
    /// `std::array::from_fn` writes a `None` into every slot, so the ring's footprint is a
    /// compile-time constant and no `unsafe` is needed anywhere in the crate.
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            submitted: 0,
        }
    }

    /// Number of occupied slots.
    pub fn used(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// Number of free slots.
    pub fn available(&self) -> usize {
        VERIFY_RING_SLOTS - self.used()
    }

    /// Copies a burst of datagrams into the ring, length-checking each one.
    ///
    /// Returns the number of packets accepted. Submission stops at the first datagram that does not
    /// fit or exceeds the size limit; the caller flushes and retries.
    pub fn submit_burst(&mut self, burst: &[QueuedPacket]) -> Result<usize, RingError> {
        let mut accepted = 0usize;
        for packet in burst {
            if packet.datagram.len() > MAX_PACKET_BYTES {
                return Err(RingError::OversizedDatagram {
                    len: packet.datagram.len(),
                    max: MAX_PACKET_BYTES,
                });
            }
            if self.available() == 0 {
                return Err(RingError::RingFull {
                    capacity: VERIFY_RING_SLOTS,
                });
            }
            let index =
                self.slots
                    .iter()
                    .position(|slot| slot.is_none())
                    .ok_or(RingError::RingFull {
                        capacity: VERIFY_RING_SLOTS,
                    })?;
            self.slots[index] = Some(packet.clone());
            self.submitted += 1;
            accepted += 1;
        }
        Ok(accepted)
    }

    /// Verifies every queued inclusion proof against a trusted subtree hash and empties the ring.
    pub fn flush_and_verify_batch(&mut self, trusted_subtree_hash: &[u8; 32]) -> BatchVerifyStats {
        let mut stats = BatchVerifyStats {
            submitted: self.submitted,
            verified: 0,
            failed: 0,
            first_failure_index: None,
        };
        for index in 0..VERIFY_RING_SLOTS {
            let Some(packet) = self.slots[index].take() else {
                continue;
            };
            let inclusion = &packet.inclusion;
            let outcome = MerkleTreeLog::verify_inclusion(
                &inclusion.entry_hash,
                inclusion.index,
                inclusion.start,
                inclusion.end,
                &inclusion.proof,
                trusted_subtree_hash,
            );
            if outcome.is_ok() {
                stats.verified += 1;
            } else {
                stats.failed += 1;
                stats.first_failure_index.get_or_insert(index);
            }
        }
        self.submitted = 0;
        stats
    }
}

impl Default for MultishotVerifyRing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::super::parser::parse_quic_initial_256b;
    use super::*;
    #[cfg(chronos_bundled)]
    use crate::chronos_mtc_core::subtrees::MerkleTreeLog;
    #[cfg(chronos_bundled)]
    use crate::chronos_pqc_sys;
    #[cfg(not(chronos_bundled))]
    use chronos_mtc_core::subtrees::MerkleTreeLog;

    fn alert(code: u16) -> MonitorAlert {
        MonitorAlert {
            code,
            peer: super::super::policy::PeerAddr {
                ip: [10, 0, 0, 1],
                port: 443,
            },
            timestamp_ns: u64::from(code),
            packet_digest: [code as u8; 32],
            signature: vec![0u8; 32],
        }
    }

    fn inclusion_for(log: &MerkleTreeLog, index: u64) -> InclusionInputs {
        let entry_hash = log.leaf_hash_at(index).expect("leaf hash");
        let start = 0u64;
        let end = log.len();
        InclusionInputs {
            entry_hash,
            index,
            start,
            end,
            proof: log.inclusion_proof(index, start, end).expect("proof"),
            expected_subtree_hash: log.subtree_hash(start, end).expect("subtree hash"),
        }
    }

    /// A log with `size` leaves.
    fn log_with(size: usize) -> MerkleTreeLog {
        let mut log = MerkleTreeLog::new();
        for index in 0..size {
            log.append_raw_entry(&[index as u8]);
        }
        log
    }

    fn queued(log: &MerkleTreeLog, index: u64) -> QueuedPacket {
        QueuedPacket {
            datagram: initial_header(index as u32),
            inclusion: inclusion_for(log, index),
        }
    }

    /// A syntactically valid QUIC v1 Initial whose DCID encodes `index`.
    fn initial_header(index: u32) -> Vec<u8> {
        let dcid = format!("cid{index:03}");
        let mut out = vec![0xC0 | 0x03];
        out.extend_from_slice(&1u32.to_be_bytes());
        out.push(dcid.len() as u8);
        out.extend_from_slice(dcid.as_bytes());
        out.push(0);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    #[test]
    fn alert_ring_is_bounded_and_counts_evictions() {
        let mut ring = MonitorAlertRing::new();
        assert!(ring.is_empty());

        for code in 0..ALERT_RING_CAPACITY as u16 {
            assert!(ring.push(alert(code)));
        }
        assert_eq!(ring.len(), ALERT_RING_CAPACITY);
        assert_eq!(ring.total_dropped(), 0);

        for code in 0..5u16 {
            assert!(!ring.push(alert(100 + code)), "ring is full");
        }
        assert_eq!(ring.len(), ALERT_RING_CAPACITY);
        assert_eq!(ring.total_pushed(), ALERT_RING_CAPACITY as u64 + 5);
        assert_eq!(ring.total_dropped(), 5);

        // The newest entries survived.
        let last = ring.entries().back().expect("entry").clone();
        assert_eq!(last.code, 104);
        assert_eq!(ring.drain().len(), ALERT_RING_CAPACITY);
        assert!(ring.is_empty());
    }

    #[test]
    fn verify_ring_never_exceeds_its_slot_count() {
        let log = log_with(VERIFY_RING_SLOTS);
        let mut ring = MultishotVerifyRing::new();
        assert_eq!(ring.available(), VERIFY_RING_SLOTS);

        let burst: Vec<QueuedPacket> = (0..VERIFY_RING_SLOTS as u64)
            .map(|index| queued(&log, index))
            .collect();
        assert_eq!(ring.submit_burst(&burst).unwrap(), VERIFY_RING_SLOTS);
        assert_eq!(ring.used(), VERIFY_RING_SLOTS);
        assert_eq!(ring.available(), 0);

        let overflow = vec![queued(&log, 0)];
        assert_eq!(
            ring.submit_burst(&overflow),
            Err(RingError::RingFull {
                capacity: VERIFY_RING_SLOTS
            })
        );

        let root = log.subtree_hash(0, log.len()).unwrap();
        let stats = ring.flush_and_verify_batch(&root);
        assert_eq!(stats.submitted, VERIFY_RING_SLOTS);
        assert_eq!(stats.verified, VERIFY_RING_SLOTS);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.first_failure_index, None);
        assert_eq!(ring.used(), 0);
    }

    #[test]
    fn oversized_datagrams_are_rejected_before_copied() {
        let log = log_with(4);
        let mut ring = MultishotVerifyRing::new();
        let mut packet = queued(&log, 0);
        packet.datagram = vec![0u8; MAX_PACKET_BYTES + 1];
        assert_eq!(
            ring.submit_burst(&[packet]),
            Err(RingError::OversizedDatagram {
                len: MAX_PACKET_BYTES + 1,
                max: MAX_PACKET_BYTES
            })
        );
        assert_eq!(ring.used(), 0);
    }

    #[test]
    fn a_tampered_entry_hash_fails_the_batch() {
        let log = log_with(8);
        let mut ring = MultishotVerifyRing::new();
        let mut good = queued(&log, 0);
        let mut bad = queued(&log, 1);
        bad.inclusion.entry_hash[0] ^= 0x01;
        good.datagram[13] = 0x01;
        ring.submit_burst(&[good, bad]).unwrap();

        let root = log.subtree_hash(0, log.len()).unwrap();
        let stats = ring.flush_and_verify_batch(&root);
        assert_eq!(stats.verified, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.first_failure_index, Some(1));
    }

    #[test]
    fn a_wrong_trusted_root_fails_every_proof() {
        let log = log_with(8);
        let mut ring = MultishotVerifyRing::new();
        ring.submit_burst(&[queued(&log, 0), queued(&log, 3)])
            .unwrap();

        let stats = ring.flush_and_verify_batch(&[0xAB; 32]);
        assert_eq!(stats.verified, 0);
        assert_eq!(stats.failed, 2);
        assert_eq!(stats.first_failure_index, Some(0));
    }

    #[test]
    fn submission_and_verification_round_trip_real_initial_packets() {
        let log = log_with(16);
        let burst: Vec<QueuedPacket> = (0..4).map(|index| queued(&log, index)).collect();
        for (index, packet) in burst.iter().enumerate() {
            let summary =
                parse_quic_initial_256b(&packet.datagram).expect("queued packet must parse");
            assert_eq!(summary.dcid, format!("cid{index:03}").as_bytes());
        }

        let mut ring = MultishotVerifyRing::new();
        ring.submit_burst(&burst).unwrap();
        let root = log.subtree_hash(0, log.len()).unwrap();
        let stats = ring.flush_and_verify_batch(&root);
        assert_eq!(stats.verified, 4);
    }
}
