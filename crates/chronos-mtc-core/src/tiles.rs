//! C2SP `tlog-tiles` rendering (H = 8, W = 256) and the monotonic landmark rollback guard.
//!
//! A level-`L` tile holds 256 node hashes, each covering `2^L` leaves, so a full tile is
//! `256 · 32 = 8,192` bytes and a full tile at level `L` covers `256 · 2^L` leaves.

use crate::error::{MtcError, MtcResult};
use crate::subtrees::{MerkleTreeLog, MAX_UINT48};
use serde::{Deserialize, Serialize};

/// C2SP tile height: `H = 8`.
pub const TLOG_TILE_HEIGHT: u8 = 8;

/// C2SP tile width in hashes: `W = 256`.
pub const TILE_WIDTH: usize = 256;

/// Full tile size in bytes: `W · 32 = 8,192`.
pub const TILE_BYTES: usize = TILE_WIDTH * 32;

/// Highest tile level that cannot overflow the uint48 index space when scaled by the tile width.
const MAX_TILE_LEVEL: u8 = 40;

/// Coordinates of one C2SP tile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TileCoord {
    /// Tile level (`0` = leaf hashes).
    pub level: u8,
    /// Tile index within the level.
    pub index: u64,
    /// Declared partial width; `0` means "derive from the log".
    pub partial_width: u8,
}

impl TileCoord {
    /// Builds a full-width tile coordinate.
    pub fn new(level: u8, index: u64) -> Self {
        Self {
            level,
            index,
            partial_width: 0,
        }
    }
}

/// A rendered tile: its coordinates, effective width and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedTile {
    /// Coordinates this tile was rendered from.
    pub coord: TileCoord,
    /// Number of hashes actually present (`<= 256`).
    pub width: usize,
    /// `width · 32` bytes of concatenated node hashes.
    pub bytes: Vec<u8>,
}

impl RenderedTile {
    /// True when the tile carries the full 256 hashes.
    pub fn is_full(&self) -> bool {
        self.width == TILE_WIDTH
    }
}

/// Compressed log serial: `(log_number << 48) | index`, with range validation.
pub fn serial_for(log_number: u16, index: u64) -> MtcResult<u64> {
    if index > MAX_UINT48 {
        return Err(MtcError::IndexOutOfBounds {
            index,
            size: MAX_UINT48 + 1,
        });
    }
    Ok(((log_number as u64) << 48) | index)
}

/// Renders a C2SP tile from a Merkle log.
pub fn render_tile(tree: &MerkleTreeLog, coord: TileCoord) -> MtcResult<RenderedTile> {
    if coord.level > MAX_TILE_LEVEL {
        return Err(MtcError::TileOutOfBounds {
            level: coord.level,
            index: coord.index,
        });
    }
    if tree.is_empty() {
        return Err(MtcError::TileOutOfBounds {
            level: coord.level,
            index: coord.index,
        });
    }

    let node_span = 1u64 << coord.level;
    let tile_span = node_span
        .checked_mul(TILE_WIDTH as u64)
        .ok_or(MtcError::TileOutOfBounds {
            level: coord.level,
            index: coord.index,
        })?;
    let first_leaf = coord
        .index
        .checked_mul(tile_span)
        .ok_or(MtcError::TileOutOfBounds {
            level: coord.level,
            index: coord.index,
        })?;

    if first_leaf >= tree.len() {
        return Err(MtcError::TileOutOfBounds {
            level: coord.level,
            index: coord.index,
        });
    }

    let declared = if coord.partial_width == 0 {
        TILE_WIDTH
    } else {
        coord.partial_width as usize
    };

    let mut bytes = Vec::with_capacity(TILE_BYTES);
    let mut width = 0usize;
    for node_index in 0..declared.min(TILE_WIDTH) as u64 {
        let node_start = first_leaf + node_index * node_span;
        if node_start >= tree.len() {
            break;
        }
        let node_end = (node_start + node_span).min(tree.len());
        bytes.extend_from_slice(&tree.subtree_hash(node_start, node_end)?);
        width += 1;
    }

    Ok(RenderedTile {
        coord,
        width,
        bytes,
    })
}

/// Convenience wrapper returning only the tile bytes.
pub fn render_tile_bytes(tree: &MerkleTreeLog, coord: TileCoord) -> MtcResult<Vec<u8>> {
    Ok(render_tile(tree, coord)?.bytes)
}

/// Monotonic guard against landmark and tree-size rollback.
///
/// Both dimensions must move forward together: a landmark id that goes backwards, or a tree size
/// that regresses under a newer landmark id, is the classic checkpoint-stripping attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandmarkStateGuard {
    /// Highest accepted landmark id.
    pub current_landmark_id: u64,
    /// Tree size that accompanied `current_landmark_id`.
    pub current_tree_size: u64,
}

impl LandmarkStateGuard {
    /// Creates a guard pinned to the first trusted landmark.
    pub fn new(landmark_id: u64, tree_size: u64) -> Self {
        Self {
            current_landmark_id: landmark_id,
            current_tree_size: tree_size,
        }
    }

    /// Accepts a strictly newer landmark, otherwise fails closed.
    pub fn check_and_update(&mut self, new_landmark_id: u64, new_tree_size: u64) -> MtcResult<()> {
        if new_landmark_id < self.current_landmark_id || new_tree_size < self.current_tree_size {
            return Err(MtcError::RollbackRejected {
                current_landmark: self.current_landmark_id,
                current_tree_size: self.current_tree_size,
                new_landmark: new_landmark_id,
                new_tree_size,
            });
        }
        self.current_landmark_id = new_landmark_id;
        self.current_tree_size = new_tree_size;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(n: u64) -> MerkleTreeLog {
        let mut log = MerkleTreeLog::new();
        for i in 0..n {
            log.append_raw_entry(&i.to_be_bytes());
        }
        log
    }

    #[test]
    fn full_level_zero_tile_is_eight_kibibytes() {
        let log = log(300);
        let tile = render_tile(&log, TileCoord::new(0, 0)).unwrap();
        assert!(tile.is_full());
        assert_eq!(tile.width as usize, TILE_WIDTH);
        assert_eq!(tile.bytes.len(), TILE_BYTES);
        assert_eq!(tile.bytes.len(), 8_192);

        // Tile 0 hashes the leaf hashes themselves.
        assert_eq!(&tile.bytes[..32], &log.leaf_hash_at(0).unwrap());
        assert_eq!(&tile.bytes[32..64], &log.leaf_hash_at(1).unwrap());
    }

    #[test]
    fn higher_levels_hash_subtrees() {
        let log = log(600);
        let tile = render_tile(&log, TileCoord::new(1, 0)).unwrap();
        assert!(tile.is_full());
        assert_eq!(&tile.bytes[..32], &log.subtree_hash(0, 2).unwrap());
        assert_eq!(&tile.bytes[32..64], &log.subtree_hash(2, 4).unwrap());
        assert_eq!(&tile.bytes[64..96], &log.subtree_hash(4, 6).unwrap());
    }

    #[test]
    fn partial_tiles_are_truncated_not_padded() {
        let log = log(260);
        let tile = render_tile(&log, TileCoord::new(0, 1)).unwrap();
        assert!(!tile.is_full());
        assert_eq!(tile.width, 4, "260 leaves => tile 1 holds the remaining 4");
        assert_eq!(tile.bytes.len(), 4 * 32);

        let declared = render_tile(
            &log,
            TileCoord {
                level: 0,
                index: 1,
                partial_width: 2,
            },
        )
        .unwrap();
        assert_eq!(declared.width, 2);
    }
    #[test]
    fn out_of_range_tiles_are_rejected() {
        let log = log(10);
        assert!(matches!(
            render_tile(&log, TileCoord::new(0, 5)),
            Err(MtcError::TileOutOfBounds { .. })
        ));
        assert!(matches!(
            render_tile(&log, TileCoord::new(3, 9)),
            Err(MtcError::TileOutOfBounds { .. })
        ));
        assert!(matches!(
            render_tile(&MerkleTreeLog::new(), TileCoord::new(0, 0)),
            Err(MtcError::TileOutOfBounds { .. })
        ));
        assert!(render_tile(&log, TileCoord::new(60, 0)).is_err());
    }

    #[test]
    fn serial_range_is_checked() {
        assert_eq!(serial_for(3, 17).unwrap(), (3u64 << 48) | 17);
        assert_eq!(serial_for(0, MAX_UINT48).unwrap(), MAX_UINT48);
        assert!(serial_for(1, MAX_UINT48 + 1).is_err());
    }

    #[test]
    fn landmark_guard_rejects_rollback() {
        let mut guard = LandmarkStateGuard::new(100, 640_000);
        guard.check_and_update(101, 640_064).unwrap();
        assert_eq!(guard.current_landmark_id, 101);

        assert!(matches!(
            guard.check_and_update(100, 640_064),
            Err(MtcError::RollbackRejected { .. })
        ));
        assert!(matches!(
            guard.check_and_update(102, 640_000),
            Err(MtcError::RollbackRejected { .. })
        ));
        // Equal values are idempotent, not a rollback.
        guard.check_and_update(102, 640_064).unwrap();
    }
}
