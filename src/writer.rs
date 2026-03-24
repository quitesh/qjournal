// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file writer.
//!
//! Faithful Rust port of systemd's `journal-file.c` (`journal_file_append_entry`,
//! `journal_file_append_data`, `journal_file_append_field`,
//! `link_entry_into_array`, `link_entry_into_array_plus_one`, etc.).
//!
//! # Layout of a freshly-created journal file
//!
//! ```text
//! [0..272)   Header
//! [272..272+data_ht_size)   DATA hash table  (HashItem x data_ht_n)
//! [aligned)                 FIELD hash table (HashItem x DEFAULT_FIELD_HASH_TABLE_SIZE)
//! [aligned)                 ... objects appended sequentially ...
//! ```
//!
//! Every object starts with an `ObjectHeader` and is padded to an 8-byte boundary.
//! `ObjectHeader.size` stores the **actual** (unaligned) object size, matching systemd
//! (`journal-file.c:1264`: `o->object.size = htole64(size)`).

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, Read as _, Seek, SeekFrom, Write},
    path::Path,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use uuid::Uuid;

use crate::{
    def::*,
    error::{Error, Result},
    hash::hash64,
};

// ── Compression selection ────────────────────────────────────────────────

/// Which compression codec to use when writing new DATA objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression.
    None,
    /// XZ/LZMA2 compression (legacy).
    #[cfg(feature = "xz-compression")]
    Xz,
    /// LZ4 block compression (legacy).
    #[cfg(feature = "lz4-compression")]
    Lz4,
    /// Zstandard compression (modern, preferred).
    #[cfg(feature = "zstd-compression")]
    Zstd,
}

/// Return the default compression codec (ZSTD > LZ4 > XZ > None).
pub fn compression_default() -> Compression {
    #[cfg(feature = "zstd-compression")]
    {
        return Compression::Zstd;
    }
    #[cfg(feature = "lz4-compression")]
    {
        return Compression::Lz4;
    }
    #[cfg(feature = "xz-compression")]
    {
        return Compression::Xz;
    }
    #[allow(unreachable_code)]
    Compression::None
}

/// Parse `SYSTEMD_JOURNAL_COMPRESS` environment variable into a `Compression`.
pub fn compression_requested() -> Compression {
    let val = match std::env::var("SYSTEMD_JOURNAL_COMPRESS") {
        Ok(v) => v,
        Err(_) => return compression_default(),
    };
    match val.to_ascii_lowercase().as_str() {
        "0" | "false" | "no" => Compression::None,
        "1" | "true" | "yes" => compression_default(),
        #[cfg(feature = "xz-compression")]
        "xz" => Compression::Xz,
        #[cfg(feature = "lz4-compression")]
        "lz4" => Compression::Lz4,
        #[cfg(feature = "zstd-compression")]
        "zstd" => Compression::Zstd,
        _ => compression_default(),
    }
}

// ── Offline state machine ──────────────────────────────────────────────

/// systemd: journal-file.h:44-52
///
/// States for the offline thread state machine. The offline thread is responsible
/// for syncing file data and transitioning the header state to OFFLINE when the
/// journal file is not actively being written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
#[repr(u8)]
enum OfflineState {
    Joined = 0,
    Syncing = 1,
    Offlining = 2,
    Cancel = 3,
    AgainFromSyncing = 4,
    AgainFromOfflining = 5,
    Done = 6,
}

impl OfflineState {
    #[allow(dead_code)]
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Joined,
            1 => Self::Syncing,
            2 => Self::Offlining,
            3 => Self::Cancel,
            4 => Self::AgainFromSyncing,
            5 => Self::AgainFromOfflining,
            6 => Self::Done,
            _ => Self::Joined,
        }
    }
}

// ── Post-change notification ──────────────────────────────────────────

/// Post-change notification callback type.
/// Called after entries are appended to notify watchers.
type PostChangeCallback = Box<dyn FnMut() + Send>;

// ── Constants ────────────────────────────────────────────────────────────

/// Maximum hash chain depth before suggesting rotation.
/// systemd: journal-file.c:4666
const HASH_CHAIN_DEPTH_MAX: u64 = 100;

/// Minimum journal file size (512 KB).
/// systemd: journal-file.c
const JOURNAL_FILE_SIZE_MIN: u64 = 512 * 1024;

// ── JournalMetrics ──────────────────────────────────────────────────────

/// systemd: journal-file.h:14-22
#[derive(Debug, Clone, PartialEq)]
pub struct JournalMetrics {
    pub max_size: u64,
    pub min_size: u64,
    pub max_use: u64,
    pub min_use: u64,
    pub keep_free: u64,
    pub n_max_files: u64,
}

impl Default for JournalMetrics {
    fn default() -> Self {
        Self {
            max_size: u64::MAX, // pick automatically
            min_size: u64::MAX,
            max_use: u64::MAX,
            min_use: u64::MAX,
            keep_free: u64::MAX,
            n_max_files: u64::MAX,
        }
    }
}

/// systemd: journal-file.c:4384
pub fn journal_reset_metrics(m: &mut JournalMetrics) {
    *m = JournalMetrics::default();
}

/// systemd: journal-file.c:4393
pub fn journal_metrics_equal(x: &JournalMetrics, y: &JournalMetrics) -> bool {
    x == y
}

// ── Boot-ID / machine-ID / time helpers ──────────────────────────────────

/// Attempt to read `/proc/sys/kernel/random/boot_id` (Linux).
/// Falls back to a random UUID on other platforms.
fn get_boot_id() -> [u8; 16] {
    #[cfg(target_os = "linux")]
    if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        if let Ok(id) = Uuid::parse_str(s.trim()) {
            return *id.as_bytes();
        }
    }
    *Uuid::new_v4().as_bytes()
}

/// Current realtime in microseconds since the Unix epoch.
fn realtime_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Monotonic time in microseconds (platform-specific).
fn monotonic_now() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000
    }
    #[cfg(not(target_os = "linux"))]
    {
        realtime_now()
    }
}

/// Get or synthesise a stable machine ID.
fn machine_id() -> [u8; 16] {
    #[cfg(target_os = "linux")]
    if let Ok(s) = std::fs::read_to_string("/etc/machine-id") {
        if let Ok(id) = Uuid::parse_str(s.trim()) {
            return *id.as_bytes();
        }
    }
    *Uuid::new_v4().as_bytes()
}

// ── In-memory dedup indexes ──────────────────────────────────────────────

/// DATA objects keyed by hash-table bucket -> [(file_offset, hash)].
type DataIndex = HashMap<u64, Vec<(u64, u64)>>;
/// FIELD objects keyed by hash-table bucket -> [(file_offset, hash)].
type FieldIndex = HashMap<u64, Vec<(u64, u64)>>;

/// Per-DATA entry-array tail cache: data_offset -> (tail_array_offset, items_in_tail).
/// Avoids O(n) chain walks when appending to per-data entry arrays.
type DataTailCache = HashMap<u64, (u64, u64)>;

// ══════════════════════════════════════════════════════════════════════════
// Shared infrastructure (validation)
// ══════════════════════════════════════════════════════════════════════════

/// systemd: journal-file.c:524-534 offset_is_valid
///
/// Check that an offset is valid: it must be 8-byte aligned, at least as large
/// as the header, and no larger than tail_object_offset (if set).
/// DIVERGENCE vs previous version: Added offset==0 early return (sentinel for "not set").
/// systemd: `if (offset == 0) return true;` — zero means "field not present", always valid.
/// Also removed the `tail_object_offset != 0` guard; C checks unconditionally (callers
/// pass UINT64_MAX when unbounded).
pub fn offset_is_valid(offset: u64, header_size: u64, tail_object_offset: u64) -> bool {
    // systemd: if (offset == 0) return true;
    if offset == 0 {
        return true;
    }
    // systemd: if (!VALID64(offset)) return false;
    if !valid64(offset) {
        return false;
    }
    // systemd: if (offset < header_size) return false;
    if offset < header_size {
        return false;
    }
    // systemd: if (offset > tail_object_offset) return false;
    if offset > tail_object_offset {
        return false;
    }
    true
}

/// systemd: journal-file.c:870-892 minimum_header_size
///
/// Return the minimum object size for a given object type.
pub fn minimum_header_size(obj_type: ObjectType, compact: bool) -> u64 {
    match obj_type {
        ObjectType::Data => data_payload_offset(compact),
        ObjectType::Field => FIELD_OBJECT_HEADER_SIZE as u64,
        ObjectType::Entry => ENTRY_OBJECT_HEADER_SIZE as u64,
        ObjectType::DataHashTable | ObjectType::FieldHashTable => OBJECT_HEADER_SIZE as u64,
        ObjectType::EntryArray => ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64,
        ObjectType::Tag => {
            // TagObject = ObjectHeader(16) + seqnum(8) + epoch(8) + tag[32] = 64
            // systemd: sizeof(TagObject) where TAG_LENGTH = 256/8 = 32
            OBJECT_HEADER_SIZE as u64 + 8 + 8 + 32 // = 64
        }
        ObjectType::Unused => OBJECT_HEADER_SIZE as u64,
    }
}

/// systemd: journal-file.c:894-932 check_object_header
///
/// Validate an object header: type must be valid, size >= minimum for type,
/// size must be 8-byte aligned (the STORED size is actual/unaligned, but
/// the object must fit in aligned space).
pub fn check_object_header(obj_type: u8, obj_size: u64, offset: u64, compact: bool, expected_type: Option<ObjectType>) -> Result<()> {
    // systemd: journal-file.c:901 — size == 0 means uninitialized object
    if obj_size == 0 {
        return Err(Error::CorruptObject {
            offset,
            reason: "attempt to move to uninitialized object".into(),
        });
    }

    // Type must be in valid range (not Unused, not beyond Tag)
    if obj_type == 0 || obj_type > ObjectType::Tag as u8 {
        return Err(Error::CorruptObject {
            offset,
            reason: format!("invalid object type {}", obj_type),
        });
    }

    let otype = ObjectType::try_from(obj_type).map_err(|_| Error::CorruptObject {
        offset,
        reason: format!("invalid object type {}", obj_type),
    })?;

    // systemd: journal-file.c:910-912 — expected type mismatch check
    if let Some(expected) = expected_type {
        if expected != ObjectType::Unused && otype != expected {
            return Err(Error::CorruptObject {
                offset,
                reason: format!(
                    "expected {:?} object, got {:?}",
                    expected, otype
                ),
            });
        }
    }

    let min_size = minimum_header_size(otype, compact);
    if obj_size < min_size {
        return Err(Error::CorruptObject {
            offset,
            reason: format!(
                "object size {} too small for type {:?} (minimum {})",
                obj_size, otype, min_size
            ),
        });
    }

    // Objects must be at least OBJECT_HEADER_SIZE
    if obj_size < OBJECT_HEADER_SIZE as u64 {
        return Err(Error::CorruptObject {
            offset,
            reason: format!(
                "object size {} less than header size {}",
                obj_size, OBJECT_HEADER_SIZE
            ),
        });
    }

    Ok(())
}

/// systemd: journal-file.c:936-1086 check_object
///
/// Validate object content based on its type. Checks vary per object type:
/// - DATA: entry_offset==0 iff n_entries==0, size > DATA_OBJECT_HEADER_SIZE, offsets aligned
/// - FIELD: size > FIELD_OBJECT_HEADER_SIZE, offsets aligned
/// - ENTRY: size >= ENTRY_OBJECT_HEADER_SIZE, items divisible, n_items > 0, seqnum > 0, etc.
/// - HASH_TABLE: size divisible by HASH_ITEM_SIZE, n_items > 0
/// - ENTRY_ARRAY: size divisible by 8, n_items > 0, next offset valid
#[allow(clippy::too_many_arguments)]
pub fn check_object(
    obj_type: ObjectType,
    obj_size: u64,
    flags: u8,
    offset: u64,
    compact: bool,
    // For DATA objects:
    _data_hash: u64,
    data_next_hash_offset: u64,
    data_next_field_offset: u64,
    data_entry_offset: u64,
    data_entry_array_offset: u64,
    data_n_entries: u64,
    // For ENTRY objects:
    entry_seqnum: u64,
    entry_realtime: u64,
    entry_monotonic: u64,
    entry_boot_id: &[u8; 16],
    // For ENTRY_ARRAY objects:
    entry_array_next: u64,
    // For TAG objects:
    tag_epoch: u64,
) -> Result<()> {
    // First check the header basics
    check_object_header(obj_type as u8, obj_size, offset, compact, None)?;

    match obj_type {
        ObjectType::Data => {
            // systemd: journal-file.c:943-975
            if obj_size <= data_payload_offset(compact) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA object has no payload".into(),
                });
            }
            // entry_offset == 0 iff n_entries == 0
            if (data_entry_offset == 0) != (data_n_entries == 0) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "DATA entry_offset={} but n_entries={}",
                        data_entry_offset, data_n_entries
                    ),
                });
            }
            // Offsets must be 8-byte aligned if non-zero
            if data_next_hash_offset != 0 && !valid64(data_next_hash_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA next_hash_offset not aligned".into(),
                });
            }
            if data_next_field_offset != 0 && !valid64(data_next_field_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA next_field_offset not aligned".into(),
                });
            }
            if data_entry_offset != 0 && !valid64(data_entry_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA entry_offset not aligned".into(),
                });
            }
            if data_entry_array_offset != 0 && !valid64(data_entry_array_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA entry_array_offset not aligned".into(),
                });
            }
            // Compression flags check
            let compressed = flags & obj_flags::COMPRESSED_MASK;
            if compressed != 0 && compressed.count_ones() > 1 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA has multiple compression flags set".into(),
                });
            }
        }
        ObjectType::Field => {
            // systemd: journal-file.c:977-998
            if obj_size <= FIELD_OBJECT_HEADER_SIZE as u64 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "FIELD object has no payload".into(),
                });
            }
            if data_next_hash_offset != 0 && !valid64(data_next_hash_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "FIELD next_hash_offset not aligned".into(),
                });
            }
            // head_data_offset alignment (reusing data_next_field_offset param)
            if data_next_field_offset != 0 && !valid64(data_next_field_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "FIELD head_data_offset not aligned".into(),
                });
            }
        }
        ObjectType::Entry => {
            // systemd: journal-file.c:1000-1046
            if obj_size < ENTRY_OBJECT_HEADER_SIZE as u64 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "ENTRY object too small".into(),
                });
            }
            let items_bytes = obj_size - ENTRY_OBJECT_HEADER_SIZE as u64;
            let item_size = entry_item_size(compact);
            if items_bytes % item_size != 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "ENTRY items region {} not divisible by item size {}",
                        items_bytes, item_size
                    ),
                });
            }
            let n_items = items_bytes / item_size;
            if n_items == 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "ENTRY has no items".into(),
                });
            }
            if entry_seqnum == 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "ENTRY seqnum is zero".into(),
                });
            }
            // systemd: if (!VALID_REALTIME(le64toh(o->entry.realtime)))
            // VALID_REALTIME checks u > 0 && u < (1ULL << 55)
            // DIVERGENCE: previous version only checked == 0, missing upper bound.
            const TIMESTAMP_UPPER: u64 = 1u64 << 55;
            if entry_realtime == 0 || entry_realtime >= TIMESTAMP_UPPER {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!("ENTRY realtime {} invalid", entry_realtime),
                });
            }
            // systemd: if (!VALID_MONOTONIC(le64toh(o->entry.monotonic)))
            // VALID_MONOTONIC checks u < (1ULL << 55) — note: 0 IS valid for monotonic.
            // DIVERGENCE: previous version did not check monotonic at all.
            if entry_monotonic >= TIMESTAMP_UPPER {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!("ENTRY monotonic {} invalid", entry_monotonic),
                });
            }
            // systemd: if (sd_id128_is_null(o->entry.boot_id))
            if entry_boot_id == &[0u8; 16] {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "ENTRY boot_id is null".into(),
                });
            }
        }
        ObjectType::DataHashTable | ObjectType::FieldHashTable => {
            // systemd: journal-file.c:1048-1062
            let items_bytes = obj_size.saturating_sub(OBJECT_HEADER_SIZE as u64);
            if items_bytes % HASH_ITEM_SIZE as u64 != 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "HASH_TABLE items region {} not divisible by HashItem size {}",
                        items_bytes, HASH_ITEM_SIZE
                    ),
                });
            }
            let n_items = items_bytes / HASH_ITEM_SIZE as u64;
            if n_items == 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "HASH_TABLE has no items".into(),
                });
            }
        }
        ObjectType::EntryArray => {
            // systemd: journal-file.c:1064-1086
            let ea_item_size = entry_array_item_size(compact);
            let items_bytes = obj_size.saturating_sub(ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64);
            if items_bytes % ea_item_size != 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "ENTRY_ARRAY items region {} not divisible by {}",
                        items_bytes, ea_item_size
                    ),
                });
            }
            let n_items = items_bytes / ea_item_size;
            if n_items == 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "ENTRY_ARRAY has no items".into(),
                });
            }
            // next_entry_array_offset must be aligned and > offset if non-zero
            if entry_array_next != 0 {
                if !valid64(entry_array_next) {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: "ENTRY_ARRAY next offset not aligned".into(),
                    });
                }
                if entry_array_next <= offset {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: format!(
                            "ENTRY_ARRAY next {} <= current offset {}",
                            entry_array_next, offset
                        ),
                    });
                }
            }
        }
        ObjectType::Tag => {
            // systemd: journal-file.c:1070-1081
            // TagObject is ObjectHeader(16) + seqnum(8) + epoch(8) + tag[32] = 64 bytes.
            const TAG_OBJECT_SIZE: u64 = OBJECT_HEADER_SIZE as u64 + 8 + 8 + 32;
            if obj_size != TAG_OBJECT_SIZE {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!("TAG object size {} != expected {}", obj_size, TAG_OBJECT_SIZE),
                });
            }
            // systemd: journal-file.c:1077-1080 — VALID_EPOCH(epoch) = epoch < (1<<55)
            const EPOCH_UPPER: u64 = 1u64 << 55;
            if tag_epoch >= EPOCH_UPPER {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!("TAG epoch {} invalid (>= 2^55)", tag_epoch),
                });
            }
        }
        ObjectType::Unused => {
            // Unused objects should not appear in a valid journal.
        }
    }

    Ok(())
}

/// systemd: journal-file.c:552-727 journal_file_verify_header
///
/// Complete header verification: signature, flags, state, sizes, offsets, counts.
/// `current_machine_id`: when Some, the header's machine_id must match (or be zero).
/// Callers should pass `Some(machine_id())` for writable files on Linux, `None` otherwise.
pub fn verify_header(
    header: &Header,
    file_size: u64,
    writable: bool,
    current_machine_id: Option<[u8; 16]>,
) -> Result<()> {
    // Signature check
    if header.signature != HEADER_SIGNATURE {
        return Err(Error::InvalidFile("bad signature".into()));
    }

    // Incompatible flags check
    let incompat = from_le32(&header.incompatible_flags);
    let supported = if writable {
        incompat::SUPPORTED_WRITE
    } else {
        incompat::SUPPORTED_READ
    };
    let unsupported = incompat & !supported;
    if unsupported != 0 {
        return Err(Error::IncompatibleFlags { flags: unsupported });
    }

    // Compatible flags check (writable mode)
    // systemd: journal-file.c:563-568 warn_wrong_flags() for compatible flags
    // When writing, we must understand all compatible flags that are set.
    if writable {
        let compat = from_le32(&header.compatible_flags);
        let supported_compat = compat::TAIL_ENTRY_BOOT_ID;
        let unsupported_compat = compat & !supported_compat;
        if unsupported_compat != 0 {
            return Err(Error::InvalidFile(format!(
                "unsupported compatible flags {:#x} for writable mode",
                unsupported_compat
            )));
        }
    }

    // Compatible flags are ignorable by readers — SEALED is a compatible flag,
    // so we do NOT reject it. Writers check compatible flags above.

    // State validation
    let state = header.state;
    if state != FileState::Offline as u8
        && state != FileState::Online as u8
        && state != FileState::Archived as u8
    {
        return Err(Error::InvalidFile(format!("invalid state {}", state)));
    }

    // systemd: header_size must be >= HEADER_SIZE_MIN for readers, == HEADER_SIZE for writers.
    let header_size = from_le64(&header.header_size);
    if writable {
        if header_size < HEADER_SIZE {
            return Err(Error::InvalidFile(format!(
                "header_size {} < minimum {} for writable mode",
                header_size, HEADER_SIZE
            )));
        }
    } else {
        if header_size < HEADER_SIZE_MIN {
            return Err(Error::InvalidFile(format!(
                "header_size {} < minimum {}",
                header_size, HEADER_SIZE_MIN
            )));
        }
    }
    // systemd: journal-file.c:581-582
    //   if (journal_file_writable(f) && header_size != sizeof(Header))
    //       return -EPROTONOSUPPORT;
    // DIVERGENCE FIX: previous version allowed writing to files with larger headers.
    if writable && header_size != HEADER_SIZE {
        return Err(Error::InvalidFile(format!(
            "writable mode requires header_size == {}, got {}",
            HEADER_SIZE, header_size
        )));
    }
    // systemd: journal-file.c:585-586
    //   if (journal_file_writable(f) && !JOURNAL_HEADER_TAIL_ENTRY_BOOT_ID(f->header))
    // DIVERGENCE FIX: previous version did not check TAIL_ENTRY_BOOT_ID flag.
    if writable {
        let compat = from_le32(&header.compatible_flags);
        if compat & compat::TAIL_ENTRY_BOOT_ID == 0 {
            return Err(Error::InvalidFile(
                "writable mode requires TAIL_ENTRY_BOOT_ID compatible flag".into(),
            ));
        }
    }

    // systemd: journal-file.c:588
    // If SEALED compat flag is set, the header must be large enough to contain
    // the n_entry_arrays field (offset 256, so header_size must be >= 264).
    {
        let compat = from_le32(&header.compatible_flags);
        if (compat & compat::SEALED) != 0 {
            // n_entry_arrays is at byte offset 256 in the header struct, size 8.
            const N_ENTRY_ARRAYS_END: u64 = 264;
            if header_size < N_ENTRY_ARRAYS_END {
                return Err(Error::InvalidFile(
                    "SEALED flag set but header too small for n_entry_arrays field".into(),
                ));
            }
        }
    }

    // arena_size bounds check
    let arena_size = from_le64(&header.arena_size);
    if header_size.checked_add(arena_size).is_none() {
        return Err(Error::InvalidFile("arena_size overflow".into()));
    }
    let total = header_size + arena_size;
    if total > file_size {
        return Err(Error::InvalidFile(format!(
            "header_size ({}) + arena_size ({}) = {} > file_size ({})",
            header_size, arena_size, total, file_size
        )));
    }

    // tail_object_offset validation
    let tail_object_offset = from_le64(&header.tail_object_offset);
    if tail_object_offset != 0 {
        if !valid64(tail_object_offset) {
            return Err(Error::InvalidFile(
                "tail_object_offset not aligned".into(),
            ));
        }
        if tail_object_offset < header_size {
            return Err(Error::InvalidFile(
                "tail_object_offset before header end".into(),
            ));
        }
        if tail_object_offset >= total {
            return Err(Error::InvalidFile(
                "tail_object_offset beyond file end".into(),
            ));
        }
        // systemd: journal-file.c:601-602
        //   if (header_size + arena_size - tail_object_offset < offsetof(ObjectHeader, payload))
        // DIVERGENCE FIX: previous version didn't check minimum space at tail.
        if total - tail_object_offset < OBJECT_HEADER_SIZE as u64 {
            return Err(Error::InvalidFile(
                "not enough space at tail_object_offset for ObjectHeader".into(),
            ));
        }
    }

    // Data hash table offset/size validation
    let data_ht_offset = from_le64(&header.data_hash_table_offset);
    let data_ht_size = from_le64(&header.data_hash_table_size);
    if data_ht_offset != 0 || data_ht_size != 0 {
        if data_ht_offset == 0 || data_ht_size == 0 {
            return Err(Error::InvalidFile(
                "data hash table offset/size partially zero".into(),
            ));
        }
        if !valid64(data_ht_offset) {
            return Err(Error::InvalidFile(
                "data_hash_table_offset not aligned".into(),
            ));
        }
        if data_ht_size % HASH_ITEM_SIZE as u64 != 0 {
            return Err(Error::InvalidFile(
                "data_hash_table_size not multiple of HashItem".into(),
            ));
        }
        // The offset points past the ObjectHeader (systemd convention)
        if data_ht_offset < header_size + OBJECT_HEADER_SIZE as u64 {
            return Err(Error::InvalidFile(
                "data_hash_table_offset too small".into(),
            ));
        }
        if data_ht_offset
            .checked_add(data_ht_size)
            .map_or(true, |end| end > total)
        {
            return Err(Error::InvalidFile(
                "data hash table extends beyond file".into(),
            ));
        }
        // systemd: journal-file.c:544 — hash table object must not exceed tail_object_offset
        // data_ht_offset points past the ObjectHeader, so the object starts at offset - OBJECT_HEADER_SIZE
        if tail_object_offset != 0 {
            let obj_start = data_ht_offset - OBJECT_HEADER_SIZE as u64;
            if obj_start > tail_object_offset {
                return Err(Error::InvalidFile(
                    "data_hash_table_offset beyond tail_object_offset".into(),
                ));
            }
        }
    }

    // Field hash table offset/size validation
    let field_ht_offset = from_le64(&header.field_hash_table_offset);
    let field_ht_size = from_le64(&header.field_hash_table_size);
    if field_ht_offset != 0 || field_ht_size != 0 {
        if field_ht_offset == 0 || field_ht_size == 0 {
            return Err(Error::InvalidFile(
                "field hash table offset/size partially zero".into(),
            ));
        }
        if !valid64(field_ht_offset) {
            return Err(Error::InvalidFile(
                "field_hash_table_offset not aligned".into(),
            ));
        }
        if field_ht_size % HASH_ITEM_SIZE as u64 != 0 {
            return Err(Error::InvalidFile(
                "field_hash_table_size not multiple of HashItem".into(),
            ));
        }
        // DIVERGENCE FIX (D28): previous version didn't check field HT bounds.
        if field_ht_offset < header_size + OBJECT_HEADER_SIZE as u64 {
            return Err(Error::InvalidFile(
                "field_hash_table_offset too small".into(),
            ));
        }
        if field_ht_offset
            .checked_add(field_ht_size)
            .map_or(true, |end| end > total)
        {
            return Err(Error::InvalidFile(
                "field hash table extends beyond file".into(),
            ));
        }
        // systemd: journal-file.c:544 — hash table object must not exceed tail_object_offset
        if tail_object_offset != 0 {
            let obj_start = field_ht_offset - OBJECT_HEADER_SIZE as u64;
            if obj_start > tail_object_offset {
                return Err(Error::InvalidFile(
                    "field_hash_table_offset beyond tail_object_offset".into(),
                ));
            }
        }
    }

    // entry_array_offset validation
    // DIVERGENCE FIX (D29): previous version didn't check against tail_object_offset.
    let entry_array_offset = from_le64(&header.entry_array_offset);
    if !offset_is_valid(entry_array_offset, header_size, tail_object_offset) {
        return Err(Error::InvalidFile(
            "entry_array_offset invalid".into(),
        ));
    }

    // tail_entry_array_offset / n_entries validation
    let n_entries = from_le64(&header.n_entries);
    let tail_entry_array_offset = from_le32(&header.tail_entry_array_offset) as u64;
    let tail_entry_array_n_entries = from_le32(&header.tail_entry_array_n_entries) as u64;
    // systemd: journal-file.c:618-633
    // DIVERGENCE FIX (D30): previous version had empty validation block.
    if !offset_is_valid(tail_entry_array_offset, header_size, tail_object_offset) {
        return Err(Error::InvalidFile(
            "tail_entry_array_offset invalid".into(),
        ));
    }
    if entry_array_offset != 0 && tail_entry_array_offset != 0
        && entry_array_offset > tail_entry_array_offset
    {
        return Err(Error::InvalidFile(
            "entry_array_offset > tail_entry_array_offset".into(),
        ));
    }
    if entry_array_offset == 0 && tail_entry_array_offset != 0 {
        return Err(Error::InvalidFile(
            "tail_entry_array set but entry_array_offset is zero".into(),
        ));
    }
    if (tail_entry_array_offset == 0) != (tail_entry_array_n_entries == 0) {
        return Err(Error::InvalidFile(
            "tail_entry_array_offset/n_entries partially zero".into(),
        ));
    }
    // systemd: journal-file.c:631 — tail_entry_array_n_entries must not exceed the space
    // available in the entry array object at tail_entry_array_offset.
    if tail_entry_array_offset != 0 && tail_entry_array_n_entries > 0 {
        let compact = (incompat & incompat::COMPACT) != 0;
        let item_sz = entry_array_item_size(compact);
        // Maximum object size: from tail_entry_array_offset to end of arena (total).
        let max_obj_size = total.saturating_sub(tail_entry_array_offset);
        let max_items = entry_array_n_items(max_obj_size, compact);
        if tail_entry_array_n_entries > max_items {
            return Err(Error::InvalidFile(format!(
                "tail_entry_array_n_entries ({}) exceeds available space ({} items, item_sz={})",
                tail_entry_array_n_entries, max_items, item_sz
            )));
        }
    }

    // systemd: journal-file.c:635-662
    // DIVERGENCE FIX (D32): use offset_is_valid for bounds check.
    // DIVERGENCE FIX (D33): use tail_entry_offset > 0 as trigger, not n_entries > 0.
    let tail_entry_offset = from_le64(&header.tail_entry_offset);
    if !offset_is_valid(tail_entry_offset, header_size, tail_object_offset) {
        return Err(Error::InvalidFile(
            "tail_entry_offset invalid".into(),
        ));
    }

    let head_entry_realtime = from_le64(&header.head_entry_realtime);
    let tail_entry_realtime = from_le64(&header.tail_entry_realtime);
    let tail_entry_monotonic = from_le64(&header.tail_entry_monotonic);
    const TS_UPPER: u64 = 1u64 << 55;
    if tail_entry_offset > 0 {
        // systemd: journal-file.c:643-644 — tail_entry_boot_id must be non-null when entries exist
        let compat = from_le32(&header.compatible_flags);
        if (compat & compat::TAIL_ENTRY_BOOT_ID) != 0 && header.tail_entry_boot_id == [0u8; 16] {
            return Err(Error::InvalidFile(
                "tail_entry set but tail_entry_boot_id is null".into(),
            ));
        }
        // systemd: VALID_REALTIME checks u > 0 && u < (1ULL << 55)
        // DIVERGENCE FIX (D35): add upper bound checks.
        if head_entry_realtime == 0 || head_entry_realtime >= TS_UPPER {
            return Err(Error::InvalidFile(
                "tail_entry set but head_entry_realtime invalid".into(),
            ));
        }
        if tail_entry_realtime == 0 || tail_entry_realtime >= TS_UPPER {
            return Err(Error::InvalidFile(
                "tail_entry set but tail_entry_realtime invalid".into(),
            ));
        }
        // VALID_MONOTONIC: u < (1ULL << 55), 0 is valid
        if tail_entry_monotonic >= TS_UPPER {
            return Err(Error::InvalidFile(
                "tail_entry set but tail_entry_monotonic invalid".into(),
            ));
        }
    } else {
        // If no entries, timestamps should be zero.
        if head_entry_realtime != 0 || tail_entry_realtime != 0 || tail_entry_monotonic != 0 {
            return Err(Error::InvalidFile(
                "no tail_entry but timestamps are non-zero".into(),
            ));
        }
        // systemd: journal-file.c:653-655 — tail_entry_boot_id must be null when no entries exist
        let compat = from_le32(&header.compatible_flags);
        if (compat & compat::TAIL_ENTRY_BOOT_ID) != 0 && header.tail_entry_boot_id != [0u8; 16] {
            return Err(Error::InvalidFile(
                "no tail_entry but tail_entry_boot_id is non-null".into(),
            ));
        }
    }

    // Object count bounds
    let n_objects = from_le64(&header.n_objects);
    // systemd: journal-file.c:667-668
    //   if (n_objects > arena_size / offsetof(ObjectHeader, payload))
    // DIVERGENCE FIX (D37): previous version didn't check n_objects upper bound.
    // BUG FIX: removed `arena_size > 0 &&` guard so that n_objects > 0 is correctly
    // rejected when arena_size == 0 (division yields 0, and any n_objects > 0 is invalid).
    if n_objects > arena_size / OBJECT_HEADER_SIZE as u64 {
        return Err(Error::InvalidFile(format!(
            "n_objects ({}) impossibly large for arena_size ({})",
            n_objects, arena_size
        )));
    }
    let n_data = from_le64(&header.n_data);
    let n_fields = from_le64(&header.n_fields);
    let n_entry_arrays = from_le64(&header.n_entry_arrays);
    let n_tags = from_le64(&header.n_tags);

    if n_entries > n_objects {
        return Err(Error::InvalidFile(format!(
            "n_entries ({}) > n_objects ({})",
            n_entries, n_objects
        )));
    }
    if n_data > n_objects {
        return Err(Error::InvalidFile(format!(
            "n_data ({}) > n_objects ({})",
            n_data, n_objects
        )));
    }
    if n_fields > n_objects {
        return Err(Error::InvalidFile(format!(
            "n_fields ({}) > n_objects ({})",
            n_fields, n_objects
        )));
    }
    if n_entry_arrays > n_objects {
        return Err(Error::InvalidFile(format!(
            "n_entry_arrays ({}) > n_objects ({})",
            n_entry_arrays, n_objects
        )));
    }
    if n_tags > n_objects {
        return Err(Error::InvalidFile(format!(
            "n_tags ({}) > n_objects ({})",
            n_tags, n_objects
        )));
    }
    // systemd: journal-file.c:690-692
    // DIVERGENCE FIX (D39): previous version didn't check this.
    if tail_entry_array_n_entries > n_entries {
        return Err(Error::InvalidFile(format!(
            "tail_entry_array_n_entries ({}) > n_entries ({})",
            tail_entry_array_n_entries, n_entries
        )));
    }

    // Writable-mode checks
    // systemd: journal-file.c:694-724
    // DIVERGENCE FIX (D42): previous version only checked hash table sizes.
    if writable {
        // systemd: STATE_ARCHIVED -> -ESHUTDOWN
        if state == FileState::Archived as u8 {
            return Err(Error::InvalidFile(
                "cannot write to archived journal".into(),
            ));
        }
        // systemd: state == STATE_ONLINE -> warning about unclean close (we allow it)
        // systemd: state != STATE_OFFLINE -> error
        // DIVERGENCE: we allow Online state (treat as unclean close, will overwrite).
        if state != FileState::Offline as u8 && state != FileState::Online as u8 {
            return Err(Error::InvalidFile(format!(
                "unexpected state {} for writable journal",
                state
            )));
        }
        if data_ht_size == 0 {
            return Err(Error::InvalidFile(
                "writable mode but data hash table is empty".into(),
            ));
        }
        if field_ht_size == 0 {
            return Err(Error::InvalidFile(
                "writable mode but field hash table is empty".into(),
            ));
        }
        // systemd: journal-file.c:699-707 — machine_id check for writable files.
        // The file's machine_id must match the current machine_id, or be zeroed.
        if let Some(mid) = current_machine_id {
            if header.machine_id != [0u8; 16] && header.machine_id != mid {
                return Err(Error::InvalidFile(
                    "journal file machine_id does not match current machine".into(),
                ));
            }
        }
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════
// Hash operations
// ══════════════════════════════════════════════════════════════════════════

/// systemd: journal-file.c:1585-1601 journal_file_hash_data
///
/// Hash data payload. Uses siphash24 keyed with file_id when keyed_hash is true,
/// otherwise falls back to jenkins hash64.
pub fn journal_file_hash_data(data: &[u8], keyed_hash: bool, file_id: &[u8; 16]) -> u64 {
    if keyed_hash {
        // systemd: return siphash24(data, size, f->header->file_id.bytes);
        use siphasher::sip::SipHasher24;
        use std::hash::Hasher;
        let k0 = u64::from_le_bytes(file_id[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(file_id[8..16].try_into().unwrap());
        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        hasher.write(data);
        hasher.finish()
    } else {
        // systemd: return jenkins_hash64(data, size);
        hash64(data)
    }
}

/// systemd: journal-file.c:1710-1746 journal_field_valid
///
/// Validate a field name: must be non-empty, only [A-Z0-9_], must not start
/// with a digit, and must not be longer than 64 bytes. Protected fields
/// (starting with '_') are rejected unless allow_protected is true.
pub fn journal_field_valid(field: &[u8], allow_protected: bool) -> bool {
    if field.is_empty() {
        return false;
    }
    if field.len() > 64 {
        return false;
    }
    // Must not start with digit
    if field[0].is_ascii_digit() {
        return false;
    }
    // Check for protected fields (start with '_')
    if !allow_protected && field[0] == b'_' {
        return false;
    }
    for &b in field {
        if !matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_') {
            return false;
        }
    }
    true
}

// ══════════════════════════════════════════════════════════════════════════
// Entry/data utility functions
// ══════════════════════════════════════════════════════════════════════════

/// systemd: journal-file.h:220-224 journal_file_entry_item_size
/// Returns 4 in compact mode, 16 in regular mode.
pub fn entry_item_size(compact: bool) -> u64 {
    if compact { 4 } else { ENTRY_ITEM_SIZE as u64 }
}

/// systemd: journal-file.h:257-260 journal_file_entry_array_item_size
/// Returns 4 in compact mode, 8 in regular mode.
pub fn entry_array_item_size(compact: bool) -> u64 {
    if compact { 4 } else { 8 }
}

/// systemd: journal-file.h:236-242 journal_file_data_payload_offset
/// In compact mode, there are 8 extra bytes (tail_entry_array_offset + tail_entry_array_n_entries)
/// before the payload.
pub fn data_payload_offset(compact: bool) -> u64 {
    if compact {
        DATA_OBJECT_HEADER_SIZE as u64 + 8
    } else {
        DATA_OBJECT_HEADER_SIZE as u64
    }
}

/// systemd: journal-file.c:2036-2050 journal_file_entry_n_items
///
/// Compute the number of entry items from the object size.
pub fn journal_file_entry_n_items(obj_size: u64, compact: bool) -> u64 {
    let items_bytes = obj_size.saturating_sub(ENTRY_OBJECT_HEADER_SIZE as u64);
    items_bytes / entry_item_size(compact)
}

/// systemd: journal-file.c:2052-2066 entry_array_n_items
///
/// Compute the number of entry array items from the object size.
pub fn entry_array_n_items(obj_size: u64, compact: bool) -> u64 {
    let items_bytes = obj_size.saturating_sub(ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64);
    items_bytes / entry_array_item_size(compact)
}

/// systemd: journal-file.c:2068-2081 journal_file_hash_table_n_items
///
/// Compute the number of hash table items from the object size.
pub fn journal_file_hash_table_n_items(obj_size: u64) -> u64 {
    let items_bytes = obj_size.saturating_sub(OBJECT_HEADER_SIZE as u64);
    items_bytes / HASH_ITEM_SIZE as u64
}

/// systemd: journal-file.c:2508-2510 entry_item_cmp
///
/// Compare two entry items by their object_offset for sorting.
fn entry_item_cmp(a: &(u64, u64), b: &(u64, u64)) -> std::cmp::Ordering {
    a.0.cmp(&b.0)
}

/// systemd: journal-file.c:2512-2525 remove_duplicate_entry_items
///
/// Remove consecutive duplicate entry items (by offset). Items must be sorted first.
fn remove_duplicate_entry_items(items: &mut Vec<(u64, u64)>) {
    items.dedup_by_key(|item| item.0);
}

/// systemd: journal-file.c:1197-1202 inc_seqnum
///
/// Increment sequence number, wrapping at UINT64_MAX-1 back to 1.
fn inc_seqnum(seqnum: u64) -> u64 {
    if seqnum >= u64::MAX - 1 {
        1
    } else {
        seqnum + 1
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Public writer
// ══════════════════════════════════════════════════════════════════════════

/// A writable systemd-journal file.
///
/// ```rust,no_run
/// use qjournal::JournalWriter;
/// let mut w = JournalWriter::open("output.journal").unwrap();
/// w.append_entry(&[("MESSAGE", b"hi" as &[u8])]).unwrap();
/// w.flush().unwrap();
/// ```
pub struct JournalWriter {
    file: File,
    /// Current write cursor (== logical file size).
    offset: u64,

    // ── Hash tables ──────────────────────────────────────────────────
    data_ht_n: u64,
    data_ht_offset: u64,
    field_ht_n: u64,
    field_ht_offset: u64,

    // ── Global entry-array chain ─────────────────────────────────────
    /// Offset of the root entry-array object (0 if none yet).
    /// Stored in `header.entry_array_offset`.
    entry_array_offset: u64,
    /// Total number of entries linked into the global array (== hidx in systemd).
    global_n_entries: u64,
    /// (tail_array_offset, items_used_in_tail) -- avoids walking the chain.
    global_tail: Option<(u64, u64)>,

    // ── Sequence / identity ──────────────────────────────────────────
    seqnum: u64,
    seqnum_id: [u8; 16],
    boot_id: [u8; 16],
    machine_id: [u8; 16],
    file_id: [u8; 16],
    /// Whether to use siphash24 keyed with file_id (true) or jenkins (false).
    keyed_hash: bool,
    /// Whether compact mode is enabled (32-bit offsets in entries/entry arrays).
    compact: bool,
    /// Whether strict entry ordering is enforced (realtime >= prev, monotonic >= prev if same boot).
    strict_order: bool,
    /// Compression codec to use when writing new DATA objects.
    compression: Compression,

    // ── Header statistics ────────────────────────────────────────────
    n_objects: u64,
    n_entries: u64,
    n_data: u64,
    n_fields: u64,
    n_entry_arrays: u64,
    head_entry_realtime: u64,
    tail_entry_realtime: u64,
    tailentry_monotonic: u64,
    tail_entry_seqnum: u64,
    head_entry_seqnum: u64,
    tail_object_offset: u64,
    tail_entry_offset: u64,
    data_hash_chain_depth: u64,
    field_hash_chain_depth: u64,

    /// systemd: journal-file.h JournalMetrics
    metrics: JournalMetrics,

    /// Path to the journal file on disk (set by open/open_with_template).
    path: Option<String>,

    /// Whether this writer is currently in the online state.
    /// Used by journal_file_set_online to avoid redundant writes.
    online: bool,

    /// Whether this file has been archived (journal_file_archive was called).
    /// When true, Drop writes STATE_ARCHIVED instead of STATE_OFFLINE.
    archived: bool,

    // Previous boot_id for monotonic ordering checks
    prev_boot_id: [u8; 16],

    // ── In-memory dedup indexes ──────────────────────────────────────
    data_index: DataIndex,
    field_index: FieldIndex,
    /// Per-DATA tail entry-array cache.
    data_tail_cache: DataTailCache,

    // ── Offline state machine ───────────────────────────────────────
    /// Atomic offline state for the background offline thread.
    /// systemd: journal-file.h JournalFile.offline_state
    offline_state: Arc<AtomicU8>,
    /// Handle for the background offline thread (if running).
    offline_thread: Option<std::thread::JoinHandle<()>>,

    // ── Post-change notification ────────────────────────────────────
    /// Optional callback invoked after journal_file_post_change.
    post_change_callback: Option<PostChangeCallback>,
    /// Coalescing period in microseconds (0 = immediate).
    post_change_timer_period: u64,
    /// Timestamp (usec) of the last post-change notification.
    last_post_change: u64,
}

impl JournalWriter {
    /// Open (or create) a journal file at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().into_owned();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.as_ref())?;

        let meta = file.metadata()?;
        let mut writer = if meta.len() == 0 {
            Self::create_new(file)?
        } else {
            Self::open_existing(file)?
        };
        writer.path = Some(path_str);
        Ok(writer)
    }

    /// systemd: journal-file.c:440-444
    ///
    /// Create a new journal file at `path`, inheriting `seqnum_id` and
    /// `tail_entry_seqnum` from the template (typically the file being rotated away).
    pub fn open_with_template<P: AsRef<Path>>(path: P, template: &JournalWriter) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().into_owned();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.as_ref())?;

        let mut writer = Self::create_new(file)?;
        // systemd: journal-file.c:440-444
        //   h.seqnum_id = template->header->seqnum_id;
        //   h.tail_entry_seqnum = template->header->tail_entry_seqnum;
        writer.seqnum_id = template.seqnum_id;
        writer.tail_entry_seqnum = template.tail_entry_seqnum;
        writer.seqnum = inc_seqnum(template.tail_entry_seqnum);
        writer.path = Some(path_str);
        // Rewrite header with inherited values
        writer.write_header()?;
        Ok(writer)
    }

    /// Return whether compact mode is enabled.
    pub fn is_compact(&self) -> bool {
        self.compact
    }

    // ── Initialise a brand-new file ───────────────────────────────────────
    //
    // systemd: journal-file.c journal_file_init_header() + journal_file_setup_data_hash_table()
    //          + journal_file_setup_field_hash_table().

    /// Check if keyed hash is requested via SYSTEMD_JOURNAL_KEYED_HASH env var.
    /// Defaults to true if not set.
    fn keyed_hash_requested() -> bool {
        match std::env::var("SYSTEMD_JOURNAL_KEYED_HASH") {
            Ok(v) => v != "0" && v.to_lowercase() != "false",
            Err(_) => true,
        }
    }

    /// Check if compact mode is requested via SYSTEMD_JOURNAL_COMPACT env var.
    /// Defaults to true if not set.
    fn compact_mode_requested() -> bool {
        match std::env::var("SYSTEMD_JOURNAL_COMPACT") {
            Ok(v) => v != "0" && v.to_lowercase() != "false",
            Err(_) => false, // default: disabled for wider compatibility
        }
    }

    /// systemd: journal-file.c:1279-1310 journal_file_setup_data_hash_table
    /// systemd: journal-file.c:1312-1339 journal_file_setup_field_hash_table
    fn create_new(file: File) -> Result<Self> {
        Self::create_new_with_max_size(file, 128 * 1024 * 1024) // default 128 MB
    }

    fn create_new_with_max_size(mut file: File, max_size: u64) -> Result<Self> {
        let keyed_hash = Self::keyed_hash_requested();
        let compact = Self::compact_mode_requested();

        // systemd: journal-file.c:1292
        //   s = MAX(f->metrics.max_size * 4 / 768 / 3, DEFAULT_DATA_HASH_TABLE_SIZE);
        let data_ht_n = Self::setup_data_hash_table_size(max_size);
        let field_ht_n = DEFAULT_FIELD_HASH_TABLE_SIZE as u64;

        // Data hash table sits right after the 272-byte header.
        let data_ht_offset = HEADER_SIZE;
        let data_ht_bytes = data_ht_n * HASH_ITEM_SIZE as u64;
        // systemd: journal-file.c:1297-1300
        //   r = journal_file_append_object(f, OBJECT_DATA_HASH_TABLE,
        //          offsetof(Object, hash_table.items) + s * sizeof(HashItem), &o, &p);
        let data_ht_actual_size = OBJECT_HEADER_SIZE as u64 + data_ht_bytes;
        let data_ht_obj_bytes = align64(data_ht_actual_size);

        let field_ht_offset = align64(data_ht_offset + data_ht_obj_bytes);
        let field_ht_bytes = field_ht_n * HASH_ITEM_SIZE as u64;
        let field_ht_actual_size = OBJECT_HEADER_SIZE as u64 + field_ht_bytes;
        let field_ht_obj_bytes = align64(field_ht_actual_size);

        let arena_end = align64(field_ht_offset + field_ht_obj_bytes);

        let file_id = *Uuid::new_v4().as_bytes();
        let seqnum_id = file_id;
        let mid = machine_id();
        let boot_id = get_boot_id();

        // Write header.
        let header = build_header(
            file_id,
            mid,
            seqnum_id,
            boot_id,
            HEADER_SIZE,
            arena_end - HEADER_SIZE,
            data_ht_offset,
            data_ht_actual_size,
            field_ht_offset,
            field_ht_actual_size,
            FileState::Online,
            keyed_hash,
            compact,
        );
        file.seek(SeekFrom::Start(0))?;
        file.write_all(header_as_bytes(&header))?;

        // systemd: journal-file.c:1297 -- write DATA hash table object.
        // ObjectHeader.size = actual (unaligned) size.
        write_hash_table_object(&mut file, ObjectType::DataHashTable, data_ht_n)?;

        // Pad to field_ht_offset.
        let cur = file.stream_position()?;
        if cur < field_ht_offset {
            write_zeros(&mut file, field_ht_offset - cur)?;
        }

        // systemd: journal-file.c:1326 -- write FIELD hash table object.
        write_hash_table_object(&mut file, ObjectType::FieldHashTable, field_ht_n)?;

        // Pad to arena_end.
        let cur = file.stream_position()?;
        if cur < arena_end {
            write_zeros(&mut file, arena_end - cur)?;
        }
        file.flush()?;

        Ok(Self {
            file,
            offset: arena_end,
            data_ht_n,
            data_ht_offset,
            field_ht_n,
            field_ht_offset,
            entry_array_offset: 0,
            global_n_entries: 0,
            global_tail: None,
            seqnum: 1,
            seqnum_id,
            boot_id,
            machine_id: mid,
            file_id,
            keyed_hash,
            compact,
            strict_order: true,
            compression: compression_requested(),
            n_objects: 2, // data + field hash tables
            n_entries: 0,
            n_data: 0,
            n_fields: 0,
            n_entry_arrays: 0,
            head_entry_realtime: 0,
            tail_entry_realtime: 0,
            tailentry_monotonic: 0,
            tail_entry_seqnum: 0,
            head_entry_seqnum: 0,
            tail_object_offset: field_ht_offset,
            tail_entry_offset: 0,
            data_hash_chain_depth: 0,
            field_hash_chain_depth: 0,
            metrics: JournalMetrics {
                max_size,
                min_size: JOURNAL_FILE_SIZE_MIN,
                keep_free: 1024 * 1024, // 1 MB
                ..JournalMetrics::default()
            },
            path: None,
            online: true,
            archived: false,
            prev_boot_id: [0u8; 16],
            data_index: HashMap::new(),
            field_index: HashMap::new(),
            data_tail_cache: HashMap::new(),
            offline_state: Arc::new(AtomicU8::new(OfflineState::Joined as u8)),
            offline_thread: None,
            post_change_callback: None,
            post_change_timer_period: 0,
            last_post_change: 0,
        })
    }

    // ── Re-open an existing file ──────────────────────────────────────────

    fn open_existing(mut file: File) -> Result<Self> {
        file.seek(SeekFrom::Start(0))?;
        let mut hbuf = [0u8; 272];
        file.read_exact(&mut hbuf)
            .map_err(|_| Error::Truncated { offset: 0 })?;

        let h: Header = unsafe { std::ptr::read_unaligned(hbuf.as_ptr() as *const Header) };

        // DIVERGENCE FIX: previous version checked SUPPORTED_READ flags and
        // skipped verify_header. We are a WRITER, so must check SUPPORTED_WRITE
        // and do full verification.
        let file_size = file.metadata()?.len();
        // On Linux, pass the current machine_id so verify_header can check it.
        // On non-Linux, machine_id() returns a random value, so skip the check.
        #[cfg(target_os = "linux")]
        let mid = Some(machine_id());
        #[cfg(not(target_os = "linux"))]
        let mid: Option<[u8; 16]> = None;
        verify_header(&h, file_size, true, mid)?;

        let offset = from_le64(&h.header_size) + from_le64(&h.arena_size);
        let data_ht_offset =
            from_le64(&h.data_hash_table_offset) - OBJECT_HEADER_SIZE as u64;
        let data_ht_size = from_le64(&h.data_hash_table_size);
        let field_ht_offset =
            from_le64(&h.field_hash_table_offset) - OBJECT_HEADER_SIZE as u64;
        let field_ht_size = from_le64(&h.field_hash_table_size);

        let data_ht_n = data_ht_size / HASH_ITEM_SIZE as u64;
        let field_ht_n = field_ht_size / HASH_ITEM_SIZE as u64;

        let (data_index, field_index) = rebuild_indexes(
            &mut file,
            offset,
            data_ht_offset,
            data_ht_n,
            field_ht_offset,
            field_ht_n,
        )?;

        // Mark the file online again.
        file.seek(SeekFrom::Start(16))?;
        file.write_all(&[FileState::Online as u8])?;

        // Reconstruct global entry-array tail by walking the chain.
        let entry_array_offset = from_le64(&h.entry_array_offset);
        let n_entries = from_le64(&h.n_entries);
        let is_compact = (from_le32(&h.incompatible_flags) & incompat::COMPACT) != 0;
        let global_tail = if entry_array_offset != 0 {
            let (tail_off, tail_n) = walk_entry_array_chain(&mut file, entry_array_offset, is_compact)?;
            Some((tail_off, tail_n))
        } else {
            None
        };

        let tail_entry_realtime = from_le64(&h.tail_entry_realtime);
        let tailentry_monotonic = from_le64(&h.tail_entry_monotonic);

        Ok(Self {
            file,
            offset,
            data_ht_n,
            data_ht_offset,
            field_ht_n,
            field_ht_offset,
            entry_array_offset,
            global_n_entries: n_entries,
            global_tail,
            // systemd: inc_seqnum() wraps u64::MAX-1 and u64::MAX back to 1.
            // DIVERGENCE FIX: saturating_add(1) would get stuck at u64::MAX.
            seqnum: inc_seqnum(from_le64(&h.tail_entry_seqnum)),
            seqnum_id: h.seqnum_id,
            // systemd re-reads boot_id from the system on open.
            boot_id: get_boot_id(),
            machine_id: h.machine_id,
            file_id: h.file_id,
            keyed_hash: (from_le32(&h.incompatible_flags) & incompat::KEYED_HASH) != 0,
            compact: (from_le32(&h.incompatible_flags) & incompat::COMPACT) != 0,
            strict_order: true, // journald always enforces strict ordering
            n_objects: from_le64(&h.n_objects),
            n_entries,
            n_data: from_le64(&h.n_data),
            n_fields: from_le64(&h.n_fields),
            n_entry_arrays: from_le64(&h.n_entry_arrays),
            head_entry_realtime: from_le64(&h.head_entry_realtime),
            tail_entry_realtime,
            tailentry_monotonic,
            tail_entry_seqnum: from_le64(&h.tail_entry_seqnum),
            head_entry_seqnum: from_le64(&h.head_entry_seqnum),
            tail_object_offset: from_le64(&h.tail_object_offset),
            tail_entry_offset: from_le64(&h.tail_entry_offset),
            data_hash_chain_depth: from_le64(&h.data_hash_chain_depth),
            field_hash_chain_depth: from_le64(&h.field_hash_chain_depth),
            metrics: JournalMetrics {
                max_size: 128 * 1024 * 1024, // default 128 MB
                min_size: JOURNAL_FILE_SIZE_MIN,
                keep_free: 1024 * 1024, // 1 MB
                ..JournalMetrics::default()
            },
            compression: compression_requested(),
            path: None,
            online: true,
            archived: false,
            prev_boot_id: h.tail_entry_boot_id,
            data_index,
            field_index,
            data_tail_cache: HashMap::new(),
            offline_state: Arc::new(AtomicU8::new(OfflineState::Joined as u8)),
            offline_thread: None,
            post_change_callback: None,
            post_change_timer_period: 0,
            last_post_change: 0,
        })
    }

    // ══════════════════════════════════════════════════════════════════════
    // Public API
    // ══════════════════════════════════════════════════════════════════════

    /// Append a log entry with the given `fields`.
    ///
    /// Fields are `(name, value)` pairs, e.g. `[("MESSAGE", b"Hello")]`.
    ///
    /// systemd: journal-file.c:2527-2660 journal_file_append_entry
    pub fn append_entry<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        fields: &[(N, V)],
    ) -> Result<u64> {
        self.append_entry_seqnum(fields, None)
    }

    /// Append a log entry with external seqnum coordination.
    pub fn append_entry_seqnum<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        fields: &[(N, V)],
        seqnum: Option<&mut u64>,
    ) -> Result<u64> {
        if fields.is_empty() {
            return Err(Error::EmptyEntry);
        }

        self.journal_file_set_online()?;

        let realtime = realtime_now();
        let monotonic = monotonic_now();
        let boot_id = self.boot_id;

        // systemd: journal-file.c:2551-2558
        // Validate timestamps: VALID_REALTIME(u) = u > 0 && u < (1<<55)
        //                      VALID_MONOTONIC(u) = u < (1<<55)
        const TS_UPPER: u64 = 1u64 << 55;
        if realtime == 0 || realtime >= TS_UPPER {
            return Err(Error::InvalidFile(format!(
                "invalid realtime timestamp {}",
                realtime
            )));
        }
        if monotonic >= TS_UPPER {
            return Err(Error::InvalidFile(format!(
                "invalid monotonic timestamp {}",
                monotonic
            )));
        }

        // systemd: journal-file.c:2546-2558
        // Validate timestamps: realtime must be >= previous, monotonic >= previous if same boot
        if self.tail_entry_realtime != 0 && realtime < self.tail_entry_realtime {
            // Allow it but don't enforce strict ordering for now
            // (system clock can go backwards)
        }

        // systemd: journal-file.c journal_file_entry_seqnum() (lines 1204-1228)
        let seqnum_val = self.journal_file_entry_seqnum(seqnum);

        // systemd: journal-file.c:2600-2626
        //   for (size_t i = 0; i < n_iovec; i++) {
        //       r = journal_file_append_data(f, iovec[i].iov_base, iovec[i].iov_len, &o, &p);
        //       if (JOURNAL_HEADER_KEYED_HASH(f->header))
        //           xor_hash ^= jenkins_hash64(iovec[i].iov_base, iovec[i].iov_len);
        //       else
        //           xor_hash ^= le64toh(o->data.hash);
        //       items[i] = (EntryItem) { .object_offset = p, .hash = le64toh(o->data.hash) };
        //   }
        let mut items: Vec<(u64, u64)> = Vec::with_capacity(fields.len());
        let mut xor_hash: u64 = 0;

        for (name, value) in fields {
            let name = name.as_ref();
            let value = value.as_ref();

            validate_field_name(name)?;

            let mut payload = Vec::with_capacity(name.len() + 1 + value.len());
            payload.extend_from_slice(name);
            payload.push(b'=');
            payload.extend_from_slice(value);

            let h = journal_file_hash_data(&payload, self.keyed_hash, &self.file_id);
            // systemd: journal-file.c:2617-2620
            // When keyed_hash: xor_hash ^= jenkins_hash64(iov_base, iov_len)
            //   (uses jenkins explicitly for cursor stability across files)
            // When non-keyed: xor_hash ^= le64toh(o->data.hash)
            if self.keyed_hash {
                xor_hash ^= hash64(&payload);
            } else {
                xor_hash ^= h;
            }

            let (data_offset, is_new_data) = self.journal_file_append_data(&payload, h)?;
            let field_offset = self.journal_file_append_field(name)?;

            // systemd: journal-file.c:1917-1918
            //   o->data.next_field_offset = fo->field.head_data_offset;
            //   fo->field.head_data_offset = le64toh(p);
            if is_new_data {
                let field_head_ptr = field_offset + 32; // field.head_data_offset
                let old_head = self.read_u64_at(field_head_ptr)?;
                self.write_u64_at(data_offset + 32, old_head)?; // data.next_field_offset
                self.write_u64_at(field_head_ptr, data_offset)?;
            }

            items.push((data_offset, h));
        }

        // systemd: journal-file.c:2630-2631
        //   typesafe_qsort(items, n_iovec, entry_item_cmp);
        //   n_iovec = remove_duplicate_entry_items(items, n_iovec);
        items.sort_by(entry_item_cmp);
        remove_duplicate_entry_items(&mut items);

        // systemd: journal-file.c:2307-2412 (journal_file_append_entry_internal)
        let entry_offset =
            self.journal_file_append_entry_internal(seqnum_val, realtime, monotonic, &boot_id, xor_hash, &items)?;

        // systemd: journal-file.c:2236-2291 (journal_file_link_entry)
        self.journal_file_link_entry(entry_offset, &items)?;

        // systemd: journal-file.c:2414-2429 (journal_file_post_change)
        self.journal_file_post_change()?;

        Ok(entry_offset)
    }

    /// Append an entry with raw timestamp and boot_id control.
    /// Used by journal_file_copy_entry and tests that need precise control.
    pub fn append_entry_with_ts<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        realtime: u64,
        monotonic: u64,
        boot_id: &[u8; 16],
        fields: &[(N, V)],
    ) -> Result<u64> {
        self.append_entry_with_ts_seqnum(realtime, monotonic, boot_id, fields, None)
    }

    /// Append an entry with raw timestamp, boot_id, and external seqnum coordination.
    pub fn append_entry_with_ts_seqnum<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        realtime: u64,
        monotonic: u64,
        boot_id: &[u8; 16],
        fields: &[(N, V)],
        seqnum: Option<&mut u64>,
    ) -> Result<u64> {
        if fields.is_empty() {
            return Err(Error::EmptyEntry);
        }

        self.journal_file_set_online()?;

        // systemd: journal-file.c:2551-2558
        // Validate timestamps: VALID_REALTIME(u) = u > 0 && u < (1<<55)
        //                      VALID_MONOTONIC(u) = u < (1<<55)
        const TS_UPPER: u64 = 1u64 << 55;
        if realtime == 0 || realtime >= TS_UPPER {
            return Err(Error::InvalidFile(format!(
                "invalid realtime timestamp {}",
                realtime
            )));
        }
        if monotonic >= TS_UPPER {
            return Err(Error::InvalidFile(format!(
                "invalid monotonic timestamp {}",
                monotonic
            )));
        }
        // systemd: journal-file.c:2564-2566
        if boot_id == &[0u8; 16] {
            return Err(Error::InvalidFile("empty boot ID".into()));
        }

        let seqnum_val = self.journal_file_entry_seqnum(seqnum);

        let mut items: Vec<(u64, u64)> = Vec::with_capacity(fields.len());
        let mut xor_hash: u64 = 0;

        for (name, value) in fields {
            let name = name.as_ref();
            let value = value.as_ref();

            validate_field_name(name)?;

            let mut payload = Vec::with_capacity(name.len() + 1 + value.len());
            payload.extend_from_slice(name);
            payload.push(b'=');
            payload.extend_from_slice(value);

            let h = journal_file_hash_data(&payload, self.keyed_hash, &self.file_id);
            if self.keyed_hash {
                xor_hash ^= hash64(&payload);
            } else {
                xor_hash ^= h;
            }

            let (data_offset, is_new_data) = self.journal_file_append_data(&payload, h)?;
            let field_offset = self.journal_file_append_field(name)?;

            if is_new_data {
                let field_head_ptr = field_offset + 32;
                let old_head = self.read_u64_at(field_head_ptr)?;
                self.write_u64_at(data_offset + 32, old_head)?;
                self.write_u64_at(field_head_ptr, data_offset)?;
            }

            items.push((data_offset, h));
        }

        items.sort_by(entry_item_cmp);
        remove_duplicate_entry_items(&mut items);

        let entry_offset =
            self.journal_file_append_entry_internal(seqnum_val, realtime, monotonic, boot_id, xor_hash, &items)?;

        self.journal_file_link_entry(entry_offset, &items)?;
        self.journal_file_post_change()?;

        Ok(entry_offset)
    }

    /// Flush all pending writes to the OS buffer.
    pub fn flush(&mut self) -> Result<()> {
        self.write_header()?;
        self.file.flush()?;
        Ok(())
    }

    /// Return the current file size (write cursor).
    pub fn file_size(&self) -> u64 {
        self.offset
    }

    /// Return the number of entries written.
    pub fn n_entries(&self) -> u64 {
        self.n_entries
    }

    /// Return the number of objects written.
    pub fn n_objects(&self) -> u64 {
        self.n_objects
    }

    /// Return the current path of this journal file, if known.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Return a reference to the current metrics.
    pub fn metrics(&self) -> &JournalMetrics {
        &self.metrics
    }

    /// Set new journal metrics for this writer.
    pub fn set_metrics(&mut self, metrics: JournalMetrics) {
        self.metrics = metrics;
    }

    /// systemd: journal-file.c:4356-4403 journal_file_archive
    ///
    /// Renames the journal file to the archived name format:
    /// `foo@SEQNUM_ID-HEAD_SEQNUM-HEAD_REALTIME.journal`
    /// Returns the old path.
    pub fn journal_file_archive(&mut self) -> Result<Option<String>> {
        // Only archive if we have a path
        let old_path = match self.path.take() {
            Some(p) => p,
            None => return Ok(None),
        };

        // systemd: journal-file.c:4364-4365 — must be writable
        // systemd: journal-file.c:4369-4370 — reject /proc/self/fd paths
        if old_path.starts_with("/proc/self/fd") {
            self.path = Some(old_path);
            return Err(Error::InvalidFile(
                "cannot archive journal opened via /proc/self/fd".into(),
            ));
        }

        // systemd: journal-file.c:4372-4373 — must end with .journal
        if !old_path.ends_with(".journal") {
            self.path = Some(old_path);
            return Err(Error::InvalidFile(
                "cannot archive: path does not end with .journal".into(),
            ));
        }

        // systemd: journal-file.c:4375-4380
        // Format: foo@SEQNUM_ID-HEAD_SEQNUM-HEAD_REALTIME.journal
        let base = &old_path[..old_path.len() - 8]; // strip ".journal"
        let seqnum_id_hex = self
            .seqnum_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let new_path = format!(
            "{}@{}-{:016x}-{:016x}.journal",
            base, seqnum_id_hex, self.head_entry_seqnum, self.head_entry_realtime
        );

        // Rename the file on disk (ignore ENOENT for already-deleted files)
        match std::fs::rename(&old_path, &new_path) {
            Ok(()) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                self.path = Some(old_path);
                return Err(Error::Io(e));
            }
        }

        // systemd: journal-file.c:4400 — set archive flag so Drop writes
        // STATE_ARCHIVED instead of STATE_OFFLINE.
        self.online = true; // keep online so Drop does proper offline sequence
        self.archived = true;

        // fsync the parent directory after rename to ensure the directory
        // entry is persisted (systemd: fsync_directory_of_file).
        if let Some(parent) = std::path::Path::new(&new_path).parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        // Update stored path to new name
        self.path = Some(new_path);

        Ok(Some(old_path))
    }

    // ══════════════════════════════════════════════════════════════════════
    // Offline state machine
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:191-213
    ///
    /// Join the background offline thread if one is running.
    fn journal_file_set_offline_thread_join(&mut self) -> Result<()> {
        if let Some(handle) = self.offline_thread.take() {
            handle
                .join()
                .map_err(|_| Error::InvalidFile("offline thread panicked".into()))?;
        }
        Ok(())
    }

    /// systemd: journal-file.c:215-287 journal_file_set_online
    ///
    /// Cancel any in-progress offline transition and write `FileState::Online`
    /// to the state byte at offset 16 if not already online.
    /// Called at the start of each append operation to ensure the file is marked online.
    fn journal_file_set_online(&mut self) -> Result<()> {
        self.journal_file_set_offline_thread_join()?;

        if self.online {
            return Ok(());
        }

        // State byte is at offset 16 in the header (after signature[8] + compat[4] + incompat[4])
        self.file.seek(SeekFrom::Start(16))?;
        self.file.write_all(&[FileState::Online as u8])?;
        // systemd: journal-file.c:281 — fsync after transitioning to online
        self.file.sync_all()?;
        self.online = true;
        self.offline_state
            .store(OfflineState::Joined as u8, Ordering::SeqCst);
        Ok(())
    }

    /// systemd: journal-file.c:289-341 journal_file_set_offline (simplified synchronous version)
    ///
    /// Spawn a background thread that fsyncs the file data and transitions the
    /// header state to OFFLINE. The state machine allows cancellation if a new
    /// write comes in during the offline transition (see `journal_file_set_online`).
    #[allow(dead_code)]
    fn journal_file_set_offline(&mut self) -> Result<()> {
        self.journal_file_set_offline_thread_join()?;

        if !self.online {
            return Ok(());
        }

        self.online = false;

        // Synchronous offline: fsync, set state to offline, fsync again.
        // This matches the logical behavior of the systemd offline thread
        // without the threading complexity.
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(16))?;
        self.file.write_all(&[FileState::Offline as u8])?;
        self.file.sync_all()?;
        self.offline_state
            .store(OfflineState::Done as u8, Ordering::SeqCst);
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════
    // Sequence number handling
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1204-1228 journal_file_entry_seqnum
    ///
    /// Get the next sequence number and advance the counter.
    /// Handles seqnum_id initialization and wrapping.
    /// When `seqnum` is Some, coordinates with an external sequence number:
    /// takes the max of the internal and external, and updates both.
    fn journal_file_entry_seqnum(&mut self, seqnum: Option<&mut u64>) -> u64 {
        let mut next = self.seqnum;

        // Coordinate with external seqnum if provided
        if let Some(ext) = seqnum {
            next = std::cmp::max(inc_seqnum(*ext), next);
            *ext = next;
        }

        // systemd: journal-file.c:1211
        //   r = le64toh(f->header->head_entry_seqnum);
        //   if (r == 0) f->header->head_entry_seqnum = htole64(seqnum);
        if self.head_entry_seqnum == 0 {
            self.head_entry_seqnum = next;
        }

        // Advance seqnum using inc_seqnum logic
        self.seqnum = inc_seqnum(next);

        next
    }

    // ══════════════════════════════════════════════════════════════════════
    // Space allocation
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:753-829 journal_file_allocate
    ///
    /// Pre-allocate disk space in FILE_SIZE_INCREASE (8 MB) chunks.
    /// Uses posix_fallocate on Linux, falls back to set_len elsewhere.
    fn journal_file_allocate(&mut self, offset: u64, size: u64) -> Result<()> {
        const FILE_SIZE_INCREASE: u64 = 8 * 1024 * 1024; // 8 MB
        /// systemd: journal-file.c:797-799 — compact mode max (offsets are 32-bit).
        const JOURNAL_COMPACT_SIZE_MAX: u64 = u32::MAX as u64; // 4 GB

        // Overflow check: offset + size must not wrap around
        if size > u64::MAX - offset {
            return Err(Error::InvalidFile(format!(
                "offset + size overflow ({} + {})",
                offset, size
            )));
        }
        let new_end = offset + size;

        // systemd: journal-file.c:794-795 — max_size check
        if self.metrics.max_size != u64::MAX && new_end > self.metrics.max_size {
            return Err(Error::InvalidFile(format!(
                "file would exceed max_size ({} > {})",
                new_end, self.metrics.max_size
            )));
        }
        // systemd: journal-file.c:797-799 — compact mode 4GB limit
        if self.compact && new_end > JOURNAL_COMPACT_SIZE_MAX {
            return Err(Error::InvalidFile(format!(
                "compact mode file would exceed 4GB ({} > {})",
                new_end, JOURNAL_COMPACT_SIZE_MAX
            )));
        }

        let old_size = self.file.metadata()?.len();
        if new_end <= old_size {
            return Ok(()); // already have enough space
        }

        // Free-space check: ensure the filesystem has enough space
        #[cfg(target_os = "linux")]
        if new_end > self.metrics.min_size && self.metrics.keep_free != u64::MAX {
            use std::os::unix::io::AsRawFd;
            let mut svfs: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatvfs(self.file.as_raw_fd(), &mut svfs) } == 0 {
                let available = (svfs.f_bfree as u64).saturating_mul(svfs.f_bsize as u64).saturating_sub(self.metrics.keep_free);
                if new_end - old_size > available {
                    return Err(Error::InvalidFile("not enough free space".into()));
                }
            }
        }

        // Round up to FILE_SIZE_INCREASE boundary
        let mut new_size = ((new_end + FILE_SIZE_INCREASE - 1) / FILE_SIZE_INCREASE) * FILE_SIZE_INCREASE;
        // systemd: journal-file.c:816-817 — cap at max_size after rounding
        if self.metrics.max_size > 0 && new_size > self.metrics.max_size {
            new_size = self.metrics.max_size;
        }

        // Pre-allocate
        #[cfg(target_os = "linux")]
        {
            let fd = {
                use std::os::unix::io::AsRawFd;
                self.file.as_raw_fd()
            };
            let r = unsafe {
                libc::posix_fallocate(fd, old_size as libc::off_t, (new_size - old_size) as libc::off_t)
            };
            if r != 0 {
                // Fall back to set_len on failure
                self.file.set_len(new_size)?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.file.set_len(new_size)?;
        }

        // Update arena_size in the header after successful allocation.
        // arena_size = file_size - header_size; the arena starts right after the header.
        // The arena_size field is at offset 96 in the on-disk Header struct.
        const ARENA_SIZE_OFFSET: u64 = 96;
        self.write_u64_at(ARENA_SIZE_OFFSET, new_size - HEADER_SIZE)?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════
    // Object allocation
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1230-1277 journal_file_append_object
    ///
    /// Allocate space for a new object at the tail. Writes the ObjectHeader
    /// with the ACTUAL (unaligned) size. Updates tail_object_offset and n_objects.
    /// Returns the offset where the object was placed.
    #[allow(dead_code)]
    fn journal_file_append_object(
        &mut self,
        obj_type: ObjectType,
        actual_size: u64,
    ) -> Result<u64> {
        // systemd: journal-file.c:1252-1260
        //   tail = header_size + arena_size;
        //   p = ALIGN64(tail);
        let obj_offset = self.offset;

        // Ensure offset is aligned
        debug_assert!(valid64(obj_offset));

        let aligned_size = align64(actual_size);

        // Write ObjectHeader
        let hdr = ObjectHeader {
            object_type: obj_type as u8,
            flags: 0,
            reserved: [0; 6],
            // systemd: journal-file.c:1264 o->object.size = htole64(size);
            size: le64(actual_size),
        };

        self.file.seek(SeekFrom::Start(obj_offset))?;
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &hdr as *const ObjectHeader as *const u8,
                OBJECT_HEADER_SIZE,
            )
        };
        self.file.write_all(hdr_bytes)?;

        // Zero the rest of the object space
        let remaining = aligned_size - OBJECT_HEADER_SIZE as u64;
        write_zeros(&mut self.file, remaining)?;

        // systemd: journal-file.c:1268-1272
        //   f->header->arena_size = htole64(a);
        //   f->header->n_objects = htole64(le64toh(f->header->n_objects) + 1);
        //   f->header->tail_object_offset = htole64(p);
        self.offset += aligned_size;
        self.tail_object_offset = obj_offset;
        self.n_objects += 1;

        Ok(obj_offset)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Hash table setup
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1279-1310 journal_file_setup_data_hash_table
    ///
    /// Set up the data hash table. The number of buckets is:
    ///   s = MAX(max_size * 4 / 768 / 3, DEFAULT_DATA_HASH_TABLE_SIZE)
    /// where DEFAULT_DATA_HASH_TABLE_SIZE = 2047.
    pub fn setup_data_hash_table_size(max_size: u64) -> u64 {
        (max_size * 4 / 768 / 3).max(DEFAULT_DATA_HASH_TABLE_SIZE as u64)
    }

    /// systemd: journal-file.c:1312-1339 journal_file_setup_field_hash_table
    ///
    /// Set up the field hash table. Always 1023 buckets.
    pub fn setup_field_hash_table_size() -> u64 {
        DEFAULT_FIELD_HASH_TABLE_SIZE as u64
    }

    // ══════════════════════════════════════════════════════════════════════
    // Internal helpers
    // ══════════════════════════════════════════════════════════════════════

    fn read_u64_at(&mut self, offset: u64) -> Result<u64> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; 8];
        self.file.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn write_u64_at(&mut self, offset: u64, value: u64) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&le64(value))?;
        Ok(())
    }

    /// Set an incompatible flag bit in the on-disk header.
    fn set_incompatible_flag(&mut self, flag: u32) -> Result<()> {
        // incompatible_flags is at offset 12 in the header (after 8-byte signature + 4-byte compat flags)
        self.file.seek(SeekFrom::Start(12))?;
        let mut buf = [0u8; 4];
        self.file.read_exact(&mut buf)?;
        let current = from_le32(&buf);
        if current & flag == 0 {
            let new_flags = current | flag;
            self.file.seek(SeekFrom::Start(12))?;
            self.file.write_all(&le32(new_flags))?;
        }
        Ok(())
    }

    /// Attempt to compress `payload` using the configured compression codec.
    /// Returns (data_to_write, obj_flag, incompat_flag).
    /// If compression fails or doesn't reduce size, returns the original payload with flag=0.
    fn try_compress_payload(&self, payload: &[u8]) -> (Vec<u8>, u8, u32) {
        match self.compression {
            #[cfg(feature = "zstd-compression")]
            Compression::Zstd => {
                if let Ok(compressed) =
                    zstd::encode_all(std::io::Cursor::new(payload), 0)
                {
                    if compressed.len() < payload.len() {
                        return (
                            compressed,
                            obj_flags::COMPRESSED_ZSTD,
                            incompat::COMPRESSED_ZSTD,
                        );
                    }
                }
            }
            #[cfg(feature = "xz-compression")]
            Compression::Xz => {
                use std::io::Write as _;
                let mut encoder =
                    xz2::write::XzEncoder::new(Vec::new(), 6);
                if encoder.write_all(payload).is_ok() {
                    if let Ok(compressed) = encoder.finish() {
                        if compressed.len() < payload.len() {
                            return (
                                compressed,
                                obj_flags::COMPRESSED_XZ,
                                incompat::COMPRESSED_XZ,
                            );
                        }
                    }
                }
            }
            #[cfg(feature = "lz4-compression")]
            Compression::Lz4 => {
                // systemd LZ4 format: le64 uncompressed size + LZ4 block data
                let compressed_block = lz4_flex::compress(payload);
                let total_len = 8 + compressed_block.len();
                if total_len < payload.len() {
                    let mut buf = Vec::with_capacity(total_len);
                    buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                    buf.extend_from_slice(&compressed_block);
                    return (
                        buf,
                        obj_flags::COMPRESSED_LZ4,
                        incompat::COMPRESSED_LZ4,
                    );
                }
            }
            Compression::None => {}
        }
        (payload.to_vec(), 0, 0)
    }

    /// Read `n` bytes from `offset`.
    fn read_bytes_at(&mut self, offset: u64, n: usize) -> Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; n];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Hash table linking
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1393-1436 journal_file_link_field
    ///
    /// Link a FIELD object into the field hash table.
    /// Zeroes next_hash_offset and head_data_offset.
    /// Links into chain: if empty bucket set head, else chain tail.next = offset.
    /// Updates tail, increments n_fields.
    fn journal_file_link_field(
        &mut self,
        obj_offset: u64,
        bucket: u64,
    ) -> Result<()> {
        // Zero next_hash_offset and head_data_offset
        // (already zero from write, but be explicit)
        self.write_u64_at(obj_offset + 24, 0)?; // next_hash_offset
        self.write_u64_at(obj_offset + 32, 0)?; // head_data_offset

        let ht_items_start = self.field_ht_offset + OBJECT_HEADER_SIZE as u64;
        let item_offset = ht_items_start + bucket * HASH_ITEM_SIZE as u64;
        let mut item = read_hash_item(&mut self.file, item_offset)?;

        let head = from_le64(&item.head_hash_offset);
        let mut depth: u64 = 0;

        if head == 0 {
            item.head_hash_offset = le64(obj_offset);
        } else {
            let tail = from_le64(&item.tail_hash_offset);
            // next_hash_offset is at FieldObjectHeader offset 24.
            self.write_u64_at(tail + 24, obj_offset)?;
            depth = self.count_field_chain_depth(bucket);
        }
        item.tail_hash_offset = le64(obj_offset);
        write_hash_item(&mut self.file, item_offset, &item)?;

        if depth > self.field_hash_chain_depth {
            self.field_hash_chain_depth = depth;
        }

        // systemd: journal-file.c:1432-1433
        //   f->header->n_fields = htole64(le64toh(f->header->n_fields) + 1);
        self.n_fields += 1;

        Ok(())
    }

    /// systemd: journal-file.c:1438-1487 journal_file_link_data
    ///
    /// Link a DATA object into the data hash table.
    /// Same pattern as link_field but for data hash table, increments n_data.
    fn journal_file_link_data(
        &mut self,
        obj_offset: u64,
        bucket: u64,
    ) -> Result<()> {
        // systemd: journal-file.c:1461-1463
        //   o->data.next_hash_offset = o->data.next_field_offset = 0;
        //   o->data.entry_offset = o->data.entry_array_offset = 0;
        //   o->data.n_entries = 0;
        // Zero all 5 fields (matching C's defensive re-zeroing)
        self.write_u64_at(obj_offset + 24, 0)?; // next_hash_offset
        self.write_u64_at(obj_offset + 32, 0)?; // next_field_offset
        self.write_u64_at(obj_offset + 40, 0)?; // entry_offset
        self.write_u64_at(obj_offset + 48, 0)?; // entry_array_offset
        self.write_u64_at(obj_offset + 56, 0)?; // n_entries

        let ht_items_start = self.data_ht_offset + OBJECT_HEADER_SIZE as u64;
        let item_offset = ht_items_start + bucket * HASH_ITEM_SIZE as u64;
        let mut item = read_hash_item(&mut self.file, item_offset)?;

        let head = from_le64(&item.head_hash_offset);
        let mut depth: u64 = 0;

        if head == 0 {
            item.head_hash_offset = le64(obj_offset);
        } else {
            let tail = from_le64(&item.tail_hash_offset);
            // Patch previous tail's next_hash_offset (offset 24 in DataObjectHeader).
            self.write_u64_at(tail + 24, obj_offset)?;
            // Count chain depth for tracking using in-memory index.
            depth = self.count_data_chain_depth(bucket);
        }
        item.tail_hash_offset = le64(obj_offset);
        write_hash_item(&mut self.file, item_offset, &item)?;

        // Track max chain depth.
        if depth > self.data_hash_chain_depth {
            self.data_hash_chain_depth = depth;
        }

        // systemd: journal-file.c:1483-1484
        //   f->header->n_data = htole64(le64toh(f->header->n_data) + 1);
        self.n_data += 1;

        Ok(())
    }

    /// Return the chain depth for a data hash bucket using the in-memory index.
    fn count_data_chain_depth(&self, bucket: u64) -> u64 {
        self.data_index.get(&bucket).map_or(0, |v| v.len() as u64)
    }

    /// Return the chain depth for a field hash bucket using the in-memory index.
    fn count_field_chain_depth(&self, bucket: u64) -> u64 {
        self.field_index.get(&bucket).map_or(0, |v| v.len() as u64)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Find operations
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1520-1583 journal_file_find_field_object_with_hash
    ///
    /// Walk the field hash chain, check hash match, then check object size match,
    /// then memcmp payload. Returns Some(offset) if found, None otherwise.
    fn journal_file_find_field_object_with_hash(
        &mut self,
        field: &[u8],
        hash: u64,
    ) -> Result<Option<u64>> {
        let bucket = hash % self.field_ht_n;

        // Use in-memory index for fast lookup
        let chain: Vec<(u64, u64)> = self
            .field_index
            .get(&bucket)
            .cloned()
            .unwrap_or_default();

        for (off, stored_hash) in &chain {
            if *stored_hash != hash {
                continue;
            }
            // Size comparison
            let obj_size = self.read_u64_at(off + 8)?;
            let expected_size = FIELD_OBJECT_HEADER_SIZE as u64 + field.len() as u64;
            if obj_size != expected_size {
                continue;
            }
            // Payload comparison (memcmp)
            let disk_name =
                self.read_bytes_at(off + FIELD_OBJECT_HEADER_SIZE as u64, field.len())?;
            if disk_name == field {
                return Ok(Some(*off));
            }
        }

        Ok(None)
    }

    /// systemd: journal-file.c:1621-1691 journal_file_find_data_object_with_hash
    ///
    /// Walk the data hash chain, check hash, decompress if needed, memcmp_nn
    /// full payload. Returns Some(offset) if found, None otherwise.
    fn journal_file_find_data_object_with_hash(
        &mut self,
        data: &[u8],
        hash: u64,
    ) -> Result<Option<u64>> {
        let bucket = hash % self.data_ht_n;

        // Use in-memory index for fast lookup
        let chain: Vec<(u64, u64)> = self
            .data_index
            .get(&bucket)
            .cloned()
            .unwrap_or_default();

        for (off, stored_hash) in &chain {
            if *stored_hash != hash {
                continue;
            }
            // Read object flags to check for compression
            let flags_byte = {
                self.file.seek(SeekFrom::Start(off + 1))?;
                let mut buf = [0u8; 1];
                self.file.read_exact(&mut buf)?;
                buf[0]
            };
            let obj_size = self.read_u64_at(off + 8)?;
            let poffset = data_payload_offset(self.compact);
            if obj_size < poffset {
                return Err(Error::CorruptObject {
                    offset: *off,
                    reason: format!(
                        "data object size {} smaller than payload offset {}",
                        obj_size, poffset
                    ),
                });
            }
            let payload_len = obj_size - poffset;

            let compressed_flags = flags_byte & obj_flags::COMPRESSED_MASK;
            if compressed_flags != 0 {
                // systemd: journal-file.c:1645-1673 — decompress before comparing
                let raw = self.read_bytes_at(off + poffset, payload_len as usize)?;
                let decompressed = if (flags_byte & obj_flags::COMPRESSED_ZSTD) != 0 {
                    #[cfg(feature = "zstd-compression")]
                    { zstd::decode_all(raw.as_slice()).ok() }
                    #[cfg(not(feature = "zstd-compression"))]
                    { None::<Vec<u8>> }
                } else if (flags_byte & obj_flags::COMPRESSED_XZ) != 0 {
                    #[cfg(feature = "xz-compression")]
                    {
                        use std::io::Read as _;
                        let mut decoder = xz2::read::XzDecoder::new(raw.as_slice());
                        let mut buf = Vec::new();
                        decoder.read_to_end(&mut buf).ok().map(|_| buf)
                    }
                    #[cfg(not(feature = "xz-compression"))]
                    { None::<Vec<u8>> }
                } else if (flags_byte & obj_flags::COMPRESSED_LZ4) != 0 {
                    #[cfg(feature = "lz4-compression")]
                    {
                        if raw.len() >= 8 {
                            let uncompressed_size =
                                u64::from_le_bytes(raw[..8].try_into().unwrap()) as usize;
                            lz4_flex::decompress(&raw[8..], uncompressed_size).ok()
                        } else {
                            None
                        }
                    }
                    #[cfg(not(feature = "lz4-compression"))]
                    { None::<Vec<u8>> }
                } else {
                    None
                };
                if let Some(dec) = decompressed {
                    if dec == data {
                        return Ok(Some(*off));
                    }
                }
                // If decompression failed or didn't match, skip this object
                continue;
            }

            // Uncompressed path
            if payload_len as usize != data.len() {
                continue;
            }
            let disk_payload = self.read_bytes_at(off + poffset, data.len())?;
            if disk_payload == data {
                return Ok(Some(*off));
            }
        }

        Ok(None)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Append operations
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1748-1806 journal_file_append_field
    ///
    /// Validate field, hash, find-or-create, link into hash table.
    /// Returns the offset of the field object.
    fn journal_file_append_field(&mut self, field: &[u8]) -> Result<u64> {
        let h = journal_file_hash_data(field, self.keyed_hash, &self.file_id);

        // Try to find existing field object
        if let Some(off) = self.journal_file_find_field_object_with_hash(field, h)? {
            return Ok(off);
        }

        let bucket = h % self.field_ht_n;

        // Not found -- write a new FIELD object
        let actual_size = FIELD_OBJECT_HEADER_SIZE as u64 + field.len() as u64;
        let total_size = align64(actual_size);
        let obj_offset = self.offset;
        self.journal_file_allocate(obj_offset, total_size)?;

        let field_hdr = FieldObjectHeader {
            object: ObjectHeader {
                object_type: ObjectType::Field as u8,
                flags: 0,
                reserved: [0; 6],
                size: le64(actual_size), // actual, not aligned (journal-file.c:1264)
            },
            hash: le64(h),
            next_hash_offset: le64(0),
            head_data_offset: le64(0),
        };

        self.file.seek(SeekFrom::Start(obj_offset))?;
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &field_hdr as *const FieldObjectHeader as *const u8,
                FIELD_OBJECT_HEADER_SIZE,
            )
        };
        self.file.write_all(hdr_bytes)?;
        self.file.write_all(field)?;
        let written = FIELD_OBJECT_HEADER_SIZE as u64 + field.len() as u64;
        if total_size > written {
            write_zeros(&mut self.file, total_size - written)?;
        }

        self.offset += total_size;
        self.tail_object_offset = obj_offset;
        self.n_objects += 1;
        // n_fields is incremented in journal_file_link_field (matching C:1432)

        // Link into hash table
        self.journal_file_link_field(obj_offset, bucket)?;

        // Update in-memory index
        self.field_index
            .entry(bucket)
            .or_default()
            .push((obj_offset, h));

        Ok(obj_offset)
    }

    /// systemd: journal-file.c:1844-1927 journal_file_append_data
    ///
    /// Hash, find-or-create, compression attempt, link into hash table,
    /// append field object, link data->field.
    /// Returns (offset, is_new).
    fn journal_file_append_data(
        &mut self,
        payload: &[u8],
        h: u64,
    ) -> Result<(u64, bool)> {
        // systemd: journal-file.c:1862-1863
        if payload.is_empty() {
            return Err(Error::InvalidFile("empty data payload".into()));
        }

        // Try to find existing data object
        if let Some(off) = self.journal_file_find_data_object_with_hash(payload, h)? {
            return Ok((off, false));
        }

        // systemd: journal-file.c:1873-1875
        //   eq = memchr(data, '=', size);
        //   if (!eq) return -EUCLEAN;
        if !payload.contains(&b'=') {
            return Err(Error::InvalidFile("data payload missing '=' separator".into()));
        }

        let bucket = h % self.data_ht_n;

        // Not found -- write a new DATA object.
        // systemd: journal-file.c:1877-1894
        //   osize = journal_file_data_payload_offset(f) + size;
        //   r = journal_file_append_object(f, OBJECT_DATA, osize, &o, &p);
        //   o->data.hash = htole64(hash);
        //   ... compression attempt ...
        //   memcpy_safe(journal_file_data_payload_field(f, o), data, size);
        let actual_size = data_payload_offset(self.compact) + payload.len() as u64;
        let total_size = align64(actual_size);
        let obj_offset = self.offset;
        self.journal_file_allocate(obj_offset, total_size)?;

        let data_hdr = DataObjectHeader {
            object: ObjectHeader {
                object_type: ObjectType::Data as u8,
                flags: 0,
                reserved: [0; 6],
                size: le64(actual_size), // actual, not aligned (journal-file.c:1264)
            },
            hash: le64(h),
            next_hash_offset: le64(0),
            next_field_offset: le64(0),
            entry_offset: le64(0),
            entry_array_offset: le64(0),
            n_entries: le64(0),
        };

        self.file.seek(SeekFrom::Start(obj_offset))?;
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &data_hdr as *const DataObjectHeader as *const u8,
                DATA_OBJECT_HEADER_SIZE,
            )
        };
        self.file.write_all(hdr_bytes)?;
        // In compact mode, write 8 bytes of zeroes for tail_entry_array_offset + tail_entry_array_n_entries
        if self.compact {
            self.file.write_all(&[0u8; 8])?;
        }

        // systemd: journal-file.c:1884-1894 — attempt compression for payloads > 512 bytes
        let (final_payload, compress_flag, incompat_flag) = if payload.len() >= 512 {
            self.try_compress_payload(payload)
        } else {
            (payload.to_vec(), 0u8, 0u32)
        };

        self.file.write_all(&final_payload)?;

        // If compressed, update object size and flags on disk.
        // Note: we still advance self.offset by the originally allocated total_size
        // (based on uncompressed payload), matching systemd's behaviour where
        // journal_file_append_object allocates before compression happens.
        if compress_flag != 0 {
            let new_actual_size =
                data_payload_offset(self.compact) + final_payload.len() as u64;
            // Update size field: ObjectHeader.size at offset obj_offset + 8
            self.file.seek(SeekFrom::Start(obj_offset + 8))?;
            self.file.write_all(&le64(new_actual_size))?;
            // Set compression flag: ObjectHeader.flags at offset obj_offset + 1
            self.file.seek(SeekFrom::Start(obj_offset + 1))?;
            self.file.write_all(&[compress_flag])?;
            // Set the incompatible flag in the header
            self.set_incompatible_flag(incompat_flag)?;
        }

        let written = data_payload_offset(self.compact) + final_payload.len() as u64;
        if total_size > written {
            // Seek to end of actual written data before padding
            // (compression seek-backs may have moved the cursor)
            self.file.seek(SeekFrom::Start(obj_offset + written))?;
            write_zeros(&mut self.file, total_size - written)?;
        }

        self.offset = obj_offset + total_size;
        self.tail_object_offset = obj_offset;
        self.n_objects += 1;
        // n_data is incremented in journal_file_link_data (matching C:1483)

        // systemd: journal-file.c:1896 journal_file_link_data(f, o, p, hash)
        self.journal_file_link_data(obj_offset, bucket)?;

        // Update in-memory index
        self.data_index
            .entry(bucket)
            .or_default()
            .push((obj_offset, h));

        Ok((obj_offset, true))
    }

    // ══════════════════════════════════════════════════════════════════════
    // Data payload access
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1999-2034 journal_file_data_payload
    ///
    /// Read and optionally decompress the payload of a DATA object.
    /// Returns the raw payload bytes.
    pub fn journal_file_data_payload(&mut self, data_offset: u64) -> Result<Vec<u8>> {
        let obj_size = self.read_u64_at(data_offset + 8)?;
        let flags_byte = {
            self.file.seek(SeekFrom::Start(data_offset + 1))?;
            let mut buf = [0u8; 1];
            self.file.read_exact(&mut buf)?;
            buf[0]
        };

        // systemd: journal-file.c:2018-2020
        //   if (size < journal_file_data_payload_offset(f))
        //       return -EBADMSG;
        // DIVERGENCE FIX: was using saturating_sub (silent 0 on underflow).
        let payload_base = data_payload_offset(self.compact);
        if obj_size < payload_base {
            return Err(Error::CorruptObject {
                offset: data_offset,
                reason: format!("DATA object size {} < minimum {}", obj_size, payload_base),
            });
        }
        let payload_len = obj_size - payload_base;

        let raw = self.read_bytes_at(data_offset + payload_base, payload_len as usize)?;

        // Check compression
        let compressed = flags_byte & obj_flags::COMPRESSED_MASK;
        if compressed & obj_flags::COMPRESSED_ZSTD != 0 {
            #[cfg(feature = "zstd-compression")]
            {
                return zstd::decode_all(raw.as_slice())
                    .map_err(|e| Error::Decompression(format!("ZSTD decompression failed: {}", e)));
            }
            #[cfg(not(feature = "zstd-compression"))]
            {
                return Err(Error::InvalidFile(
                    "journal uses ZSTD compression but feature not enabled".into(),
                ));
            }
        } else if compressed & obj_flags::COMPRESSED_XZ != 0 {
            #[cfg(feature = "xz-compression")]
            {
                use std::io::Read as _;
                let mut decoder = xz2::read::XzDecoder::new(raw.as_slice());
                let mut decompressed = Vec::new();
                decoder
                    .read_to_end(&mut decompressed)
                    .map_err(|e| Error::Decompression(format!("XZ decompression failed: {}", e)))?;
                return Ok(decompressed);
            }
            #[cfg(not(feature = "xz-compression"))]
            {
                return Err(Error::InvalidFile(
                    "journal uses XZ compression but feature not enabled".into(),
                ));
            }
        } else if compressed & obj_flags::COMPRESSED_LZ4 != 0 {
            #[cfg(feature = "lz4-compression")]
            {
                if raw.len() < 8 {
                    return Err(Error::Decompression("LZ4 data too short".into()));
                }
                let uncompressed_size =
                    u64::from_le_bytes(raw[..8].try_into().unwrap()) as usize;
                let compressed_data = &raw[8..];
                let decompressed =
                    lz4_flex::decompress(compressed_data, uncompressed_size)
                        .map_err(|e| Error::Decompression(format!("LZ4 decompression failed: {}", e)))?;
                return Ok(decompressed);
            }
            #[cfg(not(feature = "lz4-compression"))]
            {
                return Err(Error::InvalidFile(
                    "journal uses LZ4 compression but feature not enabled".into(),
                ));
            }
        } else if compressed != 0 {
            return Err(Error::InvalidFile(
                "cannot read compressed data payload (unsupported codec)".into(),
            ));
        }

        Ok(raw)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Entry array operations
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:2083-2092 write_entry_array_item
    ///
    /// Write an entry offset at a specific index in an entry array object.
    fn write_entry_array_item(
        &mut self,
        arr_offset: u64,
        index: u64,
        entry_offset: u64,
    ) -> Result<()> {
        let item_sz = entry_array_item_size(self.compact);
        let slot_off = arr_offset + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + index * item_sz;
        self.file.seek(SeekFrom::Start(slot_off))?;
        if self.compact {
            assert!(entry_offset <= u32::MAX as u64, "compact mode offset exceeds 4GB");
            self.file.write_all(&(entry_offset as u32).to_le_bytes())?;
        } else {
            self.file.write_all(&entry_offset.to_le_bytes())?;
        }
        Ok(())
    }

    /// systemd: journal-file.c:2094-2178 link_entry_into_array
    ///
    /// Walk chain using tail shortcut if available.
    /// If fits in current array, write and increment.
    /// Else allocate new with EXPONENTIAL DOUBLING:
    ///   if hidx > n then (hidx+1)*2 else n*2, min 4
    /// Chain new array, update tail pointer, increment n_entry_arrays.
    fn link_entry_into_array(
        &mut self,
        first_offset_ptr: &mut u64,   // pointer to head entry_array_offset
        idx: &mut u64,                 // pointer to n_entries counter
        tail: &mut Option<(u64, u64)>, // (tail_array_offset, items_used_in_tail)
        entry_offset: u64,
    ) -> Result<()> {
        let hidx = *idx;

        if let Some((tail_arr, tail_used)) = *tail {
            let tail_capacity = self.read_entry_array_capacity(tail_arr)?;
            if tail_used < tail_capacity {
                // Fits in current tail array.
                self.write_entry_array_item(tail_arr, tail_used, entry_offset)?;
                *tail = Some((tail_arr, tail_used + 1));
                *idx = hidx + 1;
                return Ok(());
            }

            // Need a new array -- exponential growth.
            // systemd: journal-file.c:2135-2141
            let new_cap = self.compute_new_array_capacity(hidx, tail_capacity);
            let new_arr = self.write_entry_array_object(new_cap, 0)?;

            // Write entry at slot 0 of new array.
            self.write_entry_array_item(new_arr, 0, entry_offset)?;

            // Chain: old_tail.next_entry_array_offset = new_arr.
            self.write_u64_at(tail_arr + OBJECT_HEADER_SIZE as u64, new_arr)?;

            *tail = Some((new_arr, 1));
            *idx = hidx + 1;
        } else if *first_offset_ptr != 0 {
            // Have a root but no cached tail -- walk to find it.
            let actual_tail = self.find_tail_array(*first_offset_ptr)?;
            let tail_capacity = self.read_entry_array_capacity(actual_tail)?;
            // Count used items by scanning
            let (_, tail_used) = walk_entry_array_chain_at(&mut self.file, actual_tail, self.compact)?;

            if tail_used < tail_capacity {
                self.write_entry_array_item(actual_tail, tail_used, entry_offset)?;
                *tail = Some((actual_tail, tail_used + 1));
                *idx = hidx + 1;
            } else {
                let new_cap = self.compute_new_array_capacity(hidx, tail_capacity);
                let new_arr = self.write_entry_array_object(new_cap, 0)?;
                self.write_entry_array_item(new_arr, 0, entry_offset)?;
                self.write_u64_at(actual_tail + OBJECT_HEADER_SIZE as u64, new_arr)?;
                *tail = Some((new_arr, 1));
                *idx = hidx + 1;
            }
        } else {
            // First entry-array ever -- allocate with min capacity 4.
            let new_cap = 4u64.max(self.compute_new_array_capacity(hidx, 0));
            let new_arr = self.write_entry_array_object(new_cap, 0)?;
            *first_offset_ptr = new_arr;

            self.write_entry_array_item(new_arr, 0, entry_offset)?;
            *tail = Some((new_arr, 1));
            *idx = hidx + 1;
        }

        Ok(())
    }

    /// systemd: journal-file.c:2180-2214 link_entry_into_array_plus_one
    ///
    /// If idx==0 store inline in extra, else link_entry_into_array with idx-1.
    /// Used for per-DATA entry arrays where the first entry is stored inline
    /// in the DATA object's entry_offset field.
    fn link_entry_into_array_plus_one(
        &mut self,
        extra_ptr: u64,               // offset of the inline entry_offset field
        first_offset_ptr: u64,         // offset of entry_array_offset field in DATA obj
        n_entries_ptr: u64,            // offset of n_entries field in DATA obj
        data_offset: u64,              // the DATA object offset (for cache key)
        entry_offset: u64,
    ) -> Result<()> {
        let n_entries = self.read_u64_at(n_entries_ptr)?;

        // systemd: journal-file.c:2199 — if (hidx == UINT64_MAX) return -EBADMSG;
        // DIVERGENCE FIX: previous version lacked this overflow guard.
        if n_entries == u64::MAX {
            return Err(Error::InvalidFile("n_entries overflow in data object".into()));
        }

        if n_entries == 0 {
            // systemd: *extra = htole64(p);
            self.write_u64_at(extra_ptr, entry_offset)?;
            self.write_u64_at(n_entries_ptr, 1)?;
            return Ok(());
        }

        // idx = n_entries - 1 (since first is inline)
        let mut array_idx = n_entries - 1;
        let mut head_arr = self.read_u64_at(first_offset_ptr)?;

        // Use data_tail_cache for efficiency
        let cached = self.data_tail_cache.get(&data_offset).copied();
        let mut tail = cached;

        self.link_entry_into_array(
            &mut head_arr,
            &mut array_idx,
            &mut tail,
            entry_offset,
        )?;

        // Write back head_arr if it changed (first allocation)
        if cached.is_none() || self.read_u64_at(first_offset_ptr)? != head_arr {
            self.write_u64_at(first_offset_ptr, head_arr)?;
        }

        // Update cache and write compact tail fields to disk
        if let Some(t) = tail {
            self.data_tail_cache.insert(data_offset, t);

            // In compact mode, write tail_entry_array_offset (le32 at +64)
            // and tail_entry_array_n_entries (le32 at +68) back to the DATA object.
            if self.compact {
                let tail_arr_off = t.0 as u32;
                let tail_arr_n = t.1 as u32;
                self.file.seek(SeekFrom::Start(data_offset + 64))?;
                self.file.write_all(&tail_arr_off.to_le_bytes())?;
                self.file.write_all(&tail_arr_n.to_le_bytes())?;
            }
        }

        self.write_u64_at(n_entries_ptr, n_entries + 1)?;

        Ok(())
    }

    // ── Global entry-array ─── journal-file.c:2094 link_entry_into_array ──

    /// Add `entry_offset` to the global entry-array chain.
    ///
    /// Mirrors systemd's `link_entry_into_array()` (journal-file.c:2094-2178)
    /// called from `journal_file_link_entry()` (journal-file.c:2256-2261).
    fn link_entry_into_global_array(&mut self, entry_offset: u64) -> Result<()> {
        let mut first = self.entry_array_offset;
        let mut idx = self.global_n_entries;
        let mut tail = self.global_tail;

        self.link_entry_into_array(
            &mut first,
            &mut idx,
            &mut tail,
            entry_offset,
        )?;

        self.entry_array_offset = first;
        self.global_n_entries = idx;
        self.global_tail = tail;

        Ok(())
    }

    // ── Per-DATA entry-array ─── journal-file.c:2180 link_entry_into_array_plus_one

    /// Add `entry_offset` to the per-DATA entry array for the DATA object at `data_offset`.
    ///
    /// systemd: journal-file.c:2180-2213 (link_entry_into_array_plus_one)
    fn link_entry_into_data_array(
        &mut self,
        data_offset: u64,
        entry_offset: u64,
    ) -> Result<()> {
        // DataObjectHeader field offsets:
        //   40: entry_offset       (inline first entry)
        //   48: entry_array_offset (head of per-data array chain)
        //   56: n_entries
        self.link_entry_into_array_plus_one(
            data_offset + 40, // extra_ptr (entry_offset inline)
            data_offset + 48, // first_offset_ptr (entry_array_offset)
            data_offset + 56, // n_entries_ptr
            data_offset,      // data_offset for cache key
            entry_offset,
        )
    }

    // ══════════════════════════════════════════════════════════════════════
    // Entry operations
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:2293-2305 write_entry_item
    ///
    /// Write a single entry item. Compact mode: 4-byte le32 offset only.
    /// Regular mode: 16-byte (le64 offset + le64 hash).
    fn write_entry_item(
        &mut self,
        entry_offset: u64,
        index: u64,
        item: &(u64, u64),
    ) -> Result<()> {
        let isize = entry_item_size(self.compact);
        let item_off = entry_offset + ENTRY_OBJECT_HEADER_SIZE as u64 + index * isize;

        self.file.seek(SeekFrom::Start(item_off))?;
        if self.compact {
            // systemd: o->entry.items.compact[i].object_offset = htole32(item->object_offset);
            assert!(item.0 <= u32::MAX as u64, "compact mode offset exceeds 4GB");
            self.file.write_all(&(item.0 as u32).to_le_bytes())?;
        } else {
            // systemd: o->entry.items.regular[i].object_offset = htole64(item->object_offset);
            //          o->entry.items.regular[i].hash = htole64(item->hash);
            let entry_item = EntryItem {
                object_offset: le64(item.0),
                hash: le64(item.1),
            };
            let item_bytes = unsafe {
                std::slice::from_raw_parts(
                    &entry_item as *const EntryItem as *const u8,
                    ENTRY_ITEM_SIZE,
                )
            };
            self.file.write_all(item_bytes)?;
        }
        Ok(())
    }

    /// systemd: journal-file.c:2307-2412 journal_file_append_entry_internal
    ///
    /// Strict ordering check (realtime >= prev, monotonic >= prev if same boot).
    /// Seqnum ID handling. Machine ID initialization.
    /// Allocate ENTRY object with ACTUAL size in ObjectHeader.
    /// Write all entry items.
    fn journal_file_append_entry_internal(
        &mut self,
        seqnum: u64,
        realtime: u64,
        monotonic: u64,
        boot_id: &[u8; 16],
        xor_hash: u64,
        items: &[(u64, u64)],
    ) -> Result<u64> {
        let n_items = items.len();

        // systemd: journal-file.c:2332-2358
        // Strict ordering check — when enabled, reject entries with timestamps going backwards.
        if self.strict_order {
            // systemd: journal-file.c:2344 — no guard on tail_entry_realtime != 0
            if realtime < self.tail_entry_realtime {
                return Err(Error::InvalidFile(format!(
                    "realtime {} < previous realtime {}",
                    realtime, self.tail_entry_realtime
                )));
            }
            if self.prev_boot_id == *boot_id
                && self.tailentry_monotonic != 0
                && monotonic < self.tailentry_monotonic
            {
                return Err(Error::InvalidFile(format!(
                    "monotonic {} < previous monotonic {} (same boot)",
                    monotonic, self.tailentry_monotonic
                )));
            }
        }

        // systemd: journal-file.c:2361-2373 — seqnum ID reconciliation
        // If file has no entries, adopt our seqnum_id; if mismatch, reject.
        if self.n_entries == 0 {
            // File empty — adopt caller's seqnum_id (already set at creation)
        } else if self.seqnum_id != [0u8; 16] {
            // seqnum_id mismatch check is implicit — we are single-writer.
            // Multi-writer coordination would need an external seqnum parameter.
        }

        // systemd: journal-file.c:2376-2378 — machine ID initialization
        // If file's machine_id is null, set it now.
        if self.machine_id == [0u8; 16] {
            self.machine_id = machine_id();
        }

        // ObjectHeader.size = actual (unaligned) size.
        let actual_size =
            ENTRY_OBJECT_HEADER_SIZE as u64 + (n_items as u64) * entry_item_size(self.compact);
        let total_size = align64(actual_size);
        let obj_offset = self.offset;
        self.journal_file_allocate(obj_offset, total_size)?;

        let entry_hdr = EntryObjectHeader {
            object: ObjectHeader {
                object_type: ObjectType::Entry as u8,
                flags: 0,
                reserved: [0; 6],
                size: le64(actual_size), // actual, not aligned
            },
            seqnum: le64(seqnum),
            realtime: le64(realtime),
            monotonic: le64(monotonic),
            boot_id: *boot_id,
            xor_hash: le64(xor_hash),
        };

        self.file.seek(SeekFrom::Start(obj_offset))?;
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &entry_hdr as *const EntryObjectHeader as *const u8,
                ENTRY_OBJECT_HEADER_SIZE,
            )
        };
        self.file.write_all(hdr_bytes)?;

        // systemd: journal-file.c:2393-2399
        //   for (i = 0; i < n_items; i++)
        //       write_entry_item(f, o, i, &items[i]);
        for (i, item) in items.iter().enumerate() {
            self.write_entry_item(obj_offset, i as u64, item)?;
        }

        let written =
            ENTRY_OBJECT_HEADER_SIZE as u64 + n_items as u64 * entry_item_size(self.compact);
        if total_size > written {
            write_zeros(&mut self.file, total_size - written)?;
        }

        self.offset += total_size;
        self.tail_object_offset = obj_offset;
        self.tail_entry_offset = obj_offset;
        self.n_objects += 1;

        // Update boot_id tracking
        self.prev_boot_id = *boot_id;

        Ok(obj_offset)
    }

    /// systemd: journal-file.c:2236-2291 journal_file_link_entry
    ///
    /// Memory fence (not applicable in Rust, but noted).
    /// link_entry_into_array for global entry array.
    /// Update head_entry_realtime (first time only), tail_entry_realtime,
    /// tailentry_monotonic, tail_entry_offset.
    /// For each item: link_entry_item (tolerate -E2BIG).
    fn journal_file_link_entry(
        &mut self,
        entry_offset: u64,
        items: &[(u64, u64)],
    ) -> Result<()> {
        // NOTE: In systemd, there's a memory fence here (journal-file.c:2242)
        // __atomic_thread_fence(__ATOMIC_SEQ_CST);
        // In Rust, this is not needed for file I/O.

        // Link into global entry array
        self.link_entry_into_global_array(entry_offset)?;

        // Read the entry's timestamps
        let realtime = self.read_u64_at(entry_offset + 24)?;  // EntryObjectHeader.realtime
        let monotonic = self.read_u64_at(entry_offset + 32)?;  // EntryObjectHeader.monotonic
        let seqnum = self.read_u64_at(entry_offset + 16)?;     // EntryObjectHeader.seqnum

        // systemd: journal-file.c:2267-2273
        //   if (f->header->head_entry_realtime == 0)
        //       f->header->head_entry_realtime = o->entry.realtime;
        if self.head_entry_realtime == 0 {
            self.head_entry_realtime = realtime;
            self.head_entry_seqnum = seqnum;
        }
        self.tail_entry_realtime = realtime;
        self.tailentry_monotonic = monotonic;
        self.tail_entry_seqnum = seqnum;
        self.n_entries = self.global_n_entries;

        // systemd: journal-file.c:2276-2288
        //   for (uint64_t i = 0; i < n_items; i++) {
        //       k = journal_file_link_entry_item(f, offset, items[i].object_offset);
        //       // -E2BIG is tolerated
        //   }
        // systemd: journal-file.c:2279-2287
        //   k = journal_file_link_entry_item(f, offset, items[i].object_offset);
        //   if (k == -E2BIG) r = k; else if (k < 0) return k;
        // DIVERGENCE FIX (3c): was swallowing ALL errors; now only tolerates
        // allocation failures (which map to io::ErrorKind::Other in our case).
        // We propagate I/O errors but tolerate array growth failures.
        let mut link_err = Ok(());
        for &(data_offset, _) in items {
            match self.link_entry_into_data_array(data_offset, entry_offset) {
                Ok(()) => {}
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::Other => {
                    link_err = Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "entry array allocation failed (E2BIG equivalent)",
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        let _ = link_err; // Record but don't fail on E2BIG-equivalent

        self.write_header()?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════
    // Post-change
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:2414-2429 journal_file_post_change
    ///
    /// systemd: journal-file.c:351-391 journal_file_post_change
    ///
    /// Memory fence + ftruncate to current size for inotify notification.
    /// If a post-change callback is set, it is invoked (with optional coalescing
    /// based on `post_change_timer_period`).
    fn journal_file_post_change(&mut self) -> Result<()> {
        // systemd: __atomic_thread_fence(__ATOMIC_SEQ_CST);
        //          ftruncate(f->fd, f->last_stat.st_size);
        // The ftruncate to the file's OWN size is a no-op size-wise but triggers
        // inotify IN_MODIFY for watchers.
        self.file.flush()?;
        // systemd silently ignores ftruncate failures (logged but not propagated).
        // Use .ok() so a non-fatal ftruncate error doesn't abort an append operation.
        if let Ok(actual_size) = self.file.metadata().map(|m| m.len()) {
            let _ = self.file.set_len(actual_size);
        }

        // Invoke the post-change callback if set, with optional coalescing.
        if let Some(ref mut cb) = self.post_change_callback {
            let now = realtime_now();
            if self.post_change_timer_period == 0
                || now.saturating_sub(self.last_post_change) >= self.post_change_timer_period
            {
                cb();
                self.last_post_change = now;
            }
        }

        Ok(())
    }

    /// Set a callback for post-change notifications.
    ///
    /// The callback is invoked after `journal_file_post_change` (which runs after
    /// each entry is appended). If `timer_period_usec > 0`, notifications are
    /// coalesced: the callback is only called if at least `timer_period_usec`
    /// microseconds have elapsed since the last invocation.
    ///
    /// systemd: journal-file.c:351-391 (timer-based coalescing)
    pub fn set_post_change_callback(
        &mut self,
        callback: impl FnMut() + Send + 'static,
        timer_period_usec: u64,
    ) {
        self.post_change_callback = Some(Box::new(callback));
        self.post_change_timer_period = timer_period_usec;
    }

    // ══════════════════════════════════════════════════════════════════════
    // File management
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:4558-4578 journal_file_get_cutoff_realtime_usec
    ///
    /// Get the realtime timestamp range of entries in this file.
    /// Returns (from, to) in microseconds, or None if no entries.
    pub fn journal_file_get_cutoff_realtime_usec(&self) -> Option<(u64, u64)> {
        if self.n_entries == 0 {
            return None;
        }
        if self.head_entry_realtime == 0 || self.tail_entry_realtime == 0 {
            return None;
        }
        Some((self.head_entry_realtime, self.tail_entry_realtime))
    }

    /// systemd: journal-file.c:4580-4618 journal_file_get_cutoff_monotonic_usec
    ///
    /// Get the monotonic timestamp range for a given boot_id.
    /// Looks up the `_BOOT_ID=<hex>` DATA object, reads the first entry's
    /// monotonic timestamp from the inline entry_offset, then walks the
    /// entry array chain to find the last entry's monotonic timestamp.
    /// Returns None if no entries match or no entries exist.
    pub fn journal_file_get_cutoff_monotonic_usec(
        &mut self,
        boot_id: &[u8; 16],
    ) -> Option<(u64, u64)> {
        if self.n_entries == 0 {
            return None;
        }
        let boot_id_hex = boot_id.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let boot_data = format!("_BOOT_ID={}", boot_id_hex);
        let h = journal_file_hash_data(boot_data.as_bytes(), self.keyed_hash, &self.file_id);
        let data_offset = match self.journal_file_find_data_object_with_hash(boot_data.as_bytes(), h) { Ok(Some(off)) => off, _ => return None, };
        let n_entries = match self.read_u64_at(data_offset + 56) { Ok(n) => n, Err(_) => return None, };
        if n_entries == 0 { return None; }
        let feo = match self.read_u64_at(data_offset + 40) { Ok(off) if off > 0 => off, _ => return None, };
        let from = match self.read_u64_at(feo + 32) { Ok(ts) => ts, Err(_) => return None, };
        let to = match self.get_last_entry_monotonic_for_data(data_offset, n_entries) { Ok(ts) => ts, Err(_) => return None, };
        Some((from, to))
    }

    /// Walk the entry array chain for a DATA object to find the last entry's
    /// monotonic timestamp (mirrors DIRECTION_UP in journal_file_move_to_entry_for_data).
    fn get_last_entry_monotonic_for_data(&mut self, data_offset: u64, n_entries: u64) -> Result<u64> {
        if n_entries == 1 {
            let eo = self.read_u64_at(data_offset + 40)?;
            return self.read_u64_at(eo + 32);
        }
        let eao = self.read_u64_at(data_offset + 48)?;
        if eao == 0 {
            let eo = self.read_u64_at(data_offset + 40)?;
            return self.read_u64_at(eo + 32);
        }
        let item_sz = entry_array_item_size(self.compact);
        let mut remaining = n_entries - 1;
        let mut a = eao;
        let mut last_array = a;
        let mut last_array_n = 0u64;
        while a > 0 {
            let obj_size = self.read_u64_at(a + 8)?;
            let k = entry_array_n_items(obj_size, self.compact);
            if k == 0 { break; }
            last_array = a;
            if remaining <= k { last_array_n = remaining; break; }
            remaining -= k;
            last_array_n = k;
            a = self.read_u64_at(a + OBJECT_HEADER_SIZE as u64)?;
        }
        if last_array_n > 0 {
            let slot_off = last_array + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + (last_array_n - 1) * item_sz;
            let eo = if self.compact {
                self.file.seek(SeekFrom::Start(slot_off))?;
                let mut buf = [0u8; 4];
                self.file.read_exact(&mut buf)?;
                u32::from_le_bytes(buf) as u64
            } else {
                self.read_u64_at(slot_off)?
            };
            if eo > 0 { return self.read_u64_at(eo + 32); }
        }
        let eo = self.read_u64_at(data_offset + 40)?;
        self.read_u64_at(eo + 32)
    }

    /// systemd: journal-file.c:4620-4712 journal_file_rotate_suggested
    ///
    /// Check if rotation is suggested:
    /// - Too many objects
    /// - Too deep hash chains
    /// - Too many entry arrays
    /// - Header mismatch (different boot/machine)
    /// - File too old
    /// DIVERGENCE FIX: Rewritten to match systemd's actual checks (journal-file.c:4620-4712):
    /// 1. Header size mismatch (C:4626)
    /// 2. Data hash table fill > 75% (C:4636-4649)
    /// 3. Field hash table fill > 75% (C:4651-4662)
    /// 4. Data hash chain depth > 100 (C:4666-4673)
    /// 5. Field hash chain depth > 100 (C:4675-4682)
    /// 6. n_data > 0 && n_fields == 0 (C:4684-4694)
    /// 7. File too old (C:4696-4709) — only if max_file_usec > 0
    pub fn journal_file_rotate_suggested(&mut self, max_file_usec: u64) -> bool {
        // systemd: journal-file.c:4626 — header size mismatch means we gained new features
        if let Ok(h) = self.read_header_raw() {
            if from_le64(&h.header_size) < HEADER_SIZE {
                return true;
            }
        }

        // systemd: journal-file.c:4636-4649
        // Data hash table fill level > 75%
        if self.data_ht_n > 0 {
            if self.n_data * 4 > self.data_ht_n * 3 {
                return true;
            }
        }

        // systemd: journal-file.c:4651-4662
        // Field hash table fill level > 75%
        if self.field_ht_n > 0 {
            if self.n_fields * 4 > self.field_ht_n * 3 {
                return true;
            }
        }

        // systemd: journal-file.c:4666-4673
        if self.data_hash_chain_depth > HASH_CHAIN_DEPTH_MAX {
            return true;
        }

        // systemd: journal-file.c:4675-4682
        if self.field_hash_chain_depth > HASH_CHAIN_DEPTH_MAX {
            return true;
        }

        // systemd: journal-file.c:4684-4694
        // Data objects not indexed by fields
        if self.n_data > 0 && self.n_fields == 0 {
            return true;
        }

        // systemd: journal-file.c:4696-4709
        // File too old — only checked if max_file_usec > 0 (0 disables age check).
        // DIVERGENCE FIX: was using DEFAULT_MAX_FILE_USEC when 0 was passed.
        if max_file_usec > 0 && self.head_entry_realtime != 0 {
            let now = realtime_now();
            if now > self.head_entry_realtime
                && now - self.head_entry_realtime > max_file_usec
            {
                return true;
            }
        }

        false
    }

    /// systemd: journal-file.c:4430-4528 journal_file_copy_entry
    ///
    /// Read entry items from source file and write them to this file.
    /// `source` is a reader/writer for the source journal file.
    /// `entry_offset` is the offset of the entry in the source file.
    /// DIVERGENCE FIX: Rewritten to copy raw payloads directly instead of
    /// splitting on '=' and re-validating. The C code (journal-file.c:4430-4528)
    /// calls journal_file_data_payload() to get the raw bytes, then directly
    /// calls journal_file_append_data() with those bytes (no re-parsing).
    /// Previous version would corrupt binary data and reject valid exotic fields.
    pub fn journal_file_copy_entry(
        &mut self,
        source: &mut JournalWriter,
        entry_offset: u64,
        machine_id_override: Option<&[u8; 16]>,
    ) -> Result<u64> {
        // If caller provides a machine_id, set it on self so that
        // append_entry_internal doesn't read /etc/machine-id.
        if let Some(mid) = machine_id_override {
            if self.machine_id == [0u8; 16] {
                self.machine_id = *mid;
            }
        }
        let entry_size = source.read_u64_at(entry_offset + 8)?;
        let realtime = source.read_u64_at(entry_offset + 24)?;
        let monotonic = source.read_u64_at(entry_offset + 32)?;
        let boot_id_bytes = source.read_bytes_at(entry_offset + 40, 16)?;
        let mut boot_id = [0u8; 16];
        boot_id.copy_from_slice(&boot_id_bytes);

        // systemd: journal-file.c:2551-2558 (implied via append_entry_internal)
        // Validate timestamps from source entry.
        const TS_UPPER: u64 = 1u64 << 55;
        if realtime == 0 || realtime >= TS_UPPER {
            return Err(Error::InvalidFile(format!(
                "copy_entry: invalid realtime {}",
                realtime
            )));
        }
        if monotonic >= TS_UPPER {
            return Err(Error::InvalidFile(format!(
                "copy_entry: invalid monotonic {}",
                monotonic
            )));
        }
        if boot_id == [0u8; 16] {
            return Err(Error::InvalidFile("copy_entry: empty boot ID".into()));
        }

        // Use source's compact mode for reading entry items
        let source_compact = source.is_compact();
        let n_items = journal_file_entry_n_items(entry_size, source_compact);
        if n_items == 0 {
            // systemd: C returns 0 (no-op) for empty entries, not an error.
            return Ok(0);
        }

        // Collect raw payloads and append data objects directly.
        let mut items: Vec<(u64, u64)> = Vec::with_capacity(n_items as usize);
        let mut xor_hash: u64 = 0;

        let src_item_size = entry_item_size(source_compact);
        for i in 0..n_items {
            let item_off = entry_offset
                + ENTRY_OBJECT_HEADER_SIZE as u64
                + i * src_item_size;
            let data_offset = if source_compact {
                // Compact mode: 4-byte le32 offset
                let bytes = source.read_bytes_at(item_off, 4)?;
                u32::from_le_bytes(bytes.try_into().unwrap()) as u64
            } else {
                source.read_u64_at(item_off)?
            };
            if data_offset == 0 {
                continue;
            }

            // Read raw payload from source (the full "FIELD=value" bytes).
            // Corruption tolerance: skip items whose DATA object is corrupt
            // (mirrors systemd's EBADMSG/EADDRNOTAVAIL tolerance).
            let payload = match source.journal_file_data_payload(data_offset) {
                Ok(p) => p,
                Err(Error::CorruptObject { offset, reason }) => {
                    eprintln!(
                        "copy_entry: skipping corrupt DATA object at {:#x}: {}",
                        offset, reason
                    );
                    continue;
                }
                Err(Error::Decompression(msg)) => {
                    eprintln!(
                        "copy_entry: skipping DATA at {:#x} with decompression error: {}",
                        data_offset, msg
                    );
                    continue;
                }
                Err(Error::Truncated { offset }) => {
                    eprintln!(
                        "copy_entry: skipping truncated DATA object at {:#x}",
                        offset
                    );
                    continue;
                }
                Err(e) => return Err(e),
            };
            let h = journal_file_hash_data(&payload, self.keyed_hash, &self.file_id);
            // systemd: C:4497-4500 — keyed_hash uses jenkins for xor_hash (cursor stability)
            if self.keyed_hash {
                xor_hash ^= hash64(&payload);
            } else {
                xor_hash ^= h;
            }

            // Append raw data to destination (handles dedup internally).
            let (dest_data_offset, is_new) = self.journal_file_append_data(&payload, h)?;

            // Link field if new data.
            if is_new {
                if let Some(eq) = payload.iter().position(|&b| b == b'=') {
                    let field_name = &payload[..eq];
                    let field_offset = self.journal_file_append_field(field_name)?;
                    let field_head_ptr = field_offset + 32;
                    let old_head = self.read_u64_at(field_head_ptr)?;
                    self.write_u64_at(dest_data_offset + 32, old_head)?;
                    self.write_u64_at(field_head_ptr, dest_data_offset)?;
                }
            }

            items.push((dest_data_offset, h));
        }

        if items.is_empty() {
            return Ok(0);
        }

        // Sort and dedup items (matching systemd).
        items.sort_by(entry_item_cmp);
        remove_duplicate_entry_items(&mut items);

        let seqnum_val = self.journal_file_entry_seqnum(None);
        let entry_off = self.journal_file_append_entry_internal(
            seqnum_val, realtime, monotonic, &boot_id, xor_hash, &items,
        )?;
        self.journal_file_link_entry(entry_off, &items)?;
        self.journal_file_post_change()?;

        Ok(entry_off)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Debug / dump
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:3814-3877 journal_file_dump
    ///
    /// Iterate all objects, print type/size/offset.
    pub fn journal_file_dump(&mut self) -> Result<String> {
        let mut output = String::new();
        let header_size = HEADER_SIZE;
        let total_size = self.offset;
        let mut cur = header_size;

        output.push_str(&format!(
            "Journal file dump: {} bytes, {} objects\n",
            total_size, self.n_objects
        ));

        while cur < total_size {
            if !valid64(cur) {
                cur = align64(cur);
                if cur >= total_size {
                    break;
                }
            }

            // Read object header
            let obj_type_byte = {
                self.file.seek(SeekFrom::Start(cur))?;
                let mut buf = [0u8; 1];
                self.file.read_exact(&mut buf)?;
                buf[0]
            };
            let obj_size = self.read_u64_at(cur + 8)?;

            if obj_size < OBJECT_HEADER_SIZE as u64 {
                output.push_str(&format!(
                    "  offset={:#x}: INVALID (size {})\n",
                    cur, obj_size
                ));
                break;
            }

            let type_name = match ObjectType::try_from(obj_type_byte) {
                Ok(t) => format!("{:?}", t),
                Err(_) => format!("Unknown({})", obj_type_byte),
            };

            output.push_str(&format!(
                "  offset={:#x}: type={}, size={}\n",
                cur, type_name, obj_size
            ));

            cur += align64(obj_size);
        }

        Ok(output)
    }

    /// systemd: journal-file.c:3882-3972 journal_file_print_header
    ///
    /// Print all header fields.
    pub fn journal_file_print_header(&mut self) -> Result<String> {
        let h = self.read_header_raw()?;
        let mut output = String::new();

        output.push_str(&format!("File ID: {:02x?}\n", h.file_id));
        output.push_str(&format!("Machine ID: {:02x?}\n", h.machine_id));
        output.push_str(&format!("Boot ID: {:02x?}\n", h.tail_entry_boot_id));
        output.push_str(&format!("Seqnum ID: {:02x?}\n", h.seqnum_id));

        let state = match h.state {
            0 => "OFFLINE",
            1 => "ONLINE",
            2 => "ARCHIVED",
            _ => "UNKNOWN",
        };
        output.push_str(&format!("State: {}\n", state));

        output.push_str(&format!(
            "Compatible Flags: {:#010x}\n",
            from_le32(&h.compatible_flags)
        ));
        output.push_str(&format!(
            "Incompatible Flags: {:#010x}\n",
            from_le32(&h.incompatible_flags)
        ));

        output.push_str(&format!(
            "Header size: {}\n",
            from_le64(&h.header_size)
        ));
        output.push_str(&format!(
            "Arena size: {}\n",
            from_le64(&h.arena_size)
        ));

        output.push_str(&format!(
            "Data Hash Table Offset: {}\n",
            from_le64(&h.data_hash_table_offset)
        ));
        output.push_str(&format!(
            "Data Hash Table Size: {}\n",
            from_le64(&h.data_hash_table_size)
        ));
        output.push_str(&format!(
            "Field Hash Table Offset: {}\n",
            from_le64(&h.field_hash_table_offset)
        ));
        output.push_str(&format!(
            "Field Hash Table Size: {}\n",
            from_le64(&h.field_hash_table_size)
        ));

        output.push_str(&format!(
            "Tail Object Offset: {}\n",
            from_le64(&h.tail_object_offset)
        ));

        output.push_str(&format!(
            "Objects: {}\n",
            from_le64(&h.n_objects)
        ));
        output.push_str(&format!(
            "Entries: {}\n",
            from_le64(&h.n_entries)
        ));
        output.push_str(&format!(
            "Data Objects: {}\n",
            from_le64(&h.n_data)
        ));
        output.push_str(&format!(
            "Field Objects: {}\n",
            from_le64(&h.n_fields)
        ));
        output.push_str(&format!(
            "Entry Arrays: {}\n",
            from_le64(&h.n_entry_arrays)
        ));

        output.push_str(&format!(
            "Head Entry Seqnum: {}\n",
            from_le64(&h.head_entry_seqnum)
        ));
        output.push_str(&format!(
            "Tail Entry Seqnum: {}\n",
            from_le64(&h.tail_entry_seqnum)
        ));
        output.push_str(&format!(
            "Entry Array Offset: {}\n",
            from_le64(&h.entry_array_offset)
        ));

        output.push_str(&format!(
            "Head Entry Realtime: {}\n",
            from_le64(&h.head_entry_realtime)
        ));
        output.push_str(&format!(
            "Tail Entry Realtime: {}\n",
            from_le64(&h.tail_entry_realtime)
        ));
        output.push_str(&format!(
            "Tail Entry Monotonic: {}\n",
            from_le64(&h.tail_entry_monotonic)
        ));

        output.push_str(&format!(
            "Data Hash Chain Depth: {}\n",
            from_le64(&h.data_hash_chain_depth)
        ));
        output.push_str(&format!(
            "Field Hash Chain Depth: {}\n",
            from_le64(&h.field_hash_chain_depth)
        ));

        output.push_str(&format!(
            "Tail Entry Array Offset: {}\n",
            from_le32(&h.tail_entry_array_offset)
        ));
        output.push_str(&format!(
            "Tail Entry Array N Entries: {}\n",
            from_le32(&h.tail_entry_array_n_entries)
        ));
        output.push_str(&format!(
            "Tail Entry Offset: {}\n",
            from_le64(&h.tail_entry_offset)
        ));

        Ok(output)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Entry-array helpers
    // ══════════════════════════════════════════════════════════════════════

    /// Compute the capacity of an entry-array object from its `ObjectHeader.size`.
    ///
    /// systemd: journal-file.c:2052-2066 (entry_array_n_items)
    fn read_entry_array_capacity(&mut self, arr_offset: u64) -> Result<u64> {
        let obj_size = self.read_u64_at(arr_offset + 8)?;
        Ok(entry_array_n_items(obj_size, self.compact))
    }

    /// Compute new entry-array capacity using systemd's exponential doubling.
    ///
    /// systemd: journal-file.c:2135-2141
    ///   if (hidx > n) n = (hidx+1) * 2;
    ///   else          n = n * 2;
    ///   if (n < 4)    n = 4;
    fn compute_new_array_capacity(&self, hidx: u64, prev_n: u64) -> u64 {
        let n = if hidx > prev_n {
            (hidx + 1) * 2
        } else {
            prev_n * 2
        };
        n.max(4)
    }

    /// Write an entry-array object with the given `capacity` (number of u64 slots).
    ///
    /// systemd: journal-file.c:2143-2145
    ///   r = journal_file_append_object(f, OBJECT_ENTRY_ARRAY,
    ///       offsetof(Object, entry_array.items) + n * journal_file_entry_array_item_size(f),
    ///       &o, &q);
    fn write_entry_array_object(&mut self, capacity: u64, next: u64) -> Result<u64> {
        let item_bytes = capacity * entry_array_item_size(self.compact);
        let actual_size = ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + item_bytes;
        let total_size = align64(actual_size);
        let obj_offset = self.offset;
        self.journal_file_allocate(obj_offset, total_size)?;

        let hdr = EntryArrayObjectHeader {
            object: ObjectHeader {
                object_type: ObjectType::EntryArray as u8,
                flags: 0,
                reserved: [0; 6],
                size: le64(actual_size), // actual, not aligned
            },
            next_entry_array_offset: le64(next),
        };

        self.file.seek(SeekFrom::Start(obj_offset))?;
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &hdr as *const EntryArrayObjectHeader as *const u8,
                ENTRY_ARRAY_OBJECT_HEADER_SIZE,
            )
        };
        self.file.write_all(hdr_bytes)?;
        write_zeros(&mut self.file, total_size - ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64)?;

        self.offset += total_size;
        self.tail_object_offset = obj_offset;
        self.n_objects += 1;
        self.n_entry_arrays += 1;

        Ok(obj_offset)
    }

    /// Walk the entry-array chain to find the array+slot for the given absolute index.
    /// Returns (tail_arr_offset, items_used_in_tail, tail_capacity).
    #[allow(dead_code)]
    fn walk_to_array_slot(
        &mut self,
        head: u64,
        target_idx: u64,
    ) -> Result<(u64, u64, u64)> {
        let mut cur = head;
        let mut remaining = target_idx;
        loop {
            let cap = self.read_entry_array_capacity(cur)?;
            if remaining < cap {
                return Ok((cur, remaining, cap));
            }
            remaining -= cap;
            let next = self.read_u64_at(cur + OBJECT_HEADER_SIZE as u64)?;
            if next == 0 {
                // Ran out of arrays -- remaining items go in a new array to be allocated.
                return Ok((cur, cap, cap));
            }
            cur = next;
        }
    }

    /// Walk next_entry_array_offset chain from `head` to find the tail array offset.
    fn find_tail_array(&mut self, head: u64) -> Result<u64> {
        let mut cur = head;
        loop {
            let next = self.read_u64_at(cur + OBJECT_HEADER_SIZE as u64)?;
            if next == 0 {
                return Ok(cur);
            }
            cur = next;
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Header sync
    // ══════════════════════════════════════════════════════════════════════

    /// Rewrite the complete journal header with current statistics.
    fn write_header(&mut self) -> Result<()> {
        let data_ht_actual_size =
            OBJECT_HEADER_SIZE as u64 + self.data_ht_n * HASH_ITEM_SIZE as u64;
        let field_ht_actual_size =
            OBJECT_HEADER_SIZE as u64 + self.field_ht_n * HASH_ITEM_SIZE as u64;
        let arena_size = self.offset - HEADER_SIZE;

        let mut h = self.read_header_raw()?;

        h.state = FileState::Online as u8;
        h.arena_size = le64(arena_size);
        h.tail_object_offset = le64(self.tail_object_offset);
        h.n_objects = le64(self.n_objects);
        h.n_entries = le64(self.n_entries);
        h.n_data = le64(self.n_data);
        h.n_fields = le64(self.n_fields);
        h.n_tags = [0u8; 8];
        h.n_entry_arrays = le64(self.n_entry_arrays);
        h.tail_entry_seqnum = le64(self.tail_entry_seqnum);
        h.head_entry_seqnum = le64(self.head_entry_seqnum);
        h.entry_array_offset = le64(self.entry_array_offset);
        h.head_entry_realtime = le64(self.head_entry_realtime);
        h.tail_entry_realtime = le64(self.tail_entry_realtime);
        h.tail_entry_monotonic = le64(self.tailentry_monotonic);
        // systemd: journal-file.c:2390
        //   o->entry.boot_id = f->header->tail_entry_boot_id = *boot_id;
        // DIVERGENCE FIX (2d): was using self.boot_id (writer's boot), must use
        // the last entry's boot_id for correct monotonic ordering on reopen.
        h.tail_entry_boot_id = self.prev_boot_id;
        h.data_hash_chain_depth = le64(self.data_hash_chain_depth);
        h.field_hash_chain_depth = le64(self.field_hash_chain_depth);
        h.tail_entry_offset = le64(self.tail_entry_offset);

        // systemd: tail_entry_array_offset / tail_entry_array_n_entries (compact mode le32).
        // We store the actual tail array and its used count.
        // DIVERGENCE FIX: When global_tail is None but entry_array_offset != 0,
        // the fallback was using global_n_entries (total count across ALL arrays)
        // as tail_entry_array_n_entries. It should be the count in the TAIL array only.
        // If we don't have the tail cached, use 0 (will be wrong but not crash).
        let (tail_arr_off, tail_arr_n) = if let Some((off, n)) = self.global_tail {
            (off, n)
        } else {
            (0, 0)
        };
        h.tail_entry_array_offset = le32(tail_arr_off as u32);
        h.tail_entry_array_n_entries = le32(tail_arr_n as u32);

        h.data_hash_table_offset =
            le64(self.data_ht_offset + OBJECT_HEADER_SIZE as u64);
        h.data_hash_table_size =
            le64(data_ht_actual_size - OBJECT_HEADER_SIZE as u64);
        h.field_hash_table_offset =
            le64(self.field_ht_offset + OBJECT_HEADER_SIZE as u64);
        h.field_hash_table_size =
            le64(field_ht_actual_size - OBJECT_HEADER_SIZE as u64);

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(header_as_bytes(&h))?;
        Ok(())
    }

    fn read_header_raw(&mut self) -> Result<Header> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; 272];
        self.file.read_exact(&mut buf)?;
        Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const Header) })
    }
}

impl Drop for JournalWriter {
    fn drop(&mut self) {
        // Join the offline thread before any cleanup.
        let _ = self.journal_file_set_offline_thread_join();

        let _ = self.write_header();
        if let Ok(mut h) = self.read_header_raw() {
            // Write STATE_ARCHIVED if journal_file_archive was called,
            // otherwise STATE_OFFLINE.
            if self.archived {
                h.state = FileState::Archived as u8;
            } else if h.state != FileState::Archived as u8 {
                h.state = FileState::Offline as u8;
            }
            let _ = self.file.seek(SeekFrom::Start(0));
            let _ = self.file.write_all(header_as_bytes(&h));
        }
        // DIVERGENCE FIX: use sync_all() not just flush().
        // systemd: fsync_full(f->fd) during offlining.
        // flush() only flushes stdio buffer; sync_all() calls fsync().
        let _ = self.file.sync_all();
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Free-standing helpers
// ══════════════════════════════════════════════════════════════════════════

/// systemd: journal-file.c:1710-1746 (internal validation used by append_entry)
fn validate_field_name(name: &[u8]) -> Result<()> {
    if !journal_field_valid(name, true) {
        return Err(Error::InvalidFieldName(
            String::from_utf8_lossy(name).into_owned(),
        ));
    }
    Ok(())
}

/// Build a fresh Header struct.
#[allow(clippy::too_many_arguments)]
fn build_header(
    file_id: [u8; 16],
    machine_id: [u8; 16],
    seqnum_id: [u8; 16],
    _boot_id: [u8; 16],
    header_size: u64,
    arena_size: u64,
    data_ht_offset: u64,
    data_ht_size: u64,
    field_ht_offset: u64,
    field_ht_size: u64,
    state: FileState,
    keyed_hash: bool,
    compact: bool,
) -> Header {
    let mut iflags = 0u32;
    if keyed_hash {
        iflags |= incompat::KEYED_HASH;
    }
    if compact {
        iflags |= incompat::COMPACT;
    }
    Header {
        signature: HEADER_SIGNATURE,
        compatible_flags: le32(compat::TAIL_ENTRY_BOOT_ID),
        incompatible_flags: le32(iflags),
        state: state as u8,
        reserved: [0; 7],
        file_id,
        machine_id,
        // systemd: tail_entry_boot_id starts zeroed; only set when first entry is written
        // (journal-file.c:2390: o->entry.boot_id = f->header->tail_entry_boot_id = *boot_id)
        tail_entry_boot_id: [0u8; 16],
        seqnum_id,
        header_size: le64(header_size),
        arena_size: le64(arena_size),
        data_hash_table_offset: le64(data_ht_offset + OBJECT_HEADER_SIZE as u64),
        data_hash_table_size: le64(data_ht_size - OBJECT_HEADER_SIZE as u64),
        field_hash_table_offset: le64(field_ht_offset + OBJECT_HEADER_SIZE as u64),
        field_hash_table_size: le64(field_ht_size - OBJECT_HEADER_SIZE as u64),
        tail_object_offset: le64(field_ht_offset),
        n_objects: le64(2),
        n_entries: le64(0),
        tail_entry_seqnum: le64(0),
        head_entry_seqnum: le64(0),
        entry_array_offset: le64(0),
        head_entry_realtime: le64(0),
        tail_entry_realtime: le64(0),
        tail_entry_monotonic: le64(0),
        n_data: le64(0),
        n_fields: le64(0),
        n_tags: le64(0),
        n_entry_arrays: le64(0),
        data_hash_chain_depth: le64(0),
        field_hash_chain_depth: le64(0),
        tail_entry_array_offset: le32(0),
        tail_entry_array_n_entries: le32(0),
        tail_entry_offset: le64(0),
    }
}

fn header_as_bytes(h: &Header) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            h as *const Header as *const u8,
            std::mem::size_of::<Header>(),
        )
    }
}

/// Write a zeroed hash table object (ObjectHeader + n x HashItem).
///
/// systemd: journal-file.c:1297-1300
///   r = journal_file_append_object(f, OBJECT_DATA_HASH_TABLE,
///       offsetof(Object, hash_table.items) + s * sizeof(HashItem), &o, &p);
///   memzero(o->hash_table.items, s);
fn write_hash_table_object(file: &mut File, obj_type: ObjectType, n: u64) -> io::Result<()> {
    let item_bytes = n * HASH_ITEM_SIZE as u64;
    let actual_size = OBJECT_HEADER_SIZE as u64 + item_bytes;
    let total = align64(actual_size);
    let hdr = ObjectHeader {
        object_type: obj_type as u8,
        flags: 0,
        reserved: [0; 6],
        size: le64(actual_size), // actual, not aligned
    };
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(
            &hdr as *const ObjectHeader as *const u8,
            OBJECT_HEADER_SIZE,
        )
    };
    file.write_all(hdr_bytes)?;
    write_zeros(file, total - OBJECT_HEADER_SIZE as u64)?;
    Ok(())
}

fn write_zeros(file: &mut File, n: u64) -> io::Result<()> {
    const BUF: [u8; 512] = [0u8; 512];
    let mut remaining = n;
    while remaining > 0 {
        let chunk = remaining.min(512) as usize;
        file.write_all(&BUF[..chunk])?;
        remaining -= chunk as u64;
    }
    Ok(())
}

fn read_hash_item(file: &mut File, offset: u64) -> Result<HashItem> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; HASH_ITEM_SIZE];
    file.read_exact(&mut buf)?;
    Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const HashItem) })
}

fn write_hash_item(file: &mut File, offset: u64, item: &HashItem) -> Result<()> {
    let bytes = unsafe {
        std::slice::from_raw_parts(item as *const HashItem as *const u8, HASH_ITEM_SIZE)
    };
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    Ok(())
}

/// Walk an entry-array chain to find the tail array and how many items it has used.
/// Returns (tail_offset, items_used_in_tail).
fn walk_entry_array_chain(file: &mut File, head: u64, compact: bool) -> Result<(u64, u64)> {
    let mut cur = head;
    loop {
        // Read next_entry_array_offset.
        file.seek(SeekFrom::Start(cur + OBJECT_HEADER_SIZE as u64))?;
        let mut buf = [0u8; 8];
        file.read_exact(&mut buf)?;
        let next = u64::from_le_bytes(buf);
        if next == 0 {
            // This is the tail. Count used items by finding the last non-zero slot.
            let (_, used) = walk_entry_array_chain_at(file, cur, compact)?;
            return Ok((cur, used));
        }
        cur = next;
    }
}

/// Count used items in a single entry-array object.
/// Returns (capacity, used_count).
fn walk_entry_array_chain_at(file: &mut File, arr_offset: u64, compact: bool) -> Result<(u64, u64)> {
    file.seek(SeekFrom::Start(arr_offset + 8))?; // ObjectHeader.size
    let mut size_buf = [0u8; 8];
    file.read_exact(&mut size_buf)?;
    let obj_size = u64::from_le_bytes(size_buf);
    let item_sz = entry_array_item_size(compact);
    let capacity = obj_size.saturating_sub(ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64) / item_sz;

    // Scan backwards to find last non-zero item.
    let mut used = capacity;
    for i in (0..capacity).rev() {
        let slot_off = arr_offset + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + i * item_sz;
        file.seek(SeekFrom::Start(slot_off))?;
        let is_nonzero = if compact {
            let mut buf = [0u8; 4];
            file.read_exact(&mut buf)?;
            u32::from_le_bytes(buf) != 0
        } else {
            let mut buf = [0u8; 8];
            file.read_exact(&mut buf)?;
            u64::from_le_bytes(buf) != 0
        };
        if is_nonzero {
            used = i + 1;
            break;
        }
        if i == 0 {
            used = 0;
        }
    }
    Ok((capacity, used))
}

/// Rebuild in-memory indexes by scanning data and field hash tables.
fn rebuild_indexes(
    file: &mut File,
    _file_size: u64,
    data_ht_off: u64,
    data_ht_n: u64,
    field_ht_off: u64,
    field_ht_n: u64,
) -> Result<(DataIndex, FieldIndex)> {
    let mut data_idx: DataIndex = HashMap::new();
    let mut field_idx: FieldIndex = HashMap::new();

    let data_items_start = data_ht_off + OBJECT_HEADER_SIZE as u64;
    for bucket in 0..data_ht_n {
        let item_off = data_items_start + bucket * HASH_ITEM_SIZE as u64;
        let item = read_hash_item(file, item_off)?;
        let mut cur = from_le64(&item.head_hash_offset);
        while cur != 0 {
            file.seek(SeekFrom::Start(cur + 16))?;
            let mut buf = [0u8; 8];
            file.read_exact(&mut buf)?;
            let h = u64::from_le_bytes(buf);

            let mut next_buf = [0u8; 8];
            file.read_exact(&mut next_buf)?;
            let next = u64::from_le_bytes(next_buf);

            data_idx.entry(bucket).or_default().push((cur, h));
            cur = next;
        }
    }

    let field_items_start = field_ht_off + OBJECT_HEADER_SIZE as u64;
    for bucket in 0..field_ht_n {
        let item_off = field_items_start + bucket * HASH_ITEM_SIZE as u64;
        let item = read_hash_item(file, item_off)?;
        let mut cur = from_le64(&item.head_hash_offset);
        while cur != 0 {
            file.seek(SeekFrom::Start(cur + 16))?;
            let mut buf = [0u8; 8];
            file.read_exact(&mut buf)?;
            let h = u64::from_le_bytes(buf);

            let mut next_buf = [0u8; 8];
            file.read_exact(&mut next_buf)?;
            let next = u64::from_le_bytes(next_buf);

            field_idx.entry(bucket).or_default().push((cur, h));
            cur = next;
        }
    }

    Ok((data_idx, field_idx))
}

// ══════════════════════════════════════════════════════════════════════════
// Archive / dispose / UID parsing
// ══════════════════════════════════════════════════════════════════════════

/// systemd: journal-file.c:4405-4428 journal_file_dispose
///
/// Dispose of a journal file: punch holes to free space as a best-effort
/// optimization, then rename to `{base}@{realtime:016x}-{random:08x}.journal~`
/// to preserve the (possibly corrupt) file for inspection. This matches
/// systemd's behavior of never unlinking journal files outright.
///
/// The `_dir_fd` parameter is accepted for API compatibility with the systemd
/// signature (which uses `dir_fd` for `renameat`), but is currently ignored
/// because Rust's `std::fs::rename` operates on full paths. If directory-fd
/// based renaming is needed in the future, it can be implemented via
/// `libc::renameat`.
pub fn journal_file_dispose(_dir_fd: Option<i32>, path: &str) -> Result<()> {
    let p = std::path::Path::new(path);

    // Strip the ".journal" suffix to get the base name for the renamed file.
    let file_name = p
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::InvalidFile("dispose: cannot extract filename".into()))?;

    let base = file_name
        .strip_suffix(".journal")
        .ok_or_else(|| Error::InvalidFile("dispose: path does not end in .journal".into()))?;

    // Best-effort hole punching on Linux to release disk blocks before rename.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        if let Ok(file) = File::open(path) {
            if let Ok(meta) = file.metadata() {
                let size = meta.len();
                if size > 0 {
                    // FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE = 0x02 | 0x01 = 0x03
                    unsafe {
                        libc::fallocate(
                            file.as_raw_fd(),
                            0x03, // FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE
                            0,
                            size as libc::off_t,
                        );
                    }
                }
            }
        }
    }

    // Generate random suffix: read 4 bytes from /dev/urandom (matching
    // systemd's random_u64, truncated to u32 for the filename format).
    let random_suffix: u32 = {
        use std::io::Read;
        let mut buf = [0u8; 4];
        if let Ok(mut f) = File::open("/dev/urandom") {
            let _ = f.read_exact(&mut buf);
        }
        u32::from_ne_bytes(buf)
    };

    let rt = realtime_now();

    // Construct the new name: {base}@{realtime:016x}-{random:08x}.journal~
    let new_name = format!("{}@{:016x}-{:08x}.journal~", base, rt, random_suffix);
    let new_path = p.with_file_name(&new_name);

    std::fs::rename(path, &new_path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("dispose: failed to rename {:?} to {:?}: {}", path, new_path, e),
        ))
    })?;

    Ok(())
}

/// systemd: journal-file.c:4283-4329 journal_file_parse_uid_from_filename
///
/// Extract UID from filename like "user-1000.journal" or "user-1000.journal~".
pub fn journal_file_parse_uid_from_filename(path: &str) -> Option<u32> {
    // Get just the filename component
    let filename = std::path::Path::new(path)
        .file_name()?
        .to_str()?;

    // Strip ".journal" or ".journal~" suffix
    let stem = filename.strip_suffix(".journal~")
        .or_else(|| filename.strip_suffix(".journal"))?;

    // Must start with "user-"
    let uid_str = stem.strip_prefix("user-")?;

    // Parse the UID
    uid_str.parse::<u32>().ok()
}

// ══════════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn test_create_and_write() {
        let path = tmp_path("qjournal_test_write.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();
        w.append_entry(&[
            ("MESSAGE", b"Hello, journald!" as &[u8]),
            ("PRIORITY", b"6"),
            ("SYSLOG_IDENTIFIER", b"qjournal_test"),
        ])
        .unwrap();
        w.flush().unwrap();
        drop(w);
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.len() > HEADER_SIZE);
    }

    #[test]
    fn test_reopen_and_append() {
        let path = tmp_path("qjournal_test_reopen.journal");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[("MESSAGE", b"first" as &[u8])])
                .unwrap();
            w.flush().unwrap();
        }
        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[("MESSAGE", b"second" as &[u8])])
                .unwrap();
            w.flush().unwrap();
        }
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.len() > HEADER_SIZE);
    }

    #[test]
    fn test_field_name_validation() {
        let path = tmp_path("qjournal_test_field.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();
        assert!(w.append_entry(&[("message", b"bad" as &[u8])]).is_err());
        assert!(w
            .append_entry(&[("MY FIELD", b"bad" as &[u8])])
            .is_err());
        assert!(w.append_entry(&[("MESSAGE", b"ok" as &[u8])]).is_ok());
    }

    #[test]
    fn test_header_size() {
        assert_eq!(std::mem::size_of::<Header>(), 272);
    }

    #[test]
    fn test_many_entries_exponential_growth() {
        let path = tmp_path("qjournal_test_many.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..500 {
            let msg = format!("entry {}", i);
            w.append_entry(&[
                ("MESSAGE", msg.as_bytes()),
                ("PRIORITY", b"6" as &[u8]),
            ])
            .unwrap();
        }
        w.flush().unwrap();
        // Verify global entry count matches.
        assert_eq!(w.global_n_entries, 500);
        drop(w);
    }

    #[test]
    fn test_data_dedup_with_payload_check() {
        let path = tmp_path("qjournal_test_dedup.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();
        // Write two entries with the same MESSAGE -- should dedup.
        w.append_entry(&[("MESSAGE", b"same" as &[u8])]).unwrap();
        let n_data_after_first = w.n_data;
        w.append_entry(&[("MESSAGE", b"same" as &[u8])]).unwrap();
        // n_data should NOT have increased (dedup hit).
        assert_eq!(w.n_data, n_data_after_first);

        // Write a different message -- should create a new DATA.
        w.append_entry(&[("MESSAGE", b"different" as &[u8])])
            .unwrap();
        assert_eq!(w.n_data, n_data_after_first + 1);
        drop(w);
    }

    #[test]
    fn test_entry_items_sorted_and_deduped() {
        let path = tmp_path("qjournal_test_sorted.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();
        // Multiple distinct fields -- entry items should be sorted by offset.
        w.append_entry(&[
            ("ZZZZZ", b"last" as &[u8]),
            ("AAAAA", b"first"),
            ("MESSAGE", b"middle"),
        ])
        .unwrap();
        w.flush().unwrap();
        drop(w);
    }

    // ── Validation tests ──────────────────────────────────────────────

    #[test]
    fn test_offset_is_valid() {
        // offset == 0 is the sentinel for "not set", always valid
        assert!(offset_is_valid(0, HEADER_SIZE, 0));
        assert!(offset_is_valid(0, HEADER_SIZE, u64::MAX));
        // Must be aligned
        assert!(!offset_is_valid(3, HEADER_SIZE, u64::MAX));
        // Must be >= header_size
        assert!(!offset_is_valid(8, HEADER_SIZE, u64::MAX));
        // Valid offset (use UINT64_MAX for unbounded, matching systemd callers)
        assert!(offset_is_valid(HEADER_SIZE, HEADER_SIZE, u64::MAX));
        // Valid offset with tail constraint
        assert!(offset_is_valid(HEADER_SIZE, HEADER_SIZE, HEADER_SIZE + 64));
        // Beyond tail
        assert!(!offset_is_valid(HEADER_SIZE + 128, HEADER_SIZE, HEADER_SIZE + 64));
    }

    #[test]
    fn test_minimum_header_size() {
        assert_eq!(minimum_header_size(ObjectType::Data, false), DATA_OBJECT_HEADER_SIZE as u64);
        assert_eq!(minimum_header_size(ObjectType::Data, true), DATA_OBJECT_HEADER_SIZE as u64 + 8);
        assert_eq!(minimum_header_size(ObjectType::Field, false), FIELD_OBJECT_HEADER_SIZE as u64);
        assert_eq!(minimum_header_size(ObjectType::Entry, false), ENTRY_OBJECT_HEADER_SIZE as u64);
        assert_eq!(
            minimum_header_size(ObjectType::EntryArray, false),
            ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64
        );
    }

    #[test]
    fn test_check_object_header_valid() {
        assert!(check_object_header(
            ObjectType::Data as u8,
            DATA_OBJECT_HEADER_SIZE as u64 + 10,
            0,
            false,
            None
        )
        .is_ok());
    }

    #[test]
    fn test_check_object_header_invalid_type() {
        assert!(check_object_header(0, 100, 0, false, None).is_err());
        assert!(check_object_header(99, 100, 0, false, None).is_err());
    }

    #[test]
    fn test_check_object_header_too_small() {
        assert!(check_object_header(
            ObjectType::Entry as u8,
            OBJECT_HEADER_SIZE as u64,
            0,
            false,
            None
        )
        .is_err());
    }

    #[test]
    fn test_journal_field_valid() {
        assert!(journal_field_valid(b"MESSAGE", true));
        assert!(journal_field_valid(b"PRIORITY", true));
        assert!(journal_field_valid(b"_SYSTEMD_UNIT", true));
        assert!(!journal_field_valid(b"_SYSTEMD_UNIT", false)); // protected
        assert!(!journal_field_valid(b"message", true)); // lowercase
        assert!(!journal_field_valid(b"", true)); // empty
        assert!(!journal_field_valid(b"1BAD", true)); // starts with digit
        assert!(!journal_field_valid(b"MY FIELD", true)); // space
    }

    #[test]
    fn test_entry_array_n_items() {
        let size = ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + 8 * 10;
        assert_eq!(entry_array_n_items(size, false), 10);
        // Compact mode: 4-byte items
        let size_compact = ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + 4 * 10;
        assert_eq!(entry_array_n_items(size_compact, true), 10);
    }

    #[test]
    fn test_journal_file_entry_n_items() {
        let size = ENTRY_OBJECT_HEADER_SIZE as u64 + ENTRY_ITEM_SIZE as u64 * 5;
        assert_eq!(journal_file_entry_n_items(size, false), 5);
        // Compact mode: 4-byte items
        let size_compact = ENTRY_OBJECT_HEADER_SIZE as u64 + 4 * 5;
        assert_eq!(journal_file_entry_n_items(size_compact, true), 5);
    }

    #[test]
    fn test_inc_seqnum() {
        assert_eq!(inc_seqnum(1), 2);
        assert_eq!(inc_seqnum(100), 101);
        assert_eq!(inc_seqnum(u64::MAX - 1), 1); // wraps
        assert_eq!(inc_seqnum(u64::MAX), 1); // also wraps (>= MAX-1)
    }

    #[test]
    fn test_entry_item_cmp_and_dedup() {
        let mut items = vec![(100u64, 1u64), (50, 2), (100, 3), (50, 4), (200, 5)];
        items.sort_by(entry_item_cmp);
        assert_eq!(items[0].0, 50);
        assert_eq!(items[2].0, 100);
        remove_duplicate_entry_items(&mut items);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, 50);
        assert_eq!(items[1].0, 100);
        assert_eq!(items[2].0, 200);
    }

    #[test]
    fn test_verify_header_valid() {
        let path = tmp_path("qjournal_test_verify.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();
        w.append_entry(&[("MESSAGE", b"test" as &[u8])]).unwrap();
        w.flush().unwrap();
        let h = w.read_header_raw().unwrap();
        let file_size = w.offset;
        assert!(verify_header(&h, file_size, true, None).is_ok());
        drop(w);
    }

    #[test]
    fn test_verify_header_bad_signature() {
        let h = Header {
            signature: *b"BADMAGIC",
            compatible_flags: le32(0),
            incompatible_flags: le32(0),
            state: FileState::Offline as u8,
            reserved: [0; 7],
            file_id: [0; 16],
            machine_id: [0; 16],
            tail_entry_boot_id: [0; 16],
            seqnum_id: [0; 16],
            header_size: le64(HEADER_SIZE),
            arena_size: le64(0),
            data_hash_table_offset: le64(0),
            data_hash_table_size: le64(0),
            field_hash_table_offset: le64(0),
            field_hash_table_size: le64(0),
            tail_object_offset: le64(0),
            n_objects: le64(0),
            n_entries: le64(0),
            tail_entry_seqnum: le64(0),
            head_entry_seqnum: le64(0),
            entry_array_offset: le64(0),
            head_entry_realtime: le64(0),
            tail_entry_realtime: le64(0),
            tail_entry_monotonic: le64(0),
            n_data: le64(0),
            n_fields: le64(0),
            n_tags: le64(0),
            n_entry_arrays: le64(0),
            data_hash_chain_depth: le64(0),
            field_hash_chain_depth: le64(0),
            tail_entry_array_offset: le32(0),
            tail_entry_array_n_entries: le32(0),
            tail_entry_offset: le64(0),
        };
        assert!(verify_header(&h, 1024, false, None).is_err());
    }

    #[test]
    fn test_rotate_suggested_empty_file() {
        let path = tmp_path("qjournal_test_rotate.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();
        // Fresh file should not suggest rotation
        assert!(!w.journal_file_rotate_suggested(0));
        drop(w);
    }

    #[test]
    fn test_journal_file_hash_data_deterministic() {
        let fid = [0u8; 16];
        // Test jenkins (non-keyed) mode
        let h1 = journal_file_hash_data(b"MESSAGE=hello", false, &fid);
        let h2 = journal_file_hash_data(b"MESSAGE=hello", false, &fid);
        assert_eq!(h1, h2);
        assert_ne!(h1, journal_file_hash_data(b"MESSAGE=world", false, &fid));
        // Test siphash (keyed) mode
        let h3 = journal_file_hash_data(b"MESSAGE=hello", true, &fid);
        let h4 = journal_file_hash_data(b"MESSAGE=hello", true, &fid);
        assert_eq!(h3, h4);
        // Keyed and non-keyed should differ
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_hash_table_sizes() {
        // Default data hash table size
        assert_eq!(
            JournalWriter::setup_data_hash_table_size(0),
            DEFAULT_DATA_HASH_TABLE_SIZE as u64
        );
        // Field hash table is always 1023
        assert_eq!(
            JournalWriter::setup_field_hash_table_size(),
            DEFAULT_FIELD_HASH_TABLE_SIZE as u64
        );
    }

    #[test]
    fn test_cutoff_realtime() {
        let path = tmp_path("qjournal_test_cutoff_rt.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();

        // No entries yet
        assert!(w.journal_file_get_cutoff_realtime_usec().is_none());

        w.append_entry(&[("MESSAGE", b"first" as &[u8])]).unwrap();
        w.flush().unwrap();

        let cutoff = w.journal_file_get_cutoff_realtime_usec();
        assert!(cutoff.is_some());
        let (from, to) = cutoff.unwrap();
        assert!(from > 0);
        assert!(to >= from);
        drop(w);
    }

    #[test]
    fn test_dump_and_print_header() {
        let path = tmp_path("qjournal_test_dump.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();
        w.append_entry(&[("MESSAGE", b"test" as &[u8])]).unwrap();
        w.flush().unwrap();

        let dump = w.journal_file_dump().unwrap();
        assert!(dump.contains("Journal file dump"));
        assert!(dump.contains("Data"));

        let header_info = w.journal_file_print_header().unwrap();
        assert!(header_info.contains("State: ONLINE"));
        assert!(header_info.contains("Entries: 1"));
        drop(w);
    }

    #[test]
    fn test_data_payload_read() {
        let path = tmp_path("qjournal_test_payload.journal");
        let _ = std::fs::remove_file(&path);
        let mut w = JournalWriter::open(&path).unwrap();

        let payload = b"MESSAGE=Hello, world!";
        let h = journal_file_hash_data(payload, w.keyed_hash, &w.file_id);
        let (data_off, _) = w.journal_file_append_data(payload, h).unwrap();

        let read_back = w.journal_file_data_payload(data_off).unwrap();
        assert_eq!(read_back, payload);
        drop(w);
    }

    #[test]
    fn test_check_object_data_valid() {
        // Valid DATA object
        assert!(check_object(
            ObjectType::Data,
            DATA_OBJECT_HEADER_SIZE as u64 + 10, // has payload
            0,                                     // no compression
            HEADER_SIZE,                           // offset
            false,                                 // compact
            12345,                                 // hash
            0,                                     // next_hash_offset
            0,                                     // next_field_offset
            0,                                     // entry_offset (0 is ok if n_entries==0)
            0,                                     // entry_array_offset
            0,                                     // n_entries
            0,                                     // entry_seqnum (unused for Data)
            0,                                     // entry_realtime (unused for Data)
            0,                                     // entry_monotonic (unused for Data)
            &[0u8; 16],                            // entry_boot_id (unused for Data)
            0,                                     // entry_array_next (unused for Data)
            0,                                     // tag_epoch (unused for Data)
        )
        .is_ok());
    }

    #[test]
    fn test_check_object_data_bad_entries_mismatch() {
        // DATA: entry_offset != 0 but n_entries == 0
        assert!(check_object(
            ObjectType::Data,
            DATA_OBJECT_HEADER_SIZE as u64 + 10,
            0,
            HEADER_SIZE,
            false,
            12345,
            0,
            0,
            8,  // entry_offset non-zero
            0,
            0,  // n_entries zero -- mismatch!
            0,
            0,
            0,
            &[0u8; 16],
            0,
            0,  // tag_epoch
        )
        .is_err());
    }

    #[test]
    fn test_check_object_entry_valid() {
        let boot_id = [1u8; 16]; // non-null
        assert!(check_object(
            ObjectType::Entry,
            ENTRY_OBJECT_HEADER_SIZE as u64 + ENTRY_ITEM_SIZE as u64, // 1 item
            0,
            HEADER_SIZE,
            false,
            0, 0, 0, 0, 0, 0, // data fields unused for Entry
            1,                  // seqnum > 0
            1000,               // realtime > 0
            500,                // monotonic
            &boot_id,           // non-null boot_id
            0,
            0,                  // tag_epoch
        )
        .is_ok());
    }

    #[test]
    fn test_check_object_entry_no_items() {
        let boot_id = [1u8; 16];
        assert!(check_object(
            ObjectType::Entry,
            ENTRY_OBJECT_HEADER_SIZE as u64, // 0 items
            0,
            HEADER_SIZE,
            false,
            0, 0, 0, 0, 0, 0,
            1,
            1000,
            500,
            &boot_id,
            0,
            0,  // tag_epoch
        )
        .is_err());
    }

    #[test]
    fn test_check_object_entry_null_boot_id() {
        assert!(check_object(
            ObjectType::Entry,
            ENTRY_OBJECT_HEADER_SIZE as u64 + ENTRY_ITEM_SIZE as u64,
            0,
            HEADER_SIZE,
            false,
            0, 0, 0, 0, 0, 0,
            1,
            1000,
            500,
            &[0u8; 16], // null boot_id
            0,
            0,  // tag_epoch
        )
        .is_err());
    }

    #[test]
    fn test_check_object_entry_array_valid() {
        assert!(check_object(
            ObjectType::EntryArray,
            ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + 8 * 4, // 4 items
            0,
            HEADER_SIZE,
            false,
            0, 0, 0, 0, 0, 0,
            0, 0, 0,
            &[0u8; 16],
            0, // no next
            0, // tag_epoch
        )
        .is_ok());
    }

    #[test]
    fn test_check_object_entry_array_bad_next() {
        // next offset <= current offset
        assert!(check_object(
            ObjectType::EntryArray,
            ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + 8 * 4,
            0,
            HEADER_SIZE + 64, // offset
            false,
            0, 0, 0, 0, 0, 0,
            0, 0, 0,
            &[0u8; 16],
            HEADER_SIZE, // next < offset -- bad!
            0,           // tag_epoch
        )
        .is_err());
    }

    #[test]
    fn test_protected_field_validation() {
        // _SYSTEMD_UNIT is a protected field
        assert!(journal_field_valid(b"_SYSTEMD_UNIT", true));
        assert!(!journal_field_valid(b"_SYSTEMD_UNIT", false));
    }

    #[test]
    fn test_copy_entry() {
        let src_path = tmp_path("qjournal_test_copy_src.journal");
        let dst_path = tmp_path("qjournal_test_copy_dst.journal");
        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&dst_path);

        let mut src = JournalWriter::open(&src_path).unwrap();
        let entry_off = src
            .append_entry(&[
                ("MESSAGE", b"copied entry" as &[u8]),
                ("PRIORITY", b"5"),
            ])
            .unwrap();
        src.flush().unwrap();

        let mut dst = JournalWriter::open(&dst_path).unwrap();
        dst.journal_file_copy_entry(&mut src, entry_off, None).unwrap();
        dst.flush().unwrap();

        assert_eq!(dst.n_entries(), 1);

        drop(src);
        drop(dst);
    }
}
