// SPDX-License-Identifier: LGPL-2.1-or-later
//! Binary on-disk layout definitions, ported from systemd's `journal-def.h`.
//!
//! All structures on disk are in **little-endian** byte order and aligned to
//! 8-byte boundaries. The canonical reference is:
//! <https://systemd.io/JOURNAL_FILE_FORMAT>

use std::mem;

// ── Magic ────────────────────────────────────────────────────────────────────

/// Magic bytes at offset 0 of every journal file: `"LPKSHHRH"`.
pub const HEADER_SIGNATURE: [u8; 8] = *b"LPKSHHRH";

/// Number of hash-table buckets created for a freshly initialised file.
/// Matches systemd's defaults: 2047 for data, 1023 for fields.
pub const DEFAULT_DATA_HASH_TABLE_SIZE: usize = 2047;
pub const DEFAULT_FIELD_HASH_TABLE_SIZE: usize = 1023;

/// The header is always exactly 272 bytes (from `assert_cc` in journal-def.h).
pub const HEADER_SIZE: u64 = 272;

/// Minimum header size for reading older journal files.
/// Matches systemd's `HEADER_SIZE_MIN = ALIGN64(offsetof(Header, n_data))`.
/// The `n_data` field is at byte offset 208 in the packed Header struct.
pub const HEADER_SIZE_MIN: u64 = 208;

/// Objects and the header start must be 8-byte aligned.
pub const ALIGN: u64 = 8;

// ── File / object state ───────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    Offline  = 0,
    Online   = 1,
    Archived = 2,
}

// ── Header compatible/incompatible flags ─────────────────────────────────

/// Compatible flags – readers that don't understand them can still read.
pub mod compat {
    pub const SEALED: u32              = 1 << 0;
    pub const TAIL_ENTRY_BOOT_ID: u32  = 1 << 1;
    pub const SEALED_CONTINUOUS: u32   = 1 << 2;

    /// Mask of all known compatible flags.
    pub const ANY: u32 = SEALED | TAIL_ENTRY_BOOT_ID | SEALED_CONTINUOUS;

    /// Mask of compatible flags we support.
    /// SEALED and SEALED_CONTINUOUS require FSS crypto (like systemd's HAVE_GCRYPT gate).
    pub const SUPPORTED: u32 = {
        let mut flags = TAIL_ENTRY_BOOT_ID;
        if cfg!(feature = "fss") {
            flags |= SEALED | SEALED_CONTINUOUS;
        }
        flags
    };
}

/// incompatible flags – readers that don't understand them MUST refuse the file.
pub mod incompat {
    pub const COMPRESSED_XZ:   u32 = 1 << 0;
    pub const COMPRESSED_LZ4:  u32 = 1 << 1;
    pub const KEYED_HASH:      u32 = 1 << 2;
    pub const COMPRESSED_ZSTD: u32 = 1 << 3;
    pub const COMPACT:         u32 = 1 << 4;

    /// Mask of all known incompatible flags.
    pub const ANY: u32 = COMPRESSED_XZ | COMPRESSED_LZ4 | KEYED_HASH | COMPRESSED_ZSTD | COMPACT;

    /// Mask of flags we support when writing.
    /// We support KEYED_HASH (siphash24 keyed with file_id) and COMPACT.
    pub const SUPPORTED_WRITE: u32 = KEYED_HASH | COMPACT;

    /// Mask of flags we support when reading.
    /// Compression flags are conditional on Cargo features, matching systemd's
    /// compile-time HAVE_XZ / HAVE_LZ4 / HAVE_ZSTD gates.
    pub const SUPPORTED_READ: u32 = {
        let mut v = KEYED_HASH | COMPACT;
        if cfg!(feature = "xz-compression")   { v |= COMPRESSED_XZ; }
        if cfg!(feature = "lz4-compression")  { v |= COMPRESSED_LZ4; }
        if cfg!(feature = "zstd-compression") { v |= COMPRESSED_ZSTD; }
        v
    };
}

// ── Object types ─────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Unused         = 0,
    Data           = 1,
    Field          = 2,
    Entry          = 3,
    DataHashTable  = 4,
    FieldHashTable = 5,
    EntryArray     = 6,
    Tag            = 7,
}

impl TryFrom<u8> for ObjectType {
    type Error = u8;
    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Unused),
            1 => Ok(Self::Data),
            2 => Ok(Self::Field),
            3 => Ok(Self::Entry),
            4 => Ok(Self::DataHashTable),
            5 => Ok(Self::FieldHashTable),
            6 => Ok(Self::EntryArray),
            7 => Ok(Self::Tag),
            x => Err(x),
        }
    }
}

// ── Object compression flags ──────────────────────────────────────────────

pub mod obj_flags {
    pub const COMPRESSED_XZ:   u8 = 1 << 0;
    pub const COMPRESSED_LZ4:  u8 = 1 << 1;
    pub const COMPRESSED_ZSTD: u8 = 1 << 2;
    pub const COMPRESSED_MASK: u8 = COMPRESSED_XZ | COMPRESSED_LZ4 | COMPRESSED_ZSTD;
}

// ── Wire-format structures ────────────────────────────────────────────────
//
// All structs below use `#[repr(C, packed)]` to match the exact systemd layout.
// Individual fields are read through unaligned reads (ptr::read_unaligned) to
// avoid UB on platforms that require alignment.

/// Common 16-byte prefix shared by every object.
///
/// ```text
/// Offset  Size  Field
///      0     1  type   (ObjectType)
///      1     1  flags  (obj_flags)
///      2     6  reserved (must be zero)
///      8     8  size   (le64, total size of this object incl. header)
/// ```
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ObjectHeader {
    pub object_type: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
    pub size: [u8; 8], // le64
}

pub const OBJECT_HEADER_SIZE: usize = mem::size_of::<ObjectHeader>(); // 16

impl ObjectHeader {
    pub fn size_le(&self) -> u64 {
        u64::from_le_bytes(self.size)
    }
}

/// A single entry in a hash table bucket chain (16 bytes).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HashItem {
    pub head_hash_offset: [u8; 8], // le64
    pub tail_hash_offset: [u8; 8], // le64
}

pub const HASH_ITEM_SIZE: usize = mem::size_of::<HashItem>(); // 16

/// DATA object header fields (after `ObjectHeader`).
///
/// ```text
/// Offset  Size  Field
///     16     8  hash               (le64)
///     24     8  next_hash_offset   (le64)
///     32     8  next_field_offset  (le64)
///     40     8  entry_offset       (le64) – first inline entry
///     48     8  entry_array_offset (le64)
///     56     8  n_entries          (le64)
///     64     ?  payload bytes (field=value)
/// ```
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DataObjectHeader {
    pub object: ObjectHeader,
    pub hash: [u8; 8],
    pub next_hash_offset: [u8; 8],
    pub next_field_offset: [u8; 8],
    pub entry_offset: [u8; 8],
    pub entry_array_offset: [u8; 8],
    pub n_entries: [u8; 8],
    // payload follows
}
pub const DATA_OBJECT_HEADER_SIZE: usize = mem::size_of::<DataObjectHeader>(); // 64

/// FIELD object header fields (after `ObjectHeader`).
///
/// ```text
/// Offset  Size  Field
///     16     8  hash
///     24     8  next_hash_offset
///     32     8  head_data_offset
///     40     ?  payload (field name)
/// ```
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FieldObjectHeader {
    pub object: ObjectHeader,
    pub hash: [u8; 8],
    pub next_hash_offset: [u8; 8],
    pub head_data_offset: [u8; 8],
    // payload follows
}
pub const FIELD_OBJECT_HEADER_SIZE: usize = mem::size_of::<FieldObjectHeader>(); // 40

/// One entry item in the regular (non-compact) ENTRY object.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EntryItem {
    pub object_offset: [u8; 8], // le64
    pub hash: [u8; 8],          // le64
}
pub const ENTRY_ITEM_SIZE: usize = mem::size_of::<EntryItem>(); // 16

/// ENTRY object header fields (before the item array).
///
/// ```text
/// Offset  Size  Field
///     16     8  seqnum
///     24     8  realtime   (usec since epoch)
///     32     8  monotonic  (usec since boot)
///     40    16  boot_id    (sd_id128)
///     56     8  xor_hash
///     64     ?  items[]   (EntryItem × n)
/// ```
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EntryObjectHeader {
    pub object: ObjectHeader,
    pub seqnum: [u8; 8],
    pub realtime: [u8; 8],
    pub monotonic: [u8; 8],
    pub boot_id: [u8; 16],
    pub xor_hash: [u8; 8],
    // items[] follow
}
pub const ENTRY_OBJECT_HEADER_SIZE: usize = mem::size_of::<EntryObjectHeader>(); // 64

/// ENTRY_ARRAY object header.
///
/// ```text
/// Offset  Size  Field
///     16     8  next_entry_array_offset (le64)
///     24     ?  items[] le64 offsets
/// ```
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EntryArrayObjectHeader {
    pub object: ObjectHeader,
    pub next_entry_array_offset: [u8; 8],
    // items[] follow (le64 each)
}
pub const ENTRY_ARRAY_OBJECT_HEADER_SIZE: usize = mem::size_of::<EntryArrayObjectHeader>(); // 24

/// The 272-byte file header.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub signature: [u8; 8],               // "LPKSHHRH"
    pub compatible_flags: [u8; 4],        // le32
    pub incompatible_flags: [u8; 4],      // le32
    pub state: u8,
    pub reserved: [u8; 7],
    pub file_id: [u8; 16],               // sd_id128
    pub machine_id: [u8; 16],            // sd_id128
    pub tail_entry_boot_id: [u8; 16],    // sd_id128
    pub seqnum_id: [u8; 16],             // sd_id128
    pub header_size: [u8; 8],            // le64
    pub arena_size: [u8; 8],             // le64
    pub data_hash_table_offset: [u8; 8], // le64
    pub data_hash_table_size: [u8; 8],   // le64
    pub field_hash_table_offset: [u8; 8],// le64
    pub field_hash_table_size: [u8; 8],  // le64
    pub tail_object_offset: [u8; 8],     // le64
    pub n_objects: [u8; 8],              // le64
    pub n_entries: [u8; 8],              // le64
    pub tail_entry_seqnum: [u8; 8],      // le64
    pub head_entry_seqnum: [u8; 8],      // le64
    pub entry_array_offset: [u8; 8],     // le64
    pub head_entry_realtime: [u8; 8],    // le64
    pub tail_entry_realtime: [u8; 8],    // le64
    pub tail_entry_monotonic: [u8; 8],   // le64
    // Added in 187:
    pub n_data: [u8; 8],                 // le64
    pub n_fields: [u8; 8],              // le64
    // Added in 189:
    pub n_tags: [u8; 8],                 // le64
    pub n_entry_arrays: [u8; 8],         // le64
    // Added in 246:
    pub data_hash_chain_depth: [u8; 8],  // le64
    pub field_hash_chain_depth: [u8; 8], // le64
    // Added in 252:
    pub tail_entry_array_offset: [u8; 4], // le32
    pub tail_entry_array_n_entries: [u8; 4], // le32
    // Added in 254:
    pub tail_entry_offset: [u8; 8],      // le64
}

const _: () = assert!(mem::size_of::<Header>() == 272);

// ── Helper: align up to 8-byte boundary ──────────────────────────────────

/// Align `x` up to the next 8-byte boundary, matching systemd's `ALIGN64` macro.
#[inline]
pub fn align64(x: u64) -> u64 {
    (x + 7) & !7
}

/// Return `true` if `x` is 8-byte aligned, matching systemd's `VALID64` macro.
#[inline]
pub fn valid64(x: u64) -> bool {
    x & 7 == 0
}

// ── le64 / le32 helpers ───────────────────────────────────────────────────

#[inline]
pub fn le64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}
#[inline]
pub fn from_le64(b: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*b)
}
#[inline]
pub fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
#[inline]
pub fn from_le32(b: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*b)
}

// ── Timestamp validity (matching systemd's VALID_REALTIME / VALID_MONOTONIC / VALID_EPOCH) ──

/// Upper bound for plausible timestamps (2^55 usec ≈ year 3104).
pub const VALID_UPPER: u64 = 1u64 << 55;

/// Return `true` if `u` is a plausible wall-clock timestamp (non-zero, < 2^55).
#[inline]
pub fn valid_realtime(u: u64) -> bool {
    u > 0 && u < VALID_UPPER
}

/// Return `true` if `u` is a plausible monotonic timestamp (< 2^55).
#[inline]
pub fn valid_monotonic(u: u64) -> bool {
    u < VALID_UPPER
}

/// Return `true` if `u` is a plausible epoch timestamp (< 2^55).
#[inline]
pub fn valid_epoch(u: u64) -> bool {
    u < VALID_UPPER
}
