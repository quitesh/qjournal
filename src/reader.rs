// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file reader.
//!
//! Faithful Rust port of systemd's `journal-file.c` read path:
//! `journal_file_move_to_object`, `generic_array_get`, `generic_array_bisect`,
//! `journal_file_next_entry`, `journal_file_find_data_object_with_hash`,
//! `journal_file_move_to_entry_by_seqnum/realtime/monotonic`, etc.

use std::{
    fs::File,
    path::Path,
};

use indexmap::IndexMap;

use crate::{
    def::*,
    error::{Error, Result},
    mmap_cache::MmapCache,
    writer::{
        check_object, check_object_header, data_payload_offset, entry_array_item_size,
        entry_item_size, entry_array_n_items, journal_file_hash_data,
        verify_header,
    },
};

// ── Direction enum ────────────────────────────────────────────────────────
// systemd: journal-file.h:24-28

/// Direction for entry traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Move towards newer entries (increasing offsets/timestamps).
    Down,
    /// Move towards older entries (decreasing offsets/timestamps).
    Up,
}

// ── Bisection test results ───────────────────────────────────────────────
// systemd: journal-file.c:2903-2911

const TEST_FOUND: i32 = 0;
const TEST_LEFT: i32 = 1;
const TEST_RIGHT: i32 = 2;
const TEST_GOTO_NEXT: i32 = 3;
const TEST_GOTO_PREVIOUS: i32 = 4;

// ── Location type ────────────────────────────────────────────────────────
// systemd: journal-file.h:30-42

/// Current seek position within a journal file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationType {
    /// The first entry (head of file).
    Head,
    /// The last entry (tail of file).
    Tail,
    /// Already read the entry at the current position; the next call should
    /// advance past it.
    Discrete,
    /// Seek to the precise location; it has not been read yet.
    Seek,
}

// ── Chain cache ──────────────────────────────────────────────────────────
// systemd: journal-file.c:2662-2710

const CHAIN_CACHE_MAX: usize = 1024;

/// systemd: journal-file.c:2662-2669 ChainCacheItem
#[derive(Debug, Clone)]
struct ChainCacheItem {
    #[allow(dead_code)]
    first: u64,
    array: u64,
    begin: u64,
    total: u64,
    last_index: u64,
}

// ── Public entry type ─────────────────────────────────────────────────────

/// A single log entry as parsed from the journal.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Per-entry sequence number.
    pub seqnum: u64,
    /// Realtime timestamp in microseconds since Unix epoch.
    pub realtime: u64,
    /// Monotonic timestamp in microseconds since boot.
    pub monotonic: u64,
    /// Boot ID (128-bit).
    pub boot_id: [u8; 16],
    /// All fields as (name, value) pairs.
    fields: Vec<(Vec<u8>, Vec<u8>)>,
}

impl JournalEntry {
    /// Lookup the first value for a given field `name`.
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(k, _)| k.as_slice() == name)
            .map(|(_, v)| v.as_slice())
    }

    /// Return all (name, value) pairs.
    pub fn fields(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.fields
    }

    /// Convenience: get `MESSAGE` as a UTF-8 string if it is valid UTF-8.
    pub fn message(&self) -> Option<&str> {
        self.get(b"MESSAGE").and_then(|v| std::str::from_utf8(v).ok())
    }
}

// ── Public reader ─────────────────────────────────────────────────────────

/// A read-only view of a systemd-journald `.journal` file.
pub struct JournalReader {
    #[allow(dead_code)]
    file: File,
    mmap: MmapCache,
    header: Header,
    /// Whether the file uses keyed hash (siphash24 with file_id).
    keyed_hash: bool,
    /// True when the file uses the COMPACT layout.
    compact: bool,
    /// Byte offset of the data hash table items (past ObjectHeader).
    data_ht_items: u64,
    data_ht_n: u64,
    /// Byte offset of the field hash table items (past ObjectHeader).
    #[allow(dead_code)]
    field_ht_items: u64,
    #[allow(dead_code)]
    field_ht_n: u64,
    /// Offset of the root entry-array object, or 0.
    entry_array_offset: u64,
    n_entries: u64,
    /// Chain cache for bisection acceleration.
    /// systemd: journal-file.c:2662 (ordered_hashmap keyed by chain first offset)
    chain_cache: IndexMap<u64, ChainCacheItem>,
    /// Current location state.
    /// systemd: journal-file.h:66
    location_type: LocationType,
    /// systemd: journal-file.h:65
    last_direction: Option<Direction>,
    /// systemd: journal-file.h:77-82
    current_offset: u64,
    current_seqnum: u64,
    current_realtime: u64,
    current_monotonic: u64,
    current_boot_id: [u8; 16],
    current_xor_hash: u64,
}

impl JournalReader {
    /// Open a journal file for reading.
    ///
    /// systemd: journal_file_open() read path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = MmapCache::new(&file)?;

        if mmap.len() < 272 {
            return Err(Error::Truncated { offset: 0 });
        }
        let hbuf = mmap
            .read_bytes(0, 272)
            .ok_or(Error::Truncated { offset: 0 })?;
        let h: Header = unsafe { std::ptr::read_unaligned(hbuf.as_ptr() as *const Header) };

        let file_size = file.metadata()?.len();
        verify_header(&h, file_size, false, None)?;

        let incompat = from_le32(&h.incompatible_flags);
        let keyed_hash = (incompat & incompat::KEYED_HASH) != 0;
        let compact = (incompat & incompat::COMPACT) != 0;

        let data_ht_items = from_le64(&h.data_hash_table_offset);
        let data_ht_size = from_le64(&h.data_hash_table_size);
        let data_ht_n = data_ht_size / HASH_ITEM_SIZE as u64;

        let field_ht_items = from_le64(&h.field_hash_table_offset);
        let field_ht_size = from_le64(&h.field_hash_table_size);
        let field_ht_n = field_ht_size / HASH_ITEM_SIZE as u64;

        Ok(Self {
            file,
            mmap,
            keyed_hash,
            compact,
            data_ht_items,
            data_ht_n,
            field_ht_items,
            field_ht_n,
            entry_array_offset: from_le64(&h.entry_array_offset),
            n_entries: from_le64(&h.n_entries),
            chain_cache: IndexMap::new(),
            location_type: LocationType::Head,
            last_direction: None,
            current_offset: 0,
            current_seqnum: 0,
            current_realtime: 0,
            current_monotonic: 0,
            current_boot_id: [0u8; 16],
            current_xor_hash: 0,
            header: h,
        })
    }

    // ══════════════════════════════════════════════════════════════════════
    // Error classification (matching systemd's IN_SET(r, -EBADMSG, -EADDRNOTAVAIL))
    // ══════════════════════════════════════════════════════════════════════

    /// Returns true if the error indicates corruption (not a fatal I/O error).
    /// systemd: IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)
    fn is_corruption_error(e: &Error) -> bool {
        matches!(e, Error::CorruptObject { .. } | Error::Truncated { .. } | Error::InvalidFile(_))
    }

    // ══════════════════════════════════════════════════════════════════════
    // Low-level I/O helpers
    // ══════════════════════════════════════════════════════════════════════

    fn read_u64_at(&mut self, offset: u64) -> Result<u64> {
        self.mmap.read_u64(offset).ok_or(Error::Truncated { offset })
    }

    fn read_u32_at(&mut self, offset: u64) -> Result<u32> {
        self.mmap.read_u32(offset).ok_or(Error::Truncated { offset })
    }

    fn read_bytes_at(&mut self, offset: u64, n: usize) -> Result<Vec<u8>> {
        self.mmap
            .read_bytes(offset, n)
            .map(|s| s.to_vec())
            .ok_or(Error::Truncated { offset })
    }

    // ══════════════════════════════════════════════════════════════════════
    // Object access
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1088-1136 journal_file_move_to_object
    ///
    /// Validate that the object at `offset` is well-formed and of the expected type.
    /// Returns (object_type, object_size) on success.
    fn move_to_object(&mut self, expected_type: ObjectType, offset: u64) -> Result<(u8, u64)> {
        if !valid64(offset) {
            return Err(Error::CorruptObject {
                offset,
                reason: "offset not 8-byte aligned".into(),
            });
        }
        let header_size = from_le64(&self.header.header_size);
        if offset < header_size {
            return Err(Error::CorruptObject {
                offset,
                reason: "offset inside file header".into(),
            });
        }

        // Read ObjectHeader (16 bytes)
        let obj_type = self.mmap.read_u8(offset).ok_or(Error::Truncated { offset })?;
        let obj_size = self.read_u64_at(offset + 8)?;

        // check_object_header (includes type range + minimum size + expected type check)
        check_object_header(obj_type, obj_size, offset, self.compact, Some(expected_type))?;

        // Per-type validation (systemd: check_object, C:936-1086)
        // Read type-specific fields for validation
        let flags = self.mmap.read_u8(offset + 1).ok_or(Error::Truncated { offset })?;

        let otype = ObjectType::try_from(obj_type).unwrap_or(ObjectType::Unused);
        match otype {
            ObjectType::Data => {
                let next_hash = self.read_u64_at(offset + 24)?;
                let next_field = self.read_u64_at(offset + 32)?;
                let entry_off = self.read_u64_at(offset + 40)?;
                let entry_arr = self.read_u64_at(offset + 48)?;
                let n_ent = self.read_u64_at(offset + 56)?;
                check_object(otype, obj_size, flags, offset, self.compact,
                    0, next_hash, next_field, entry_off, entry_arr, n_ent,
                    0, 0, 0, &[0u8; 16], 0, 0)?;
            }
            ObjectType::Entry => {
                let seqnum = self.read_u64_at(offset + 16)?;
                let realtime = self.read_u64_at(offset + 24)?;
                let monotonic = self.read_u64_at(offset + 32)?;
                let boot_bytes = self.read_bytes_at(offset + 40, 16)?;
                let mut boot = [0u8; 16];
                boot.copy_from_slice(&boot_bytes);
                check_object(otype, obj_size, flags, offset, self.compact,
                    0, 0, 0, 0, 0, 0,
                    seqnum, realtime, monotonic, &boot, 0, 0)?;
            }
            ObjectType::EntryArray => {
                let next = self.read_u64_at(offset + OBJECT_HEADER_SIZE as u64)?;
                check_object(otype, obj_size, flags, offset, self.compact,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, &[0u8; 16], next, 0)?;
            }
            ObjectType::Tag => {
                // Read epoch from offset+24 (16-byte ObjectHeader + 8-byte seqnum = epoch at +24)
                let epoch = self.read_u64_at(offset + 24)?;
                check_object(otype, obj_size, flags, offset, self.compact,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, &[0u8; 16], 0, epoch)?;
            }
            ObjectType::Field => {
                // systemd: journal-file.c:977-998
                if obj_size <= FIELD_OBJECT_HEADER_SIZE as u64 {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: "FIELD object has no payload".into(),
                    });
                }
                let next_hash = self.read_u64_at(offset + 24)?;
                if next_hash != 0 && !valid64(next_hash) {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: "FIELD next_hash_offset not aligned".into(),
                    });
                }
                let head_data = self.read_u64_at(offset + 32)?;
                if head_data != 0 && !valid64(head_data) {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: "FIELD head_data_offset not aligned".into(),
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
            _ => {
                // Unused — minimal validation already done by check_object_header
            }
        }

        Ok((obj_type, obj_size))
    }

    /// systemd: journal-file.h:250-255 journal_file_entry_array_item
    ///
    /// Read a single item from an entry array object at the given index.
    fn entry_array_item(&mut self, arr_offset: u64, index: u64) -> Result<u64> {
        let item_sz = entry_array_item_size(self.compact);
        let slot_off = arr_offset + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + index * item_sz;
        if self.compact {
            Ok(self.read_u32_at(slot_off)? as u64)
        } else {
            self.read_u64_at(slot_off)
        }
    }

    /// systemd: journal-file.h:213-218 journal_file_entry_item_object_offset
    ///
    /// Read the data object offset from an entry item at the given index.
    fn entry_item_object_offset(&mut self, entry_offset: u64, index: u64) -> Result<u64> {
        let item_sz = entry_item_size(self.compact);
        let slot_off = entry_offset + ENTRY_OBJECT_HEADER_SIZE as u64 + index * item_sz;
        if self.compact {
            Ok(self.read_u32_at(slot_off)? as u64)
        } else {
            self.read_u64_at(slot_off)
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Data object lookup
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1621-1691 journal_file_find_data_object_with_hash
    ///
    /// Walk the data hash chain for `hash`, compare payloads (with decompression),
    /// return the offset of the matching DATA object.
    pub fn find_data_object_with_hash(
        &mut self,
        data: &[u8],
        hash: u64,
    ) -> Result<Option<u64>> {
        if self.data_ht_n == 0 {
            return Ok(None);
        }

        let h = hash % self.data_ht_n;
        let item_off = self.data_ht_items + h * HASH_ITEM_SIZE as u64;
        // Read head_hash_offset from the hash table bucket
        let mut p = self.read_u64_at(item_off)?;

        // systemd: get_next_hash_offset detects loops via monotonicity check (nextp <= p)
        while p > 0 {
            let (_, _obj_size) = self.move_to_object(ObjectType::Data, p)?;

            let stored_hash = self.read_u64_at(p + 16)?; // data.hash
            let nextp = self.read_u64_at(p + 24)?; // data.next_hash_offset
            if stored_hash != hash {
                if nextp > 0 && nextp <= p {
                    return Err(Error::InvalidFile("data hash chain loop detected".into()));
                }
                p = nextp;
                continue;
            }

            // Compare payload (with decompression)
            let payload = self.read_data_payload_raw(p)?;
            if payload.len() == data.len() && payload == data {
                return Ok(Some(p));
            }

            if nextp > 0 && nextp <= p {
                return Err(Error::InvalidFile("data hash chain loop detected".into()));
            }
            p = nextp;
        }

        Ok(None)
    }

    /// systemd: journal-file.c:1693-1708 journal_file_find_data_object
    pub fn find_data_object(&mut self, data: &[u8]) -> Result<Option<u64>> {
        let hash = journal_file_hash_data(data, self.keyed_hash, &self.header.file_id);
        self.find_data_object_with_hash(data, hash)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Field object lookup
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:1520-1583 journal_file_find_field_object_with_hash
    ///
    /// Walk the field hash chain for `hash`, compare payloads,
    /// return the offset of the matching FIELD object.
    pub fn find_field_object_with_hash(
        &mut self,
        field: &[u8],
        hash: u64,
    ) -> Result<Option<u64>> {
        if field.is_empty() {
            return Ok(None);
        }
        if self.field_ht_n == 0 {
            return Ok(None);
        }

        let expected_obj_size = FIELD_OBJECT_HEADER_SIZE as u64 + field.len() as u64;

        let h = hash % self.field_ht_n;
        let item_off = self.field_ht_items + h * HASH_ITEM_SIZE as u64;
        // Read head_hash_offset from the hash table bucket
        let mut p = self.read_u64_at(item_off)?;

        #[allow(unused_assignments)]
        let mut prev = 0u64;

        while p > 0 {
            let (_, obj_size) = self.move_to_object(ObjectType::Field, p)?;

            let stored_hash = self.read_u64_at(p + 16)?; // field.hash
            if stored_hash == hash
                && obj_size == expected_obj_size
            {
                // Compare payload
                let payload = self.read_bytes_at(
                    p + FIELD_OBJECT_HEADER_SIZE as u64,
                    field.len(),
                )?;
                if payload == field {
                    return Ok(Some(p));
                }
            }

            // Advance to next in chain with loop detection
            prev = p;
            p = self.read_u64_at(p + 24)?; // field.next_hash_offset
            if p > 0 && p <= prev {
                return Err(Error::InvalidFile("field hash chain loop detected".into()));
            }
        }

        Ok(None)
    }

    /// systemd: journal-file.c:1603-1619 journal_file_find_field_object
    pub fn find_field_object(&mut self, field: &[u8]) -> Result<Option<u64>> {
        let hash = journal_file_hash_data(field, self.keyed_hash, &self.header.file_id);
        self.find_field_object_with_hash(field, hash)
    }

    /// Read the raw payload of a DATA object, handling compact mode and decompression.
    ///
    /// systemd: journal-file.c:1999-2034 journal_file_data_payload
    fn read_data_payload_raw(&mut self, data_offset: u64) -> Result<Vec<u8>> {
        let obj_size = self.read_u64_at(data_offset + 8)?;
        let flags_byte = self.mmap.read_u8(data_offset + 1)
            .ok_or(Error::Truncated { offset: data_offset })?;

        let poffset = data_payload_offset(self.compact);
        if obj_size < poffset {
            return Err(Error::CorruptObject {
                offset: data_offset,
                reason: format!("DATA object size {} < minimum {}", obj_size, poffset),
            });
        }
        let payload_len = (obj_size - poffset) as usize;
        let raw = self.read_bytes_at(data_offset + poffset, payload_len)?;

        let compressed = flags_byte & obj_flags::COMPRESSED_MASK;
        if compressed & obj_flags::COMPRESSED_ZSTD != 0 {
            #[cfg(feature = "zstd-compression")]
            {
                let decompressed = zstd::decode_all(raw.as_slice())
                    .map_err(|e| Error::Decompression(e.to_string()))?;
                if decompressed.len() as u64 > 4 * 1024 * 1024 * 1024 {
                    return Err(Error::Decompression("ZSTD decompressed size exceeds 4GiB limit".into()));
                }
                return Ok(decompressed);
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
                    .map_err(|e| Error::Decompression(e.to_string()))?;
                if decompressed.len() as u64 > 4 * 1024 * 1024 * 1024 {
                    return Err(Error::Decompression("XZ decompressed size exceeds 4GiB limit".into()));
                }
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
                // systemd LZ4 format: first 8 bytes are le64 uncompressed size,
                // followed by the LZ4 block-compressed data.
                if raw.len() < 8 {
                    return Err(Error::Decompression("LZ4 data too short".into()));
                }
                let uncompressed_size_u64 =
                    u64::from_le_bytes(raw[..8].try_into().unwrap());
                if uncompressed_size_u64 > 4 * 1024 * 1024 * 1024 {
                    return Err(Error::Decompression("LZ4 uncompressed size exceeds 4GiB limit".into()));
                }
                let uncompressed_size = uncompressed_size_u64 as usize;
                let compressed_data = &raw[8..];
                let decompressed =
                    lz4_flex::decompress(compressed_data, uncompressed_size)
                        .map_err(|e| Error::Decompression(e.to_string()))?;
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
                "journal uses unknown compression".into(),
            ));
        }

        Ok(raw)
    }

    /// Read the payload of a DATA object, split into (field_name, field_value).
    pub fn read_data_payload(&mut self, offset: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        let (obj_type, _) = self.move_to_object(ObjectType::Data, offset)?;
        if obj_type != ObjectType::Data as u8 {
            return Err(Error::CorruptObject {
                offset,
                reason: format!("expected Data object, got type {}", obj_type),
            });
        }

        let payload = self.read_data_payload_raw(offset)?;

        if let Some(eq) = payload.iter().position(|&b| b == b'=') {
            Ok((payload[..eq].to_vec(), payload[eq + 1..].to_vec()))
        } else {
            Ok((payload, Vec::new()))
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Entry reading
    // ══════════════════════════════════════════════════════════════════════

    /// Read a full journal entry at the given offset.
    pub fn read_entry_at(&mut self, entry_offset: u64) -> Result<JournalEntry> {
        let (_, obj_size) = self.move_to_object(ObjectType::Entry, entry_offset)?;

        let seqnum = self.read_u64_at(entry_offset + 16)?;
        let realtime = self.read_u64_at(entry_offset + 24)?;
        let monotonic = self.read_u64_at(entry_offset + 32)?;
        let boot_id_bytes = self.read_bytes_at(entry_offset + 40, 16)?;
        let mut boot_id = [0u8; 16];
        boot_id.copy_from_slice(&boot_id_bytes);

        let item_sz = entry_item_size(self.compact);
        let items_bytes = obj_size.saturating_sub(ENTRY_OBJECT_HEADER_SIZE as u64);
        let n_items = items_bytes / item_sz;

        let mut fields = Vec::with_capacity(n_items as usize);
        for i in 0..n_items {
            let data_off = self.entry_item_object_offset(entry_offset, i)?;
            if data_off == 0 {
                continue;
            }
            let field = self.read_data_payload(data_off)?;
            fields.push(field);
        }

        Ok(JournalEntry {
            seqnum,
            realtime,
            monotonic,
            boot_id,
            fields,
        })
    }

    // ══════════════════════════════════════════════════════════════════════
    // Chain cache
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:2671-2710 chain_cache_put
    fn chain_cache_put(
        &mut self,
        first: u64,
        array: u64,
        begin: u64,
        total: u64,
        last_index: u64,
    ) {
        // Don't cache if array == first (first array in chain, not worth caching)
        if array == first {
            return;
        }

        // Evict oldest (insertion-order FIFO, matching systemd's ordered_hashmap_steal_first)
        if !self.chain_cache.contains_key(&first) && self.chain_cache.len() >= CHAIN_CACHE_MAX {
            self.chain_cache.shift_remove_index(0);
        }

        self.chain_cache.insert(
            first,
            ChainCacheItem {
                first,
                array,
                begin,
                total,
                last_index,
            },
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Array helpers
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:2712-2730 bump_array_index
    fn bump_array_index(i: &mut u64, direction: Direction, n: u64) -> bool {
        match direction {
            Direction::Down => {
                if *i >= n - 1 {
                    return false;
                }
                *i += 1;
            }
            Direction::Up => {
                if *i == 0 {
                    return false;
                }
                *i -= 1;
            }
        }
        true
    }

    /// systemd: journal-file.c:2732-2778 bump_entry_array
    ///
    /// Navigate to the next (Down) or previous (Up) entry array in the chain.
    fn bump_entry_array(
        &mut self,
        arr_offset: u64,
        first: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        match direction {
            Direction::Down => {
                // Verify the object at arr_offset is actually an EntryArray
                let obj_type = self.mmap.read_u8(arr_offset).ok_or(Error::Truncated { offset: arr_offset })?;
                if obj_type != ObjectType::EntryArray as u8 {
                    return Err(Error::CorruptObject {
                        offset: arr_offset,
                        reason: format!(
                            "expected EntryArray object type, found {}",
                            obj_type
                        ),
                    });
                }
                // Read next_entry_array_offset from current array
                let next = self.read_u64_at(arr_offset + OBJECT_HEADER_SIZE as u64)?;
                Ok(if next > 0 { Some(next) } else { None })
            }
            Direction::Up => {
                // Singly linked — walk from first to find predecessor of arr_offset
                let mut p = first;
                let mut q = 0u64;
                while p > 0 && p != arr_offset {
                    let (_, _) = self.move_to_object(ObjectType::EntryArray, p)?;
                    q = p;
                    p = self.read_u64_at(p + OBJECT_HEADER_SIZE as u64)?;
                }
                if p == 0 {
                    return Err(Error::CorruptObject {
                        offset: arr_offset,
                        reason: "could not find previous entry array in chain".into(),
                    });
                }
                Ok(if q > 0 { Some(q) } else { None })
            }
        }
    }

    /// systemd: journal-file.c:3524-3534 check_properly_ordered
    fn check_properly_ordered(new_offset: u64, old_offset: u64, direction: Direction) -> bool {
        if old_offset == 0 || new_offset == 0 {
            return false;
        }
        match direction {
            Direction::Down => new_offset > old_offset,
            Direction::Up => new_offset < old_offset,
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // generic_array_get
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:2780-2901 generic_array_get
    ///
    /// Get the entry at index `i` in the entry array chain starting at `first`.
    /// Handles corruption by skipping bad entries in the given direction.
    pub fn generic_array_get(
        &mut self,
        first: u64,
        mut i: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let mut a = first;
        let mut t: u64 = 0;
        let mut k: u64 = 0;

        // Try chain cache
        // systemd: only uses cache when i > ci->total (strictly greater)
        if let Some(ci) = self.chain_cache.get(&first).cloned() {
            if i > ci.total {
                a = ci.array;
                i -= ci.total;
                t = ci.total;
            }
        }

        // Walk to the array containing index i
        while a > 0 {
            match self.move_to_object(ObjectType::EntryArray, a) {
                Ok((_, obj_size)) => {
                    k = entry_array_n_items(obj_size, self.compact);
                    if k == 0 {
                        return Ok(None);
                    }
                    if i < k {
                        break;
                    }
                    i -= k;
                    t += k;
                    a = self.read_u64_at(a + OBJECT_HEADER_SIZE as u64)?;
                }
                Err(ref e) if Self::is_corruption_error(e) => {
                    // systemd: IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)
                    if direction == Direction::Down {
                        return Ok(None);
                    }
                    i = u64::MAX;
                    break;
                }
                Err(e) => return Err(e), // propagate I/O errors
            }
        }

        // Now find the first valid entry at or near index i
        while a > 0 {
            if i == u64::MAX {
                match self.bump_entry_array(a, first, direction)? {
                    None => return Ok(None),
                    Some(prev) => {
                        a = prev;
                        let (_, obj_size) = self.move_to_object(ObjectType::EntryArray, a)?;
                        k = entry_array_n_items(obj_size, self.compact);
                        if k == 0 {
                            break;
                        }
                        match direction {
                            Direction::Down => i = 0,
                            Direction::Up => {
                                if t < k {
                                    return Err(Error::CorruptObject {
                                        offset: a,
                                        reason: "chain cache broken".into(),
                                    });
                                }
                                i = k - 1;
                                t -= k;
                            }
                        }
                    }
                }
            }

            loop {
                let p = self.entry_array_item(a, i)?;
                match self.move_to_object(ObjectType::Entry, p) {
                    Ok(_) => {
                        // Cache this position
                        let begin = self.entry_array_item(a, 0)?;
                        self.chain_cache_put(first, a, begin, t, i);
                        return Ok(Some(p));
                    }
                    Err(ref e) if Self::is_corruption_error(e) => {
                        // Corrupt entry, skip
                        if !Self::bump_array_index(&mut i, direction, k) {
                            break;
                        }
                    }
                    Err(e) => return Err(e), // propagate I/O errors
                }
            }

            // All entries in this array were corrupt, move to next/prev
            if direction == Direction::Down {
                t += k;
            }
            i = u64::MAX;
        }

        Ok(None)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Test callbacks for bisection
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:3321-3333 test_object_offset
    fn test_object_offset(&self, p: u64, needle: u64) -> Result<i32> {
        if p == 0 {
            return Ok(TEST_GOTO_PREVIOUS);
        }
        if p == needle {
            Ok(TEST_FOUND)
        } else if p < needle {
            Ok(TEST_LEFT)
        } else {
            Ok(TEST_RIGHT)
        }
    }

    /// systemd: journal-file.c:3355-3373 test_object_seqnum
    fn test_object_seqnum(&mut self, p: u64, needle: u64) -> Result<i32> {
        let (_, _) = self.move_to_object(ObjectType::Entry, p)?;
        let sq = self.read_u64_at(p + 16)?; // entry.seqnum
        if sq == needle {
            Ok(TEST_FOUND)
        } else if sq < needle {
            Ok(TEST_LEFT)
        } else {
            Ok(TEST_RIGHT)
        }
    }

    /// systemd: journal-file.c:3395-3413 test_object_realtime
    fn test_object_realtime(&mut self, p: u64, needle: u64) -> Result<i32> {
        let (_, _) = self.move_to_object(ObjectType::Entry, p)?;
        let rt = self.read_u64_at(p + 24)?; // entry.realtime
        if rt == needle {
            Ok(TEST_FOUND)
        } else if rt < needle {
            Ok(TEST_LEFT)
        } else {
            Ok(TEST_RIGHT)
        }
    }

    /// systemd: journal-file.c:3435-3453 test_object_monotonic
    fn test_object_monotonic(&mut self, p: u64, needle: u64) -> Result<i32> {
        let (_, _) = self.move_to_object(ObjectType::Entry, p)?;
        let m = self.read_u64_at(p + 32)?; // entry.monotonic
        if m == needle {
            Ok(TEST_FOUND)
        } else if m < needle {
            Ok(TEST_LEFT)
        } else {
            Ok(TEST_RIGHT)
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // generic_array_bisect_step
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:2913-2998 generic_array_bisect_step
    ///
    /// Test the entry at index `i` in `arr_offset` against `needle`.
    /// Adjusts `left`/`right`/`m` boundaries.
    /// Returns TEST_RIGHT, TEST_LEFT, TEST_GOTO_NEXT, TEST_GOTO_PREVIOUS.
    fn generic_array_bisect_step(
        &mut self,
        arr_offset: u64,
        i: u64,
        needle: u64,
        test_fn: &dyn Fn(&mut Self, u64, u64) -> Result<i32>,
        direction: Direction,
        m: &mut u64,
        left: &mut u64,
        right: &mut u64,
    ) -> Result<i32> {
        // Match systemd's entry assertions (journal-file.c generic_array_bisect_step).
        debug_assert!(*left <= i, "bisect_step: left ({}) > i ({})", *left, i);
        debug_assert!(i <= *right, "bisect_step: i ({}) > right ({})", i, *right);
        debug_assert!(*right < *m, "bisect_step: right ({}) >= m ({})", *right, *m);

        let p = self.entry_array_item(arr_offset, i)?;
        let r = if p == 0 {
            Err(Error::CorruptObject {
                offset: arr_offset,
                reason: "null entry in array".into(),
            })
        } else {
            test_fn(self, p, needle)
        };

        let r = match r {
            Err(ref e) if Self::is_corruption_error(e) => {
                // systemd: IN_SET(r, -EBADMSG, -EADDRNOTAVAIL) — corruption only
                if i == *left {
                    // systemd: journal-file.c:2955
                    debug_assert!(i == 0 || (*right - *left <= 1 && direction == Direction::Down));
                    return Ok(TEST_GOTO_PREVIOUS);
                }
                *m = i;
                *right = i - 1;
                return Ok(TEST_RIGHT);
            }
            Err(e) => return Err(e), // propagate I/O errors
            Ok(v) => v,
        };

        // If FOUND, treat as RIGHT (for DOWN) or LEFT (for UP) to find first/last match
        let r = if r == TEST_FOUND {
            if direction == Direction::Down {
                TEST_RIGHT
            } else {
                TEST_LEFT
            }
        } else {
            r
        };

        if r == TEST_RIGHT {
            if direction == Direction::Down {
                *right = i;
            } else {
                if i == 0 {
                    return Ok(TEST_GOTO_PREVIOUS);
                }
                *right = i - 1;
            }
        } else {
            // TEST_LEFT
            if direction == Direction::Down {
                if i == *m - 1 {
                    return Ok(TEST_GOTO_NEXT);
                }
                *left = i + 1;
            } else {
                *left = i;
            }
        }

        Ok(r)
    }

    // ══════════════════════════════════════════════════════════════════════
    // generic_array_bisect
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:3000-3234 generic_array_bisect
    ///
    /// Binary search the entry array chain for the entry closest to `needle`.
    /// Returns (entry_offset, index_from_chain_start) or None if not found.
    pub fn generic_array_bisect(
        &mut self,
        first: u64,
        mut n: u64,
        needle: u64,
        test_fn: &dyn Fn(&mut Self, u64, u64) -> Result<i32>,
        direction: Direction,
    ) -> Result<Option<(u64, u64)>> {
        if n == 0 {
            return Ok(None);
        }

        let mut a = first;
        let mut t: u64 = 0;
        let mut last_index = u64::MAX;

        // Try chain cache
        if let Some(ci) = self.chain_cache.get(&first).cloned() {
            if n > ci.total && ci.begin != 0 {
                match test_fn(self, ci.begin, needle) {
                    Ok(TEST_LEFT) => {
                        a = ci.array;
                        n -= ci.total;
                        t = ci.total;
                        last_index = ci.last_index;
                    }
                    // systemd: IN_SET(r, -EBADMSG, -EADDRNOTAVAIL) — ignore corruption
                    Err(ref e) if Self::is_corruption_error(e) => {}
                    Err(e) => return Err(e), // propagate I/O errors
                    _ => {}
                }
            }
        }

        while a > 0 {
            let (_, obj_size) = self.move_to_object(ObjectType::EntryArray, a)?;
            let k = entry_array_n_items(obj_size, self.compact);
            let mut m = k.min(n);
            let m_original = m;
            if m == 0 {
                return Ok(None);
            }

            let mut left: u64 = 0;
            let mut right: u64 = m - 1;

            // For UP direction, test first element to see if we should go to previous array
            if direction == Direction::Up && left < right {
                let r = self.generic_array_bisect_step(
                    a, 0, needle, test_fn, direction, &mut m, &mut left, &mut right,
                )?;
                if r == TEST_GOTO_PREVIOUS {
                    return self.bisect_goto_previous(a, first, t, direction);
                }
            }

            // Test last element
            let r = self.generic_array_bisect_step(
                a, right, needle, test_fn, direction, &mut m, &mut left, &mut right,
            )?;
            if r == TEST_GOTO_PREVIOUS {
                return self.bisect_goto_previous(a, first, t, direction);
            }

            if r == TEST_RIGHT {
                // Needle is in this array — bisect

                // Try near last_index first for locality
                if last_index > 0 && left < last_index - 1 && last_index - 1 < right {
                    let r = self.generic_array_bisect_step(
                        a,
                        last_index - 1,
                        needle,
                        test_fn,
                        direction,
                        &mut m,
                        &mut left,
                        &mut right,
                    )?;
                    if r == TEST_GOTO_PREVIOUS {
                        return self.bisect_goto_previous(a, first, t, direction);
                    }
                }
                if last_index < u64::MAX && left < last_index + 1 && last_index + 1 < right {
                    let r = self.generic_array_bisect_step(
                        a,
                        last_index + 1,
                        needle,
                        test_fn,
                        direction,
                        &mut m,
                        &mut left,
                        &mut right,
                    )?;
                    if r == TEST_GOTO_PREVIOUS {
                        return self.bisect_goto_previous(a, first, t, direction);
                    }
                }

                // Main bisection loop
                loop {
                    if left == right {
                        // systemd: journal-file.c:3121-3144 — only re-test on truncation+DOWN
                        if m != m_original && direction == Direction::Down {
                            let r = self.generic_array_bisect_step(
                                a, left, needle, test_fn, direction, &mut m, &mut left, &mut right,
                            )?;
                            if r == TEST_GOTO_PREVIOUS || r == TEST_GOTO_NEXT {
                                return Ok(None);
                            }
                            // systemd: journal-file.c:3139-3140
                            debug_assert!(r == TEST_RIGHT);
                            debug_assert!(left == right);
                        }
                        // Found
                        return self.bisect_found(a, first, left, t);
                    }

                    let i = (left + right + if direction == Direction::Up { 1 } else { 0 }) / 2;

                    let r = self.generic_array_bisect_step(
                        a, i, needle, test_fn, direction, &mut m, &mut left, &mut right,
                    )?;
                    if r == TEST_GOTO_PREVIOUS {
                        return self.bisect_goto_previous(a, first, t, direction);
                    }
                    if r == TEST_GOTO_NEXT {
                        return Ok(None);
                    }
                }
            }

            // systemd: journal-file.c:3161
            debug_assert!(r == (if direction == Direction::Down { TEST_GOTO_NEXT } else { TEST_LEFT }));

            // Not in this array, go to next
            if k >= n {
                if direction == Direction::Up {
                    let i = n - 1;
                    return self.bisect_found(a, first, i, t);
                }
                return Ok(None);
            }

            n -= k;
            t += k;
            last_index = u64::MAX;
            a = self.read_u64_at(a + OBJECT_HEADER_SIZE as u64)?;
        }

        Ok(None)
    }

    /// Helper: return found result from bisection.
    fn bisect_found(
        &mut self,
        arr_offset: u64,
        first: u64,
        i: u64,
        t: u64,
    ) -> Result<Option<(u64, u64)>> {
        // Cache
        let begin = self.entry_array_item(arr_offset, 0)?;
        if begin == 0 {
            return Err(Error::CorruptObject {
                offset: arr_offset,
                reason: "first entry in array is null".into(),
            });
        }
        self.chain_cache_put(first, arr_offset, begin, t, i);

        let p = self.entry_array_item(arr_offset, i)?;
        if p == 0 {
            return Err(Error::CorruptObject {
                offset: arr_offset,
                reason: "null entry at bisection result".into(),
            });
        }

        // Validate it's an entry
        let _ = self.move_to_object(ObjectType::Entry, p)?;

        Ok(Some((p, t + i)))
    }

    /// Helper: handle TEST_GOTO_PREVIOUS from bisection.
    /// systemd: journal-file.c:3197-3218 (the `previous:` label)
    fn bisect_goto_previous(
        &mut self,
        arr_offset: u64,
        first: u64,
        t: u64,
        direction: Direction,
    ) -> Result<Option<(u64, u64)>> {
        // The current array is the first in the chain — no previous array
        if t == 0 {
            return Ok(None);
        }

        // systemd: journal-file.c:3190-3191
        // When going downward, there is no matching entry in the previous array.
        if direction == Direction::Down {
            return Ok(None);
        }

        // Get the last entry of the previous array
        let prev_a = match self.bump_entry_array(arr_offset, first, Direction::Up)? {
            Some(a) => a,
            None => return Ok(None),
        };

        let (_, prev_obj_size) = self.move_to_object(ObjectType::EntryArray, prev_a)?;
        let prev_k = entry_array_n_items(prev_obj_size, self.compact);
        if prev_k == 0 || t < prev_k {
            return Err(Error::CorruptObject {
                offset: prev_a,
                reason: "chain total inconsistent with previous array size".into(),
            });
        }

        let new_t = t - prev_k;
        let i = prev_k - 1;

        self.bisect_found(prev_a, first, i, new_t)
    }

    // ══════════════════════════════════════════════════════════════════════
    // generic_array_bisect_for_data (plus_one variant)
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:3236-3319 generic_array_bisect_for_data
    ///
    /// Like generic_array_bisect but handles the extra inline entry in DATA objects.
    pub fn generic_array_bisect_for_data(
        &mut self,
        data_offset: u64,
        needle: u64,
        test_fn: &dyn Fn(&mut Self, u64, u64) -> Result<i32>,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let (_, _) = self.move_to_object(ObjectType::Data, data_offset)?;

        let mut n = self.read_u64_at(data_offset + 56)?; // n_entries
        if n == 0 {
            return Ok(None);
        }
        n -= 1; // subtract the inline entry

        let extra = self.read_u64_at(data_offset + 40)?; // entry_offset (inline)
        let first = self.read_u64_at(data_offset + 48)?; // entry_array_offset

        // systemd: journal-file.c:3264 calls test_object(f, extra, needle) unconditionally;
        // extra == 0 with n_entries >= 1 is file corruption, propagate as error.
        if extra == 0 {
            return Err(Error::CorruptObject {
                offset: data_offset,
                reason: "DATA entry_offset is zero but n_entries >= 1".into(),
            });
        }

        // Test the extra (inline) entry
        let r = test_fn(self, extra, needle)?;

        if direction == Direction::Down {
            if r == TEST_FOUND || r == TEST_RIGHT {
                // Extra is the answer
                let _ = self.move_to_object(ObjectType::Entry, extra)?;
                return Ok(Some(extra));
            }
        } else {
            // Direction::Up
            if r == TEST_RIGHT {
                return Ok(None); // All entries are before needle
            }
        }

        // Search the array chain
        if let Some((p, _)) = self.generic_array_bisect(first, n, needle, test_fn, direction)? {
            return Ok(Some(p));
        }

        // Nothing found in chain; for UP, use the extra
        if direction == Direction::Up && extra != 0 {
            let _ = self.move_to_object(ObjectType::Entry, extra)?;
            return Ok(Some(extra));
        }

        Ok(None)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Entry navigation
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:3536-3605 journal_file_next_entry
    ///
    /// Given `p` (current entry offset, 0 for first/last), move to the
    /// next (Down) or previous (Up) entry.
    pub fn next_entry(
        &mut self,
        p: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        if self.n_entries == 0 {
            return Ok(None);
        }

        if p == 0 {
            // Return first or last entry
            let idx = if direction == Direction::Down {
                0
            } else {
                self.n_entries - 1
            };
            return self.generic_array_get(self.entry_array_offset, idx, direction);
        }

        // Find current position via bisection
        let test_offset = |s: &mut Self, entry_p: u64, needle: u64| -> Result<i32> {
            s.test_object_offset(entry_p, needle)
        };

        let result = self.generic_array_bisect(
            self.entry_array_offset,
            self.n_entries,
            p,
            &test_offset,
            direction,
        )?;

        let (q, mut i) = match result {
            Some(v) => v,
            None => return Ok(None),
        };

        debug_assert!(if direction == Direction::Down { p <= q } else { q <= p });

        if p == q {
            // Found exact match — move one step
            if !Self::bump_array_index(&mut i, direction, self.n_entries) {
                return Ok(None);
            }
        }

        let result = self.generic_array_get(self.entry_array_offset, i, direction)?;

        if let Some(new_offset) = result {
            if !Self::check_properly_ordered(new_offset, p, direction) {
                return Err(Error::CorruptObject {
                    offset: new_offset,
                    reason: "entry array not properly ordered".into(),
                });
            }
        }

        Ok(result)
    }

    /// systemd: journal-file.c:3335-3353 journal_file_move_to_entry_by_offset
    pub fn move_to_entry_by_offset(
        &mut self,
        p: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let test_offset = |s: &mut Self, entry_p: u64, needle: u64| -> Result<i32> {
            s.test_object_offset(entry_p, needle)
        };
        Ok(self
            .generic_array_bisect(
                self.entry_array_offset,
                self.n_entries,
                p,
                &test_offset,
                direction,
            )?
            .map(|(off, _)| off))
    }

    /// systemd: journal-file.c:3375-3393 journal_file_move_to_entry_by_seqnum
    pub fn move_to_entry_by_seqnum(
        &mut self,
        seqnum: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let test_seqnum = |s: &mut Self, p: u64, needle: u64| -> Result<i32> {
            s.test_object_seqnum(p, needle)
        };
        Ok(self
            .generic_array_bisect(
                self.entry_array_offset,
                self.n_entries,
                seqnum,
                &test_seqnum,
                direction,
            )?
            .map(|(off, _)| off))
    }

    /// systemd: journal-file.c:3415-3433 journal_file_move_to_entry_by_realtime
    pub fn move_to_entry_by_realtime(
        &mut self,
        realtime: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let test_realtime = |s: &mut Self, p: u64, needle: u64| -> Result<i32> {
            s.test_object_realtime(p, needle)
        };
        Ok(self
            .generic_array_bisect(
                self.entry_array_offset,
                self.n_entries,
                realtime,
                &test_realtime,
                direction,
            )?
            .map(|(off, _)| off))
    }

    /// systemd: journal-file.c:3469-3493 journal_file_move_to_entry_by_monotonic
    pub fn move_to_entry_by_monotonic(
        &mut self,
        boot_id: &[u8; 16],
        monotonic: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        // Find the _BOOT_ID= data object
        // systemd: journal-file.c:3455-3467 find_data_object_by_boot_id
        let boot_id_hex = boot_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let boot_data = format!("_BOOT_ID={}", boot_id_hex);
        let data_offset = match self.find_data_object(boot_data.as_bytes())? {
            Some(off) => off,
            None => return Ok(None),
        };

        let test_monotonic = |s: &mut Self, p: u64, needle: u64| -> Result<i32> {
            s.test_object_monotonic(p, needle)
        };

        self.generic_array_bisect_for_data(data_offset, monotonic, &test_monotonic, direction)
    }

    /// systemd: journal-file.c:3674-3696 journal_file_move_to_entry_by_offset_for_data
    pub fn move_to_entry_by_offset_for_data(
        &mut self,
        data_offset: u64,
        p: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let test_offset = |s: &mut Self, entry_p: u64, needle: u64| -> Result<i32> {
            s.test_object_offset(entry_p, needle)
        };
        self.generic_array_bisect_for_data(data_offset, p, &test_offset, direction)
    }

    /// systemd: journal-file.c:3698-3720 journal_file_move_to_entry_by_seqnum_for_data
    pub fn move_to_entry_by_seqnum_for_data(
        &mut self,
        data_offset: u64,
        seqnum: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let test_seqnum = |s: &mut Self, p: u64, needle: u64| -> Result<i32> {
            s.test_object_seqnum(p, needle)
        };
        self.generic_array_bisect_for_data(data_offset, seqnum, &test_seqnum, direction)
    }

    /// systemd: journal-file.c:3722-3744 journal_file_move_to_entry_by_realtime_for_data
    pub fn move_to_entry_by_realtime_for_data(
        &mut self,
        data_offset: u64,
        realtime: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let test_realtime = |s: &mut Self, p: u64, needle: u64| -> Result<i32> {
            s.test_object_realtime(p, needle)
        };
        self.generic_array_bisect_for_data(data_offset, realtime, &test_realtime, direction)
    }

    /// systemd: journal-file.c:3746-3776 journal_file_move_to_entry_by_monotonic_for_data
    ///
    /// Find an entry that belongs to BOTH the given data object's entry array
    /// AND the boot-ID entry array, matching the requested monotonic timestamp.
    /// This uses a convergence loop that bounces between the two entry arrays
    /// via `move_to_entry_by_offset_for_data` until it finds an entry present
    /// in both, or determines no such entry exists.
    pub fn move_to_entry_by_monotonic_for_data(
        &mut self,
        data_offset: u64,
        boot_id: &[u8; 16],
        monotonic: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        // Pin the original data object
        let _ = self.move_to_object(ObjectType::Data, data_offset)?;

        // Look up the _BOOT_ID=<hex> data object
        let boot_id_hex = boot_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let boot_data = format!("_BOOT_ID={}", boot_id_hex);
        let boot_id_offset = match self.find_data_object(boot_data.as_bytes())? {
            Some(off) => off,
            None => return Ok(None),
        };

        // Bisect the boot-ID object's entry array by monotonic time
        let test_monotonic = |s: &mut Self, p: u64, needle: u64| -> Result<i32> {
            s.test_object_monotonic(p, needle)
        };
        let mut p = match self.generic_array_bisect_for_data(
            boot_id_offset,
            monotonic,
            &test_monotonic,
            direction,
        )? {
            Some(off) => off,
            None => return Ok(None),
        };

        // Convergence loop: bounce between the data object and the boot-ID
        // object entry arrays until we find an entry present in both.
        loop {
            // Find entry at offset `p` in the original data object's array
            let q = match self.move_to_entry_by_offset_for_data(data_offset, p, direction)? {
                Some(off) => off,
                None => return Ok(None),
            };

            // If both arrays agree, we found our entry
            if p == q {
                return Ok(Some(p));
            }

            // Now find entry at offset `q` in the boot-ID object's array
            p = match self.move_to_entry_by_offset_for_data(boot_id_offset, q, direction)? {
                Some(off) => off,
                None => return Ok(None),
            };

            // If both arrays agree now, we found our entry
            if q == p {
                return Ok(Some(p));
            }
        }
    }

    /// systemd: journal-file.c:3607-3672 journal_file_move_to_entry_for_data
    ///
    /// Get the first (Down) or last (Up) entry linked to a specific DATA object.
    pub fn move_to_entry_for_data(
        &mut self,
        data_offset: u64,
        direction: Direction,
    ) -> Result<Option<u64>> {
        let (_, _) = self.move_to_object(ObjectType::Data, data_offset)?;

        let mut n = self.read_u64_at(data_offset + 56)?; // n_entries
        if n == 0 {
            return Ok(None);
        }
        n -= 1;

        let extra = self.read_u64_at(data_offset + 40)?; // entry_offset
        let first = self.read_u64_at(data_offset + 48)?; // entry_array_offset

        if direction == Direction::Down && extra > 0 {
            match self.move_to_object(ObjectType::Entry, extra) {
                Ok(_) => return Ok(Some(extra)),
                Err(ref e) if Self::is_corruption_error(e) => {} // fall through to array
                Err(e) => return Err(e),
            }
        }

        if n > 0 {
            let idx = if direction == Direction::Down { 0 } else { n - 1 };
            match self.generic_array_get(first, idx, direction) {
                Ok(Some(p)) => return Ok(Some(p)),
                Ok(None) => {}
                Err(ref e) if Self::is_corruption_error(e) => {}
                Err(e) => return Err(e),
            }
        }

        if direction == Direction::Up && extra > 0 {
            match self.move_to_object(ObjectType::Entry, extra) {
                Ok(_) => return Ok(Some(extra)),
                Err(ref e) if Self::is_corruption_error(e) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(None)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Public convenience iterators
    // ══════════════════════════════════════════════════════════════════════

    /// Return an iterator over all entries in chronological order.
    pub fn entries(&mut self) -> Result<Vec<JournalEntry>> {
        let mut results = Vec::new();
        let mut p = 0u64;

        loop {
            match self.next_entry(p, Direction::Down)? {
                Some(offset) => {
                    let entry = self.read_entry_at(offset)?;
                    results.push(entry);
                    p = offset;
                }
                None => break,
            }
        }

        Ok(results)
    }

    /// Look up all entries that contain a specific `field=value` pair.
    pub fn entries_for_field<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        name: N,
        value: V,
    ) -> Result<Vec<JournalEntry>> {
        let name = name.as_ref();
        let value = value.as_ref();

        let mut payload = Vec::with_capacity(name.len() + 1 + value.len());
        payload.extend_from_slice(name);
        payload.push(b'=');
        payload.extend_from_slice(value);

        let data_offset = match self.find_data_object(&payload)? {
            Some(off) => off,
            None => return Ok(vec![]),
        };

        // Collect all entries linked to this DATA object
        let n_entries = self.read_u64_at(data_offset + 56)?;
        let entry_offset = self.read_u64_at(data_offset + 40)?;
        let entry_array_offset = self.read_u64_at(data_offset + 48)?;

        let mut results = Vec::new();

        // First inline entry
        if entry_offset != 0 {
            match self.read_entry_at(entry_offset) {
                Ok(e) => results.push(e),
                Err(ref e) if Self::is_corruption_error(e) => {} // skip corrupt
                Err(e) => return Err(e), // propagate I/O errors
            }
        }

        // Walk entry array chain
        if n_entries > 1 {
            let mut arr_off = entry_array_offset;
            let mut seen = 1u64;
            while arr_off != 0 && seen < n_entries {
                let (_, obj_size) = self.move_to_object(ObjectType::EntryArray, arr_off)?;
                let _item_sz = entry_array_item_size(self.compact);
                let n_items = entry_array_n_items(obj_size, self.compact);
                let next = self.read_u64_at(arr_off + OBJECT_HEADER_SIZE as u64)?;

                for slot in 0..n_items {
                    if seen >= n_entries {
                        break;
                    }
                    let eoff = self.entry_array_item(arr_off, slot)?;
                    if eoff != 0 {
                        match self.read_entry_at(eoff) {
                            Ok(e) => results.push(e),
                            Err(ref e) if Self::is_corruption_error(e) => {} // skip corrupt
                Err(e) => return Err(e), // propagate I/O errors
                        }
                        seen += 1;
                    }
                }
                arr_off = next;
            }
        }

        Ok(results)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Utility APIs
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:4558-4578
    ///
    /// Return the realtime range of entries in this journal file, or None
    /// if the file has no entries.
    pub fn get_cutoff_realtime_usec(&self) -> Option<(u64, u64)> {
        let head = from_le64(&self.header.head_entry_realtime);
        let tail = from_le64(&self.header.tail_entry_realtime);
        if head == 0 || tail == 0 {
            None
        } else {
            Some((head, tail))
        }
    }

    /// Return the number of entries in this journal file.
    pub fn n_entries(&self) -> u64 {
        self.n_entries
    }

    /// Return a reference to the file header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    // ══════════════════════════════════════════════════════════════════════
    // Location tracking
    // ══════════════════════════════════════════════════════════════════════

    /// systemd: journal-file.c:3495-3509 journal_file_reset_location
    ///
    /// Reset the current seek position to HEAD.  Also clears `last_direction`
    /// so that `next_beyond_location` does not wrongly assume we already hit
    /// EOF (see systemd issue #29216).
    pub fn reset_location(&mut self) {
        self.location_type = LocationType::Head;
        self.current_offset = 0;
        self.current_seqnum = 0;
        self.current_realtime = 0;
        self.current_monotonic = 0;
        self.current_boot_id = [0u8; 16];
        self.current_xor_hash = 0;
        self.last_direction = None;
    }

    /// systemd: journal-file.c:3511-3522 journal_file_save_location
    ///
    /// Save the position of entry at `offset` so that subsequent navigation
    /// calls can use it.
    pub fn save_location(&mut self, offset: u64) -> Result<()> {
        let (_, _) = self.move_to_object(ObjectType::Entry, offset)?;

        self.location_type = LocationType::Seek;
        self.current_offset = offset;
        self.current_seqnum = self.read_u64_at(offset + 16)?;
        self.current_realtime = self.read_u64_at(offset + 24)?;
        self.current_monotonic = self.read_u64_at(offset + 32)?;
        let boot_bytes = self.read_bytes_at(offset + 40, 16)?;
        self.current_boot_id.copy_from_slice(&boot_bytes);
        self.current_xor_hash = self.read_u64_at(offset + 56)?;

        Ok(())
    }

    /// Return the current location type.
    pub fn location_type(&self) -> LocationType {
        self.location_type
    }

    /// Return the last traversal direction, if any.
    pub fn last_direction(&self) -> Option<Direction> {
        self.last_direction
    }

    /// Return the current entry offset (0 if no location saved).
    pub fn current_offset(&self) -> u64 {
        self.current_offset
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::JournalWriter;
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn test_write_then_read() {
        let path = tmp_path("qjournal_readback.journal");
        let _ = std::fs::remove_file(&path);

        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[
                ("MESSAGE", b"First entry" as &[u8]),
                ("PRIORITY", b"6"),
            ])
            .unwrap();
            w.append_entry(&[
                ("MESSAGE", b"Second entry" as &[u8]),
                ("PRIORITY", b"5"),
                ("SYSLOG_IDENTIFIER", b"qtest"),
            ])
            .unwrap();
            w.flush().unwrap();
        }

        let mut reader = JournalReader::open(&path).unwrap();
        let entries = reader.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message(), Some("First entry"));
        assert_eq!(entries[1].message(), Some("Second entry"));
        assert_eq!(
            entries[1].get(b"SYSLOG_IDENTIFIER"),
            Some(b"qtest" as &[u8])
        );
    }

    #[test]
    fn test_entries_for_field() {
        let path = tmp_path("qjournal_field_query.journal");
        let _ = std::fs::remove_file(&path);

        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[("MESSAGE", b"match" as &[u8]), ("PRIORITY", b"6")])
                .unwrap();
            w.append_entry(&[("MESSAGE", b"nomatch" as &[u8]), ("PRIORITY", b"3")])
                .unwrap();
            w.flush().unwrap();
        }

        let mut reader = JournalReader::open(&path).unwrap();
        let matches = reader.entries_for_field("PRIORITY", b"6").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].message(), Some("match"));
    }

    #[test]
    fn test_next_entry_navigation() {
        let path = tmp_path("qjournal_next_entry.journal");
        let _ = std::fs::remove_file(&path);

        {
            let mut w = JournalWriter::open(&path).unwrap();
            for i in 0..10 {
                let msg = format!("entry {}", i);
                w.append_entry(&[("MESSAGE", msg.as_bytes())]).unwrap();
            }
            w.flush().unwrap();
        }

        let mut reader = JournalReader::open(&path).unwrap();

        // Forward traversal
        let mut p = 0u64;
        let mut count = 0;
        loop {
            match reader.next_entry(p, Direction::Down).unwrap() {
                Some(off) => {
                    p = off;
                    count += 1;
                }
                None => break,
            }
        }
        assert_eq!(count, 10);

        // Backward traversal from last
        let mut count_back = 0;
        loop {
            match reader.next_entry(p, Direction::Up).unwrap() {
                Some(off) => {
                    p = off;
                    count_back += 1;
                }
                None => break,
            }
        }
        assert_eq!(count_back, 9); // 9 moves back from last = first
    }

    #[test]
    fn test_move_to_entry_by_seqnum() {
        let path = tmp_path("qjournal_seqnum_seek.journal");
        let _ = std::fs::remove_file(&path);

        {
            let mut w = JournalWriter::open(&path).unwrap();
            for i in 0..5 {
                let msg = format!("entry {}", i);
                w.append_entry(&[("MESSAGE", msg.as_bytes())]).unwrap();
            }
            w.flush().unwrap();
        }

        let mut reader = JournalReader::open(&path).unwrap();

        // Find seqnum 3 (third entry)
        let off = reader
            .move_to_entry_by_seqnum(3, Direction::Down)
            .unwrap();
        assert!(off.is_some());
        let entry = reader.read_entry_at(off.unwrap()).unwrap();
        assert_eq!(entry.seqnum, 3);
    }

    #[test]
    fn test_find_data_object() {
        let path = tmp_path("qjournal_find_data.journal");
        let _ = std::fs::remove_file(&path);

        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[("MESSAGE", b"hello world" as &[u8])])
                .unwrap();
            w.flush().unwrap();
        }

        let mut reader = JournalReader::open(&path).unwrap();
        let found = reader.find_data_object(b"MESSAGE=hello world").unwrap();
        assert!(found.is_some());

        let not_found = reader
            .find_data_object(b"MESSAGE=does not exist")
            .unwrap();
        assert!(not_found.is_none());
    }
}
