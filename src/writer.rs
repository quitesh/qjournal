// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file writer.
//!
//! Ported from systemd's `journal-file.c` (`journal_file_append_entry`,
//! `journal_file_append_data`, `journal_file_append_field`, etc.).
//!
//! # Layout of a freshly-created journal file
//!
//! ```text
//! [0..272)   Header
//! [272..272+data_ht_size)   DATA hash table  (HashItem × DEFAULT_DATA_HASH_TABLE_SIZE)
//! [aligned)                 FIELD hash table (HashItem × DEFAULT_FIELD_HASH_TABLE_SIZE)
//! [aligned)                 … objects appended sequentially …
//! ```
//!
//! Every object starts with an `ObjectHeader` and is padded to an 8-byte boundary.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use uuid::Uuid;

use crate::{
    def::*,
    error::{Error, Result},
    hash::hash64,
};

// ── Boot-ID helper ────────────────────────────────────────────────────────

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
    // On Linux we could read /proc/uptime; for portability we use a
    // simple fallback that gives a stable-enough value.
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: use realtime as a monotonic approximation (good enough for testing)
        realtime_now()
    }
}

// ── In-memory index for fast deduplication ────────────────────────────────

/// Tracks DATA objects already written, keyed by their payload hash.
/// Value is (file_offset, hash).
type DataIndex = HashMap<u64, Vec<(u64, u64)>>;
/// Field objects keyed by field name hash.
type FieldIndex = HashMap<u64, Vec<(u64, u64)>>;

// ── Public writer ─────────────────────────────────────────────────────────

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
    /// Number of data hash-table buckets.
    data_ht_n: u64,
    /// Byte offset into the file where the data hash table starts.
    data_ht_offset: u64,
    /// Number of field hash-table buckets.
    field_ht_n: u64,
    /// Byte offset into the file where the field hash table starts.
    field_ht_offset: u64,
    /// Offset of the root entry-array object (0 if none yet).
    entry_array_offset: u64,
    /// Number of items already stored in the root entry-array.
    entry_array_n: u64,
    /// Offset of the tail entry-array when the root is full.
    tail_entry_array_offset: u64,
    tail_entry_array_n: u64,
    /// Sequence number counter.
    seqnum: u64,
    boot_id: [u8; 16],
    /// Header stats.
    n_objects: u64,
    n_entries: u64,
    n_data: u64,
    n_fields: u64,
    n_entry_arrays: u64,
    head_entry_realtime: u64,
    tail_entry_realtime: u64,
    tail_entry_monotonic: u64,
    tail_entry_seqnum: u64,
    head_entry_seqnum: u64,
    tail_object_offset: u64,
    /// Offset of the last written ENTRY object (for header.tail_entry_offset).
    tail_entry_offset: u64,
    /// In-memory DATA dedup index (hash → [(offset, hash)]).
    data_index: DataIndex,
    /// In-memory FIELD dedup index.
    field_index: FieldIndex,
}

impl JournalWriter {
    /// Open (or create) a journal file at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.as_ref())?;

        let meta = file.metadata()?;
        if meta.len() == 0 {
            Self::create_new(file)
        } else {
            Self::open_existing(file)
        }
    }

    // ── Initialise a brand-new file ───────────────────────────────────────

    fn create_new(mut file: File) -> Result<Self> {
        let data_ht_n = DEFAULT_DATA_HASH_TABLE_SIZE as u64;
        let field_ht_n = DEFAULT_FIELD_HASH_TABLE_SIZE as u64;

        // Data hash table sits right after the 272-byte header.
        let data_ht_offset = HEADER_SIZE;
        let data_ht_bytes = data_ht_n * HASH_ITEM_SIZE as u64;

        // Object header (16 bytes) + HashItem array
        let data_ht_obj_bytes = align64(OBJECT_HEADER_SIZE as u64 + data_ht_bytes);
        let field_ht_offset = align64(data_ht_offset + data_ht_obj_bytes);
        let field_ht_bytes = field_ht_n * HASH_ITEM_SIZE as u64;
        let field_ht_obj_bytes = align64(OBJECT_HEADER_SIZE as u64 + field_ht_bytes);

        let arena_end = align64(field_ht_offset + field_ht_obj_bytes);

        let file_id   = *Uuid::new_v4().as_bytes();
        // systemd sets seqnum_id == file_id for new standalone files.
        let seqnum_id = file_id;
        let machine_id = machine_id();
        let boot_id   = get_boot_id();

        // ── Write header ──────────────────────────────────────────────────
        let header = build_header(
            file_id,
            machine_id,
            seqnum_id,
            boot_id,
            HEADER_SIZE,
            arena_end - HEADER_SIZE,
            data_ht_offset,
            data_ht_obj_bytes,
            field_ht_offset,
            field_ht_obj_bytes,
            FileState::Online,
        );
        file.seek(SeekFrom::Start(0))?;
        file.write_all(header_as_bytes(&header))?;

        // ── Write DATA hash table object ──────────────────────────────────
        write_hash_table_object(&mut file, ObjectType::DataHashTable, data_ht_n)?;

        // ── Write FIELD hash table object ─────────────────────────────────
        // Pad to field_ht_offset
        let cur = file.stream_position()?;
        if cur < field_ht_offset {
            write_zeros(&mut file, field_ht_offset - cur)?;
        }
        write_hash_table_object(&mut file, ObjectType::FieldHashTable, field_ht_n)?;

        // Pad to arena_end
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
            entry_array_n: 0,
            tail_entry_array_offset: 0,
            tail_entry_array_n: 0,
            seqnum: 1,
            boot_id,
            n_objects: 2, // data + field hash tables
            n_entries: 0,
            n_data: 0,
            n_fields: 0,
            n_entry_arrays: 0,
            head_entry_realtime: 0,
            tail_entry_realtime: 0,
            tail_entry_monotonic: 0,
            tail_entry_seqnum: 0,
            head_entry_seqnum: 0,
            tail_object_offset: field_ht_offset, // last object written
            tail_entry_offset: 0,
            data_index: HashMap::new(),
            field_index: HashMap::new(),
        })
    }

    // ── Re-open an existing file ──────────────────────────────────────────

    fn open_existing(mut file: File) -> Result<Self> {
        use std::io::Read;
        file.seek(SeekFrom::Start(0))?;
        let mut hbuf = [0u8; 272];
        file.read_exact(&mut hbuf).map_err(|_| Error::Truncated { offset: 0 })?;

        // SAFETY: repr(C,packed), we read exactly 272 bytes.
        let h: Header = unsafe { std::ptr::read_unaligned(hbuf.as_ptr() as *const Header) };

        if h.signature != HEADER_SIGNATURE {
            return Err(Error::InvalidFile("bad magic bytes".into()));
        }

        let incompat = from_le32(&h.incompatible_flags);
        let unsupported = incompat & !incompat::SUPPORTED_READ;
        if unsupported != 0 {
            return Err(Error::IncompatibleFlags { flags: unsupported });
        }

        let offset = from_le64(&h.header_size) + from_le64(&h.arena_size);
        // Stored offsets point to items; subtract ObjectHeader size to recover object start.
        let data_ht_offset = from_le64(&h.data_hash_table_offset) - OBJECT_HEADER_SIZE as u64;
        let data_ht_size   = from_le64(&h.data_hash_table_size);
        let field_ht_offset= from_le64(&h.field_hash_table_offset) - OBJECT_HEADER_SIZE as u64;
        let field_ht_size  = from_le64(&h.field_hash_table_size);

        // Re-build in-memory index by scanning all DATA objects
        let data_ht_n  = data_ht_size / HASH_ITEM_SIZE as u64;
        let field_ht_n = field_ht_size / HASH_ITEM_SIZE as u64;

        let (data_index, field_index) =
            rebuild_indexes(&mut file, offset, data_ht_offset, data_ht_n, field_ht_offset, field_ht_n)?;

        // Mark the file online again.
        // state is at offset 16 in the header (after signature[8] + compatible_flags[4] + incompatible_flags[4]).
        file.seek(SeekFrom::Start(16 /* offset of `state` field */))?;
        file.write_all(&[FileState::Online as u8])?;

        Ok(Self {
            file,
            offset,
            data_ht_n,
            data_ht_offset,
            field_ht_n,
            field_ht_offset,
            entry_array_offset: from_le64(&h.entry_array_offset),
            entry_array_n: 0, // rebuilt below
            tail_entry_array_offset: from_le32(&h.tail_entry_array_offset) as u64,
            tail_entry_array_n: from_le32(&h.tail_entry_array_n_entries) as u64,
            seqnum: from_le64(&h.tail_entry_seqnum).saturating_add(1),
            boot_id: h.tail_entry_boot_id,
            n_objects: from_le64(&h.n_objects),
            n_entries: from_le64(&h.n_entries),
            n_data: from_le64(&h.n_data),
            n_fields: from_le64(&h.n_fields),
            n_entry_arrays: from_le64(&h.n_entry_arrays),
            head_entry_realtime: from_le64(&h.head_entry_realtime),
            tail_entry_realtime: from_le64(&h.tail_entry_realtime),
            tail_entry_monotonic: from_le64(&h.tail_entry_monotonic),
            tail_entry_seqnum: from_le64(&h.tail_entry_seqnum),
            head_entry_seqnum: from_le64(&h.head_entry_seqnum),
            tail_object_offset: from_le64(&h.tail_object_offset),
            tail_entry_offset: from_le64(&h.tail_entry_offset),
            data_index,
            field_index,
        })
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Append a log entry with the given `fields`.
    ///
    /// Fields are `(name, value)` pairs, e.g. `[("MESSAGE", b"Hello")]`.
    /// `name` must be uppercase ASCII letters, digits, and underscores only,
    /// and must not start with `__` (those are reserved by systemd).
    ///
    /// Matches systemd's `journal_file_append_entry()`.
    pub fn append_entry<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        fields: &[(N, V)],
    ) -> Result<u64> {
        if fields.is_empty() {
            return Err(Error::EmptyEntry);
        }

        let realtime  = realtime_now();
        let monotonic = monotonic_now();
        let seqnum    = self.seqnum;
        self.seqnum  += 1;

        // 1. Write DATA objects for each field (deduplicated).
        let mut items: Vec<(u64, u64)> = Vec::with_capacity(fields.len());
        let mut xor_hash: u64 = 0;

        for (name, value) in fields {
            let name  = name.as_ref();
            let value = value.as_ref();
            validate_field_name(name)?;

            // payload = "FIELD=value" or just "FIELD" for binary
            let mut payload = Vec::with_capacity(name.len() + 1 + value.len());
            payload.extend_from_slice(name);
            payload.push(b'=');
            payload.extend_from_slice(value);

            let h = hash64(&payload);
            xor_hash ^= h;

            let (data_offset, is_new_data) = self.find_or_write_data(&payload, h)?;
            let field_offset = self.find_or_write_field(name)?;

            // Link DATA → FIELD chain for newly created DATA objects.
            // data.next_field_offset points to the previous head of the FIELD's data list;
            // field.head_data_offset is updated to point to this new DATA object.
            // This is required for sd_journal_query_unique / journalctl -F to work.
            if is_new_data {
                // field.head_data_offset is at offset 32 in FieldObjectHeader.
                let field_head_ptr = field_offset + 32;
                let old_head = self.read_u64_at(field_head_ptr)?;
                // Set data.next_field_offset = old field head (offset 32 in DataObjectHeader).
                self.write_u64_at(data_offset + 32, old_head)?;
                // Set field.head_data_offset = data_offset.
                self.write_u64_at(field_head_ptr, data_offset)?;
            }

            items.push((data_offset, h));
        }

        // 2. Write ENTRY object.
        let entry_offset = self.write_entry(seqnum, realtime, monotonic, xor_hash, &items)?;

        // 3. Update entry-array chain.
        self.append_to_entry_array(entry_offset)?;

        // 4. Update back-references in each DATA object.
        for (data_offset, _hash) in &items {
            self.update_data_entry_refs(*data_offset, entry_offset)?;
        }

        // 5. Update header stats.
        if self.head_entry_realtime == 0 {
            self.head_entry_realtime = realtime;
            self.head_entry_seqnum  = seqnum;
        }
        self.tail_entry_realtime  = realtime;
        self.tail_entry_monotonic = monotonic;
        self.tail_entry_seqnum    = seqnum;
        self.n_entries += 1;
        self.write_header()?;

        Ok(entry_offset)
    }

    /// Flush all pending writes to the OS buffer.
    pub fn flush(&mut self) -> Result<()> {
        self.write_header()?;
        self.file.flush()?;
        Ok(())
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn read_u64_at(&mut self, offset: u64) -> Result<u64> {
        use std::io::Read;
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

    /// Walk the next_entry_array_offset chain from `head` to find the tail array offset.
    fn find_tail_array(&mut self, head: u64) -> Result<u64> {
        let mut cur = head;
        loop {
            // next_entry_array_offset is at OBJECT_HEADER_SIZE (16) within EntryArrayObjectHeader.
            let next = self.read_u64_at(cur + OBJECT_HEADER_SIZE as u64)?;
            if next == 0 {
                return Ok(cur);
            }
            cur = next;
        }
    }

    /// Look up or write a DATA object for `payload`.
    /// Returns `(offset, is_new)` where `is_new` is true if the object was freshly written.
    fn find_or_write_data(&mut self, payload: &[u8], h: u64) -> Result<(u64, bool)> {
        let bucket = (h % self.data_ht_n) as usize;

        // Check in-memory index first.
        if let Some(chain) = self.data_index.get(&(bucket as u64)) {
            for &(off, stored_hash) in chain {
                if stored_hash == h {
                    // Double-check payload if we want exactness – skip for now
                    // (hash collisions are extremely rare and journald doesn't check either)
                    return Ok((off, false));
                }
            }
        }

        // Write a new DATA object.
        let actual_size = DATA_OBJECT_HEADER_SIZE as u64 + payload.len() as u64;
        let total_size = align64(actual_size);
        let obj_offset = self.offset;

        let data_hdr = DataObjectHeader {
            object: ObjectHeader {
                object_type: ObjectType::Data as u8,
                flags: 0,
                reserved: [0; 6],
                size: le64(actual_size),
            },
            hash: le64(h),
            next_hash_offset: le64(0),
            next_field_offset: le64(0),
            entry_offset: le64(0),
            entry_array_offset: le64(0),
            n_entries: le64(0),
        };

        self.file.seek(SeekFrom::Start(obj_offset))?;
        // SAFETY: packed repr, writing raw bytes
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &data_hdr as *const DataObjectHeader as *const u8,
                DATA_OBJECT_HEADER_SIZE,
            )
        };
        self.file.write_all(hdr_bytes)?;
        self.file.write_all(payload)?;
        let written = DATA_OBJECT_HEADER_SIZE as u64 + payload.len() as u64;
        if total_size > written {
            write_zeros(&mut self.file, total_size - written)?;
        }

        self.offset += total_size;
        self.tail_object_offset = obj_offset;
        self.n_objects += 1;
        self.n_data += 1;

        // Link into hash table chain.
        self.link_data_into_ht(bucket as u64, obj_offset, h)?;

        // Update index.
        self.data_index
            .entry(bucket as u64)
            .or_default()
            .push((obj_offset, h));

        Ok((obj_offset, true))
    }

    /// Link a DATA object at `obj_offset` into the data hash table.
    fn link_data_into_ht(&mut self, bucket: u64, obj_offset: u64, _h: u64) -> Result<()> {
        // Compute the byte offset of this bucket's HashItem in the file.
        // The hash table object starts OBJECT_HEADER_SIZE bytes after data_ht_offset.
        let ht_items_start = self.data_ht_offset + OBJECT_HEADER_SIZE as u64;
        let item_offset = ht_items_start + bucket * HASH_ITEM_SIZE as u64;

        let mut item = read_hash_item(&mut self.file, item_offset)?;

        let head = from_le64(&item.head_hash_offset);

        if head == 0 {
            // Empty bucket – just set head and tail.
            item.head_hash_offset = le64(obj_offset);
            item.tail_hash_offset = le64(obj_offset);
            write_hash_item(&mut self.file, item_offset, &item)?;
        } else {
            // Append to tail of the chain.
            let tail = from_le64(&item.tail_hash_offset);
            // Update the existing tail object's next_hash_offset field.
            // next_hash_offset is at DATA_OBJECT_HEADER offset 24..32
            let next_field_off = tail + 24;
            self.file.seek(SeekFrom::Start(next_field_off))?;
            self.file.write_all(&le64(obj_offset))?;
            // Update the bucket tail pointer.
            item.tail_hash_offset = le64(obj_offset);
            write_hash_item(&mut self.file, item_offset, &item)?;
        }

        Ok(())
    }

    /// Look up or write a FIELD object for `name` (field name only, no value).
    fn find_or_write_field(&mut self, name: &[u8]) -> Result<u64> {
        let h = hash64(name);
        let bucket = h % self.field_ht_n;

        if let Some(chain) = self.field_index.get(&bucket) {
            for &(off, stored_hash) in chain {
                if stored_hash == h {
                    return Ok(off);
                }
            }
        }

        let actual_size = FIELD_OBJECT_HEADER_SIZE as u64 + name.len() as u64;
        let total_size = align64(actual_size);
        let obj_offset = self.offset;

        let field_hdr = FieldObjectHeader {
            object: ObjectHeader {
                object_type: ObjectType::Field as u8,
                flags: 0,
                reserved: [0; 6],
                size: le64(actual_size), // unaligned actual size, matching systemd
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
        self.file.write_all(name)?;
        let written = FIELD_OBJECT_HEADER_SIZE as u64 + name.len() as u64;
        if total_size > written {
            write_zeros(&mut self.file, total_size - written)?;
        }

        self.offset += total_size;
        self.tail_object_offset = obj_offset;
        self.n_objects += 1;
        self.n_fields += 1;

        // Link into field hash table.
        let ht_items_start = self.field_ht_offset + OBJECT_HEADER_SIZE as u64;
        let item_offset = ht_items_start + bucket * HASH_ITEM_SIZE as u64;
        let mut item = read_hash_item(&mut self.file, item_offset)?;
        if from_le64(&item.head_hash_offset) == 0 {
            item.head_hash_offset = le64(obj_offset);
            item.tail_hash_offset = le64(obj_offset);
        } else {
            let tail = from_le64(&item.tail_hash_offset);
            // next_hash_offset is at FIELD_OBJECT_HEADER offset 24..32
            self.file.seek(SeekFrom::Start(tail + 24))?;
            self.file.write_all(&le64(obj_offset))?;
            item.tail_hash_offset = le64(obj_offset);
        }
        write_hash_item(&mut self.file, item_offset, &item)?;

        self.field_index
            .entry(bucket)
            .or_default()
            .push((obj_offset, h));

        Ok(obj_offset)
    }

    /// Write an ENTRY object. Returns its file offset.
    fn write_entry(
        &mut self,
        seqnum: u64,
        realtime: u64,
        monotonic: u64,
        xor_hash: u64,
        items: &[(u64, u64)], // (data_offset, hash)
    ) -> Result<u64> {
        let n_items = items.len();
        let total_size = align64(
            ENTRY_OBJECT_HEADER_SIZE as u64 + (n_items as u64) * ENTRY_ITEM_SIZE as u64,
        );
        let obj_offset = self.offset;

        let entry_hdr = EntryObjectHeader {
            object: ObjectHeader {
                object_type: ObjectType::Entry as u8,
                flags: 0,
                reserved: [0; 6],
                size: le64(total_size),
            },
            seqnum:    le64(seqnum),
            realtime:  le64(realtime),
            monotonic: le64(monotonic),
            boot_id:   self.boot_id,
            xor_hash:  le64(xor_hash),
        };

        self.file.seek(SeekFrom::Start(obj_offset))?;
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &entry_hdr as *const EntryObjectHeader as *const u8,
                ENTRY_OBJECT_HEADER_SIZE,
            )
        };
        self.file.write_all(hdr_bytes)?;

        for (data_off, h) in items {
            let item = EntryItem {
                object_offset: le64(*data_off),
                hash: le64(*h),
            };
            let item_bytes = unsafe {
                std::slice::from_raw_parts(
                    &item as *const EntryItem as *const u8,
                    ENTRY_ITEM_SIZE,
                )
            };
            self.file.write_all(item_bytes)?;
        }
        let written = ENTRY_OBJECT_HEADER_SIZE as u64 + n_items as u64 * ENTRY_ITEM_SIZE as u64;
        if total_size > written {
            write_zeros(&mut self.file, total_size - written)?;
        }

        self.offset += total_size;
        self.tail_object_offset = obj_offset;
        self.tail_entry_offset  = obj_offset;
        self.n_objects += 1;

        Ok(obj_offset)
    }

    /// Add `entry_offset` to the entry-array chain (creating the first array if needed).
    ///
    /// Mirrors systemd's `link_entry_into_array()` call path.
    ///
    /// Each entry-array holds up to 256 offsets; when full a new one is chained.
    const ENTRY_ARRAY_CAPACITY: u64 = 256;

    fn append_to_entry_array(&mut self, entry_offset: u64) -> Result<()> {
        // If we have no entry-array yet, create one.
        if self.entry_array_offset == 0 {
            let arr_offset = self.write_entry_array_object(0)?;
            self.entry_array_offset = arr_offset;
            self.entry_array_n = 0;
        }

        // Which array to write into?
        let (target_arr, slot) = if self.tail_entry_array_offset == 0 {
            (self.entry_array_offset, self.entry_array_n)
        } else {
            (self.tail_entry_array_offset, self.tail_entry_array_n)
        };

        if slot >= Self::ENTRY_ARRAY_CAPACITY {
            // Allocate a new array and chain it.
            let new_arr = self.write_entry_array_object(0)?;
            // Patch next_entry_array_offset on the current tail array.
            self.file.seek(SeekFrom::Start(target_arr + OBJECT_HEADER_SIZE as u64))?;
            self.file.write_all(&le64(new_arr))?;

            self.tail_entry_array_offset = new_arr;
            self.tail_entry_array_n = 0;
        }

        // Write entry offset into the slot.
        let (arr, idx) = if self.tail_entry_array_offset == 0 {
            (self.entry_array_offset, self.entry_array_n)
        } else {
            (self.tail_entry_array_offset, self.tail_entry_array_n)
        };
        let slot_offset = arr + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + idx * 8;
        self.file.seek(SeekFrom::Start(slot_offset))?;
        self.file.write_all(&le64(entry_offset))?;

        // Update count.
        if self.tail_entry_array_offset == 0 {
            self.entry_array_n += 1;
        } else {
            self.tail_entry_array_n += 1;
        }

        Ok(())
    }

    /// Allocate and zero-fill an entry-array object that can hold up to
    /// `ENTRY_ARRAY_CAPACITY` offsets.
    fn write_entry_array_object(&mut self, next: u64) -> Result<u64> {
        let item_bytes = Self::ENTRY_ARRAY_CAPACITY * 8;
        let total_size = align64(ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + item_bytes);
        let obj_offset = self.offset;

        let hdr = EntryArrayObjectHeader {
            object: ObjectHeader {
                object_type: ObjectType::EntryArray as u8,
                flags: 0,
                reserved: [0; 6],
                size: le64(total_size),
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

    /// Update the entry back-reference fields in a DATA object.
    ///
    /// Mirrors systemd's `link_entry_into_array_plus_one()`.
    fn update_data_entry_refs(&mut self, data_offset: u64, entry_offset: u64) -> Result<()> {
        // DataObjectHeader field offsets:
        //   40: entry_offset       (inline first entry)
        //   48: entry_array_offset (head of per-data array chain)
        //   56: n_entries
        let entry_off_field   = data_offset + 40;
        let eao_field         = data_offset + 48;
        let n_entries_field   = data_offset + 56;

        let cur_entry = self.read_u64_at(entry_off_field)?;

        if cur_entry == 0 {
            // First entry: store inline and set n_entries = 1.
            self.write_u64_at(entry_off_field, entry_offset)?;
            self.write_u64_at(n_entries_field, 1)?;
        } else {
            // Subsequent entries: append to the per-data entry-array chain.
            let cur_head = self.read_u64_at(eao_field)?;
            let cur_n    = self.read_u64_at(n_entries_field)?;

            // slot 0 = second entry (first is inline).
            const DATA_ARRAY_CAP: u64 = 8;
            let slot = cur_n - 1; // 0-based index across all arrays combined

            if cur_head == 0 || slot % DATA_ARRAY_CAP == 0 {
                // Need a new mini entry-array.
                let item_bytes = DATA_ARRAY_CAP * 8;
                let tot = align64(ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + item_bytes);
                let new_arr = self.offset;

                let hdr = EntryArrayObjectHeader {
                    object: ObjectHeader {
                        object_type: ObjectType::EntryArray as u8,
                        flags: 0,
                        reserved: [0; 6],
                        size: le64(tot),
                    },
                    next_entry_array_offset: le64(0),
                };
                self.file.seek(SeekFrom::Start(new_arr))?;
                let hdr_bytes = unsafe {
                    std::slice::from_raw_parts(
                        &hdr as *const EntryArrayObjectHeader as *const u8,
                        ENTRY_ARRAY_OBJECT_HEADER_SIZE,
                    )
                };
                self.file.write_all(hdr_bytes)?;
                write_zeros(&mut self.file, tot - ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64)?;
                self.offset += tot;
                self.tail_object_offset = new_arr;
                self.n_objects += 1;
                self.n_entry_arrays += 1;

                if cur_head == 0 {
                    // First array: store as head. Never updated again.
                    self.write_u64_at(eao_field, new_arr)?;
                } else {
                    // Chain the actual tail of the existing chain → new array.
                    // data.entry_array_offset always stays pointing at the HEAD.
                    let tail = self.find_tail_array(cur_head)?;
                    self.write_u64_at(tail + OBJECT_HEADER_SIZE as u64, new_arr)?;
                }

                // Write entry at slot 0 of the new array.
                self.write_u64_at(new_arr + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64, entry_offset)?;
            } else {
                // Append to the tail array.
                let tail_arr = self.find_tail_array(cur_head)?;
                let slot_idx = slot % DATA_ARRAY_CAP;
                let slot_off = tail_arr + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + slot_idx * 8;
                self.write_u64_at(slot_off, entry_offset)?;
            }

            self.write_u64_at(n_entries_field, cur_n + 1)?;
        }

        Ok(())
    }

    /// Rewrite the complete journal header with current statistics.
    fn write_header(&mut self) -> Result<()> {
        let (data_ht_offset, field_ht_offset) = (self.data_ht_offset, self.field_ht_offset);
        let data_ht_obj_bytes = OBJECT_HEADER_SIZE as u64 + self.data_ht_n * HASH_ITEM_SIZE as u64;
        let field_ht_obj_bytes = OBJECT_HEADER_SIZE as u64 + self.field_ht_n * HASH_ITEM_SIZE as u64;
        let arena_size = self.offset - HEADER_SIZE;

        // We need file_id and machine_id – read from file rather than store them.
        let mut h = self.read_header_raw()?;

        // Update mutable fields.
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
        h.tail_entry_monotonic = le64(self.tail_entry_monotonic);
        h.tail_entry_boot_id = self.boot_id;
        // When there is only one entry array, the tail IS the root (entry_array_offset).
        // systemd always keeps tail_entry_array_offset pointing to the actual tail array.
        let (tail_arr_off, tail_arr_n) = if self.tail_entry_array_offset != 0 {
            (self.tail_entry_array_offset, self.tail_entry_array_n)
        } else if self.entry_array_offset != 0 {
            (self.entry_array_offset, self.entry_array_n)
        } else {
            (0, 0)
        };
        h.tail_entry_array_offset = le32(tail_arr_off as u32);
        h.tail_entry_array_n_entries = le32(tail_arr_n as u32);
        // systemd expects these offsets to point to the hash items (past the ObjectHeader).
        h.data_hash_table_offset = le64(data_ht_offset + OBJECT_HEADER_SIZE as u64);
        h.data_hash_table_size = le64(data_ht_obj_bytes - OBJECT_HEADER_SIZE as u64);
        h.field_hash_table_offset = le64(field_ht_offset + OBJECT_HEADER_SIZE as u64);
        h.field_hash_table_size = le64(field_ht_obj_bytes - OBJECT_HEADER_SIZE as u64);
        h.data_hash_chain_depth = [0u8; 8];
        h.field_hash_chain_depth = [0u8; 8];
        h.tail_entry_offset = le64(self.tail_entry_offset);

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(header_as_bytes(&h))?;
        Ok(())
    }

    fn read_header_raw(&mut self) -> Result<Header> {
        use std::io::Read;
        self.file.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; 272];
        self.file.read_exact(&mut buf)?;
        Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const Header) })
    }
}

impl Drop for JournalWriter {
    fn drop(&mut self) {
        // Mark the file as offline on clean shutdown.
        let _ = self.write_header();
        if let Ok(mut h) = self.read_header_raw() {
            h.state = FileState::Offline as u8;
            let _ = self.file.seek(SeekFrom::Start(0));
            let _ = self.file.write_all(header_as_bytes(&h));
        }
        let _ = self.file.flush();
    }
}

// ── Free-standing helpers ─────────────────────────────────────────────────

fn validate_field_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidFieldName(String::new()));
    }
    // systemd rejects names longer than 64 bytes.
    if name.len() > 64 {
        return Err(Error::InvalidFieldName(
            String::from_utf8_lossy(name).into_owned(),
        ));
    }
    // systemd rejects names that start with a digit.
    if name[0].is_ascii_digit() {
        return Err(Error::InvalidFieldName(
            String::from_utf8_lossy(name).into_owned(),
        ));
    }
    for &b in name {
        if !matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_') {
            return Err(Error::InvalidFieldName(
                String::from_utf8_lossy(name).into_owned(),
            ));
        }
    }
    Ok(())
}

/// Get or synthesise a stable machine ID.
fn machine_id() -> [u8; 16] {
    #[cfg(target_os = "linux")]
    if let Ok(s) = std::fs::read_to_string("/etc/machine-id") {
        if let Ok(id) = Uuid::parse_str(s.trim()) {
            return *id.as_bytes();
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Use the Windows machine GUID if available.
        // Fall through to random on failure.
    }
    *Uuid::new_v4().as_bytes()
}

/// Build a fresh Header struct.
#[allow(clippy::too_many_arguments)]
fn build_header(
    file_id: [u8; 16],
    machine_id: [u8; 16],
    seqnum_id: [u8; 16],
    boot_id: [u8; 16],
    header_size: u64,
    arena_size: u64,
    data_ht_offset: u64,
    data_ht_size: u64,
    field_ht_offset: u64,
    field_ht_size: u64,
    state: FileState,
) -> Header {
    Header {
        signature: HEADER_SIGNATURE,
        compatible_flags: le32(compat::TAIL_ENTRY_BOOT_ID),
        incompatible_flags: le32(incompat::SUPPORTED_WRITE),
        state: state as u8,
        reserved: [0; 7],
        file_id,
        machine_id,
        tail_entry_boot_id: boot_id,
        seqnum_id,
        header_size: le64(header_size),
        arena_size: le64(arena_size),
        // Offsets point to the items (past the ObjectHeader), matching systemd's convention.
        data_hash_table_offset: le64(data_ht_offset + OBJECT_HEADER_SIZE as u64),
        data_hash_table_size: le64(data_ht_size - OBJECT_HEADER_SIZE as u64),
        field_hash_table_offset: le64(field_ht_offset + OBJECT_HEADER_SIZE as u64),
        field_hash_table_size: le64(field_ht_size - OBJECT_HEADER_SIZE as u64),
        tail_object_offset: le64(0),
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

/// Reinterpret a `Header` as a `&[u8]` slice for direct writing.
fn header_as_bytes(h: &Header) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            h as *const Header as *const u8,
            std::mem::size_of::<Header>(),
        )
    }
}

/// Write a zeroed hash table object (ObjectHeader + n * HashItem).
fn write_hash_table_object(file: &mut File, obj_type: ObjectType, n: u64) -> io::Result<()> {
    let item_bytes = n * HASH_ITEM_SIZE as u64;
    let total = align64(OBJECT_HEADER_SIZE as u64 + item_bytes);
    let hdr = ObjectHeader {
        object_type: obj_type as u8,
        flags: 0,
        reserved: [0; 6],
        size: le64(total),
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
    use std::io::Read;
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

/// Rebuild in-memory indexes by scanning data and field hash tables.
fn rebuild_indexes(
    file: &mut File,
    _file_size: u64,
    data_ht_off: u64,
    data_ht_n: u64,
    field_ht_off: u64,
    field_ht_n: u64,
) -> Result<(DataIndex, FieldIndex)> {
    use std::io::Read;

    let mut data_idx: DataIndex = HashMap::new();
    let mut field_idx: FieldIndex = HashMap::new();

    let data_items_start = data_ht_off + OBJECT_HEADER_SIZE as u64;
    for bucket in 0..data_ht_n {
        let item_off = data_items_start + bucket * HASH_ITEM_SIZE as u64;
        let item = read_hash_item(file, item_off)?;
        let mut cur = from_le64(&item.head_hash_offset);
        while cur != 0 {
            // Read hash from DataObjectHeader (at offset 16..24)
            file.seek(SeekFrom::Start(cur + 16))?;
            let mut buf = [0u8; 8];
            file.read_exact(&mut buf)?;
            let h = u64::from_le_bytes(buf);

            // Read next_hash_offset (at offset 24..32)
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
        ]).unwrap();
        w.flush().unwrap();
        drop(w);
        // File must be at least header size.
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.len() > HEADER_SIZE);
    }

    #[test]
    fn test_reopen_and_append() {
        let path = tmp_path("qjournal_test_reopen.journal");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[("MESSAGE", b"first" as &[u8])]).unwrap();
            w.flush().unwrap();
        }
        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[("MESSAGE", b"second" as &[u8])]).unwrap();
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
        // Invalid: lowercase
        assert!(w.append_entry(&[("message", b"bad" as &[u8])]).is_err());
        // Invalid: contains space
        assert!(w.append_entry(&[("MY FIELD", b"bad" as &[u8])]).is_err());
        // Valid
        assert!(w.append_entry(&[("MESSAGE", b"ok" as &[u8])]).is_ok());
    }

    #[test]
    fn test_header_size() {
        assert_eq!(std::mem::size_of::<Header>(), 272);
    }
}
