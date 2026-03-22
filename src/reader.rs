// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file reader.
//!
//! Ported from systemd's `sd-journal.c` and `journal-file.c`
//! (`sd_journal_next`, `journal_file_find_data_object`, etc.).

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::{
    def::*,
    error::{Error, Result},
    hash::hash64,
};

// ── Public entry type ─────────────────────────────────────────────────────

/// A single log entry as parsed from the journal.
///
/// Fields are stored as raw bytes. The key is the field *name* (e.g. `MESSAGE`)
/// and the value is the field *value* (the bytes after `=`).
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Per-entry sequence number.
    pub seqnum: u64,
    /// Realtime timestamp in microseconds since Unix epoch.
    pub realtime: u64,
    /// Monotonic timestamp in microseconds since boot.
    pub monotonic: u64,
    /// Sequence-number ID (128-bit random, stable per file).
    #[allow(dead_code)]
    seqnum_id: [u8; 16],
    /// Boot ID.
    #[allow(dead_code)]
    boot_id: [u8; 16],
    /// All fields as (name, value) pairs. Multiple values for the same name
    /// are allowed by the format.
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
///
/// ```rust,no_run
/// use qjournal::JournalReader;
/// let r = JournalReader::open("/tmp/test.journal").unwrap();
/// for entry in r.entries() {
///     println!("{:?}", entry.unwrap().message());
/// }
/// ```
pub struct JournalReader {
    file: File,
    /// Byte offset of the data hash table object (past the ObjectHeader).
    data_ht_items: u64,
    data_ht_n: u64,
    /// True when the file uses the COMPACT layout (4-byte offsets in entries).
    compact: bool,
    /// Offset of the root entry-array object, or 0.
    entry_array_offset: u64,
    #[allow(dead_code)]
    n_entries: u64,
    /// Whether the DATA objects use ZSTD compression.
    #[allow(dead_code)]
    zstd: bool,
}

impl JournalReader {
    /// Open a journal file for reading.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;

        let mut hbuf = [0u8; 272];
        file.read_exact(&mut hbuf)
            .map_err(|_| Error::Truncated { offset: 0 })?;
        let h: Header = unsafe { std::ptr::read_unaligned(hbuf.as_ptr() as *const Header) };

        if h.signature != HEADER_SIGNATURE {
            return Err(Error::InvalidFile("bad magic bytes".into()));
        }

        let incompat = from_le32(&h.incompatible_flags);
        let unsupported = incompat & !incompat::SUPPORTED_READ;
        if unsupported != 0 {
            return Err(Error::IncompatibleFlags { flags: unsupported });
        }

        let compact = (incompat & incompat::COMPACT) != 0;
        let zstd    = (incompat & incompat::COMPRESSED_ZSTD) != 0;

        // data_hash_table_offset already points to the items (past the ObjectHeader),
        // per systemd's convention.
        let data_ht_items  = from_le64(&h.data_hash_table_offset);
        let data_ht_size   = from_le64(&h.data_hash_table_size);
        let data_ht_n      = data_ht_size / HASH_ITEM_SIZE as u64;

        Ok(Self {
            file,
            data_ht_items,
            data_ht_n,
            compact,
            entry_array_offset: from_le64(&h.entry_array_offset),
            n_entries: from_le64(&h.n_entries),
            zstd,
        })
    }

    /// Return an iterator over all entries in chronological order.
    pub fn entries(&self) -> EntryIter<'_> {
        EntryIter {
            reader: self,
            // We re-open the file for each iterator to avoid borrow issues.
            file: self.file.try_clone().expect("file clone"),
            current_array_offset: self.entry_array_offset,
            current_array_index: 0,
            done: self.entry_array_offset == 0,
        }
    }

    /// Look up all entries that contain a specific `field=value` pair.
    pub fn entries_for_field<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        name: N,
        value: V,
    ) -> Result<Vec<JournalEntry>> {
        let name  = name.as_ref();
        let value = value.as_ref();

        let mut payload = Vec::with_capacity(name.len() + 1 + value.len());
        payload.extend_from_slice(name);
        payload.push(b'=');
        payload.extend_from_slice(value);

        let h = hash64(&payload);
        let bucket = h % self.data_ht_n;

        let mut file = self.file.try_clone()?;
        let item_off = self.data_ht_items + bucket * HASH_ITEM_SIZE as u64;
        let item = read_hash_item_from(&mut file, item_off)?;
        let mut cur = from_le64(&item.head_hash_offset);

        let mut results = Vec::new();

        while cur != 0 {
            let (stored_h, next, data_payload, entry_offset, entry_array_offset, n_entries) =
                read_data_object_meta(&mut file, cur, self.compact)?;

            if stored_h == h {
                // Verify payload match.
                if data_payload == payload {
                    // Collect all entries referencing this DATA object.
                    let entries = self.collect_entries_for_data(
                        &mut file, entry_offset, entry_array_offset, n_entries,
                    )?;
                    results.extend(entries);
                }
            }
            cur = next;
        }

        Ok(results)
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn read_entry_at(&self, file: &mut File, entry_offset: u64) -> Result<JournalEntry> {
        file.seek(SeekFrom::Start(entry_offset))?;
        let mut hdr_buf = [0u8; ENTRY_OBJECT_HEADER_SIZE];
        file.read_exact(&mut hdr_buf)?;
        let hdr: EntryObjectHeader =
            unsafe { std::ptr::read_unaligned(hdr_buf.as_ptr() as *const EntryObjectHeader) };

        if hdr.object.object_type != ObjectType::Entry as u8 {
            return Err(Error::CorruptObject {
                offset: entry_offset,
                reason: format!("expected Entry object, got type {}", hdr.object.object_type),
            });
        }

        let obj_size = from_le64(&hdr.object.size);
        let seqnum   = from_le64(&hdr.seqnum);
        let realtime = from_le64(&hdr.realtime);
        let monotonic= from_le64(&hdr.monotonic);
        let boot_id  = hdr.boot_id;

        // How many items?
        let items_bytes = obj_size
            .saturating_sub(ENTRY_OBJECT_HEADER_SIZE as u64);
        let item_size = if self.compact {
            4u64  // le32 only
        } else {
            ENTRY_ITEM_SIZE as u64 // 16
        };
        let n_items = items_bytes / item_size;

        let mut fields = Vec::with_capacity(n_items as usize);

        // Calculate the base offset of the items array to allow random access
        let items_base = entry_offset + ENTRY_OBJECT_HEADER_SIZE as u64;

        for i in 0..n_items {
            let item_offset = items_base + i * item_size;
            file.seek(SeekFrom::Start(item_offset))?;

            let data_off = if self.compact {
                let mut buf = [0u8; 4];
                file.read_exact(&mut buf)?;
                u32::from_le_bytes(buf) as u64
            } else {
                let mut buf = [0u8; 16];
                file.read_exact(&mut buf)?;
                u64::from_le_bytes(buf[..8].try_into().unwrap())
            };

            if data_off == 0 {
                continue;
            }

            let (name, value) = self.read_data_payload(file, data_off)?;
            fields.push((name, value));
        }
        Ok(JournalEntry { seqnum, realtime, monotonic, boot_id, seqnum_id: [0; 16], fields })
    }

    /// Read the payload of a DATA object, returning (field_name, field_value).
    fn read_data_payload(&self, file: &mut File, offset: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        file.seek(SeekFrom::Start(offset))?;
        let mut hdr_buf = [0u8; DATA_OBJECT_HEADER_SIZE];
        file.read_exact(&mut hdr_buf)?;
        let hdr: DataObjectHeader =
            unsafe { std::ptr::read_unaligned(hdr_buf.as_ptr() as *const DataObjectHeader) };

        if hdr.object.object_type != ObjectType::Data as u8 {
            return Err(Error::CorruptObject {
                offset,
                reason: format!("expected Data object, got type {}", hdr.object.object_type),
            });
        }

        let obj_size = from_le64(&hdr.object.size);
        let flags    = hdr.object.flags;

        // In compact mode, the DATA object has two extra fields before the payload:
        //   tail_entry_array_offset (le32) + tail_entry_array_n_entries (le32) = 8 bytes.
        let payload_base = if self.compact {
            DATA_OBJECT_HEADER_SIZE as u64 + 8
        } else {
            DATA_OBJECT_HEADER_SIZE as u64
        };
        let payload_len = obj_size.saturating_sub(payload_base);

        // Skip the compact-mode extra fields if present.
        if self.compact {
            file.seek(SeekFrom::Current(8))?;
        }

        let raw = {
            let mut raw = vec![0u8; payload_len as usize];
            file.read_exact(&mut raw)?;
            raw
        };

        // Decompress if needed.
        let payload = if (flags & obj_flags::COMPRESSED_ZSTD) != 0 {
            #[cfg(feature = "zstd-compression")]
            {
                zstd::decode_all(raw.as_slice())
                    .map_err(|e| Error::Decompression(e.to_string()))?
            }
            #[cfg(not(feature = "zstd-compression"))]
            {
                return Err(Error::InvalidFile(
                    "journal uses ZSTD compression but feature not enabled".into(),
                ));
            }
        } else if (flags & obj_flags::COMPRESSED_MASK) != 0 {
            return Err(Error::InvalidFile(
                "journal uses LZ4 or XZ compression which is not supported".into(),
            ));
        } else {
            raw
        };

        // Split on first '='.
        if let Some(eq) = payload.iter().position(|&b| b == b'=') {
            Ok((payload[..eq].to_vec(), payload[eq + 1..].to_vec()))
        } else {
            // Binary field without '=' — key only
            Ok((payload, Vec::new()))
        }
    }

    /// Collect all entries that reference a particular DATA object.
    fn collect_entries_for_data(
        &self,
        file: &mut File,
        entry_offset: u64,
        entry_array_offset: u64,
        n_entries: u64,
    ) -> Result<Vec<JournalEntry>> {
        let mut results = Vec::new();

        // First inline entry.
        if entry_offset != 0 {
            results.push(self.read_entry_at(file, entry_offset)?);
        }

        // Remaining entries via the entry-array chain.
        let mut arr_off = entry_array_offset;
        let mut seen = 1u64;
        while arr_off != 0 && seen < n_entries {
            file.seek(SeekFrom::Start(arr_off))?;
            let mut hdr_buf = [0u8; ENTRY_ARRAY_OBJECT_HEADER_SIZE];
            file.read_exact(&mut hdr_buf)?;
            let hdr: EntryArrayObjectHeader = unsafe {
                std::ptr::read_unaligned(hdr_buf.as_ptr() as *const EntryArrayObjectHeader)
            };
            let obj_size   = from_le64(&hdr.object.size);
            let next_arr   = from_le64(&hdr.next_entry_array_offset);
            // Compact mode uses 4-byte (le32) items; regular mode uses 8-byte (le64).
            let item_size  = if self.compact { 4u64 } else { 8u64 };
            let n_items    = (obj_size.saturating_sub(ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64)) / item_size;
            let items_base = arr_off + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64;

            for slot in 0..n_items {
                if seen >= n_entries {
                    break;
                }
                // Seek to the slot explicitly — read_entry_at will move the file pointer.
                file.seek(SeekFrom::Start(items_base + slot * item_size))?;
                let eoff = if self.compact {
                    let mut buf = [0u8; 4];
                    file.read_exact(&mut buf)?;
                    u32::from_le_bytes(buf) as u64
                } else {
                    let mut buf = [0u8; 8];
                    file.read_exact(&mut buf)?;
                    u64::from_le_bytes(buf)
                };
                if eoff != 0 {
                    results.push(self.read_entry_at(file, eoff)?);
                    seen += 1;
                }
            }
            arr_off = next_arr;
        }

        Ok(results)
    }
}

// ── Entry iterator ─────────────────────────────────────────────────────────

/// An iterator over all journal entries in a file, in order.
pub struct EntryIter<'a> {
    reader: &'a JournalReader,
    file: File,
    current_array_offset: u64,
    current_array_index: u64,
    done: bool,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = Result<JournalEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        loop {
            if self.current_array_offset == 0 {
                self.done = true;
                return None;
            }

            // Read the entry-array object header.
            match self.file.seek(SeekFrom::Start(self.current_array_offset)) {
                Err(e) => return Some(Err(e.into())),
                Ok(_) => {}
            }
            let mut hdr_buf = [0u8; ENTRY_ARRAY_OBJECT_HEADER_SIZE];
            if self.file.read_exact(&mut hdr_buf).is_err() {
                self.done = true;
                return None;
            }
            let hdr: EntryArrayObjectHeader = unsafe {
                std::ptr::read_unaligned(hdr_buf.as_ptr() as *const EntryArrayObjectHeader)
            };

            let obj_size  = from_le64(&hdr.object.size);
            let item_size = if self.reader.compact { 4u64 } else { 8u64 };
            let n_items   = (obj_size.saturating_sub(ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64)) / item_size;
            let next_arr  = from_le64(&hdr.next_entry_array_offset);

            if self.current_array_index >= n_items {
                // Move to next array.
                self.current_array_offset = next_arr;
                self.current_array_index  = 0;
                if next_arr == 0 {
                    self.done = true;
                    return None;
                }
                continue;
            }

            // Seek to the slot.
            let item_size = if self.reader.compact { 4u64 } else { 8u64 };
            let slot_off = self.current_array_offset
                + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64
                + self.current_array_index * item_size;
            if self.file.seek(SeekFrom::Start(slot_off)).is_err() {
                self.done = true;
                return None;
            }
            let entry_off = if self.reader.compact {
                let mut buf = [0u8; 4];
                if self.file.read_exact(&mut buf).is_err() {
                    self.done = true;
                    return None;
                }
                u32::from_le_bytes(buf) as u64
            } else {
                let mut buf = [0u8; 8];
                if self.file.read_exact(&mut buf).is_err() {
                    self.done = true;
                    return None;
                }
                u64::from_le_bytes(buf)
            };
            self.current_array_index += 1;

            if entry_off == 0 {
                // Sparse slot — check for end-of-array.
                if self.current_array_index >= n_items {
                    self.current_array_offset = next_arr;
                    self.current_array_index  = 0;
                }
                continue;
            }

            return Some(self.reader.read_entry_at(&mut self.file, entry_off));
        }
    }
}

// ── Free-standing file I/O helpers ────────────────────────────────────────

fn read_hash_item_from(file: &mut File, offset: u64) -> Result<HashItem> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; HASH_ITEM_SIZE];
    file.read_exact(&mut buf)?;
    Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const HashItem) })
}

/// Read the metadata fields of a DATA object needed for hash-chain walking.
/// Returns (hash, next_hash_offset, payload, entry_offset, entry_array_offset, n_entries).
fn read_data_object_meta(file: &mut File, offset: u64, compact: bool) -> Result<(u64, u64, Vec<u8>, u64, u64, u64)> {
    file.seek(SeekFrom::Start(offset))?;
    let mut hdr_buf = [0u8; DATA_OBJECT_HEADER_SIZE];
    file.read_exact(&mut hdr_buf)?;
    let hdr: DataObjectHeader =
        unsafe { std::ptr::read_unaligned(hdr_buf.as_ptr() as *const DataObjectHeader) };

    let h             = from_le64(&hdr.hash);
    let next          = from_le64(&hdr.next_hash_offset);
    let entry_offset  = from_le64(&hdr.entry_offset);
    let entry_arr_off = from_le64(&hdr.entry_array_offset);
    let n_entries     = from_le64(&hdr.n_entries);
    let obj_size      = from_le64(&hdr.object.size);

    // Compact mode adds 8 bytes (tail_entry_array_offset + tail_entry_array_n_entries) before payload.
    let payload_base = if compact {
        DATA_OBJECT_HEADER_SIZE as u64 + 8
    } else {
        DATA_OBJECT_HEADER_SIZE as u64
    };
    let payload_len = obj_size.saturating_sub(payload_base);

    if compact {
        use std::io::Seek;
        file.seek(SeekFrom::Current(8))?;
    }

    let mut payload = vec![0u8; payload_len as usize];
    file.read_exact(&mut payload)?;

    Ok((h, next, payload, entry_offset, entry_arr_off, n_entries))
}

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
            ]).unwrap();
            w.append_entry(&[
                ("MESSAGE", b"Second entry" as &[u8]),
                ("PRIORITY", b"5"),
                ("SYSLOG_IDENTIFIER", b"qtest"),
            ]).unwrap();
            w.flush().unwrap();
        }

        let reader = JournalReader::open(&path).unwrap();
        let entries: Vec<_> = reader.entries().collect::<Result<_>>().unwrap();
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
            w.append_entry(&[("MESSAGE", b"match" as &[u8]), ("PRIORITY", b"6")]).unwrap();
            w.append_entry(&[("MESSAGE", b"nomatch" as &[u8]), ("PRIORITY", b"3")]).unwrap();
            w.flush().unwrap();
        }

        let reader = JournalReader::open(&path).unwrap();
        let matches = reader.entries_for_field("PRIORITY", b"6").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].message(), Some("match"));
    }
}
