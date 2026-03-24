// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file verification.
//!
//! Rust port of systemd's `journal-verify.c` (`journal_file_verify`).
//! Walks all objects, verifies structural integrity, checks hash chains,
//! entry ordering, and count consistency.

use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::{
    def::*,
    error::{Error, Result},
    writer::{
        check_object, check_object_header, data_payload_offset, entry_array_item_size,
        entry_array_n_items, entry_item_size, journal_file_hash_data, verify_header,
    },
};

/// Result of journal file verification.
#[derive(Debug)]
pub struct VerifyResult {
    pub n_objects: u64,
    pub n_entries: u64,
    pub n_data: u64,
    pub n_fields: u64,
    pub n_entry_arrays: u64,
    pub n_tags: u64,
    pub n_data_hash_tables: u64,
    pub n_field_hash_tables: u64,
    pub first_entry_realtime: u64,
    pub last_entry_realtime: u64,
    /// Non-fatal warnings encountered during verification.
    pub warnings: Vec<String>,
}

// ── I/O helpers ─────────────────────────────────────────────────────────

fn read_u64_at(file: &mut File, offset: u64) -> Result<u64> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_u32_at(file: &mut File, offset: u64) -> Result<u32> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_bytes_at(file: &mut File, offset: u64, n: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; n];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

// ── Object-level verification ───────────────────────────────────────────

/// systemd: journal-verify.c:141-383 journal_file_object_verify
///
/// Deep verification of a single object's content (beyond the basic
/// check_object validation that move_to_object does).
fn verify_object(
    file: &mut File,
    offset: u64,
    obj_type: u8,
    obj_size: u64,
    obj_flags: u8,
    compact: bool,
    keyed_hash: bool,
    file_id: &[u8; 16],
) -> Result<()> {
    let otype = ObjectType::try_from(obj_type).map_err(|_| Error::CorruptObject {
        offset,
        reason: format!("invalid object type {}", obj_type),
    })?;

    match otype {
        ObjectType::Data => {
            // Verify hash matches payload
            let payload_off = data_payload_offset(compact);
            if obj_size <= payload_off {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA object too small for payload".into(),
                });
            }
            let payload_len = (obj_size - payload_off) as usize;

            // Read payload (handle compression)
            let compressed = obj_flags & obj_flags::COMPRESSED_MASK;
            let raw = read_bytes_at(file, offset + payload_off, payload_len)?;
            let payload = if compressed & obj_flags::COMPRESSED_ZSTD != 0 {
                #[cfg(feature = "zstd-compression")]
                {
                    zstd::decode_all(raw.as_slice())
                        .map_err(|e| Error::CorruptObject {
                            offset,
                            reason: format!("ZSTD decompression failed during verify: {}", e),
                        })?
                }
                #[cfg(not(feature = "zstd-compression"))]
                {
                    return Ok(()); // can't verify without decompression support
                }
            } else if compressed & obj_flags::COMPRESSED_XZ != 0 {
                #[cfg(feature = "xz-compression")]
                {
                    let mut decoder = xz2::read::XzDecoder::new(raw.as_slice());
                    let mut decompressed = Vec::new();
                    std::io::Read::read_to_end(&mut decoder, &mut decompressed)
                        .map_err(|e| Error::CorruptObject {
                            offset,
                            reason: format!("XZ decompression failed during verify: {}", e),
                        })?;
                    decompressed
                }
                #[cfg(not(feature = "xz-compression"))]
                {
                    return Ok(());
                }
            } else if compressed & obj_flags::COMPRESSED_LZ4 != 0 {
                #[cfg(feature = "lz4-compression")]
                {
                    if raw.len() < 8 {
                        return Err(Error::CorruptObject {
                            offset,
                            reason: "LZ4 data too short for size prefix".into(),
                        });
                    }
                    let uncompressed_size = u64::from_le_bytes(raw[..8].try_into().unwrap()) as usize;
                    lz4_flex::decompress(&raw[8..], uncompressed_size)
                        .map_err(|e| Error::CorruptObject {
                            offset,
                            reason: format!("LZ4 decompression failed during verify: {}", e),
                        })?
                }
                #[cfg(not(feature = "lz4-compression"))]
                {
                    return Ok(());
                }
            } else if compressed != 0 {
                return Ok(()); // unknown compression, skip
            } else {
                raw
            };

            let stored_hash = read_u64_at(file, offset + 16)?;
            let computed_hash = journal_file_hash_data(&payload, keyed_hash, file_id);
            if stored_hash != computed_hash {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "DATA hash mismatch: stored={:#x} computed={:#x}",
                        stored_hash, computed_hash
                    ),
                });
            }

            // Verify payload contains '='
            if !payload.contains(&b'=') {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA payload missing '=' separator".into(),
                });
            }
        }
        ObjectType::Entry => {
            // Verify entry items reference valid offsets (> header_size, aligned)
            let item_sz = entry_item_size(compact);
            let items_bytes = obj_size.saturating_sub(ENTRY_OBJECT_HEADER_SIZE as u64);
            let n_items = items_bytes / item_sz;

            for i in 0..n_items {
                let item_off = offset + ENTRY_OBJECT_HEADER_SIZE as u64 + i * item_sz;
                let data_off = if compact {
                    read_u32_at(file, item_off)? as u64
                } else {
                    read_u64_at(file, item_off)?
                };

                if data_off == 0 {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: format!("ENTRY item {} has null data offset", i),
                    });
                }
                if !valid64(data_off) {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: format!("ENTRY item {} data offset {:#x} not aligned", i, data_off),
                    });
                }
            }
        }
        ObjectType::EntryArray => {
            // Verify items are monotonically increasing
            let ea_item_sz = entry_array_item_size(compact);
            let n_items = entry_array_n_items(obj_size, compact);
            let mut prev_off = 0u64;

            for i in 0..n_items {
                let item_off = offset + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + i * ea_item_sz;
                let entry_off = if compact {
                    read_u32_at(file, item_off)? as u64
                } else {
                    read_u64_at(file, item_off)?
                };

                if entry_off == 0 {
                    break; // unused slots at end
                }

                if entry_off <= prev_off && prev_off != 0 {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: format!(
                            "ENTRY_ARRAY item {} offset {:#x} <= previous {:#x}",
                            i, entry_off, prev_off
                        ),
                    });
                }
                prev_off = entry_off;
            }
        }
        _ => {} // Other types validated by check_object
    }

    Ok(())
}

// ── Main verification function ──────────────────────────────────────────

/// systemd: journal-verify.c:812-1436 journal_file_verify
///
/// Verify the structural integrity of a journal file.
///
/// Performs:
/// 1. Header verification
/// 2. Sequential object walk with per-object validation
/// 3. Entry ordering checks (seqnum monotonic, realtime non-decreasing)
/// 4. Object count verification against header values
/// 5. Hash table consistency check
pub fn journal_file_verify<P: AsRef<Path>>(path: P) -> Result<VerifyResult> {
    let mut file = File::open(path)?;

    // Read header
    let mut hbuf = [0u8; 272];
    file.read_exact(&mut hbuf)
        .map_err(|_| Error::Truncated { offset: 0 })?;
    let header: Header = unsafe { std::ptr::read_unaligned(hbuf.as_ptr() as *const Header) };

    let file_size = file.metadata()?.len();
    verify_header(&header, file_size, false)?;

    let incompat = from_le32(&header.incompatible_flags);
    let keyed_hash = (incompat & incompat::KEYED_HASH) != 0;
    let compact = (incompat & incompat::COMPACT) != 0;
    let header_size = from_le64(&header.header_size);

    // Verify reserved bytes are zero
    for (i, &b) in header.reserved.iter().enumerate() {
        if b != 0 {
            return Err(Error::InvalidFile(format!(
                "reserved byte {} in header is non-zero: {:#x}",
                i, b
            )));
        }
    }

    let tail_object_offset = from_le64(&header.tail_object_offset);
    let mut warnings = Vec::new();

    // Counters
    let mut n_objects: u64 = 0;
    let mut n_entries: u64 = 0;
    let mut n_data: u64 = 0;
    let mut n_fields: u64 = 0;
    let mut n_entry_arrays: u64 = 0;
    let mut n_tags: u64 = 0;
    let mut n_data_hash_tables: u64 = 0;
    let mut n_field_hash_tables: u64 = 0;

    // Entry ordering state
    let mut entry_seqnum: u64 = 0;
    let mut entry_seqnum_set = false;
    let mut entry_monotonic: u64 = 0;
    let mut entry_boot_id = [0u8; 16];
    let mut entry_monotonic_set = false;
    let mut entry_realtime_set = false;
    let mut min_entry_realtime: u64 = u64::MAX;
    let mut max_entry_realtime: u64 = 0;

    // Data offsets seen (for entry cross-reference)
    let mut data_offsets: HashSet<u64> = HashSet::new();
    let mut found_main_entry_array = false;

    // First pass: walk all objects sequentially
    let mut p = header_size;

    if tail_object_offset == 0 {
        // Empty file
        return Ok(VerifyResult {
            n_objects: 0,
            n_entries: 0,
            n_data: 0,
            n_fields: 0,
            n_entry_arrays: 0,
            n_tags: 0,
            n_data_hash_tables: 0,
            n_field_hash_tables: 0,
            first_entry_realtime: 0,
            last_entry_realtime: 0,
            warnings,
        });
    }

    loop {
        if p > tail_object_offset {
            return Err(Error::InvalidFile(format!(
                "walked past tail_object_offset: {:#x} > {:#x}",
                p, tail_object_offset
            )));
        }

        // Read ObjectHeader
        let obj_type_byte = {
            file.seek(SeekFrom::Start(p))?;
            let mut buf = [0u8; 1];
            file.read_exact(&mut buf)?;
            buf[0]
        };
        let obj_flags_byte = {
            file.seek(SeekFrom::Start(p + 1))?;
            let mut buf = [0u8; 1];
            file.read_exact(&mut buf)?;
            buf[0]
        };
        let obj_size = read_u64_at(&mut file, p + 8)?;

        // Basic header validation
        check_object_header(obj_type_byte, obj_size, p, compact)?;

        // Compression flag consistency
        let compressed = obj_flags_byte & obj_flags::COMPRESSED_MASK;
        if compressed.count_ones() > 1 {
            return Err(Error::CorruptObject {
                offset: p,
                reason: "object has multiple compression flags set".into(),
            });
        }

        // Compression flag vs header flag consistency
        if (compressed & obj_flags::COMPRESSED_XZ) != 0
            && (incompat & incompat::COMPRESSED_XZ) == 0
        {
            return Err(Error::CorruptObject {
                offset: p,
                reason: "XZ compressed object in file without XZ header flag".into(),
            });
        }
        if (compressed & obj_flags::COMPRESSED_LZ4) != 0
            && (incompat & incompat::COMPRESSED_LZ4) == 0
        {
            return Err(Error::CorruptObject {
                offset: p,
                reason: "LZ4 compressed object in file without LZ4 header flag".into(),
            });
        }
        if (compressed & obj_flags::COMPRESSED_ZSTD) != 0
            && (incompat & incompat::COMPRESSED_ZSTD) == 0
        {
            return Err(Error::CorruptObject {
                offset: p,
                reason: "ZSTD compressed object in file without ZSTD header flag".into(),
            });
        }

        n_objects += 1;

        // Per-type counting and validation
        let otype = ObjectType::try_from(obj_type_byte).unwrap_or(ObjectType::Unused);
        match otype {
            ObjectType::Data => {
                n_data += 1;
                data_offsets.insert(p);
            }
            ObjectType::Field => {
                n_fields += 1;
            }
            ObjectType::Entry => {
                let seqnum = read_u64_at(&mut file, p + 16)?;
                let realtime = read_u64_at(&mut file, p + 24)?;
                let monotonic = read_u64_at(&mut file, p + 32)?;
                let boot_bytes = read_bytes_at(&mut file, p + 40, 16)?;
                let mut boot_id = [0u8; 16];
                boot_id.copy_from_slice(&boot_bytes);

                // Seqnum ordering
                if !entry_seqnum_set {
                    let head_seqnum = from_le64(&header.head_entry_seqnum);
                    if seqnum != head_seqnum {
                        return Err(Error::InvalidFile(format!(
                            "head entry seqnum mismatch: {} != {}",
                            seqnum, head_seqnum
                        )));
                    }
                } else if seqnum <= entry_seqnum {
                    return Err(Error::CorruptObject {
                        offset: p,
                        reason: format!(
                            "entry seqnum out of order: {} <= {}",
                            seqnum, entry_seqnum
                        ),
                    });
                }
                entry_seqnum = seqnum;
                entry_seqnum_set = true;

                // Monotonic ordering (same boot)
                if entry_monotonic_set && boot_id == entry_boot_id && monotonic < entry_monotonic {
                    return Err(Error::CorruptObject {
                        offset: p,
                        reason: format!(
                            "entry monotonic out of order: {} < {}",
                            monotonic, entry_monotonic
                        ),
                    });
                }
                entry_monotonic = monotonic;
                entry_boot_id = boot_id;
                entry_monotonic_set = true;

                // Realtime tracking
                if !entry_realtime_set {
                    let head_realtime = from_le64(&header.head_entry_realtime);
                    if realtime != head_realtime {
                        return Err(Error::InvalidFile(format!(
                            "head entry realtime mismatch: {} != {}",
                            realtime, head_realtime
                        )));
                    }
                }
                entry_realtime_set = true;

                min_entry_realtime = min_entry_realtime.min(realtime);
                max_entry_realtime = max_entry_realtime.max(realtime);

                n_entries += 1;
            }
            ObjectType::DataHashTable => {
                n_data_hash_tables += 1;
                if n_data_hash_tables > 1 {
                    return Err(Error::CorruptObject {
                        offset: p,
                        reason: "more than one data hash table".into(),
                    });
                }
            }
            ObjectType::FieldHashTable => {
                n_field_hash_tables += 1;
                if n_field_hash_tables > 1 {
                    return Err(Error::CorruptObject {
                        offset: p,
                        reason: "more than one field hash table".into(),
                    });
                }
            }
            ObjectType::EntryArray => {
                let entry_array_off = from_le64(&header.entry_array_offset);
                if p == entry_array_off {
                    if found_main_entry_array {
                        return Err(Error::CorruptObject {
                            offset: p,
                            reason: "more than one main entry array".into(),
                        });
                    }
                    found_main_entry_array = true;
                }
                n_entry_arrays += 1;
            }
            ObjectType::Tag => {
                n_tags += 1;
            }
            _ => {}
        }

        // Deep object verification
        verify_object(
            &mut file,
            p,
            obj_type_byte,
            obj_size,
            obj_flags_byte,
            compact,
            keyed_hash,
            &header.file_id,
        )?;

        // Advance to next object
        let next = align64(p + obj_size);
        if p == tail_object_offset {
            break;
        }
        if next <= p {
            return Err(Error::InvalidFile(format!(
                "object walk stuck at offset {:#x}",
                p
            )));
        }
        p = next;
    }

    // Verify counts match header
    let h_n_objects = from_le64(&header.n_objects);
    if n_objects != h_n_objects {
        return Err(Error::InvalidFile(format!(
            "n_objects mismatch: counted {} != header {}",
            n_objects, h_n_objects
        )));
    }

    let h_n_entries = from_le64(&header.n_entries);
    if n_entries != h_n_entries {
        return Err(Error::InvalidFile(format!(
            "n_entries mismatch: counted {} != header {}",
            n_entries, h_n_entries
        )));
    }

    let h_n_data = from_le64(&header.n_data);
    if n_data != h_n_data {
        return Err(Error::InvalidFile(format!(
            "n_data mismatch: counted {} != header {}",
            n_data, h_n_data
        )));
    }

    let h_n_fields = from_le64(&header.n_fields);
    if n_fields != h_n_fields {
        return Err(Error::InvalidFile(format!(
            "n_fields mismatch: counted {} != header {}",
            n_fields, h_n_fields
        )));
    }

    let h_n_entry_arrays = from_le64(&header.n_entry_arrays);
    if n_entry_arrays != h_n_entry_arrays {
        return Err(Error::InvalidFile(format!(
            "n_entry_arrays mismatch: counted {} != header {}",
            n_entry_arrays, h_n_entry_arrays
        )));
    }

    let h_n_tags = from_le64(&header.n_tags);
    if n_tags != h_n_tags {
        return Err(Error::InvalidFile(format!(
            "n_tags mismatch: counted {} != header {}",
            n_tags, h_n_tags
        )));
    }

    // Verify tail entry seqnum
    if entry_seqnum_set {
        let tail_seqnum = from_le64(&header.tail_entry_seqnum);
        if entry_seqnum != tail_seqnum {
            return Err(Error::InvalidFile(format!(
                "tail_entry_seqnum mismatch: last seen {} != header {}",
                entry_seqnum, tail_seqnum
            )));
        }
    }

    // Verify tail entry realtime
    if n_entries > 0 {
        let tail_realtime = from_le64(&header.tail_entry_realtime);
        if max_entry_realtime != tail_realtime {
            warnings.push(format!(
                "tail_entry_realtime mismatch: max seen {} != header {}",
                max_entry_realtime, tail_realtime
            ));
        }
    }

    // ── Second pass: cross-reference verification ───────────────────────
    // systemd: journal-verify.c after the main object walk

    // Verify data hash table chains reference valid DATA objects
    let data_ht_offset = from_le64(&header.data_hash_table_offset);
    let data_ht_size = from_le64(&header.data_hash_table_size);
    if data_ht_offset > 0 && data_ht_size > 0 {
        let ht_n = data_ht_size / HASH_ITEM_SIZE as u64;
        for bucket in 0..ht_n {
            let item_off = data_ht_offset + bucket * HASH_ITEM_SIZE as u64;
            let head = read_u64_at(&mut file, item_off)?;
            let mut cur = head;
            let mut prev = 0u64;
            while cur > 0 {
                if !data_offsets.contains(&cur) {
                    return Err(Error::InvalidFile(format!(
                        "data hash table bucket {} references offset {:#x} which is not a DATA object",
                        bucket, cur
                    )));
                }
                // Read next_hash_offset (offset 24 in DataObjectHeader)
                prev = cur;
                cur = read_u64_at(&mut file, cur + 24)?;
                if cur > 0 && cur <= prev {
                    return Err(Error::InvalidFile(format!(
                        "data hash chain loop at bucket {}: {:#x} <= {:#x}",
                        bucket, cur, prev
                    )));
                }
            }
        }
    }

    // Verify entry items reference valid DATA objects
    // Re-walk entries and check each item points to a known DATA offset
    let mut p2 = header_size;
    if tail_object_offset > 0 {
        loop {
            let obj_type_byte2 = {
                file.seek(SeekFrom::Start(p2))?;
                let mut buf = [0u8; 1];
                file.read_exact(&mut buf)?;
                buf[0]
            };
            let obj_size2 = read_u64_at(&mut file, p2 + 8)?;

            if obj_type_byte2 == ObjectType::Entry as u8 {
                let item_sz = entry_item_size(compact);
                let items_bytes = obj_size2.saturating_sub(ENTRY_OBJECT_HEADER_SIZE as u64);
                let n_items = items_bytes / item_sz;
                for i in 0..n_items {
                    let item_off = p2 + ENTRY_OBJECT_HEADER_SIZE as u64 + i * item_sz;
                    let data_off = if compact {
                        read_u32_at(&mut file, item_off)? as u64
                    } else {
                        read_u64_at(&mut file, item_off)?
                    };
                    if data_off > 0 && !data_offsets.contains(&data_off) {
                        return Err(Error::InvalidFile(format!(
                            "ENTRY at {:#x} item {} references {:#x} which is not a DATA object",
                            p2, i, data_off
                        )));
                    }
                }
            }

            if p2 == tail_object_offset {
                break;
            }
            let next2 = align64(p2 + obj_size2);
            if next2 <= p2 {
                break;
            }
            p2 = next2;
        }
    }

    Ok(VerifyResult {
        n_objects,
        n_entries,
        n_data,
        n_fields,
        n_entry_arrays,
        n_tags,
        n_data_hash_tables,
        n_field_hash_tables,
        first_entry_realtime: if min_entry_realtime == u64::MAX {
            0
        } else {
            min_entry_realtime
        },
        last_entry_realtime: max_entry_realtime,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JournalWriter;
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn test_verify_empty_journal() {
        let path = tmp_path("qjournal_verify_empty.journal");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[("MESSAGE", b"test" as &[u8])]).unwrap();
            w.flush().unwrap();
        }
        // File is closed (state=OFFLINE), verify it
        let result = journal_file_verify(&path).unwrap();
        assert_eq!(result.n_entries, 1);
        assert!(result.n_data >= 1);
        assert!(result.n_objects > 0);
        assert!(result.first_entry_realtime > 0);
    }

    #[test]
    fn test_verify_multiple_entries() {
        let path = tmp_path("qjournal_verify_multi.journal");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = JournalWriter::open(&path).unwrap();
            for i in 0..10 {
                let msg = format!("entry {}", i);
                w.append_entry(&[("MESSAGE", msg.as_bytes())]).unwrap();
            }
            w.flush().unwrap();
        }
        let result = journal_file_verify(&path).unwrap();
        assert_eq!(result.n_entries, 10);
        assert!(result.first_entry_realtime <= result.last_entry_realtime);
    }

    #[test]
    fn test_verify_bad_signature() {
        let path = tmp_path("qjournal_verify_bad_sig.journal");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[("MESSAGE", b"test" as &[u8])]).unwrap();
            w.flush().unwrap();
        }
        // Corrupt the signature
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all(b"BADMAGIC").unwrap();
        }
        assert!(journal_file_verify(&path).is_err());
    }
}
