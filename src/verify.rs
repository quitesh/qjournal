// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file verification.
//!
//! Rust port of systemd's `journal-verify.c` (`journal_file_verify`).
//! Walks all objects, verifies structural integrity, checks hash chains,
//! entry ordering, and count consistency.
//!
//! Two-pass verification:
//! 1. Sequential object walk -- validate each object individually, track offsets.
//! 2. Cross-reference -- verify hash table chains, entry->data references,
//!    data reachability from hash table, and entry array chain integrity.

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
        check_object_header, data_payload_offset, entry_array_item_size, entry_array_n_items,
        entry_item_size, journal_file_hash_data, verify_header,
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

/// Upper bound for VALID_REALTIME/VALID_MONOTONIC/VALID_EPOCH checks.
/// systemd: `(1ULL << 55)`
const TIMESTAMP_UPPER: u64 = 1u64 << 55;

// -- I/O helpers ----------------------------------------------------------

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

/// Read an entry-array item (offset) at a given slot position.
fn read_entry_array_item(file: &mut File, base: u64, index: u64, compact: bool) -> Result<u64> {
    let item_sz = entry_array_item_size(compact);
    let off = base + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + index * item_sz;
    if compact {
        Ok(read_u32_at(file, off)? as u64)
    } else {
        read_u64_at(file, off)
    }
}

/// Read an entry item (data object offset) at a given slot position.
fn read_entry_item_offset(
    file: &mut File,
    entry_off: u64,
    index: u64,
    compact: bool,
) -> Result<u64> {
    let item_sz = entry_item_size(compact);
    let off = entry_off + ENTRY_OBJECT_HEADER_SIZE as u64 + index * item_sz;
    if compact {
        Ok(read_u32_at(file, off)? as u64)
    } else {
        read_u64_at(file, off)
    }
}

// -- Object-level verification --------------------------------------------

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

    // systemd: journal-verify.c:150-156
    // Reject compression flags on non-DATA objects
    let compressed = obj_flags & obj_flags::COMPRESSED_MASK;
    if compressed != 0 && otype != ObjectType::Data {
        return Err(Error::CorruptObject {
            offset,
            reason: format!(
                "non-DATA object {:?} has compression flags {:#x}",
                otype, compressed
            ),
        });
    }

    match otype {
        ObjectType::Data => {
            // systemd: journal-verify.c:158-203

            let payload_off = data_payload_offset(compact);
            if obj_size <= payload_off {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "DATA object too small for payload".into(),
                });
            }
            let payload_len = (obj_size - payload_off) as usize;

            // Read data object header fields for structural checks
            let next_hash_offset = read_u64_at(file, offset + 24)?;
            let next_field_offset = read_u64_at(file, offset + 32)?;
            let entry_offset = read_u64_at(file, offset + 40)?;
            let entry_array_offset = read_u64_at(file, offset + 48)?;
            let n_entries = read_u64_at(file, offset + 56)?;

            // systemd: journal-verify.c:167-169
            // entry_offset == 0 XOR n_entries == 0 consistency
            if (entry_offset == 0) != (n_entries == 0) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "DATA entry_offset={:#x} but n_entries={}",
                        entry_offset, n_entries
                    ),
                });
            }

            // systemd: journal-verify.c:191-201 VALID64 checks
            if next_hash_offset != 0 && !valid64(next_hash_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "DATA next_hash_offset {:#x} not aligned",
                        next_hash_offset
                    ),
                });
            }
            if next_field_offset != 0 && !valid64(next_field_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "DATA next_field_offset {:#x} not aligned",
                        next_field_offset
                    ),
                });
            }
            if entry_offset != 0 && !valid64(entry_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!("DATA entry_offset {:#x} not aligned", entry_offset),
                });
            }
            if entry_array_offset != 0 && !valid64(entry_array_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "DATA entry_array_offset {:#x} not aligned",
                        entry_array_offset
                    ),
                });
            }

            // Read payload (handle compression)
            let raw = read_bytes_at(file, offset + payload_off, payload_len)?;
            let payload = if compressed & obj_flags::COMPRESSED_ZSTD != 0 {
                #[cfg(feature = "zstd-compression")]
                {
                    zstd::decode_all(raw.as_slice()).map_err(|e| Error::CorruptObject {
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
                    std::io::Read::read_to_end(&mut decoder, &mut decompressed).map_err(|e| {
                        Error::CorruptObject {
                            offset,
                            reason: format!("XZ decompression failed during verify: {}", e),
                        }
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
                    let uncompressed_size =
                        u64::from_le_bytes(raw[..8].try_into().unwrap()) as usize;
                    lz4_flex::decompress(&raw[8..], uncompressed_size).map_err(|e| {
                        Error::CorruptObject {
                            offset,
                            reason: format!("LZ4 decompression failed during verify: {}", e),
                        }
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

            // Note: systemd does not check for '=' in DATA payloads at the verify level.
            // Binary data objects may not contain '='. We skip this check for compatibility.
        }
        ObjectType::Field => {
            // systemd: journal-verify.c:206-238

            if obj_size <= FIELD_OBJECT_HEADER_SIZE as u64 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "FIELD object has no payload".into(),
                });
            }

            // Hash verification
            let stored_hash = read_u64_at(file, offset + 16)?;
            let payload_len = (obj_size - FIELD_OBJECT_HEADER_SIZE as u64) as usize;
            let payload =
                read_bytes_at(file, offset + FIELD_OBJECT_HEADER_SIZE as u64, payload_len)?;
            let computed_hash = journal_file_hash_data(&payload, keyed_hash, file_id);
            if stored_hash != computed_hash {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "FIELD hash mismatch: stored={:#x} computed={:#x}",
                        stored_hash, computed_hash
                    ),
                });
            }

            // Pointer alignment checks
            let next_hash_offset = read_u64_at(file, offset + 24)?;
            if next_hash_offset != 0 && !valid64(next_hash_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "FIELD next_hash_offset {:#x} not aligned",
                        next_hash_offset
                    ),
                });
            }
            let head_data_offset = read_u64_at(file, offset + 32)?;
            if head_data_offset != 0 && !valid64(head_data_offset) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "FIELD head_data_offset {:#x} not aligned",
                        head_data_offset
                    ),
                });
            }
        }
        ObjectType::Entry => {
            // systemd: journal-verify.c:242-276

            let item_sz = entry_item_size(compact);
            let items_bytes = obj_size.saturating_sub(ENTRY_OBJECT_HEADER_SIZE as u64);

            // Size modulo check
            if items_bytes % item_sz != 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "ENTRY items region {} not divisible by item size {}",
                        items_bytes, item_sz
                    ),
                });
            }

            let n_items = items_bytes / item_sz;

            // n_items > 0
            if n_items == 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "ENTRY has no items".into(),
                });
            }

            // seqnum > 0
            let seqnum = read_u64_at(file, offset + 16)?;
            if seqnum == 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: "ENTRY seqnum is zero".into(),
                });
            }

            // VALID_REALTIME: u > 0 && u < (1<<55)
            let realtime = read_u64_at(file, offset + 24)?;
            if realtime == 0 || realtime >= TIMESTAMP_UPPER {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!("ENTRY realtime {} invalid", realtime),
                });
            }

            // VALID_MONOTONIC: u < (1<<55), 0 IS valid
            let monotonic = read_u64_at(file, offset + 32)?;
            if monotonic >= TIMESTAMP_UPPER {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!("ENTRY monotonic {} invalid", monotonic),
                });
            }

            // Note: systemd does not check for null boot_id in verify_object.
            // We skip that check for compatibility.

            // Verify each entry item has valid offset
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
                        reason: format!(
                            "ENTRY item {} data offset {:#x} not aligned",
                            i, data_off
                        ),
                    });
                }
            }
        }
        ObjectType::DataHashTable | ObjectType::FieldHashTable => {
            // systemd: journal-verify.c:291-334

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

            // Per-item head/tail pointer checks
            for i in 0..n_items {
                let item_off = offset + OBJECT_HEADER_SIZE as u64 + i * HASH_ITEM_SIZE as u64;
                let head = read_u64_at(file, item_off)?;
                let tail = read_u64_at(file, item_off + 8)?;

                // Both zero or both non-zero
                if (head == 0) != (tail == 0) {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: format!(
                            "HASH_TABLE bucket {} head={:#x} tail={:#x} inconsistent",
                            i, head, tail
                        ),
                    });
                }

                if head != 0 && !valid64(head) {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: format!(
                            "HASH_TABLE bucket {} head {:#x} not aligned",
                            i, head
                        ),
                    });
                }
                if tail != 0 && !valid64(tail) {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: format!(
                            "HASH_TABLE bucket {} tail {:#x} not aligned",
                            i, tail
                        ),
                    });
                }
            }
        }
        ObjectType::EntryArray => {
            // systemd: journal-verify.c:336-361

            let ea_item_sz = entry_array_item_size(compact);
            let items_bytes = obj_size.saturating_sub(ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64);

            // Size modulo check and n_items > 0 (systemd: journal-verify.c:337-338)
            if items_bytes % ea_item_sz != 0 || items_bytes / ea_item_sz == 0 {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "ENTRY_ARRAY items region {} not divisible by {} or has zero items",
                        items_bytes, ea_item_sz
                    ),
                });
            }

            // VALID64 on next_entry_array_offset
            let next_ea = read_u64_at(file, offset + 16)?;
            if next_ea != 0 && !valid64(next_ea) {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "ENTRY_ARRAY next_entry_array_offset {:#x} not aligned",
                        next_ea
                    ),
                });
            }

            // Per-item VALID64 and monotonicity check
            let n_items = entry_array_n_items(obj_size, compact);
            let mut prev_off = 0u64;
            for i in 0..n_items {
                let item_off =
                    offset + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + i * ea_item_sz;
                let entry_off = if compact {
                    read_u32_at(file, item_off)? as u64
                } else {
                    read_u64_at(file, item_off)?
                };

                if entry_off == 0 {
                    break; // unused slots at end
                }

                if !valid64(entry_off) {
                    return Err(Error::CorruptObject {
                        offset,
                        reason: format!(
                            "ENTRY_ARRAY item {} offset {:#x} not aligned",
                            i, entry_off
                        ),
                    });
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
        ObjectType::Tag => {
            // systemd: journal-verify.c:364-378

            const TAG_OBJECT_SIZE: u64 = OBJECT_HEADER_SIZE as u64 + 8 + 8 + 32;
            if obj_size != TAG_OBJECT_SIZE {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!(
                        "TAG object size {} != expected {}",
                        obj_size, TAG_OBJECT_SIZE
                    ),
                });
            }

            // Epoch validity: epoch < (1<<55)
            let epoch = read_u64_at(file, offset + 24)?;
            if epoch >= TIMESTAMP_UPPER {
                return Err(Error::CorruptObject {
                    offset,
                    reason: format!("TAG epoch {} invalid (>= 2^55)", epoch),
                });
            }
        }
        _ => {} // Unused validated by check_object_header
    }

    Ok(())
}

// -- Second-pass verification functions -----------------------------------

/// systemd: journal-verify.c:390-449 data_object_in_hash_table
///
/// Confirm that a data object at `data_offset` is reachable from its
/// correct bucket in the data hash table.
fn data_object_in_hash_table(
    file: &mut File,
    data_offset: u64,
    stored_hash: u64,
    data_ht_offset: u64,
    data_ht_size: u64,
) -> Result<bool> {
    let n_buckets = data_ht_size / HASH_ITEM_SIZE as u64;
    if n_buckets == 0 {
        return Ok(false);
    }
    let bucket = stored_hash % n_buckets;
    let item_off = data_ht_offset + bucket * HASH_ITEM_SIZE as u64;
    let mut cur = read_u64_at(file, item_off)?;

    while cur != 0 {
        if cur == data_offset {
            return Ok(true);
        }
        // next_hash_offset is at offset 24 within DataObjectHeader
        cur = read_u64_at(file, cur + 24)?;
    }
    Ok(false)
}

/// Check whether a data object's entry chain (inline entry_offset + entry_array chain)
/// contains the given entry offset.
///
/// systemd: journal-verify.c:563-691 (verify_entry calls journal_file_move_to_entry_by_offset_for_data)
fn data_object_entry_chain_contains(
    file: &mut File,
    data_off: u64,
    target_entry_off: u64,
    compact: bool,
) -> Result<bool> {
    // Check inline entry_offset
    let entry_offset = read_u64_at(file, data_off + 40)?;
    if entry_offset == target_entry_off {
        return Ok(true);
    }

    // Walk entry_array chain
    let mut cur_array = read_u64_at(file, data_off + 48)?;
    while cur_array != 0 {
        let ea_size = read_u64_at(file, cur_array + 8)?;
        let n_items = entry_array_n_items(ea_size, compact);

        for i in 0..n_items {
            let entry_off = read_entry_array_item(file, cur_array, i, compact)?;
            if entry_off == 0 {
                return Ok(false);
            }
            if entry_off == target_entry_off {
                return Ok(true);
            }
        }

        let next_ea = read_u64_at(file, cur_array + 16)?;
        if next_ea != 0 && next_ea <= cur_array {
            break; // cycle protection
        }
        cur_array = next_ea;
    }

    Ok(false)
}

/// V-01: Verify a single data object's entry references.
///
/// systemd: journal-verify.c:425-525 verify_data
///
/// For each data object, verify:
/// - Each entry in its chain exists in `entry_offsets`
/// - entry_array_offset != 0 implies n_entries >= 2 (V-06)
/// - Monotonic ordering of entries in per-data chain (V-06)
fn verify_data_object(
    file: &mut File,
    data_off: u64,
    entry_offsets: &HashSet<u64>,
    compact: bool,
) -> Result<()> {
    let entry_offset = read_u64_at(file, data_off + 40)?;
    let entry_array_offset = read_u64_at(file, data_off + 48)?;
    let n_entries = read_u64_at(file, data_off + 56)?;

    // V-06: entry_array_offset != 0 implies n_entries >= 2
    if entry_array_offset != 0 && n_entries < 2 {
        return Err(Error::InvalidFile(format!(
            "DATA at {:#x} has entry_array_offset={:#x} but n_entries={} (must be >= 2)",
            data_off, entry_array_offset, n_entries
        )));
    }

    if n_entries == 0 {
        return Ok(());
    }

    let mut counted = 0u64;
    let mut last_entry = 0u64;

    // First entry is the inline one (entry_offset)
    if entry_offset != 0 {
        if !entry_offsets.contains(&entry_offset) {
            return Err(Error::InvalidFile(format!(
                "DATA at {:#x} inline entry_offset {:#x} is not a known ENTRY",
                data_off, entry_offset
            )));
        }
        last_entry = entry_offset;
        counted += 1;
    }

    // Walk the entry array chain
    let mut cur_array = entry_array_offset;
    while cur_array != 0 {
        let ea_size = read_u64_at(file, cur_array + 8)?;
        let n_items = entry_array_n_items(ea_size, compact);

        for i in 0..n_items {
            let entry_off = read_entry_array_item(file, cur_array, i, compact)?;
            if entry_off == 0 {
                break;
            }

            // V-06: monotonic ordering check for per-data chain
            if entry_off <= last_entry && last_entry != 0 {
                return Err(Error::InvalidFile(format!(
                    "DATA at {:#x} entry array not sorted ({:#x} <= {:#x})",
                    data_off, entry_off, last_entry
                )));
            }
            last_entry = entry_off;

            if !entry_offsets.contains(&entry_off) {
                return Err(Error::InvalidFile(format!(
                    "DATA at {:#x} entry array references {:#x} which is not a known ENTRY",
                    data_off, entry_off
                )));
            }
            counted += 1;
        }

        let next_ea = read_u64_at(file, cur_array + 16)?;
        if next_ea != 0 && next_ea <= cur_array {
            return Err(Error::InvalidFile(format!(
                "DATA at {:#x} entry array chain loop: next {:#x} <= current {:#x}",
                data_off, next_ea, cur_array
            )));
        }
        cur_array = next_ea;
    }

    if counted != n_entries {
        return Err(Error::InvalidFile(format!(
            "DATA at {:#x} n_entries={} but counted {} in entry chain",
            data_off, n_entries, counted
        )));
    }

    Ok(())
}

/// Maximum allowed hash chain depth before we consider the file corrupt.
/// This is a safety bound to prevent runaway verification on degenerate files.
const MAX_HASH_CHAIN_DEPTH: u64 = 1024 * 1024;

/// systemd: journal-verify.c:452-561 verify_data_hash_table
///
/// Walk each bucket of the data hash table, verify:
/// - Each referenced object is in `data_offsets`
/// - Each object's hash maps to the correct bucket
/// - Tail pointers match the last element in each chain
/// - Call verify_data_object for each data object (V-01)
/// - Enforce max chain depth (V-13)
fn verify_data_hash_table(
    file: &mut File,
    data_ht_offset: u64,
    data_ht_size: u64,
    data_offsets: &HashSet<u64>,
    entry_offsets: &HashSet<u64>,
    compact: bool,
) -> Result<()> {
    if data_ht_offset == 0 || data_ht_size == 0 {
        return Ok(());
    }
    let n_buckets = data_ht_size / HASH_ITEM_SIZE as u64;

    for bucket in 0..n_buckets {
        let item_off = data_ht_offset + bucket * HASH_ITEM_SIZE as u64;
        let head = read_u64_at(file, item_off)?;
        let tail = read_u64_at(file, item_off + 8)?;

        let mut cur = head;
        let mut last = 0u64;
        #[allow(unused_assignments)]
        let mut prev = 0u64;
        let mut chain_depth: u64 = 0;

        while cur != 0 {
            // V-13: enforce max chain depth
            chain_depth += 1;
            if chain_depth > MAX_HASH_CHAIN_DEPTH {
                return Err(Error::InvalidFile(format!(
                    "data hash table bucket {} chain depth exceeds maximum ({})",
                    bucket, MAX_HASH_CHAIN_DEPTH
                )));
            }

            if !data_offsets.contains(&cur) {
                return Err(Error::InvalidFile(format!(
                    "data hash table bucket {} references {:#x} which is not a DATA object",
                    bucket, cur
                )));
            }

            // Verify hash maps to this bucket
            let stored_hash = read_u64_at(file, cur + 16)?;
            if stored_hash % n_buckets != bucket {
                return Err(Error::InvalidFile(format!(
                    "DATA at {:#x} has hash {:#x} -> bucket {} but is in bucket {}",
                    cur,
                    stored_hash,
                    stored_hash % n_buckets,
                    bucket
                )));
            }

            // V-01: verify this data object's entry references
            verify_data_object(file, cur, entry_offsets, compact)?;

            last = cur;
            prev = cur;
            cur = read_u64_at(file, cur + 24)?;

            if cur != 0 && cur <= prev {
                return Err(Error::InvalidFile(format!(
                    "data hash chain loop at bucket {}: {:#x} <= {:#x}",
                    bucket, cur, prev
                )));
            }
        }

        // Verify tail pointer
        if last != tail {
            return Err(Error::InvalidFile(format!(
                "data hash table bucket {} tail mismatch: chain ends at {:#x} but tail={:#x}",
                bucket, last, tail
            )));
        }
    }

    Ok(())
}

/// systemd: journal-verify.c:563-691 verify_entry
///
/// For a single entry, verify each data item:
/// - Points to a known DATA object
/// - The DATA object is reachable from the hash table
/// - V-02: The DATA object's entry chain contains this entry (reverse link check)
///   with last-entry exemption (the last entry may not be fully linked yet)
fn verify_entry(
    file: &mut File,
    entry_offset: u64,
    obj_size: u64,
    compact: bool,
    data_offsets: &HashSet<u64>,
    data_ht_offset: u64,
    data_ht_size: u64,
    is_last: bool,
) -> Result<()> {
    let item_sz = entry_item_size(compact);
    let items_bytes = obj_size.saturating_sub(ENTRY_OBJECT_HEADER_SIZE as u64);
    let n_items = items_bytes / item_sz;

    for i in 0..n_items {
        let data_off = read_entry_item_offset(file, entry_offset, i, compact)?;

        if data_off == 0 {
            return Err(Error::InvalidFile(format!(
                "ENTRY at {:#x} item {} has null data offset",
                entry_offset, i
            )));
        }

        if !data_offsets.contains(&data_off) {
            return Err(Error::InvalidFile(format!(
                "ENTRY at {:#x} item {} references {:#x} which is not a DATA object",
                entry_offset, i, data_off
            )));
        }

        // Verify the DATA object is reachable from the hash table
        let stored_hash = read_u64_at(file, data_off + 16)?;
        if !data_object_in_hash_table(file, data_off, stored_hash, data_ht_offset, data_ht_size)? {
            return Err(Error::InvalidFile(format!(
                "DATA at {:#x} (referenced by ENTRY {:#x} item {}) not reachable from hash table",
                data_off, entry_offset, i
            )));
        }

        // V-02: Verify the data object's entry chain contains this entry (reverse link check).
        // The last entry object has a very high chance of not being referenced as journal
        // files almost always run out of space during linking of entry items when trying
        // to add a new entry array, so skip this check for the last entry.
        if !is_last {
            if !data_object_entry_chain_contains(file, data_off, entry_offset, compact)? {
                return Err(Error::InvalidFile(format!(
                    "ENTRY at {:#x} not referenced by linked DATA object at {:#x}",
                    entry_offset, data_off
                )));
            }
        }
    }

    Ok(())
}

/// systemd: journal-verify.c:643-741 verify_entry_array
///
/// Walk the main entry array chain (starting from `entry_array_offset`),
/// verify each entry offset points to a known entry, and verify ordering.
fn verify_entry_array(
    file: &mut File,
    entry_array_offset: u64,
    compact: bool,
    entry_offsets: &HashSet<u64>,
    n_entries: u64,
) -> Result<()> {
    if entry_array_offset == 0 {
        return Ok(());
    }

    let mut cur_array = entry_array_offset;
    let mut total_seen = 0u64;
    let mut prev_entry_off = 0u64;

    while cur_array != 0 {
        let ea_size = read_u64_at(file, cur_array + 8)?;
        let n_items = entry_array_n_items(ea_size, compact);

        for i in 0..n_items {
            let entry_off = read_entry_array_item(file, cur_array, i, compact)?;
            if entry_off == 0 {
                break;
            }

            if !entry_offsets.contains(&entry_off) {
                return Err(Error::InvalidFile(format!(
                    "main entry array references {:#x} which is not an ENTRY object",
                    entry_off
                )));
            }

            if entry_off <= prev_entry_off && prev_entry_off != 0 {
                return Err(Error::InvalidFile(format!(
                    "main entry array not monotonic: {:#x} <= {:#x}",
                    entry_off, prev_entry_off
                )));
            }
            prev_entry_off = entry_off;
            total_seen += 1;
        }

        let next_ea = read_u64_at(file, cur_array + 16)?;
        if next_ea != 0 && next_ea <= cur_array {
            return Err(Error::InvalidFile(format!(
                "entry array chain loop: next {:#x} <= current {:#x}",
                next_ea, cur_array
            )));
        }
        cur_array = next_ea;
    }

    if total_seen != n_entries {
        return Err(Error::InvalidFile(format!(
            "main entry array contains {} entries but header says {}",
            total_seen, n_entries
        )));
    }

    Ok(())
}

// -- Main verification function -------------------------------------------

/// systemd: journal-verify.c:812-1436 journal_file_verify
///
/// Verify the structural integrity of a journal file.
///
/// Performs:
/// 1. Header verification (signature, flags, sizes, offsets)
/// 2. Compatible flags check
/// 3. Sequential object walk with per-object validation
/// 4. Entry ordering checks (seqnum monotonic, realtime non-decreasing)
/// 5. Object count verification against header values
/// 6. Hash table offset/size consistency
/// 7. Tail entry monotonic/boot_id check
/// 8. Second-pass cross-reference verification:
///    a. Data hash table chain walk and bucket mapping
///    b. Entry -> data bidirectional reference
///    c. Main entry array chain walk
///    d. Per-data entry array chain walk
pub fn journal_file_verify<P: AsRef<Path>>(path: P) -> Result<VerifyResult> {
    let mut file = File::open(path)?;

    // Read header
    let mut hbuf = [0u8; 272];
    file.read_exact(&mut hbuf)
        .map_err(|_| Error::Truncated { offset: 0 })?;
    let header: Header = unsafe { std::ptr::read_unaligned(hbuf.as_ptr() as *const Header) };

    let file_size = file.metadata()?.len();
    verify_header(&header, file_size, false, None)?;

    let incompat = from_le32(&header.incompatible_flags);
    let compat = from_le32(&header.compatible_flags);
    let keyed_hash = (incompat & incompat::KEYED_HASH) != 0;
    let compact = (incompat & incompat::COMPACT) != 0;
    let header_size = from_le64(&header.header_size);

    // systemd: journal-verify.c:915-919
    // Compatible flags check -- we understand SEALED, TAIL_ENTRY_BOOT_ID, SEALED_CONTINUOUS
    let known_compat = compat::SEALED | compat::TAIL_ENTRY_BOOT_ID | compat::SEALED_CONTINUOUS;
    let unknown_compat = compat & !known_compat;
    if unknown_compat != 0 {
        return Err(Error::InvalidFile(format!(
            "unknown compatible flags {:#x} set",
            unknown_compat
        )));
    }

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
    let warnings = Vec::new();

    // Verify hash table offset/size consistency with header
    let data_ht_offset = from_le64(&header.data_hash_table_offset);
    let data_ht_size = from_le64(&header.data_hash_table_size);
    let field_ht_offset = from_le64(&header.field_hash_table_offset);
    let field_ht_size = from_le64(&header.field_hash_table_size);

    // Data hash table bounds check
    if data_ht_offset != 0 {
        if data_ht_offset < header_size {
            return Err(Error::InvalidFile(format!(
                "data_hash_table_offset {:#x} < header_size {:#x}",
                data_ht_offset, header_size
            )));
        }
        if data_ht_size == 0 {
            return Err(Error::InvalidFile(
                "data_hash_table_offset set but data_hash_table_size is 0".into(),
            ));
        }
        if data_ht_offset
            .checked_add(data_ht_size)
            .map_or(true, |end| end > file_size)
        {
            return Err(Error::InvalidFile(
                "data hash table extends past end of file".into(),
            ));
        }
    }

    // Field hash table bounds check
    if field_ht_offset != 0 {
        if field_ht_offset < header_size {
            return Err(Error::InvalidFile(format!(
                "field_hash_table_offset {:#x} < header_size {:#x}",
                field_ht_offset, header_size
            )));
        }
        if field_ht_size == 0 {
            return Err(Error::InvalidFile(
                "field_hash_table_offset set but field_hash_table_size is 0".into(),
            ));
        }
        if field_ht_offset
            .checked_add(field_ht_size)
            .map_or(true, |end| end > file_size)
        {
            return Err(Error::InvalidFile(
                "field hash table extends past end of file".into(),
            ));
        }
    }

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

    // V-08: Track LAST entry realtime for tail_entry_realtime comparison
    let mut last_entry_realtime: u64 = 0;

    // Track last entry monotonic/boot_id for tail check
    let mut last_entry_monotonic: u64 = 0;
    let mut last_entry_boot_id = [0u8; 16];

    // Offset tracking for cross-reference
    let mut data_offsets: HashSet<u64> = HashSet::new();
    let mut entry_offsets: HashSet<u64> = HashSet::new();
    let mut found_main_entry_array = false;

    // First pass: walk all objects sequentially
    let mut p = header_size;

    if tail_object_offset == 0 {
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
        check_object_header(obj_type_byte, obj_size, p, compact, None)?;

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
                if entry_monotonic_set
                    && boot_id == entry_boot_id
                    && monotonic < entry_monotonic
                {
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

                last_entry_monotonic = monotonic;
                last_entry_boot_id = boot_id;
                last_entry_realtime = realtime;

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
                entry_offsets.insert(p);
            }
            ObjectType::DataHashTable => {
                n_data_hash_tables += 1;
                if n_data_hash_tables > 1 {
                    return Err(Error::CorruptObject {
                        offset: p,
                        reason: "more than one data hash table".into(),
                    });
                }
                // Verify hash table object offset/size matches header
                let ht_obj_data_off = p + OBJECT_HEADER_SIZE as u64;
                let ht_obj_data_size = obj_size - OBJECT_HEADER_SIZE as u64;
                if data_ht_offset != ht_obj_data_off {
                    return Err(Error::InvalidFile(format!(
                        "data_hash_table_offset {:#x} != hash table object data at {:#x}",
                        data_ht_offset, ht_obj_data_off
                    )));
                }
                if data_ht_size != ht_obj_data_size {
                    return Err(Error::InvalidFile(format!(
                        "data_hash_table_size {} != hash table object data size {}",
                        data_ht_size, ht_obj_data_size
                    )));
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
                let ht_obj_data_off = p + OBJECT_HEADER_SIZE as u64;
                let ht_obj_data_size = obj_size - OBJECT_HEADER_SIZE as u64;
                if field_ht_offset != ht_obj_data_off {
                    return Err(Error::InvalidFile(format!(
                        "field_hash_table_offset {:#x} != hash table object data at {:#x}",
                        field_ht_offset, ht_obj_data_off
                    )));
                }
                if field_ht_size != ht_obj_data_size {
                    return Err(Error::InvalidFile(format!(
                        "field_hash_table_size {} != hash table object data size {}",
                        field_ht_size, ht_obj_data_size
                    )));
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

    // -- Post-walk header consistency checks ------------------------------

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

    // V-14: Only check n_data, n_fields, n_tags, n_entry_arrays if the header
    // is large enough to contain those fields (JOURNAL_HEADER_CONTAINS equivalent).
    // n_data: offset 232, size 8 -> requires header_size >= 240
    if header_size >= 240 {
        let h_n_data = from_le64(&header.n_data);
        if n_data != h_n_data {
            return Err(Error::InvalidFile(format!(
                "n_data mismatch: counted {} != header {}",
                n_data, h_n_data
            )));
        }
    }

    // n_fields: offset 240, size 8 -> requires header_size >= 248
    if header_size >= 248 {
        let h_n_fields = from_le64(&header.n_fields);
        if n_fields != h_n_fields {
            return Err(Error::InvalidFile(format!(
                "n_fields mismatch: counted {} != header {}",
                n_fields, h_n_fields
            )));
        }
    }

    // n_tags: offset 248, size 8 -> requires header_size >= 256
    if header_size >= 256 {
        let h_n_tags = from_le64(&header.n_tags);
        if n_tags != h_n_tags {
            return Err(Error::InvalidFile(format!(
                "n_tags mismatch: counted {} != header {}",
                n_tags, h_n_tags
            )));
        }
    }

    // n_entry_arrays: offset 256, size 8 -> requires header_size >= 264
    if header_size >= 264 {
        let h_n_entry_arrays = from_le64(&header.n_entry_arrays);
        if n_entry_arrays != h_n_entry_arrays {
            return Err(Error::InvalidFile(format!(
                "n_entry_arrays mismatch: counted {} != header {}",
                n_entry_arrays, h_n_entry_arrays
            )));
        }
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

    // systemd: journal-verify.c:1348-1355 -- tail_entry_realtime hard error
    // V-08: Use LAST entry realtime, not max, matching systemd's entry_realtime
    if n_entries > 0 {
        let tail_realtime = from_le64(&header.tail_entry_realtime);
        if last_entry_realtime != tail_realtime {
            return Err(Error::InvalidFile(format!(
                "tail_entry_realtime mismatch: last seen {} != header {}",
                last_entry_realtime, tail_realtime
            )));
        }
    }

    // systemd: journal-verify.c:1336-1346 -- tail_entry_monotonic/boot_id
    // Only check tail_entry_monotonic when ALL THREE conditions hold:
    //   1. TAIL_ENTRY_BOOT_ID flag is set
    //   2. last entry's boot_id MATCHES header's tail_entry_boot_id
    //   3. monotonic values differ
    // If boot_id does NOT match, systemd silently skips (no error).
    if n_entries > 0
        && (compat & compat::TAIL_ENTRY_BOOT_ID) != 0
        && last_entry_boot_id == header.tail_entry_boot_id
    {
        let tail_monotonic = from_le64(&header.tail_entry_monotonic);
        if last_entry_monotonic != tail_monotonic {
            return Err(Error::InvalidFile(format!(
                "tail_entry_monotonic mismatch: last seen {} != header {}",
                last_entry_monotonic, tail_monotonic
            )));
        }
    }

    // Verify found_main_entry_array when entry_array_offset != 0
    let entry_array_off = from_le64(&header.entry_array_offset);
    if entry_array_off != 0 && !found_main_entry_array {
        return Err(Error::InvalidFile(format!(
            "header entry_array_offset={:#x} but no matching entry array object found",
            entry_array_off
        )));
    }
    // Note: systemd does NOT check for entry_array_offset==0 when entries exist.
    // We skip this check for compatibility.

    // -- Second pass: cross-reference verification ------------------------

    // 1. Verify data hash table chains (also validates per-data entry references: V-01)
    verify_data_hash_table(
        &mut file,
        data_ht_offset,
        data_ht_size,
        &data_offsets,
        &entry_offsets,
        compact,
    )?;

    // 2. Verify each entry's data items exist and are reachable from hash table
    //    V-02: Also verify reverse links (data->entry) with last-entry exemption
    let mut p2 = header_size;
    let mut entry_index: u64 = 0;
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
                entry_index += 1;
                let is_last = entry_index == n_entries;
                verify_entry(
                    &mut file,
                    p2,
                    obj_size2,
                    compact,
                    &data_offsets,
                    data_ht_offset,
                    data_ht_size,
                    is_last,
                )?;
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

    // 3. Verify main entry array chain
    verify_entry_array(
        &mut file,
        entry_array_off,
        compact,
        &entry_offsets,
        n_entries,
    )?;

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
        last_entry_realtime,
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
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all(b"BADMAGIC").unwrap();
        }
        assert!(journal_file_verify(&path).is_err());
    }

    #[test]
    fn test_verify_multiple_fields() {
        let path = tmp_path("qjournal_verify_multifield.journal");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = JournalWriter::open(&path).unwrap();
            w.append_entry(&[
                ("MESSAGE", b"hello" as &[u8]),
                ("PRIORITY", b"6"),
                ("_HOSTNAME", b"test"),
            ])
            .unwrap();
            w.flush().unwrap();
        }
        let result = journal_file_verify(&path).unwrap();
        assert_eq!(result.n_entries, 1);
        assert!(result.n_data >= 3);
        assert!(result.n_fields >= 3);
    }

    #[test]
    fn test_verify_data_hash_integrity() {
        let path = tmp_path("qjournal_verify_hash.journal");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = JournalWriter::open(&path).unwrap();
            for i in 0..50 {
                let msg = format!("message number {}", i);
                w.append_entry(&[("MESSAGE", msg.as_bytes())]).unwrap();
            }
            w.flush().unwrap();
        }
        let result = journal_file_verify(&path).unwrap();
        assert_eq!(result.n_entries, 50);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_verify_entry_array_chain() {
        let path = tmp_path("qjournal_verify_ea_chain.journal");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = JournalWriter::open(&path).unwrap();
            for i in 0..100 {
                let msg = format!("entry {}", i);
                w.append_entry(&[("MESSAGE", msg.as_bytes())]).unwrap();
            }
            w.flush().unwrap();
        }
        let result = journal_file_verify(&path).unwrap();
        assert_eq!(result.n_entries, 100);
    }
}
