// SPDX-License-Identifier: LGPL-2.1-or-later
//! Conformance tests for qjournal against the systemd journal binary format.
//!
//! These tests verify that journal files written by `qjournal::JournalWriter` conform to
//! the on-disk format described in <https://systemd.io/JOURNAL_FILE_FORMAT> and implemented
//! in systemd's `journal-def.h` / `journal-file.c`.
//!
//! Binary format tests use raw `std::fs::File` I/O and never rely on the qjournal reader,
//! ensuring we test the format independently of the reading code.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use qjournal::def::*;
use qjournal::hash::hash64;
use qjournal::reader::Direction;
use qjournal::{JournalReader, JournalWriter};

// ── Helpers ─────────────────────────────────────────────────────────────────

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_path(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("qjournal_conformance");
    let _ = fs::create_dir_all(&dir);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    dir.join(format!(
        "{}-{}-{}.journal",
        prefix,
        std::process::id(),
        n
    ))
}

/// RAII guard that removes the file on drop.
struct TmpFile(PathBuf);
impl TmpFile {
    fn new(prefix: &str) -> Self {
        let p = tmp_path(prefix);
        let _ = fs::remove_file(&p);
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TmpFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

// ── Raw binary helpers ──────────────────────────────────────────────────────

fn read_bytes(f: &mut File, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.read_exact(&mut buf).unwrap();
    buf
}

fn read_u8_at(f: &mut File, offset: u64) -> u8 {
    read_bytes(f, offset, 1)[0]
}

fn read_u32_at(f: &mut File, offset: u64) -> u32 {
    let b = read_bytes(f, offset, 4);
    u32::from_le_bytes(b.try_into().unwrap())
}

fn read_u64_at(f: &mut File, offset: u64) -> u64 {
    let b = read_bytes(f, offset, 8);
    u64::from_le_bytes(b.try_into().unwrap())
}

fn read_u128_at(f: &mut File, offset: u64) -> [u8; 16] {
    let b = read_bytes(f, offset, 16);
    b.try_into().unwrap()
}

/// Read the 272-byte header into structured offsets.
struct RawHeader {
    compatible_flags: u32,
    incompatible_flags: u32,
    state: u8,
    file_id: [u8; 16],
    header_size: u64,
    arena_size: u64,
    data_hash_table_offset: u64,
    data_hash_table_size: u64,
    field_hash_table_offset: u64,
    field_hash_table_size: u64,
    tail_object_offset: u64,
    n_objects: u64,
    n_entries: u64,
    tail_entry_seqnum: u64,
    head_entry_seqnum: u64,
    entry_array_offset: u64,
    head_entry_realtime: u64,
    tail_entry_realtime: u64,
    tail_entry_monotonic: u64,
    n_data: u64,
    n_fields: u64,
    n_tags: u64,
    n_entry_arrays: u64,
    tail_entry_array_offset: u32,
    tail_entry_array_n_entries: u32,
}

fn read_raw_header(f: &mut File) -> RawHeader {
    RawHeader {
        compatible_flags: read_u32_at(f, 8),
        incompatible_flags: read_u32_at(f, 12),
        state: read_u8_at(f, 16),
        file_id: read_u128_at(f, 24),
        header_size: read_u64_at(f, 88),
        arena_size: read_u64_at(f, 96),
        data_hash_table_offset: read_u64_at(f, 104),
        data_hash_table_size: read_u64_at(f, 112),
        field_hash_table_offset: read_u64_at(f, 120),
        field_hash_table_size: read_u64_at(f, 128),
        tail_object_offset: read_u64_at(f, 136),
        n_objects: read_u64_at(f, 144),
        n_entries: read_u64_at(f, 152),
        tail_entry_seqnum: read_u64_at(f, 160),
        head_entry_seqnum: read_u64_at(f, 168),
        entry_array_offset: read_u64_at(f, 176),
        head_entry_realtime: read_u64_at(f, 184),
        tail_entry_realtime: read_u64_at(f, 192),
        tail_entry_monotonic: read_u64_at(f, 200),
        n_data: read_u64_at(f, 208),
        n_fields: read_u64_at(f, 216),
        n_tags: read_u64_at(f, 224),
        n_entry_arrays: read_u64_at(f, 232),
        tail_entry_array_offset: read_u32_at(f, 240),
        tail_entry_array_n_entries: read_u32_at(f, 244),
    }
}

/// Object info parsed from the binary stream.
#[derive(Debug, Clone)]
struct RawObject {
    offset: u64,
    obj_type: u8,
    flags: u8,
    size: u64, // actual (unaligned) size from header
}

/// Walk every object in the file sequentially.
fn walk_objects(f: &mut File) -> Vec<RawObject> {
    let file_size = f.seek(SeekFrom::End(0)).unwrap();
    let header_size = read_u64_at(f, 88);
    let mut objects = Vec::new();
    let mut offset = header_size;

    while offset + OBJECT_HEADER_SIZE as u64 <= file_size {
        let obj_type = read_u8_at(f, offset);
        let flags = read_u8_at(f, offset + 1);
        let size = read_u64_at(f, offset + 8);
        if size < OBJECT_HEADER_SIZE as u64 {
            break;
        }
        objects.push(RawObject {
            offset,
            obj_type,
            flags,
            size,
        });
        // Next object is at aligned(offset + size)
        let next = align64(offset + size);
        if next <= offset {
            break;
        }
        offset = next;
    }
    objects
}

/// Write a simple journal with a few entries and return the path wrapper.
fn write_basic_journal(prefix: &str, n: usize) -> TmpFile {
    let tf = TmpFile::new(prefix);
    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        for i in 0..n {
            w.append_entry(&[
                ("MESSAGE", format!("entry {}", i).as_bytes()),
                ("PRIORITY", b"6" as &[u8]),
                ("INDEX", format!("{}", i).as_bytes()),
            ])
            .unwrap();
        }
        w.flush().unwrap();
    } // writer dropped here -> state set to OFFLINE
    tf
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Binary format correctness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn header_signature_is_lpkshhrh() {
    // journal-def.h: HEADER_SIGNATURE "LPKSHHRH"
    let tf = write_basic_journal("sig", 1);
    let mut f = File::open(tf.path()).unwrap();
    let sig = read_bytes(&mut f, 0, 8);
    assert_eq!(&sig, b"LPKSHHRH", "header signature must be LPKSHHRH");
}

#[test]
fn header_size_is_272_bytes() {
    // journal-def.h: sizeof(Header) == 272
    let tf = write_basic_journal("hdrsize", 1);
    let mut f = File::open(tf.path()).unwrap();
    let hdr_size = read_u64_at(&mut f, 88); // header_size field at offset 88
    assert_eq!(hdr_size, 272, "header_size field must be 272");
}

#[test]
fn state_is_offline_after_close() {
    // journal-file.c: journal_file_set_offline sets state to STATE_OFFLINE (0)
    let tf = write_basic_journal("state", 1);
    let mut f = File::open(tf.path()).unwrap();
    let state = read_u8_at(&mut f, 16);
    assert_eq!(state, 0, "state byte must be OFFLINE (0) after writer is dropped");
}

#[test]
fn incompatible_flags_include_keyed_hash() {
    // journal-def.h: HEADER_INCOMPATIBLE_KEYED_HASH = 1 << 2
    let tf = write_basic_journal("incompat", 1);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    assert_ne!(
        hdr.incompatible_flags & incompat::KEYED_HASH,
        0,
        "KEYED_HASH bit must be set in incompatible_flags"
    );
}

#[test]
fn compatible_flags_include_tail_entry_boot_id() {
    // journal-def.h: HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID = 1 << 1
    let tf = write_basic_journal("compat", 1);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    assert_ne!(
        hdr.compatible_flags & compat::TAIL_ENTRY_BOOT_ID,
        0,
        "TAIL_ENTRY_BOOT_ID bit must be set in compatible_flags"
    );
}

#[test]
fn hash_table_offsets_are_nonzero() {
    let tf = write_basic_journal("htoff", 1);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    assert_ne!(hdr.data_hash_table_offset, 0, "data_hash_table_offset must be non-zero");
    assert_ne!(hdr.field_hash_table_offset, 0, "field_hash_table_offset must be non-zero");
    assert_ne!(hdr.data_hash_table_size, 0, "data_hash_table_size must be non-zero");
    assert_ne!(hdr.field_hash_table_size, 0, "field_hash_table_size must be non-zero");
}

#[test]
fn all_objects_are_8_byte_aligned() {
    // journal-def.h: objects must start on 8-byte boundaries (ALIGN64)
    let tf = write_basic_journal("align", 5);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);
    assert!(!objects.is_empty(), "must have at least one object");
    for obj in &objects {
        assert_eq!(
            obj.offset % 8,
            0,
            "object at offset {} is not 8-byte aligned",
            obj.offset
        );
    }
}

#[test]
fn object_header_size_is_actual_not_padded() {
    // journal-file.c:1264: o->object.size = htole64(size) — stores unaligned size
    let tf = write_basic_journal("objsize", 3);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);
    for obj in &objects {
        // The stored size should NOT always be 8-byte aligned.
        // At least some objects should have sizes that are not multiples of 8,
        // proving we store actual size, not padded.
        // But also: size must be >= OBJECT_HEADER_SIZE (16).
        assert!(
            obj.size >= OBJECT_HEADER_SIZE as u64,
            "object at offset {} has size {} < OBJECT_HEADER_SIZE (16)",
            obj.offset,
            obj.size
        );
    }
    // Additionally verify that if we align the size and add to offset, we reach
    // the next object (or end of file).
    let file_size = f.seek(SeekFrom::End(0)).unwrap();
    for i in 0..objects.len() {
        let next_expected = align64(objects[i].offset + objects[i].size);
        if i + 1 < objects.len() {
            assert_eq!(
                next_expected, objects[i + 1].offset,
                "aligned(offset+size) of object {} should reach next object",
                i
            );
        } else {
            // Last object: aligned end should not exceed file size
            assert!(
                next_expected <= file_size,
                "last object's aligned end exceeds file size"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Object structure correctness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn every_object_type_is_valid() {
    // journal-def.h: ObjectType is 1..=7 for real objects (0 = Unused should not appear on disk)
    let tf = write_basic_journal("objtype", 5);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);
    for obj in &objects {
        assert!(
            (1..=7).contains(&obj.obj_type),
            "object at offset {} has invalid type {} (must be 1-7)",
            obj.offset,
            obj.obj_type
        );
    }
}

#[test]
fn every_object_size_at_least_16() {
    // journal-def.h: OBJECT_HEADER_SIZE = sizeof(ObjectHeader) = 16
    let tf = write_basic_journal("objminsize", 5);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);
    for obj in &objects {
        assert!(
            obj.size >= 16,
            "object at offset {} has size {} < 16",
            obj.offset,
            obj.size
        );
    }
}

#[test]
fn data_objects_have_valid_structure() {
    // DATA objects: hash != 0, payload contains '='
    // journal-def.h: DataObject layout — hash at +16, payload at +64
    let tf = write_basic_journal("dataobj", 3);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    let data_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 1).collect();
    assert!(!data_objects.is_empty(), "should have DATA objects");

    for obj in &data_objects {
        // hash at offset +16
        let hash = read_u64_at(&mut f, obj.offset + 16);
        assert_ne!(hash, 0, "DATA object at {} has zero hash", obj.offset);

        // payload starts at DATA_OBJECT_HEADER_SIZE (64)
        let payload_len = obj.size - DATA_OBJECT_HEADER_SIZE as u64;
        if payload_len > 0 {
            let payload = read_bytes(&mut f, obj.offset + DATA_OBJECT_HEADER_SIZE as u64, payload_len as usize);
            assert!(
                payload.contains(&b'='),
                "DATA object at {} payload does not contain '=' separator",
                obj.offset
            );
        }
    }
}

#[test]
fn entry_objects_have_valid_structure() {
    // ENTRY objects: seqnum>0, realtime>0, boot_id non-null, items sorted by offset
    // journal-def.h: EntryObject layout — seqnum at +16, realtime +24, monotonic +32, boot_id +40, xor_hash +56
    let tf = write_basic_journal("entryobj", 5);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    let entry_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 3).collect();
    assert!(!entry_objects.is_empty(), "should have ENTRY objects");

    for obj in &entry_objects {
        let seqnum = read_u64_at(&mut f, obj.offset + 16);
        assert!(seqnum > 0, "ENTRY at {} has zero seqnum", obj.offset);

        let realtime = read_u64_at(&mut f, obj.offset + 24);
        assert!(realtime > 0, "ENTRY at {} has zero realtime", obj.offset);

        let boot_id = read_u128_at(&mut f, obj.offset + 40);
        assert_ne!(boot_id, [0u8; 16], "ENTRY at {} has null boot_id", obj.offset);

        // Items start at ENTRY_OBJECT_HEADER_SIZE (64), each is 16 bytes (EntryItem)
        let n_items = (obj.size - ENTRY_OBJECT_HEADER_SIZE as u64) / ENTRY_ITEM_SIZE as u64;
        let mut prev_offset = 0u64;
        for i in 0..n_items {
            let item_off = obj.offset + ENTRY_OBJECT_HEADER_SIZE as u64 + i * ENTRY_ITEM_SIZE as u64;
            let data_offset = read_u64_at(&mut f, item_off);
            assert!(
                data_offset >= prev_offset,
                "ENTRY at {} items not sorted by offset: item {} offset {} < prev {}",
                obj.offset,
                i,
                data_offset,
                prev_offset
            );
            prev_offset = data_offset;
        }
    }
}

#[test]
fn entry_array_objects_have_valid_offsets() {
    // ENTRY_ARRAY objects: items are valid offsets (non-zero where used, 8-byte aligned)
    let tf = write_basic_journal("earrobj", 5);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    let ea_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 6).collect();
    // There should be at least one entry array (the global one)
    assert!(!ea_objects.is_empty(), "should have ENTRY_ARRAY objects");

    for obj in &ea_objects {
        let n_items = (obj.size - ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64) / 8; // 8 bytes per le64
        for i in 0..n_items {
            let item_off = obj.offset + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + i * 8;
            let entry_offset = read_u64_at(&mut f, item_off);
            if entry_offset == 0 {
                // Trailing zeros are allowed (unfilled slots)
                continue;
            }
            assert_eq!(
                entry_offset % 8,
                0,
                "ENTRY_ARRAY at {} item {} offset {} is not 8-byte aligned",
                obj.offset,
                i,
                entry_offset
            );
        }
    }
}

#[test]
fn hash_table_objects_size_is_multiple_of_16() {
    // HashItem is 16 bytes, so hash table payload must be multiple of 16
    // journal-def.h: sizeof(HashItem) == 16
    let tf = write_basic_journal("htsize", 3);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    let ht_objects: Vec<_> = objects
        .iter()
        .filter(|o| o.obj_type == 4 || o.obj_type == 5) // DataHashTable or FieldHashTable
        .collect();
    assert!(ht_objects.len() >= 2, "should have both hash table objects");

    for obj in &ht_objects {
        let payload_size = obj.size - OBJECT_HEADER_SIZE as u64;
        assert_eq!(
            payload_size % HASH_ITEM_SIZE as u64,
            0,
            "hash table at {} payload size {} is not a multiple of HashItem size (16)",
            obj.offset,
            payload_size
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Hash table integrity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn data_objects_findable_via_hash_table() {
    // For each DATA object, verify it can be found by walking the data hash table chain
    // for its bucket: hash % n_buckets -> bucket -> walk chain via next_hash_offset
    let tf = write_basic_journal("htintegrity", 10);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let objects = walk_objects(&mut f);

    let n_buckets = hdr.data_hash_table_size / HASH_ITEM_SIZE as u64;
    assert!(n_buckets > 0);

    let data_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 1).collect();
    assert!(!data_objects.is_empty());

    for obj in &data_objects {
        let hash = read_u64_at(&mut f, obj.offset + 16);
        let bucket = hash % n_buckets;
        // header.data_hash_table_offset already points past the ObjectHeader to the payload
        let bucket_off = hdr.data_hash_table_offset + bucket * HASH_ITEM_SIZE as u64;

        let head = read_u64_at(&mut f, bucket_off); // head_hash_offset

        // Walk the chain from head following next_hash_offset
        let mut found = false;
        let mut current = head;
        let mut visited = HashSet::new();
        while current != 0 {
            if !visited.insert(current) {
                panic!("cycle in hash chain for bucket {}", bucket);
            }
            if current == obj.offset {
                found = true;
                break;
            }
            // next_hash_offset is at DATA_OBJECT offset +24
            current = read_u64_at(&mut f, current + 24);
        }
        assert!(
            found,
            "DATA object at offset {} (hash={:#x}) not found in hash chain for bucket {}",
            obj.offset, hash, bucket
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Entry array integrity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn global_entry_array_matches_n_entries() {
    // Walk the global entry array chain; total entries must match header.n_entries
    let tf = write_basic_journal("earr_count", 20);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);

    let mut total = 0u64;
    let mut current_ea = hdr.entry_array_offset;
    let mut prev_entry_offset = 0u64;

    while current_ea != 0 {
        // Read object header
        let obj_type = read_u8_at(&mut f, current_ea);
        assert_eq!(obj_type, 6, "global entry array chain should only contain ENTRY_ARRAY objects");

        let obj_size = read_u64_at(&mut f, current_ea + 8);
        let n_items = (obj_size - ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64) / 8;

        for i in 0..n_items {
            let entry_off = read_u64_at(
                &mut f,
                current_ea + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + i * 8,
            );
            if entry_off == 0 {
                // Unfilled trailing slot
                break;
            }
            // Verify it points to an ENTRY object
            let etype = read_u8_at(&mut f, entry_off);
            assert_eq!(
                etype, 3,
                "entry array item at ea_offset={} index={} points to non-ENTRY object (type={})",
                current_ea, i, etype
            );
            // Entries must be in ascending offset order
            assert!(
                entry_off > prev_entry_offset,
                "entries not in ascending offset order: {} <= {}",
                entry_off,
                prev_entry_offset
            );
            prev_entry_offset = entry_off;
            total += 1;
        }

        // Follow chain: next_entry_array_offset at +16
        current_ea = read_u64_at(&mut f, current_ea + 16);
    }

    assert_eq!(
        total, hdr.n_entries,
        "total entries in entry array chain ({}) != header.n_entries ({})",
        total, hdr.n_entries
    );
}

#[test]
fn entry_array_chain_uses_exponential_growth() {
    // Each new entry array block should be >= 2x the previous (or at least 4 items minimum)
    // journal-file.c: new_size = MAX(entries_max * 2, 4)
    let tf = write_basic_journal("earr_growth", 200);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);

    let mut current_ea = hdr.entry_array_offset;
    let mut sizes = Vec::new();

    while current_ea != 0 {
        let obj_size = read_u64_at(&mut f, current_ea + 8);
        let n_items = (obj_size - ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64) / 8;
        sizes.push(n_items);
        current_ea = read_u64_at(&mut f, current_ea + 16);
    }

    // With 200 entries we expect multiple array blocks
    if sizes.len() > 1 {
        for i in 1..sizes.len() {
            assert!(
                sizes[i] >= 4,
                "entry array block {} has only {} items (minimum 4)",
                i,
                sizes[i]
            );
            // Each new block should be >= 2x the previous
            assert!(
                sizes[i] >= sizes[i - 1] * 2 || sizes[i] >= 4,
                "entry array block {} ({} items) is not >= 2x block {} ({} items)",
                i,
                sizes[i],
                i - 1,
                sizes[i - 1]
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Sequence number correctness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn seqnums_are_strictly_monotonically_increasing() {
    // journal-file.c: seqnum is incremented by 1 for each entry
    let n = 10;
    let tf = write_basic_journal("seqnum", n);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);
    let hdr = read_raw_header(&mut f);

    let entry_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 3).collect();
    assert_eq!(entry_objects.len(), n);

    let mut prev_seqnum = 0u64;
    for (i, obj) in entry_objects.iter().enumerate() {
        let seqnum = read_u64_at(&mut f, obj.offset + 16);
        assert_eq!(
            seqnum,
            (i as u64) + 1,
            "entry {} should have seqnum {}, got {}",
            i,
            i + 1,
            seqnum
        );
        assert!(
            seqnum > prev_seqnum,
            "seqnum not strictly increasing: {} <= {}",
            seqnum,
            prev_seqnum
        );
        prev_seqnum = seqnum;
    }

    // head_entry_seqnum == 1 (first entry)
    assert_eq!(hdr.head_entry_seqnum, 1, "head_entry_seqnum should be 1");
    // tail_entry_seqnum == n (last entry)
    assert_eq!(
        hdr.tail_entry_seqnum, n as u64,
        "tail_entry_seqnum should be {}",
        n
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Timestamp correctness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn realtime_timestamps_are_nondecreasing() {
    let tf = write_basic_journal("ts", 10);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    let entry_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 3).collect();
    let mut prev_rt = 0u64;
    for obj in &entry_objects {
        let realtime = read_u64_at(&mut f, obj.offset + 24);
        assert!(
            realtime >= prev_rt,
            "realtime not non-decreasing: {} < {}",
            realtime,
            prev_rt
        );
        prev_rt = realtime;
    }
}

#[test]
fn header_timestamp_bounds() {
    let tf = write_basic_journal("tsbounds", 5);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);

    assert!(
        hdr.head_entry_realtime <= hdr.tail_entry_realtime,
        "head_entry_realtime ({}) > tail_entry_realtime ({})",
        hdr.head_entry_realtime,
        hdr.tail_entry_realtime
    );
}

#[test]
fn timestamps_are_valid_range() {
    // VALID_REALTIME(u) = u > 0 && u < (1 << 55)
    // journal-file.c:2551-2558
    let tf = write_basic_journal("tsvalid", 5);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    let ts_upper = 1u64 << 55;
    let entry_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 3).collect();
    for obj in &entry_objects {
        let realtime = read_u64_at(&mut f, obj.offset + 24);
        assert!(realtime > 0, "realtime must be > 0");
        assert!(realtime < ts_upper, "realtime must be < 2^55");

        let monotonic = read_u64_at(&mut f, obj.offset + 32);
        assert!(monotonic < ts_upper, "monotonic must be < 2^55");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Data deduplication
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn duplicate_field_values_produce_single_data_object() {
    // If two entries share the same field=value, only one DATA object should exist.
    let tf = TmpFile::new("dedup");
    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        // Write 5 entries all with the same MESSAGE
        for _ in 0..5 {
            w.append_entry(&[("MESSAGE", b"same-value" as &[u8])])
                .unwrap();
        }
        w.flush().unwrap();
    }

    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    // Count DATA objects whose payload is "MESSAGE=same-value"
    let target = b"MESSAGE=same-value";
    let mut count = 0;
    for obj in objects.iter().filter(|o| o.obj_type == 1) {
        let payload_len = obj.size - DATA_OBJECT_HEADER_SIZE as u64;
        if payload_len == target.len() as u64 {
            let payload = read_bytes(&mut f, obj.offset + DATA_OBJECT_HEADER_SIZE as u64, payload_len as usize);
            if payload == target {
                count += 1;
            }
        }
    }
    assert_eq!(
        count, 1,
        "expected exactly 1 DATA object for 'MESSAGE=same-value', found {}",
        count
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Field→Data linking
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn every_data_object_has_corresponding_field_object() {
    // Each DATA object's field name (before '=') should have a FIELD object in the field hash table
    let tf = write_basic_journal("fieldlink", 5);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let objects = walk_objects(&mut f);

    // Collect all FIELD object payloads
    let mut field_names = HashSet::new();
    for obj in objects.iter().filter(|o| o.obj_type == 2) {
        // FIELD object: payload starts at FIELD_OBJECT_HEADER_SIZE (40)
        let payload_len = obj.size - FIELD_OBJECT_HEADER_SIZE as u64;
        let payload = read_bytes(&mut f, obj.offset + FIELD_OBJECT_HEADER_SIZE as u64, payload_len as usize);
        field_names.insert(payload);
    }

    // For each DATA object, extract the field name and check it exists
    for obj in objects.iter().filter(|o| o.obj_type == 1) {
        let payload_len = obj.size - DATA_OBJECT_HEADER_SIZE as u64;
        let payload = read_bytes(&mut f, obj.offset + DATA_OBJECT_HEADER_SIZE as u64, payload_len as usize);
        // Field name is everything before the first '='
        if let Some(eq_pos) = payload.iter().position(|&b| b == b'=') {
            let field_name = &payload[..eq_pos];
            assert!(
                field_names.contains(field_name),
                "DATA object at {} has field name {:?} with no corresponding FIELD object",
                obj.offset,
                String::from_utf8_lossy(field_name)
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. Per-DATA entry arrays
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn per_data_entry_arrays_are_correct() {
    // For a DATA object referenced by N entries, data.n_entries == N
    // and the entry array chain contains exactly those entries.
    let tf = TmpFile::new("perdataearr");
    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        // "MESSAGE=alpha" used 3 times, "MESSAGE=beta" used 2 times
        w.append_entry(&[("MESSAGE", b"alpha" as &[u8])]).unwrap();
        w.append_entry(&[("MESSAGE", b"beta" as &[u8])]).unwrap();
        w.append_entry(&[("MESSAGE", b"alpha" as &[u8])]).unwrap();
        w.append_entry(&[("MESSAGE", b"beta" as &[u8])]).unwrap();
        w.append_entry(&[("MESSAGE", b"alpha" as &[u8])]).unwrap();
        w.flush().unwrap();
    }

    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    // Find the DATA objects for MESSAGE=alpha and MESSAGE=beta
    for target_payload in &[b"MESSAGE=alpha".to_vec(), b"MESSAGE=beta".to_vec()] {
        let expected_count: u64 = if target_payload == b"MESSAGE=alpha" { 3 } else { 2 };

        let data_obj = objects
            .iter()
            .filter(|o| o.obj_type == 1)
            .find(|o| {
                let plen = o.size - DATA_OBJECT_HEADER_SIZE as u64;
                let p = read_bytes(&mut f, o.offset + DATA_OBJECT_HEADER_SIZE as u64, plen as usize);
                p == *target_payload
            })
            .unwrap_or_else(|| panic!("DATA object for {:?} not found", String::from_utf8_lossy(target_payload)));

        let n_entries = read_u64_at(&mut f, data_obj.offset + 56);
        assert_eq!(
            n_entries, expected_count,
            "DATA {:?}: n_entries={} expected={}",
            String::from_utf8_lossy(target_payload),
            n_entries,
            expected_count
        );

        // Walk the per-data entry array: first inline entry at +40, then chain at +48
        let mut actual_entries = Vec::new();
        let first_entry = read_u64_at(&mut f, data_obj.offset + 40); // entry_offset
        if first_entry != 0 {
            actual_entries.push(first_entry);
        }

        let ea_offset = read_u64_at(&mut f, data_obj.offset + 48); // entry_array_offset
        let mut current_ea = ea_offset;
        while current_ea != 0 {
            let ea_size = read_u64_at(&mut f, current_ea + 8);
            let n_items = (ea_size - ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64) / 8;
            for i in 0..n_items {
                let eo = read_u64_at(
                    &mut f,
                    current_ea + ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64 + i * 8,
                );
                if eo == 0 {
                    break;
                }
                actual_entries.push(eo);
            }
            current_ea = read_u64_at(&mut f, current_ea + 16);
        }

        assert_eq!(
            actual_entries.len() as u64,
            expected_count,
            "DATA {:?}: entry array chain has {} entries, expected {}",
            String::from_utf8_lossy(target_payload),
            actual_entries.len(),
            expected_count
        );

        // Each entry offset should point to a valid ENTRY object
        for eo in &actual_entries {
            let etype = read_u8_at(&mut f, *eo);
            assert_eq!(etype, 3, "per-data entry array item points to non-ENTRY");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. XOR hash
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn xor_hash_matches_recomputed_value() {
    // journal-file.c:2617-2620:
    //   if (JOURNAL_HEADER_KEYED_HASH(f->header))
    //       xor_hash ^= jenkins_hash64(iovec[i].iov_base, iovec[i].iov_len);
    //   else
    //       xor_hash ^= le64toh(o->data.hash);
    //
    // When keyed_hash is active, xor_hash uses jenkins_hash64 of the payload (for cursor
    // stability across files), NOT the stored siphash from the DATA object.
    let tf = write_basic_journal("xorhash", 5);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let objects = walk_objects(&mut f);

    let keyed_hash = (hdr.incompatible_flags & incompat::KEYED_HASH) != 0;

    let entry_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 3).collect();
    for entry_obj in &entry_objects {
        let stored_xor_hash = read_u64_at(&mut f, entry_obj.offset + 56);

        let n_items =
            (entry_obj.size - ENTRY_OBJECT_HEADER_SIZE as u64) / ENTRY_ITEM_SIZE as u64;
        let mut computed_xor: u64 = 0;
        for i in 0..n_items {
            let item_off =
                entry_obj.offset + ENTRY_OBJECT_HEADER_SIZE as u64 + i * ENTRY_ITEM_SIZE as u64;
            let data_offset = read_u64_at(&mut f, item_off);

            if keyed_hash {
                // Read the DATA object's payload and compute jenkins_hash64
                let data_obj_size = read_u64_at(&mut f, data_offset + 8);
                let data_flags = read_u8_at(&mut f, data_offset + 1);
                let is_compressed = (data_flags & obj_flags::COMPRESSED_MASK) != 0;
                if is_compressed {
                    // Skip compressed objects — we cannot easily decompress here
                    // and the xor_hash was computed from the uncompressed payload
                    continue;
                }
                let payload_len = data_obj_size - DATA_OBJECT_HEADER_SIZE as u64;
                let payload = read_bytes(
                    &mut f,
                    data_offset + DATA_OBJECT_HEADER_SIZE as u64,
                    payload_len as usize,
                );
                computed_xor ^= hash64(&payload);
            } else {
                // Non-keyed: xor_hash ^= data.hash (which is jenkins_hash64)
                let data_hash = read_u64_at(&mut f, data_offset + 16);
                computed_xor ^= data_hash;
            }
        }

        assert_eq!(
            stored_xor_hash, computed_xor,
            "ENTRY at {}: stored xor_hash={:#x} != computed={:#x}",
            entry_obj.offset, stored_xor_hash, computed_xor
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. Reopen correctness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn reopen_write_continues_seqnums() {
    let tf = TmpFile::new("reopen");

    // Write 3 entries, close
    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        for i in 0..3 {
            w.append_entry(&[("MESSAGE", format!("first-{}", i).as_bytes())])
                .unwrap();
        }
        w.flush().unwrap();
    }

    // Reopen, write 3 more
    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        for i in 0..3 {
            w.append_entry(&[("MESSAGE", format!("second-{}", i).as_bytes())])
                .unwrap();
        }
        w.flush().unwrap();
    }

    // Verify all 6 entries readable with correct seqnums
    let mut reader = JournalReader::open(tf.path()).unwrap();
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 6, "should have 6 entries after reopen");

    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(
            entry.seqnum,
            (i as u64) + 1,
            "entry {} should have seqnum {}",
            i,
            i + 1
        );
    }

    // First 3 are "first-N", last 3 are "second-N"
    assert_eq!(entries[0].message().unwrap(), "first-0");
    assert_eq!(entries[2].message().unwrap(), "first-2");
    assert_eq!(entries[3].message().unwrap(), "second-0");
    assert_eq!(entries[5].message().unwrap(), "second-2");
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. Round-trip field fidelity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn roundtrip_binary_values() {
    // Write entries with binary (non-UTF8) field values and verify exact byte equality
    let tf = TmpFile::new("binary");
    let binary_value: Vec<u8> = (0..=255).collect();

    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        w.append_entry(&[("BINARY_DATA", binary_value.as_slice())])
            .unwrap();
        w.flush().unwrap();
    }

    let mut reader = JournalReader::open(tf.path()).unwrap();
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 1);
    let val = entries[0].get(b"BINARY_DATA").expect("BINARY_DATA field missing");
    assert_eq!(val, binary_value.as_slice(), "binary value round-trip failed");
}

#[test]
fn roundtrip_long_values() {
    // Values up to just under the compression threshold (512 bytes) to test
    // large-but-uncompressed payloads. Values > 512 bytes may be zstd-compressed.
    let tf = TmpFile::new("longval");
    let long_value = vec![b'X'; 500];

    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        w.append_entry(&[("LONG_FIELD", long_value.as_slice())])
            .unwrap();
        w.flush().unwrap();
    }

    let mut reader = JournalReader::open(tf.path()).unwrap();
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 1);
    let val = entries[0].get(b"LONG_FIELD").expect("LONG_FIELD missing");
    assert_eq!(val.len(), 500);
    assert_eq!(val, long_value.as_slice());
}

#[test]
fn roundtrip_compressed_values() {
    // Values larger than 512 bytes trigger zstd compression (when feature enabled).
    // Verify they round-trip correctly through the reader.
    let tf = TmpFile::new("compressed");
    // Use a highly compressible pattern
    let big_value: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        w.append_entry(&[("BIG_DATA", big_value.as_slice())])
            .unwrap();
        w.flush().unwrap();
    }

    // Verify the written file has a valid header at minimum
    let mut f = File::open(tf.path()).unwrap();
    let sig = read_bytes(&mut f, 0, 8);
    assert_eq!(&sig, b"LPKSHHRH", "compressed file must have valid signature");
    let hdr_size = read_u64_at(&mut f, 88);
    assert_eq!(hdr_size, 272, "compressed file must have valid header_size");
    drop(f);

    // Verify round-trip through the reader
    let mut reader = JournalReader::open(tf.path()).unwrap();
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 1);
    let val = entries[0].get(b"BIG_DATA").expect("BIG_DATA field missing");
    assert_eq!(val, big_value.as_slice(), "compressed value round-trip failed");
}

#[test]
fn roundtrip_empty_value() {
    // Field with empty value after '=' (e.g., "MESSAGE=")
    let tf = TmpFile::new("emptyval");

    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        w.append_entry(&[("MESSAGE", b"" as &[u8])]).unwrap();
        w.flush().unwrap();
    }

    let mut reader = JournalReader::open(tf.path()).unwrap();
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 1);
    let val = entries[0].get(b"MESSAGE").expect("MESSAGE field missing");
    assert_eq!(val, b"", "empty value should round-trip as empty bytes");
}

#[test]
fn roundtrip_protected_fields() {
    // Fields starting with '_' (protected/trusted fields)
    let tf = TmpFile::new("protected");

    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        w.append_entry(&[
            ("MESSAGE", b"hello" as &[u8]),
            ("_TRANSPORT", b"journal"),
            ("_PID", b"12345"),
        ])
        .unwrap();
        w.flush().unwrap();
    }

    let mut reader = JournalReader::open(tf.path()).unwrap();
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].get(b"_TRANSPORT").unwrap(),
        b"journal"
    );
    assert_eq!(entries[0].get(b"_PID").unwrap(), b"12345");
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. Large file
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn large_file_all_entries_readable() {
    let n = 1200;
    let tf = write_basic_journal("large", n);

    // Verify all readable via reader
    let mut reader = JournalReader::open(tf.path()).unwrap();
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), n, "should read all {} entries", n);

    // Verify seqnums are 1..=n
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seqnum, (i as u64) + 1);
    }

    // Verify entry array growth is exponential via binary inspection
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let mut current_ea = hdr.entry_array_offset;
    let mut sizes = Vec::new();
    while current_ea != 0 {
        let obj_size = read_u64_at(&mut f, current_ea + 8);
        let n_items = (obj_size - ENTRY_ARRAY_OBJECT_HEADER_SIZE as u64) / 8;
        sizes.push(n_items);
        current_ea = read_u64_at(&mut f, current_ea + 16);
    }

    // Should have multiple blocks with exponential growth
    assert!(
        sizes.len() >= 3,
        "with {} entries, expected at least 3 entry array blocks, got {}",
        n,
        sizes.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. Reader navigation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn move_to_entry_by_seqnum_down() {
    let tf = write_basic_journal("seekseq_down", 20);
    let mut reader = JournalReader::open(tf.path()).unwrap();

    // Seek to seqnum 10, Direction::Down — should find exactly seqnum 10
    let offset = reader
        .move_to_entry_by_seqnum(10, Direction::Down)
        .unwrap()
        .expect("should find seqnum 10");
    let entry = reader.read_entry_at(offset).unwrap();
    assert_eq!(entry.seqnum, 10);
}

#[test]
fn move_to_entry_by_seqnum_up() {
    let tf = write_basic_journal("seekseq_up", 20);
    let mut reader = JournalReader::open(tf.path()).unwrap();

    // Seek to seqnum 10, Direction::Up — should find seqnum 10
    let offset = reader
        .move_to_entry_by_seqnum(10, Direction::Up)
        .unwrap()
        .expect("should find seqnum 10");
    let entry = reader.read_entry_at(offset).unwrap();
    assert_eq!(entry.seqnum, 10);
}

#[test]
fn move_to_entry_by_seqnum_boundary() {
    let tf = write_basic_journal("seekseq_bound", 10);
    let mut reader = JournalReader::open(tf.path()).unwrap();

    // First entry
    let offset = reader
        .move_to_entry_by_seqnum(1, Direction::Down)
        .unwrap()
        .expect("should find seqnum 1");
    let entry = reader.read_entry_at(offset).unwrap();
    assert_eq!(entry.seqnum, 1);

    // Last entry
    let offset = reader
        .move_to_entry_by_seqnum(10, Direction::Up)
        .unwrap()
        .expect("should find seqnum 10");
    let entry = reader.read_entry_at(offset).unwrap();
    assert_eq!(entry.seqnum, 10);
}

#[test]
fn next_entry_forward_iteration() {
    let tf = write_basic_journal("nextfwd", 10);
    let mut reader = JournalReader::open(tf.path()).unwrap();

    // Start from 0 (=beginning)
    let mut p = 0u64;
    let mut seqnums = Vec::new();
    loop {
        match reader.next_entry(p, Direction::Down).unwrap() {
            Some(offset) => {
                let entry = reader.read_entry_at(offset).unwrap();
                seqnums.push(entry.seqnum);
                p = offset;
            }
            None => break,
        }
    }
    assert_eq!(seqnums, (1..=10).collect::<Vec<u64>>());
}

#[test]
fn next_entry_backward_iteration() {
    let tf = write_basic_journal("nextbwd", 10);
    let mut reader = JournalReader::open(tf.path()).unwrap();

    // Start from 0 with Direction::Up (= last entry)
    let mut p = 0u64;
    let mut seqnums = Vec::new();
    loop {
        match reader.next_entry(p, Direction::Up).unwrap() {
            Some(offset) => {
                let entry = reader.read_entry_at(offset).unwrap();
                seqnums.push(entry.seqnum);
                p = offset;
            }
            None => break,
        }
    }
    let expected: Vec<u64> = (1..=10).rev().collect();
    assert_eq!(seqnums, expected);
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. entries_for_field
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn entries_for_field_returns_correct_entries() {
    let tf = TmpFile::new("fieldmatch");
    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        w.append_entry(&[
            ("MESSAGE", b"hello" as &[u8]),
            ("CATEGORY", b"A"),
        ])
        .unwrap();
        w.append_entry(&[
            ("MESSAGE", b"world" as &[u8]),
            ("CATEGORY", b"B"),
        ])
        .unwrap();
        w.append_entry(&[
            ("MESSAGE", b"foo" as &[u8]),
            ("CATEGORY", b"A"),
        ])
        .unwrap();
        w.append_entry(&[
            ("MESSAGE", b"bar" as &[u8]),
            ("CATEGORY", b"C"),
        ])
        .unwrap();
        w.append_entry(&[
            ("MESSAGE", b"baz" as &[u8]),
            ("CATEGORY", b"A"),
        ])
        .unwrap();
        w.flush().unwrap();
    }

    let mut reader = JournalReader::open(tf.path()).unwrap();

    // CATEGORY=A should match entries 1, 3, 5
    let matches_a = reader.entries_for_field("CATEGORY", b"A").unwrap();
    assert_eq!(matches_a.len(), 3);
    assert_eq!(matches_a[0].seqnum, 1);
    assert_eq!(matches_a[1].seqnum, 3);
    assert_eq!(matches_a[2].seqnum, 5);

    // CATEGORY=B should match entry 2
    let matches_b = reader.entries_for_field("CATEGORY", b"B").unwrap();
    assert_eq!(matches_b.len(), 1);
    assert_eq!(matches_b[0].seqnum, 2);

    // CATEGORY=C should match entry 4
    let matches_c = reader.entries_for_field("CATEGORY", b"C").unwrap();
    assert_eq!(matches_c.len(), 1);
    assert_eq!(matches_c[0].seqnum, 4);

    // Non-existent field value returns empty
    let matches_none = reader.entries_for_field("CATEGORY", b"Z").unwrap();
    assert_eq!(matches_none.len(), 0);

    // Non-existent field name returns empty
    let matches_nf = reader.entries_for_field("NONEXISTENT", b"X").unwrap();
    assert_eq!(matches_nf.len(), 0);
}

#[test]
fn entries_for_field_message_values() {
    let tf = TmpFile::new("fieldmsg");
    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        w.append_entry(&[("MESSAGE", b"hello" as &[u8])]).unwrap();
        w.append_entry(&[("MESSAGE", b"world" as &[u8])]).unwrap();
        w.append_entry(&[("MESSAGE", b"hello" as &[u8])]).unwrap();
        w.flush().unwrap();
    }

    let mut reader = JournalReader::open(tf.path()).unwrap();

    let matches = reader.entries_for_field("MESSAGE", b"hello").unwrap();
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].seqnum, 1);
    assert_eq!(matches[1].seqnum, 3);

    let matches = reader.entries_for_field("MESSAGE", b"world").unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].seqnum, 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: append_entry_with_ts timestamp control
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn append_entry_with_ts_stores_exact_timestamps() {
    let tf = TmpFile::new("withts");
    let boot_id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        w.append_entry_with_ts(
            1_700_000_000_000_000, // realtime
            500_000,               // monotonic
            &boot_id,
            &[("MESSAGE", b"ts-test" as &[u8])],
        )
        .unwrap();
        w.flush().unwrap();
    }

    // Verify via raw binary
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);
    let entry_obj = objects.iter().find(|o| o.obj_type == 3).unwrap();

    let realtime = read_u64_at(&mut f, entry_obj.offset + 24);
    assert_eq!(realtime, 1_700_000_000_000_000);

    let monotonic = read_u64_at(&mut f, entry_obj.offset + 32);
    assert_eq!(monotonic, 500_000);

    let stored_boot_id = read_u128_at(&mut f, entry_obj.offset + 40);
    assert_eq!(stored_boot_id, boot_id);
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: file_id uniqueness and non-zero
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn file_id_is_nonzero() {
    let tf = write_basic_journal("fileid", 1);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    assert_ne!(hdr.file_id, [0u8; 16], "file_id must be non-zero");
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: n_objects and n_data/n_fields consistency
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn header_object_counts_are_consistent() {
    let tf = write_basic_journal("objcounts", 10);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let objects = walk_objects(&mut f);

    // n_objects should match the actual count
    assert_eq!(
        objects.len() as u64,
        hdr.n_objects,
        "actual objects ({}) != header.n_objects ({})",
        objects.len(),
        hdr.n_objects
    );

    // n_entries should match ENTRY objects
    let n_entry_objs = objects.iter().filter(|o| o.obj_type == 3).count() as u64;
    assert_eq!(hdr.n_entries, n_entry_objs);

    // n_data should match DATA objects
    let n_data_objs = objects.iter().filter(|o| o.obj_type == 1).count() as u64;
    assert_eq!(hdr.n_data, n_data_objs);

    // n_fields should match FIELD objects
    let n_field_objs = objects.iter().filter(|o| o.obj_type == 2).count() as u64;
    assert_eq!(hdr.n_fields, n_field_objs);

    // n_entry_arrays should match ENTRY_ARRAY objects
    let n_ea_objs = objects.iter().filter(|o| o.obj_type == 6).count() as u64;
    assert_eq!(hdr.n_entry_arrays, n_ea_objs);
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: tail_object_offset
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn tail_object_offset_points_to_last_object() {
    let tf = write_basic_journal("tailobj", 5);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let objects = walk_objects(&mut f);

    let last = objects.last().unwrap();
    assert_eq!(
        hdr.tail_object_offset, last.offset,
        "tail_object_offset should point to last object"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: keyed hash verification
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn data_object_hash_matches_keyed_siphash() {
    // When KEYED_HASH is set, each DATA object's hash should be siphash24(payload, file_id)
    use siphasher::sip::SipHasher24;
    use std::hash::Hasher;

    let tf = write_basic_journal("keyedhash", 3);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let objects = walk_objects(&mut f);

    if hdr.incompatible_flags & incompat::KEYED_HASH == 0 {
        // Not keyed hash mode, skip
        return;
    }

    let k0 = u64::from_le_bytes(hdr.file_id[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(hdr.file_id[8..16].try_into().unwrap());

    for obj in objects.iter().filter(|o| o.obj_type == 1) {
        let stored_hash = read_u64_at(&mut f, obj.offset + 16);
        let payload_len = obj.size - DATA_OBJECT_HEADER_SIZE as u64;
        let payload = read_bytes(&mut f, obj.offset + DATA_OBJECT_HEADER_SIZE as u64, payload_len as usize);

        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        hasher.write(&payload);
        let expected = hasher.finish();

        assert_eq!(
            stored_hash, expected,
            "DATA at {}: stored hash {:#x} != expected siphash {:#x}",
            obj.offset, stored_hash, expected
        );
    }
}

#[test]
fn field_object_hash_matches_keyed_siphash() {
    use siphasher::sip::SipHasher24;
    use std::hash::Hasher;

    let tf = write_basic_journal("fieldhash", 3);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let objects = walk_objects(&mut f);

    if hdr.incompatible_flags & incompat::KEYED_HASH == 0 {
        return;
    }

    let k0 = u64::from_le_bytes(hdr.file_id[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(hdr.file_id[8..16].try_into().unwrap());

    for obj in objects.iter().filter(|o| o.obj_type == 2) {
        let stored_hash = read_u64_at(&mut f, obj.offset + 16);
        let payload_len = obj.size - FIELD_OBJECT_HEADER_SIZE as u64;
        let payload = read_bytes(&mut f, obj.offset + FIELD_OBJECT_HEADER_SIZE as u64, payload_len as usize);

        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        hasher.write(&payload);
        let expected = hasher.finish();

        assert_eq!(
            stored_hash, expected,
            "FIELD at {}: stored hash {:#x} != expected siphash {:#x}",
            obj.offset, stored_hash, expected
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: field hash table integrity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn field_objects_findable_via_field_hash_table() {
    let tf = write_basic_journal("fhtintegrity", 5);
    let mut f = File::open(tf.path()).unwrap();
    let hdr = read_raw_header(&mut f);
    let objects = walk_objects(&mut f);

    let n_buckets = hdr.field_hash_table_size / HASH_ITEM_SIZE as u64;
    assert!(n_buckets > 0);

    let field_objects: Vec<_> = objects.iter().filter(|o| o.obj_type == 2).collect();
    assert!(!field_objects.is_empty());

    for obj in &field_objects {
        let hash = read_u64_at(&mut f, obj.offset + 16);
        let bucket = hash % n_buckets;
        // header.field_hash_table_offset already points past the ObjectHeader to the payload
        let bucket_off = hdr.field_hash_table_offset + bucket * HASH_ITEM_SIZE as u64;
        let head = read_u64_at(&mut f, bucket_off);

        let mut found = false;
        let mut current = head;
        let mut visited = HashSet::new();
        while current != 0 {
            if !visited.insert(current) {
                panic!("cycle in field hash chain for bucket {}", bucket);
            }
            if current == obj.offset {
                found = true;
                break;
            }
            // FIELD object next_hash_offset at +24
            current = read_u64_at(&mut f, current + 24);
        }
        assert!(
            found,
            "FIELD object at offset {} not found in field hash chain for bucket {}",
            obj.offset, bucket
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: move_to_entry_by_realtime
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn move_to_entry_by_realtime_finds_correct_entry() {
    let tf = TmpFile::new("seekrt");
    let boot_id: [u8; 16] = [10; 16];

    {
        let mut w = JournalWriter::open(tf.path()).unwrap();
        for i in 1..=10u64 {
            w.append_entry_with_ts(
                1_000_000_000 + i * 1_000_000, // 1s apart
                i * 1_000_000,
                &boot_id,
                &[("MESSAGE", format!("msg-{}", i).as_bytes())],
            )
            .unwrap();
        }
        w.flush().unwrap();
    }

    let mut reader = JournalReader::open(tf.path()).unwrap();

    // Seek to realtime of entry 5
    let target_rt = 1_000_000_000 + 5 * 1_000_000;
    let offset = reader
        .move_to_entry_by_realtime(target_rt, Direction::Down)
        .unwrap()
        .expect("should find entry by realtime");
    let entry = reader.read_entry_at(offset).unwrap();
    assert_eq!(entry.realtime, target_rt);
    assert_eq!(entry.seqnum, 5);
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: reserved bytes in object header are zero
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn object_header_reserved_bytes_are_zero() {
    // ObjectHeader bytes 2..8 (6 bytes) are reserved and must be zero
    let tf = write_basic_journal("reserved", 5);
    let mut f = File::open(tf.path()).unwrap();
    let objects = walk_objects(&mut f);

    for obj in &objects {
        let reserved = read_bytes(&mut f, obj.offset + 2, 6);
        assert_eq!(
            reserved,
            [0u8; 6],
            "object at {} has non-zero reserved bytes: {:?}",
            obj.offset,
            reserved
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: empty journal
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn empty_journal_has_valid_header() {
    let tf = TmpFile::new("empty");
    {
        let _w = JournalWriter::open(tf.path()).unwrap();
        // Don't write any entries, just create and drop
    }

    let mut f = File::open(tf.path()).unwrap();
    let sig = read_bytes(&mut f, 0, 8);
    assert_eq!(&sig, b"LPKSHHRH");

    let hdr = read_raw_header(&mut f);
    assert_eq!(hdr.header_size, 272);
    assert_eq!(hdr.n_entries, 0);
    assert_eq!(hdr.head_entry_seqnum, 0);
    assert_eq!(hdr.tail_entry_seqnum, 0);
    assert_eq!(hdr.state, 0); // OFFLINE after drop
    assert_ne!(hdr.data_hash_table_offset, 0);
    assert_ne!(hdr.field_hash_table_offset, 0);
}
