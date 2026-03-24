// SPDX-License-Identifier: LGPL-2.1-or-later
//! Forward Secure Sealing (FSS) journal integration.
//!
//! This module implements HMAC-based sealing for journal files, matching
//! systemd's `journal-authenticate.c`. It uses FSPRG (Forward-Secure
//! Pseudorandom Generator) keys to produce per-epoch HMAC-SHA256 tags
//! that allow tamper detection without the ability to forge past entries.

use std::fs;
use std::io;
use std::mem;
use std::path::Path;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::def::{
    Header, ObjectType, OBJECT_HEADER_SIZE,
    ENTRY_OBJECT_HEADER_SIZE, FIELD_OBJECT_HEADER_SIZE,
};
use crate::fsprg;
use crate::writer::data_payload_offset;

type HmacSha256 = Hmac<Sha256>;

// ── FSS header on-disk format ────────────────────────────────────────────

/// Signature bytes at offset 0 of every `.fss` file: `"KSHHRHLP"`.
pub const FSS_HEADER_SIGNATURE: [u8; 8] = *b"KSHHRHLP";

/// Length of an HMAC-SHA256 tag in bytes (256 / 8).
pub const TAG_LENGTH: usize = 32;

/// FSPRG recommended security parameter (matches systemd's default).
pub const FSPRG_RECOMMENDED_SECPAR: u16 = 1536;

/// FSPRG recommended seed length in bytes (96 / 8 = 12).
pub const FSPRG_RECOMMENDED_SEEDLEN: usize = 96 / 8;

/// On-disk FSS header, stored at the beginning of the `.fss` key file.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FssHeader {
    pub signature: [u8; 8],          // "KSHHRHLP"
    pub compatible_flags: [u8; 4],   // le32
    pub incompatible_flags: [u8; 4], // le32
    pub machine_id: [u8; 16],       // sd_id128
    pub boot_id: [u8; 16],          // sd_id128 – last writer
    pub header_size: [u8; 8],       // le64
    pub start_usec: [u8; 8],        // le64
    pub interval_usec: [u8; 8],     // le64
    pub fsprg_secpar: [u8; 2],      // le16
    pub reserved: [u8; 6],          // le16[3]
    pub fsprg_state_size: [u8; 8],  // le64
}

const _: () = assert!(mem::size_of::<FssHeader>() == 88);

// ── HMAC state ───────────────────────────────────────────────────────────

/// Running HMAC-SHA256 state used for journal sealing.
pub struct JournalHmac {
    hmac: Option<HmacSha256>,
    running: bool,
}

/// State loaded from a `.fss` key file.
pub struct FssState {
    pub header: FssHeader,
    pub fsprg_state: Vec<u8>,
    pub start_usec: u64,
    pub interval_usec: u64,
}

// ── HMAC lifecycle ───────────────────────────────────────────────────────

/// Create an empty (uninitialised) HMAC handle.
///
/// Matches `journal_file_hmac_setup()` — the HMAC is allocated but no key
/// is set yet.
pub fn journal_file_hmac_setup() -> JournalHmac {
    JournalHmac {
        hmac: None,
        running: false,
    }
}

/// Derive the HMAC key from the current FSPRG state and start a new
/// HMAC cycle.
///
/// Matches `journal_file_hmac_start()`.
pub fn journal_file_hmac_start(state: &mut JournalHmac, fsprg_state: &[u8]) {
    let key = fsprg::get_key(fsprg_state, 32, 0); // 256 / 8 — same as systemd

    state.hmac = Some(
        HmacSha256::new_from_slice(&key).expect("HMAC-SHA256 accepts any key size"),
    );
    state.running = true;
}

// ── Feeding header / objects into the HMAC ───────────────────────────────

/// Feed the immutable portions of the journal file `Header` into the HMAC.
///
/// Matches `journal_file_hmac_put_header()` (journal-authenticate.c:329-358).
///
/// The ranges fed are:
///   1. signature .. state           (skips state + reserved)
///   2. file_id   .. tail_entry_boot_id  (skips tail_entry_boot_id)
///   3. seqnum_id .. arena_size      (skips arena_size)
///   4. data_hash_table_offset .. tail_object_offset (skips the rest)
pub fn journal_file_hmac_put_header(state: &mut JournalHmac, header: &Header) {
    let hmac = match state.hmac.as_mut() {
        Some(h) => h,
        None => return,
    };

    // Safety: Header is repr(C, packed) and we treat it as a bag of bytes,
    // computing the same byte ranges that systemd does via offsetof().
    let base = header as *const Header as *const u8;

    // Range 1: signature through compatible_flags + incompatible_flags
    // offsetof(Header, signature) == 0
    // offsetof(Header, state) == 16  (8 + 4 + 4)
    let off_state = offset_of_state();
    hmac.update(unsafe { std::slice::from_raw_parts(base, off_state) });

    // Range 2: file_id up to (but not including) tail_entry_boot_id
    let off_file_id = offset_of_file_id();
    let off_tail_entry_boot_id = offset_of_tail_entry_boot_id();
    hmac.update(unsafe {
        std::slice::from_raw_parts(base.add(off_file_id), off_tail_entry_boot_id - off_file_id)
    });

    // Range 3: seqnum_id up to (but not including) arena_size
    let off_seqnum_id = offset_of_seqnum_id();
    let off_arena_size = offset_of_arena_size();
    hmac.update(unsafe {
        std::slice::from_raw_parts(base.add(off_seqnum_id), off_arena_size - off_seqnum_id)
    });

    // Range 4: data_hash_table_offset through field_hash_table_size
    // (up to but not including tail_object_offset)
    let off_data_hash_table_offset = offset_of_data_hash_table_offset();
    let off_tail_object_offset = offset_of_tail_object_offset();
    hmac.update(unsafe {
        std::slice::from_raw_parts(
            base.add(off_data_hash_table_offset),
            off_tail_object_offset - off_data_hash_table_offset,
        )
    });
}

/// Feed an object's immutable fields into the HMAC.
///
/// Matches `journal_file_hmac_put_object()` (journal-authenticate.c:267-327).
///
/// `obj_data` is the complete on-disk object (header + body).
pub fn journal_file_hmac_put_object(
    state: &mut JournalHmac,
    obj_type: ObjectType,
    obj_data: &[u8],
    _offset: u64,
    compact: bool,
) -> Result<(), &'static str> {
    let hmac = match state.hmac.as_mut() {
        Some(h) => h,
        None => return Ok(()),
    };

    if obj_data.len() < OBJECT_HEADER_SIZE {
        return Err("object too small for ObjectHeader");
    }

    // ObjectHeader fields up to (but not including) payload — that is the
    // full 16-byte ObjectHeader (type, flags, reserved, size).
    hmac.update(&obj_data[..OBJECT_HEADER_SIZE]);

    let obj_size = obj_data.len();

    match obj_type {
        ObjectType::Data => {
            // Feed: hash (8 bytes at offset 16) then payload.
            // Skip: next_hash_offset, next_field_offset, entry_offset,
            //        entry_array_offset, n_entries (5 * 8 = 40 bytes).
            // In compact mode, payload starts 8 bytes later (72 vs 64).
            let payload_off = data_payload_offset(compact) as usize;
            if obj_size < payload_off {
                return Err("DATA object too small");
            }
            // hash is at offset 16, 8 bytes
            hmac.update(&obj_data[OBJECT_HEADER_SIZE..OBJECT_HEADER_SIZE + 8]);
            // payload starts after data_payload_offset (64 normal, 72 compact)
            if obj_size > payload_off {
                hmac.update(&obj_data[payload_off..]);
            }
        }

        ObjectType::Field => {
            // Feed: hash (8 bytes) then payload.
            // Skip: next_hash_offset, head_data_offset.
            if obj_size < FIELD_OBJECT_HEADER_SIZE {
                return Err("FIELD object too small");
            }
            // hash at offset 16, 8 bytes
            hmac.update(&obj_data[OBJECT_HEADER_SIZE..OBJECT_HEADER_SIZE + 8]);
            // payload starts after FieldObjectHeader (40 bytes)
            if obj_size > FIELD_OBJECT_HEADER_SIZE {
                hmac.update(&obj_data[FIELD_OBJECT_HEADER_SIZE..]);
            }
        }

        ObjectType::Entry => {
            // Feed everything from seqnum onwards (offset 16 to end).
            if obj_size < ENTRY_OBJECT_HEADER_SIZE {
                return Err("ENTRY object too small");
            }
            hmac.update(&obj_data[OBJECT_HEADER_SIZE..]);
        }

        ObjectType::DataHashTable | ObjectType::FieldHashTable | ObjectType::EntryArray => {
            // Nothing beyond the object header — all content is mutable.
        }

        ObjectType::Tag => {
            // Feed seqnum (8 bytes) and epoch (8 bytes), skip the tag itself.
            // seqnum is at offset 16, epoch at offset 24.
            let tag_fixed_end = OBJECT_HEADER_SIZE + 8 + 8; // 32
            if obj_size < tag_fixed_end {
                return Err("TAG object too small");
            }
            hmac.update(&obj_data[OBJECT_HEADER_SIZE..tag_fixed_end]);
        }

        ObjectType::Unused => {
            return Err("cannot HMAC an UNUSED object");
        }
    }

    Ok(())
}

/// Finalise the current HMAC cycle and return the 32-byte tag.
///
/// Matches `journal_file_append_tag()` (journal-authenticate.c:44-88).
/// The C version feeds the tag object's header, seqnum and epoch into the
/// HMAC before extracting the digest. We do the same: the caller provides
/// the complete on-disk tag object bytes (header + seqnum + epoch + space
/// for the tag itself, i.e. 64 bytes) so that we can HMAC the immutable
/// portions before finalising.
pub fn journal_file_append_tag(
    state: &mut JournalHmac,
    tag_object: &[u8],
) -> [u8; TAG_LENGTH] {
    let hmac = state
        .hmac
        .as_mut()
        .expect("journal_file_append_tag called without active HMAC");

    // Feed the tag object's immutable fields into the HMAC before
    // finalising, matching journal-authenticate.c:73-74:
    //   journal_file_hmac_put_object(f, OBJECT_TAG, o, p);
    // ObjectHeader (16 bytes) + seqnum (8) + epoch (8) = 32 bytes.
    let tag_fixed_end = OBJECT_HEADER_SIZE + 8 + 8; // 32
    assert!(
        tag_object.len() >= tag_fixed_end,
        "tag_object too small for TAG header + seqnum + epoch"
    );
    // Feed the object header
    hmac.update(&tag_object[..OBJECT_HEADER_SIZE]);
    // Feed seqnum + epoch (skip the tag hash bytes themselves)
    hmac.update(&tag_object[OBJECT_HEADER_SIZE..tag_fixed_end]);

    let hmac = state.hmac.take().unwrap();
    let result = hmac.finalize();
    let tag_bytes = result.into_bytes();

    state.running = false;

    let mut tag = [0u8; TAG_LENGTH];
    tag.copy_from_slice(&tag_bytes);
    tag
}

// ── FSS key file loading ─────────────────────────────────────────────────

/// Load and validate an FSS key file (`.fss`), returning the parsed state.
///
/// Matches `journal_file_fss_load()`.
pub fn journal_file_fss_load(path: &Path) -> io::Result<FssState> {
    let data = fs::read(path)?;

    if data.len() < mem::size_of::<FssHeader>() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "FSS file too small"));
    }

    // Safety: FssHeader is repr(C, packed), so any alignment is fine.
    let header: FssHeader =
        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const FssHeader) };

    if header.signature != FSS_HEADER_SIGNATURE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FSS signature mismatch",
        ));
    }

    let incompat = u32::from_le_bytes(header.incompatible_flags);
    if incompat != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported FSS incompatible flags",
        ));
    }

    let header_size = u64::from_le_bytes(header.header_size);
    if header_size < mem::size_of::<FssHeader>() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FSS header_size too small",
        ));
    }

    let secpar = u16::from_le_bytes(header.fsprg_secpar);
    let fsprg_state_size = u64::from_le_bytes(header.fsprg_state_size);
    if fsprg_state_size != fsprg::stateinbytes(secpar as u32) as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FSPRG state size mismatch",
        ));
    }

    let total = header_size + fsprg_state_size;
    if (data.len() as u64) < total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FSS file truncated",
        ));
    }

    let start_usec = u64::from_le_bytes(header.start_usec);
    let interval_usec = u64::from_le_bytes(header.interval_usec);
    if start_usec == 0 || interval_usec == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FSS start_usec or interval_usec is zero",
        ));
    }

    // Validate that the FSS key file's machine_id matches this machine.
    // Matches journal-authenticate.c:415-416:
    //   if (!sd_id128_equal(machine, m->fss_file->machine_id))
    //       return -EHOSTDOWN;
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = fs::read_to_string("/etc/machine-id") {
            let trimmed = s.trim().replace('-', "");
            if trimmed.len() == 32 {
                let mut local_id = [0u8; 16];
                let mut valid = true;
                for i in 0..16 {
                    if let Ok(b) = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16) {
                        local_id[i] = b;
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && local_id != header.machine_id {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "FSS key file machine_id does not match this machine",
                    ));
                }
            }
        }
    }

    let state_start = header_size as usize;
    let state_end = total as usize;
    let fsprg_state = data[state_start..state_end].to_vec();

    Ok(FssState {
        header,
        fsprg_state,
        start_usec,
        interval_usec,
    })
}

// ── Verification key parsing ─────────────────────────────────────────────

/// Parse a human-readable verification key string.
///
/// Format: `"HEXSEED/START_EPOCH_HEX-INTERVAL_HEX"`
///
/// where `HEXSEED` is hex-encoded bytes (dashes allowed as separators),
/// `START_EPOCH_HEX` is the epoch counter at key creation, and
/// `INTERVAL_HEX` is the interval in microseconds. The actual
/// `start_usec` is computed as `start * interval`.
///
/// Returns `(seed, start_usec, interval_usec)`.
///
/// Matches `journal_file_parse_verification_key()`.
pub fn journal_file_parse_verification_key(
    key_str: &str,
) -> Result<(Vec<u8>, u64, u64), &'static str> {
    let slash_pos = key_str
        .rfind('/')
        .ok_or("verification key missing '/'")?;

    let hex_part = &key_str[..slash_pos];
    let tail = &key_str[slash_pos + 1..];

    // Parse hex seed (dashes are allowed separators, skip them).
    let seed_size = FSPRG_RECOMMENDED_SEEDLEN;
    let mut seed = Vec::with_capacity(seed_size);
    let mut chars = hex_part.chars().filter(|&c| c != '-');

    for _ in 0..seed_size {
        let hi = chars
            .next()
            .and_then(|c| c.to_digit(16))
            .ok_or("invalid hex in seed")? as u8;
        let lo = chars
            .next()
            .and_then(|c| c.to_digit(16))
            .ok_or("invalid hex in seed")? as u8;
        seed.push(hi * 16 + lo);
    }

    // Parse "START_HEX-INTERVAL_HEX"
    let dash_pos = tail.find('-').ok_or("missing '-' in epoch/interval")?;
    let start = u64::from_str_radix(&tail[..dash_pos], 16)
        .map_err(|_| "invalid start epoch hex")?;
    let interval = u64::from_str_radix(&tail[dash_pos + 1..], 16)
        .map_err(|_| "invalid interval hex")?;

    let start_usec = start * interval;
    let interval_usec = interval;

    Ok((seed, start_usec, interval_usec))
}

// ── Epoch calculation ────────────────────────────────────────────────────

/// Compute the epoch number for a given realtime timestamp.
///
/// Matches `journal_file_get_epoch()`.
pub fn journal_file_get_epoch(
    start_usec: u64,
    interval_usec: u64,
    realtime: u64,
) -> Result<u64, &'static str> {
    if start_usec == 0 || interval_usec == 0 {
        return Err("FSS not configured");
    }
    if realtime < start_usec {
        return Err("realtime before FSS start");
    }
    Ok((realtime - start_usec) / interval_usec)
}

// ── Header offset helpers ────────────────────────────────────────────────
//
// These compute the same byte offsets that systemd uses via `offsetof()`.
// The Header struct is repr(C, packed) so these are deterministic.

#[inline]
const fn offset_of_state() -> usize {
    // signature(8) + compatible_flags(4) + incompatible_flags(4) = 16
    8 + 4 + 4
}

#[inline]
const fn offset_of_file_id() -> usize {
    // state(1) + reserved(7) = 8 past offset_of_state
    offset_of_state() + 1 + 7
}

#[inline]
const fn offset_of_tail_entry_boot_id() -> usize {
    // file_id(16) + machine_id(16) past offset_of_file_id
    offset_of_file_id() + 16 + 16
}

#[inline]
const fn offset_of_seqnum_id() -> usize {
    // tail_entry_boot_id is 16 bytes
    offset_of_tail_entry_boot_id() + 16
}

#[inline]
const fn offset_of_arena_size() -> usize {
    // seqnum_id(16) + header_size(8)
    offset_of_seqnum_id() + 16 + 8
}

#[inline]
const fn offset_of_data_hash_table_offset() -> usize {
    // arena_size(8) past offset_of_arena_size
    offset_of_arena_size() + 8
}

#[inline]
const fn offset_of_tail_object_offset() -> usize {
    // data_hash_table_offset(8) + data_hash_table_size(8)
    // + field_hash_table_offset(8) + field_hash_table_size(8)
    offset_of_data_hash_table_offset() + 8 + 8 + 8 + 8
}

// Compile-time sanity checks against known Header layout.
const _: () = assert!(offset_of_state() == 16);
const _: () = assert!(offset_of_file_id() == 24);
const _: () = assert!(offset_of_tail_entry_boot_id() == 56);
const _: () = assert!(offset_of_seqnum_id() == 72);
const _: () = assert!(offset_of_arena_size() == 96);
const _: () = assert!(offset_of_data_hash_table_offset() == 104);
const _: () = assert!(offset_of_tail_object_offset() == 136);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fss_header_size() {
        assert_eq!(mem::size_of::<FssHeader>(), 88);
    }

    #[test]
    fn test_epoch_calculation() {
        // start=1000, interval=100, realtime=1550 => epoch 5
        assert_eq!(journal_file_get_epoch(1000, 100, 1550).unwrap(), 5);
    }

    #[test]
    fn test_epoch_before_start() {
        assert!(journal_file_get_epoch(1000, 100, 500).is_err());
    }

    #[test]
    fn test_parse_verification_key() {
        // 12-byte seed = 24 hex chars, with optional dashes
        let key = "0102030405060708090a0b0c/a-3e8";
        let (seed, start_usec, interval_usec) = journal_file_parse_verification_key(key).unwrap();
        assert_eq!(seed, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        // start=0xa=10, interval=0x3e8=1000, start_usec = 10*1000 = 10000
        assert_eq!(start_usec, 10000);
        assert_eq!(interval_usec, 1000);
    }

    #[test]
    fn test_hmac_roundtrip() {
        let mut hmac = journal_file_hmac_setup();
        // Use a fake FSPRG state — we just need enough bytes for get_key to work.
        // Since fsprg::get_key isn't available yet, we test the HMAC path directly.
        let key = [0x42u8; 32];
        hmac.hmac = Some(HmacSha256::new_from_slice(&key).unwrap());
        hmac.running = true;

        // Feed some data
        hmac.hmac.as_mut().unwrap().update(b"test data");

        // Build a minimal tag object: ObjectHeader(16) + seqnum(8) + epoch(8) + tag_space(32) = 64
        let tag_object = [0u8; 64];
        let tag = journal_file_append_tag(&mut hmac, &tag_object);
        assert_eq!(tag.len(), TAG_LENGTH);
        assert!(!hmac.running);
    }
}
