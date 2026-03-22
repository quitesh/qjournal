/// Comprehensive journalctl compatibility tests.
///
/// Each test exercises one or more of the inconsistencies fixed relative to
/// the systemd reference implementation and validates the result with
/// `journalctl --file=...` so we know the on-disk format is correct.
///
/// Tests are automatically skipped when journalctl is not available.
use qjournal::{JournalReader, JournalWriter};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// ── helpers ───────────────────────────────────────────────────────────────────

fn tmp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("qjournal_compat_tests");
    fs::create_dir_all(&dir).ok();
    dir.join(name)
}

fn journalctl_available() -> bool {
    Command::new("journalctl").arg("--version").output().is_ok()
}

/// Run journalctl with arbitrary extra args against `path`.
/// Returns stdout on success, panics with a helpful message on failure.
fn jctl(path: &PathBuf, extra: &[&str]) -> String {
    let mut cmd = Command::new("journalctl");
    cmd.args(["--file", path.to_str().unwrap(), "--no-pager"]);
    cmd.args(extra);
    let out = cmd.output().expect("journalctl failed to run");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "journalctl {extra:?} exited {}: stderr={stderr}\nstdout={stdout}",
        out.status
    );
    stdout
}

// ── test 1: basic multi-entry read-back ──────────────────────────────────────
//
// Sanity-check that basic write→journalctl round-trip works with several
// distinct entries.

#[test]
fn test_basic_multi_entry() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-basic.journal");
    let _ = fs::remove_file(&path);

    {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..5u32 {
            w.append_entry(&[
                ("MESSAGE",           format!("entry {i}").as_bytes()),
                ("PRIORITY",          b"6" as &[u8]),
                ("SYSLOG_IDENTIFIER", b"qjournal-compat" as &[u8]),
            ]).unwrap();
        }
        w.flush().unwrap();
    }

    let out = jctl(&path, &["--output=json"]);
    for i in 0..5u32 {
        assert!(out.contains(&format!("entry {i}")), "missing entry {i} in:\n{out}");
    }
    assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 5);
    let _ = fs::remove_file(&path);
}

// ── test 2: FIELD→DATA linking (head_data_offset / next_field_offset) ────────
//
// `journalctl -F FIELD` lists unique values by walking the FIELD→DATA chain.
// Before the fix, head_data_offset was always 0, so -F returned nothing.

#[test]
fn test_field_enumeration_via_journalctl() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-field-enum.journal");
    let _ = fs::remove_file(&path);

    let unique_messages = ["alpha", "beta", "gamma", "delta", "epsilon"];
    {
        let mut w = JournalWriter::open(&path).unwrap();
        for msg in &unique_messages {
            w.append_entry(&[
                ("MESSAGE",           msg.as_bytes()),
                ("SYSLOG_IDENTIFIER", b"qjournal-compat" as &[u8]),
            ]).unwrap();
        }
        // Write a duplicate – -F should still return each value only once.
        w.append_entry(&[
            ("MESSAGE",           b"alpha" as &[u8]),
            ("SYSLOG_IDENTIFIER", b"qjournal-compat" as &[u8]),
        ]).unwrap();
        w.flush().unwrap();
    }

    let out = jctl(&path, &["-F", "MESSAGE"]);
    let found: HashSet<&str> = out.lines().collect();
    for msg in &unique_messages {
        assert!(found.contains(msg), "-F MESSAGE missing '{msg}', got:\n{out}");
    }
    // Exactly 5 unique values (duplicate "alpha" not repeated).
    assert_eq!(found.len(), unique_messages.len(), "-F MESSAGE output:\n{out}");
    let _ = fs::remove_file(&path);
}

// ── test 3: tail_entry_offset (journalctl --reverse / -n 1) ──────────────────
//
// header.tail_entry_offset must point at the last ENTRY object, not the last
// written object overall (which was an ENTRY_ARRAY before the fix).
// `journalctl -n 1` and `--reverse` both use tail_entry_offset for backward seeks.

#[test]
fn test_tail_entry_offset_reverse_and_n1() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-tail.journal");
    let _ = fs::remove_file(&path);

    let messages = ["first", "second", "third", "fourth", "last"];
    {
        let mut w = JournalWriter::open(&path).unwrap();
        for msg in &messages {
            w.append_entry(&[("MESSAGE", msg.as_bytes())]).unwrap();
        }
        w.flush().unwrap();
    }

    // -n 1 should return only the very last entry.
    let out_n1 = jctl(&path, &["-n", "1", "--output=cat"]);
    assert!(
        out_n1.trim().ends_with("last"),
        "-n 1 should show last message, got:\n{out_n1}"
    );

    // --reverse should list in reverse chronological order.
    let out_rev = jctl(&path, &["--reverse", "--output=cat"]);
    let lines: Vec<&str> = out_rev.lines().collect();
    assert_eq!(lines.len(), messages.len(), "--reverse should show all entries");
    assert!(
        lines[0].contains("last"),
        "--reverse: first line should be 'last', got:\n{out_rev}"
    );
    assert!(
        lines[messages.len() - 1].contains("first"),
        "--reverse: last line should be 'first', got:\n{out_rev}"
    );
    let _ = fs::remove_file(&path);
}

// ── test 4: per-DATA entry array chain with >8 entries for the same value ────
//
// Before the fix, data.entry_array_offset was overwritten with the tail array
// on each overflow, so only entries from the latest array were visible.
// This test writes 20 entries all sharing PRIORITY=6, forcing 3 mini-arrays,
// and verifies journalctl finds all 20 via entries_for_field.

#[test]
fn test_data_entry_array_chain_overflow() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-array-chain.journal");
    let _ = fs::remove_file(&path);

    const N: usize = 20;
    {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..N {
            w.append_entry(&[
                ("MESSAGE",  format!("msg{i}").as_bytes()),
                ("PRIORITY", b"6" as &[u8]),
            ]).unwrap();
        }
        w.flush().unwrap();
    }

    // All N entries should be visible in forward iteration.
    let reader = JournalReader::open(&path).unwrap();
    let all: Vec<_> = reader.entries().collect::<Result<_, _>>().unwrap();
    assert_eq!(all.len(), N, "forward iter should see all {N} entries");

    // entries_for_field on the repeated value must find all N entries.
    let by_priority = reader.entries_for_field("PRIORITY", b"6").unwrap();
    assert_eq!(
        by_priority.len(), N,
        "entries_for_field(PRIORITY=6) should return {N}, got {}",
        by_priority.len()
    );

    // journalctl should also see all N.
    let out = jctl(&path, &["--output=json"]);
    let count = out.lines().filter(|l| l.starts_with('{')).count();
    assert_eq!(count, N, "journalctl should see all {N} entries, got {count}");
    let _ = fs::remove_file(&path);
}

// ── test 5: reopen and append (tests state field + index rebuild) ─────────────
//
// Write entries in two separate open/close cycles.  Both state=Online bookends
// and the index rebuild must work correctly.  journalctl must see all entries.

#[test]
fn test_reopen_and_append() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-reopen.journal");
    let _ = fs::remove_file(&path);

    {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..5u32 {
            w.append_entry(&[("MESSAGE", format!("round1-{i}").as_bytes())]).unwrap();
        }
        w.flush().unwrap();
    }
    // File is now Offline.  Reopen and append more entries.
    {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..5u32 {
            w.append_entry(&[("MESSAGE", format!("round2-{i}").as_bytes())]).unwrap();
        }
        w.flush().unwrap();
    }

    let out = jctl(&path, &["--output=cat"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 10, "should see 10 entries total:\n{out}");
    for i in 0..5u32 {
        assert!(out.contains(&format!("round1-{i}")), "missing round1-{i}");
        assert!(out.contains(&format!("round2-{i}")), "missing round2-{i}");
    }
    let _ = fs::remove_file(&path);
}

// ── test 6: field-name validation ─────────────────────────────────────────────
//
// Exercises the two newly-added validation rules:
//   • names longer than 64 bytes are rejected
//   • names starting with a digit are rejected

#[test]
fn test_field_name_validation_extended() {
    let path = tmp_path("compat-field-validation.journal");
    let _ = fs::remove_file(&path);
    let mut w = JournalWriter::open(&path).unwrap();

    // Exactly 64 uppercase ASCII chars — must succeed.
    let name_64 = "A".repeat(64);
    assert!(
        w.append_entry(&[(name_64.as_str(), b"v" as &[u8])]).is_ok(),
        "64-char name should be accepted"
    );

    // 65 chars — must be rejected.
    let name_65 = "A".repeat(65);
    assert!(
        w.append_entry(&[(name_65.as_str(), b"v" as &[u8])]).is_err(),
        "65-char name should be rejected"
    );

    // Leading digit — must be rejected.
    assert!(
        w.append_entry(&[("1FIELD", b"v" as &[u8])]).is_err(),
        "leading digit should be rejected"
    );

    // Underscore at start is allowed.
    assert!(
        w.append_entry(&[("_PRIVATE_FIELD", b"v" as &[u8])]).is_ok(),
        "underscore-prefixed name should be accepted"
    );

    // Digits after first char are allowed.
    assert!(
        w.append_entry(&[("FIELD2", b"v" as &[u8])]).is_ok(),
        "digit after first char should be accepted"
    );
    let _ = fs::remove_file(&path);
}

// ── test 7: entries_for_field across many distinct values ────────────────────
//
// Exercises the hash-table lookup path with enough entries that several
// buckets get populated.

#[test]
fn test_entries_for_field_many_values() {
    let path = tmp_path("compat-many-values.journal");
    let _ = fs::remove_file(&path);

    const N: usize = 50;
    {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..N {
            w.append_entry(&[
                ("MESSAGE",  format!("msg-{i:03}").as_bytes()),
                ("PRIORITY", b"6" as &[u8]),
                ("COUNTER",  i.to_string().as_bytes()),
            ]).unwrap();
        }
        w.flush().unwrap();
    }

    let reader = JournalReader::open(&path).unwrap();

    // Every unique COUNTER value should map to exactly one entry.
    for i in 0..N {
        let matches = reader.entries_for_field("COUNTER", i.to_string().as_bytes()).unwrap();
        assert_eq!(
            matches.len(), 1,
            "COUNTER={i} should match exactly 1 entry, got {}",
            matches.len()
        );
        assert_eq!(
            matches[0].message().unwrap(),
            format!("msg-{i:03}"),
        );
    }

    // PRIORITY=6 should match all N.
    let all = reader.entries_for_field("PRIORITY", b"6").unwrap();
    assert_eq!(all.len(), N);
    let _ = fs::remove_file(&path);
}

// ── test 8: forward iteration ordering ───────────────────────────────────────
//
// Entries must come back in strictly ascending seqnum / insertion order.

#[test]
fn test_iteration_ordering() {
    let path = tmp_path("compat-ordering.journal");
    let _ = fs::remove_file(&path);

    const N: usize = 30;
    {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..N {
            w.append_entry(&[("MESSAGE", format!("seq-{i:02}").as_bytes())]).unwrap();
        }
        w.flush().unwrap();
    }

    let reader = JournalReader::open(&path).unwrap();
    let entries: Vec<_> = reader.entries().collect::<Result<_, _>>().unwrap();
    assert_eq!(entries.len(), N);
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.message().unwrap(),
            format!("seq-{i:02}"),
            "entry {i} out of order"
        );
        if i > 0 {
            assert!(
                entries[i].seqnum > entries[i - 1].seqnum,
                "seqnum not monotonically increasing at index {i}"
            );
            assert!(
                entries[i].realtime >= entries[i - 1].realtime,
                "realtime not monotonically non-decreasing at index {i}"
            );
        }
    }
    let _ = fs::remove_file(&path);
}

// ── test 9: journalctl JSON field presence ────────────────────────────────────
//
// Checks that known fields appear in --output=json with the correct values.

#[test]
fn test_journalctl_json_field_presence() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-json-fields.journal");
    let _ = fs::remove_file(&path);

    {
        let mut w = JournalWriter::open(&path).unwrap();
        w.append_entry(&[
            ("MESSAGE",           b"check-fields" as &[u8]),
            ("PRIORITY",          b"3" as &[u8]),
            ("SYSLOG_IDENTIFIER", b"test-app" as &[u8]),
        ]).unwrap();
        w.flush().unwrap();
    }

    let out = jctl(&path, &["--output=json"]);
    assert!(out.contains("check-fields"),     "MESSAGE missing");
    assert!(out.contains("test-app"),         "SYSLOG_IDENTIFIER missing");
    assert!(out.contains("PRIORITY"),         "PRIORITY key missing");
    // journalctl adds these from the journal metadata:
    assert!(out.contains("__REALTIME_TIMESTAMP"), "__REALTIME_TIMESTAMP missing");
    assert!(out.contains("__MONOTONIC_TIMESTAMP"),"__MONOTONIC_TIMESTAMP missing");
    let _ = fs::remove_file(&path);
}

// ── test 10: journalctl -F with repeated values and multiple fields ──────────
//
// Writes entries where two different fields each have repeated values.
// -F on each field must return only the distinct set.

#[test]
fn test_field_enum_multiple_fields() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-field-multi.journal");
    let _ = fs::remove_file(&path);

    // 4 entries: LEVEL cycles through "info"/"warn", APP cycles through "svc-a"/"svc-b"
    {
        let mut w = JournalWriter::open(&path).unwrap();
        let combos: &[(&str, &str)] = &[
            ("info",  "svc-a"),
            ("warn",  "svc-b"),
            ("info",  "svc-a"),
            ("warn",  "svc-b"),
        ];
        for (level, app) in combos {
            w.append_entry(&[
                ("MESSAGE", format!("{app} {level}").as_bytes()),
                ("LEVEL",   level.as_bytes()),
                ("APP",     app.as_bytes()),
            ]).unwrap();
        }
        w.flush().unwrap();
    }

    let levels = jctl(&path, &["-F", "LEVEL"]);
    let level_set: HashSet<&str> = levels.lines().collect();
    assert_eq!(level_set, HashSet::from(["info", "warn"]),
        "-F LEVEL: {levels}");

    let apps = jctl(&path, &["-F", "APP"]);
    let app_set: HashSet<&str> = apps.lines().collect();
    assert_eq!(app_set, HashSet::from(["svc-a", "svc-b"]),
        "-F APP: {apps}");
    let _ = fs::remove_file(&path);
}

// ── test 11: very long value, binary-safe payload ────────────────────────────
//
// Tests that large payloads round-trip correctly through qjournal's reader
// and journalctl.

#[test]
fn test_large_payload() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-large.journal");
    let _ = fs::remove_file(&path);

    // 4 KB of printable ASCII repeated.
    let big_msg: Vec<u8> = (0u16..4096)
        .map(|i| b'A' + (i % 26) as u8)
        .collect();

    {
        let mut w = JournalWriter::open(&path).unwrap();
        w.append_entry(&[
            ("MESSAGE",  big_msg.as_slice()),
            ("PRIORITY", b"6" as &[u8]),
        ]).unwrap();
        w.flush().unwrap();
    }

    // Round-trip via qjournal reader.
    let reader = JournalReader::open(&path).unwrap();
    let entries: Vec<_> = reader.entries().collect::<Result<_, _>>().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].get(b"MESSAGE").unwrap(), big_msg.as_slice());

    // journalctl should not error even if it truncates display.
    let out = jctl(&path, &["--output=json"]);
    assert!(out.contains("MESSAGE"), "journalctl didn't see MESSAGE field");
    let _ = fs::remove_file(&path);
}

// ── test 12: high-volume with both per-data and global entry arrays ───────────
//
// Writes 100 entries: 50 with BATCH=odd, 50 with BATCH=even.
// Forces multiple per-data entry-array blocks and a multi-block global
// entry-array chain.  All entries must be findable via both iteration and
// entries_for_field.

#[test]
fn test_high_volume_mixed() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-high-vol.journal");
    let _ = fs::remove_file(&path);

    const N: usize = 100;
    {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..N {
            let batch = if i % 2 == 0 { "even" } else { "odd" };
            w.append_entry(&[
                ("MESSAGE", format!("item-{i:03}").as_bytes()),
                ("BATCH",   batch.as_bytes()),
            ]).unwrap();
        }
        w.flush().unwrap();
    }

    let reader = JournalReader::open(&path).unwrap();

    // Forward iteration must yield all N entries in order.
    let all: Vec<_> = reader.entries().collect::<Result<_, _>>().unwrap();
    assert_eq!(all.len(), N, "expected {N} entries from forward iter");
    for (i, e) in all.iter().enumerate() {
        assert_eq!(e.message().unwrap(), format!("item-{i:03}"),
            "wrong message at position {i}");
    }

    // entries_for_field must find exactly N/2 for each batch.
    let evens = reader.entries_for_field("BATCH", b"even").unwrap();
    let odds  = reader.entries_for_field("BATCH", b"odd").unwrap();
    assert_eq!(evens.len(), N / 2, "BATCH=even count");
    assert_eq!(odds.len(),  N / 2, "BATCH=odd count");

    // Confirm all even messages come from even-indexed entries.
    for e in &evens {
        let msg = e.message().unwrap();
        let idx: usize = msg.strip_prefix("item-").unwrap().parse().unwrap();
        assert_eq!(idx % 2, 0, "BATCH=even entry has odd index {idx}");
    }

    // journalctl must also see all N.
    let out = jctl(&path, &["--output=json"]);
    let count = out.lines().filter(|l| l.starts_with('{')).count();
    assert_eq!(count, N, "journalctl saw {count}, expected {N}");
    let _ = fs::remove_file(&path);
}

// ── test 13: seqnums are monotonically increasing across reopens ──────────────
//
// After a close-and-reopen the sequence counter must continue from where
// it left off, not restart from 1.

#[test]
fn test_seqnum_continuity_across_reopens() {
    let path = tmp_path("compat-seqnum.journal");
    let _ = fs::remove_file(&path);

    for round in 0..3u32 {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..5u32 {
            w.append_entry(&[
                ("MESSAGE", format!("r{round}-{i}").as_bytes()),
            ]).unwrap();
        }
        w.flush().unwrap();
    }

    let reader = JournalReader::open(&path).unwrap();
    let entries: Vec<_> = reader.entries().collect::<Result<_, _>>().unwrap();
    assert_eq!(entries.len(), 15);
    for i in 1..entries.len() {
        assert!(
            entries[i].seqnum > entries[i - 1].seqnum,
            "seqnum regressed at index {i}: {} -> {}",
            entries[i - 1].seqnum, entries[i].seqnum
        );
    }
    let _ = fs::remove_file(&path);
}

// ── test 14: journalctl -F after reopen (FIELD chain survives close) ──────────
//
// Unique MESSAGE values written in two separate sessions must all appear in
// `journalctl -F MESSAGE`, confirming the FIELD→DATA chain is rebuilt correctly
// on reopen.

#[test]
fn test_field_enum_after_reopen() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-field-reopen.journal");
    let _ = fs::remove_file(&path);

    let session1 = ["apple", "banana", "cherry"];
    let session2 = ["date", "elderberry", "fig"];

    {
        let mut w = JournalWriter::open(&path).unwrap();
        for msg in &session1 {
            w.append_entry(&[("MESSAGE", msg.as_bytes())]).unwrap();
        }
        w.flush().unwrap();
    }
    {
        let mut w = JournalWriter::open(&path).unwrap();
        for msg in &session2 {
            w.append_entry(&[("MESSAGE", msg.as_bytes())]).unwrap();
        }
        w.flush().unwrap();
    }

    let out = jctl(&path, &["-F", "MESSAGE"]);
    for msg in session1.iter().chain(session2.iter()) {
        assert!(out.contains(msg), "-F MESSAGE missing '{msg}' after reopen:\n{out}");
    }
    let _ = fs::remove_file(&path);
}

// ── test 15: xor_hash integrity ───────────────────────────────────────────────
//
// journalctl --verify checks object integrity including the xor_hash in each
// ENTRY.  If any hash is wrong the verify command will report errors.

#[test]
fn test_journalctl_verify() {
    if !journalctl_available() { return; }
    let path = tmp_path("compat-verify.journal");
    let _ = fs::remove_file(&path);

    {
        let mut w = JournalWriter::open(&path).unwrap();
        for i in 0..10u32 {
            w.append_entry(&[
                ("MESSAGE",           format!("verify-{i}").as_bytes()),
                ("PRIORITY",          b"6" as &[u8]),
                ("SYSLOG_IDENTIFIER", b"verify-test" as &[u8]),
                ("INDEX",             i.to_string().as_bytes()),
            ]).unwrap();
        }
        w.flush().unwrap();
    }

    // --verify checks structural integrity of the journal file.
    // It should exit 0 with no errors for a correctly-written file.
    let out = Command::new("journalctl")
        .args(["--file", path.to_str().unwrap(), "--verify"])
        .output()
        .expect("journalctl --verify failed to run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // journalctl --verify exits 0 on a clean file.
    assert!(
        out.status.success(),
        "journalctl --verify failed:\nstdout={stdout}\nstderr={stderr}"
    );
    // Combine stdout+stderr; neither should contain "FAIL" or "error".
    let combined = format!("{stdout}{stderr}").to_lowercase();
    assert!(
        !combined.contains("fail"),
        "journalctl --verify reported FAIL:\n{combined}"
    );
    let _ = fs::remove_file(&path);
}
