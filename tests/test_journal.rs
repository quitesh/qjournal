use qjournal::{JournalReader, JournalWriter};
use std::fs;
use std::path::PathBuf;

fn tmp_path(name: &str) -> PathBuf {
    let _ = fs::create_dir_all(std::env::temp_dir().join("qjournal_tests"));
    std::env::temp_dir().join("qjournal_tests").join(name)
}

#[test]
fn test_empty_one() {
    let path = tmp_path("test-empty.journal");
    let _ = fs::remove_file(&path);

    // Create a new empty journal
    let w1 = JournalWriter::open(&path);
    assert!(w1.is_ok(), "Failed to open new journal file for writing");
    drop(w1);

    // Verify it is readable
    let mut r1 = JournalReader::open(&path).expect("Failed to open for reading");
    let items = r1.entries().unwrap();
    assert_eq!(items.len(), 0, "Expected empty journal");

    let _ = fs::remove_file(&path);
}

#[test]
fn test_non_empty_one() {
    let path = tmp_path("test-non-empty.journal");
    let _ = fs::remove_file(&path);

    // Write a couple entries
    let mut writer = JournalWriter::open(&path).expect("Failed to open writer");

    // seqnum 1
    writer.append_entry(&[
        ("TEST1", b"1" as &[u8])
    ]).unwrap();

    // seqnum 2
    writer.append_entry(&[
        ("TEST2", b"2" as &[u8])
    ]).unwrap();

    // seqnum 3
    writer.append_entry(&[
        ("TEST1", b"1" as &[u8])
    ]).unwrap();

    writer.flush().unwrap();
    drop(writer);

    let mut reader = JournalReader::open(&path).expect("Failed to open reader");

    // Test forward iteration
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].seqnum, 1);
    assert_eq!(entries[1].seqnum, 2);
    assert_eq!(entries[2].seqnum, 3);

    // Ensure we can query fields
    let matches_test1 = reader.entries_for_field("TEST1", b"1").unwrap();
    assert_eq!(matches_test1.len(), 2);
    assert_eq!(matches_test1[0].seqnum, 1);
    assert_eq!(matches_test1[1].seqnum, 3);

    let matches_test2 = reader.entries_for_field("TEST2", b"2").unwrap();
    assert_eq!(matches_test2.len(), 1);
    assert_eq!(matches_test2[0].seqnum, 2);

    let _ = fs::remove_file(&path);
}
