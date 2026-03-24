use qjournal::{JournalReader, JournalWriter};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

fn tmp_path(name: &str) -> PathBuf {
    let _ = fs::create_dir_all(std::env::temp_dir().join("qjournal_tests"));
    std::env::temp_dir().join("qjournal_tests").join(name)
}

#[test]
fn test_journal_append() {
    let path = tmp_path("test-append.journal");
    let _ = fs::remove_file(&path);

    let mut writer = JournalWriter::open(&path).expect("Failed to open writer");

    for i in 0..10 {
        let msg = format!("Initial message {}", i);
        writer.append_entry(&[
            ("MESSAGE", msg.as_bytes()),
            ("ITERATION", i.to_string().as_bytes())
        ]).unwrap();
    }
    writer.flush().unwrap();
    drop(writer);

    // Verify
    let mut reader = JournalReader::open(&path).expect("Failed to open reader");
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 10);

    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.message().unwrap(), format!("Initial message {}", i));
        assert_eq!(entry.get(b"ITERATION").unwrap(), i.to_string().as_bytes());
    }

    let _ = fs::remove_file(&path);
}

#[test]
fn test_corrupt_and_append() {
    let path = tmp_path("test-corrupt.journal");
    let _ = fs::remove_file(&path);

    let mut writer = JournalWriter::open(&path).expect("Failed to open writer");

    for i in 0..10 {
        let msg = format!("Initial message {}", i);
        writer.append_entry(&[
            ("MESSAGE", msg.as_bytes())
        ]).unwrap();
    }
    writer.flush().unwrap();
    drop(writer);

    let file_len = fs::metadata(&path).unwrap().len();
    assert!(file_len > 0);

    // Corrupt the header (at offset 10)
    let mut file = fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(10)).unwrap();
    let mut b = [0u8; 1];
    file.read_exact(&mut b).unwrap();
    b[0] |= 0x1;
    file.seek(SeekFrom::Start(10)).unwrap();
    file.write_all(&b).unwrap();
    drop(file);

    // Now try to open it. It might fail, but it shouldn't panic!
    let res = JournalWriter::open(&path);
    if let Ok(mut w) = res {
        // If it opened, appending shouldn't panic
        let _ = w.append_entry(&[("MESSAGE", b"Hello world" as &[u8])]);
    }

    let _ = fs::remove_file(&path);
}
