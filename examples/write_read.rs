// SPDX-License-Identifier: LGPL-2.1-or-later
//! Example: write a few entries then read them back.
//!
//! Run with:  cargo run --example write_read

use qjournal::{JournalReader, JournalWriter};

fn main() -> qjournal::Result<()> {
    let path = std::env::temp_dir().join("qjournal_example.journal");
    println!("Writing journal to: {}", path.display());

    // --- Write ---
    {
        let mut writer = JournalWriter::open(&path)?;

        writer.append_entry(&[
            ("MESSAGE", b"Application started" as &[u8]),
            ("PRIORITY", b"6"),
            ("SYSLOG_IDENTIFIER", b"myapp"),
        ])?;

        writer.append_entry(&[
            ("MESSAGE", b"Doing some work" as &[u8]),
            ("PRIORITY", b"7"),
            ("SYSLOG_IDENTIFIER", b"myapp"),
        ])?;

        writer.append_entry(&[
            ("MESSAGE", b"An error occurred" as &[u8]),
            ("PRIORITY", b"3"),
            ("SYSLOG_IDENTIFIER", b"myapp"),
            ("ERRNO", b"5"),
        ])?;

        writer.flush()?;
        println!("Wrote 3 entries.");
    }

    // --- Read ---
    let mut reader = JournalReader::open(&path)?;

    println!("\nAll entries:");
    let entries = reader.entries()?;
    for (i, entry) in entries.iter().enumerate() {
        println!(
            "  [{}] seqnum={} realtime={} msg={:?}",
            i,
            entry.seqnum,
            entry.realtime,
            entry.message().unwrap_or("<binary>"),
        );
        for (k, v) in entry.fields() {
            println!("       {}={}", String::from_utf8_lossy(k), String::from_utf8_lossy(v));
        }
    }

    println!("\nEntries with PRIORITY=3:");
    let errors = reader.entries_for_field("PRIORITY", b"3")?;
    for e in &errors {
        println!("  msg={:?}", e.message());
    }

    println!("\nDone. You can verify with: journalctl --file={}", path.display());
    Ok(())
}
