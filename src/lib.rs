// SPDX-License-Identifier: LGPL-2.1-or-later
//! # qjournal
//!
//! Cross-platform native implementation of the systemd-journald binary journal format.
//!
//! This library can read and write `.journal` files that are fully compatible with
//! `journalctl --file=<path>`, without depending on `libsystemd`.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use qjournal::JournalWriter;
//! use std::path::Path;
//!
//! let mut writer = JournalWriter::open(Path::new("/tmp/test.journal")).unwrap();
//! writer.append_entry(&[
//!     ("MESSAGE", b"Hello, world!" as &[u8]),
//!     ("PRIORITY", b"6"),
//!     ("SYSLOG_IDENTIFIER", b"myapp"),
//! ]).unwrap();
//! writer.flush().unwrap();
//! ```
//!
//! ## Reading
//!
//! ```rust,no_run
//! use qjournal::JournalReader;
//! use std::path::Path;
//!
//! let mut reader = JournalReader::open(Path::new("/tmp/test.journal")).unwrap();
//! for entry in reader.entries().unwrap() {
//!     if let Some(msg) = entry.get(b"MESSAGE") {
//!         println!("{}", String::from_utf8_lossy(msg));
//!     }
//! }
//! ```

pub mod def;
pub mod error;
#[cfg(feature = "fss")]
pub mod fsprg;
#[cfg(feature = "fss")]
pub mod fss;
pub mod hash;
pub mod mmap_cache;
pub mod reader;
pub mod verify;
pub mod writer;

pub use error::{Error, Result};
pub use reader::JournalReader;
pub use verify::{journal_file_verify, VerifyResult};
pub use writer::{
    Compression, JournalMetrics, JournalWriter,
    compression_default, compression_requested,
    journal_file_dispose, journal_file_parse_uid_from_filename,
    journal_metrics_equal, journal_reset_metrics,
};
