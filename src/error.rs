// SPDX-License-Identifier: LGPL-2.1-or-later
//! Error types for qjournal operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid journal file: {0}")]
    InvalidFile(String),

    #[error("Incompatible journal format flags: {flags:#010x}")]
    IncompatibleFlags { flags: u32 },

    #[error("Corrupt object at offset {offset:#x}: {reason}")]
    CorruptObject { offset: u64, reason: String },

    #[error("Journal file is truncated at offset {offset:#x}")]
    Truncated { offset: u64 },

    #[error("Field name is invalid: {0:?}")]
    InvalidFieldName(String),

    #[error("Entry has no fields")]
    EmptyEntry,

    #[error("End of journal")]
    EndOfJournal,

    #[error("Decompression error: {0}")]
    Decompression(String),
}

pub type Result<T> = std::result::Result<T, Error>;
