// SPDX-License-Identifier: LGPL-2.1-or-later
//! Simplified mmap cache for read-only journal file access.
//!
//! This is a simplified version of systemd's `mmap-cache.c`. Instead of managing
//! multiple windows with LRU eviction across many file descriptors, we simply
//! memory-map the entire file once. This provides zero-copy access to file contents
//! and eliminates the many seek+read syscalls that the plain `File` path requires.

use memmap2::Mmap;
use std::fs::File;

/// A memory-mapped read-only view of a journal file.
/// Provides zero-copy access to file contents.
pub struct MmapCache {
    mmap: Mmap,
}

impl MmapCache {
    /// Create a new memory-mapped view of the given file.
    ///
    /// # Safety
    /// The caller must ensure the file is not concurrently truncated while the
    /// mapping is live. For journal files opened read-only this is safe because
    /// the writer only appends.
    pub fn new(file: &File) -> std::io::Result<Self> {
        // SAFETY: journal files are append-only; concurrent truncation does not occur.
        let mmap = unsafe { Mmap::map(file)? };
        Ok(Self { mmap })
    }

    /// Return the length of the mapped region.
    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    /// Returns true if the mapped region is empty.
    pub fn is_empty(&self) -> bool {
        self.mmap.is_empty()
    }

    /// Read a u64 at the given offset (little-endian).
    pub fn read_u64(&self, offset: u64) -> Option<u64> {
        let off = offset as usize;
        if off + 8 > self.mmap.len() {
            return None;
        }
        let bytes: [u8; 8] = self.mmap[off..off + 8].try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    /// Read a u32 at the given offset (little-endian).
    pub fn read_u32(&self, offset: u64) -> Option<u32> {
        let off = offset as usize;
        if off + 4 > self.mmap.len() {
            return None;
        }
        let bytes: [u8; 4] = self.mmap[off..off + 4].try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    /// Read a single byte.
    pub fn read_u8(&self, offset: u64) -> Option<u8> {
        let off = offset as usize;
        self.mmap.get(off).copied()
    }

    /// Read a slice of bytes. Returns a reference into the mapped memory
    /// (zero-copy).
    pub fn read_bytes(&self, offset: u64, len: usize) -> Option<&[u8]> {
        let off = offset as usize;
        if off + len > self.mmap.len() {
            return None;
        }
        Some(&self.mmap[off..off + len])
    }
}
