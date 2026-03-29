# qjournal vs systemd Audit: Divergence Report

Seven-round audit of qjournal against systemd's journal implementation.
Rounds 1–3 used training-data knowledge; Rounds 4–14 used actual systemd source
files from `.systemd-ref/`.

## Fixed in this PR

### def.rs
- **HEADER_SIZE_MIN** (CRITICAL, R2): Fixed from 232 to 208 (correct offset of n_data)
- **compat::SUPPORTED** (MEDIUM, R2): SEALED/SEALED_CONTINUOUS gated on `fss` feature
- **incompat::SUPPORTED_READ** (HIGH, R1): Feature-gated on compression features
- **compat::ANY**, **incompat::ANY** (LOW, R1): Added
- **valid_realtime/monotonic/epoch** (LOW, R1): Added centralized helpers

### writer.rs
- **Seqnum timing** (HIGH, R1): Moved after data append to prevent waste on failure
- **Compression threshold** (HIGH, R1): Now configurable (`set_compress_threshold_bytes()`)
- **posix_fallocate retry** (HIGH, R1): EINTR retry loop added
- **posix_fallocate fallback** (MEDIUM, R3): Removed sparse file fallback (set_len) — systemd assumes non-sparse
- **Compact mode default** (MEDIUM, R1): Changed to true (matches systemd)
- **Archive filename** (HIGH, R2): 32-hex-no-dashes (R1 wrongly added dashes, R2 corrected)
- **Dispose hole-punching** (MEDIUM, R2): Removed (systemd doesn't modify file contents)
- **Dispose random** (LOW, R1): 64-bit random in filename
- **Monotonic guard** (LOW, R2): Removed extra `!= 0` guard
- **Dead strict_order block** (HIGH, R3): Removed misleading no-op code
- **Compression offset** (HIGH, R4): After compression, `self.offset` now advances by `ALIGN64(compressed_size)`

### reader.rs
- **find_field_object** (HIGH, R1): Implemented field hash table lookup
- **Location tracking** (HIGH, R1): Added LocationType, reset/save_location
- **Debug assertions** (MEDIUM, R1+R2+R3): Entry invariants in bisect_step
- **entries_for_field seen counter** (MEDIUM, R7): All slots count toward n_entries cap
- **BISECT_FOUND_UNCONDITIONAL_ENTRY_VALIDATION** (MEDIUM, R8): Removed unconditional `move_to_object` from `bisect_found`; systemd only validates when `ret_object != NULL`
- **R-NEW-1** (MEDIUM, R9): Removed unconditional `move_to_object` on `extra` in `generic_array_bisect_for_data`; systemd only validates when `ret_object != NULL`

### verify.rs
- **Bidirectional entry<->data check** (CRITICAL, R1): verify_data_hash_table now validates
- **Reverse link check** (CRITICAL, R1): verify_entry checks data->entry back-reference
- **Data entry array invariants** (HIGH, R1): n_entries >= 2 when array exists + ordering
- **tail_entry_monotonic** (HIGH, R2+R3): Now only checks when boot_id matches AND flag set; boot_id mismatch silently skips (not an error)
- **Extra boot_id null check** (HIGH, R2): Removed (systemd doesn't do this)
- **Extra '=' payload check** (HIGH, R2): Removed (binary data is valid)
- **Extra entry_array_offset==0 check** (MEDIUM, R3): Removed (systemd doesn't do this)
- **tail_entry_realtime** (MEDIUM, R1+R2): Uses last entry (not max)
- **Hash chain depth limit** (MEDIUM, R1): Added 1M cap
- **Header-version-aware counts** (MEDIUM, R1): Conditional on header_size
- **Zero-item ENTRY_ARRAY rejection** (MEDIUM, R4): Added (systemd rejects `n_items <= 0`)
- **DATA-ENTRY-ARRAY-FIRSTPASS** (MEDIUM, R7): Removed n_entries/entry_array_offset consistency check from first pass (belongs only in second pass)
- **VERIFY-ENTRY-SCOPE** (HIGH, R7): verify_entry now only called for entries in main entry array (not orphans), matching systemd's verify_entry_array architecture
- **IS-LAST-ENTRY-DETERMINATION** (HIGH, R7): Main entry array scan bounded by n_entries; last entry determined from the first n_entries slots only
- **EPOCH-CONTINUOUS-1** (MEDIUM, R7): SEALED_CONTINUOUS epoch check now strict for 3rd+ tags (must advance by exactly 1)
- **SEALED-ENTRY-BEFORE-TAG** (MEDIUM, R8): Entries before first TAG in sealed journals now rejected, matching systemd journal-verify.c:1259
- **ENTRY-ARRAY-ITEM-MONOTONIC-FIRST-PASS** (LOW, R8): Removed extra monotonicity check from first-pass EntryArray; systemd only checks monotonicity in second pass for referenced arrays
- **VERIFY-DATA-ENTRY-NOT-IN-MAIN-ARRAY** (HIGH, R8): verify_data_object now validates that data-linked entries are in main_entry_set (not just any ENTRY object)
- **BUG-VERIFY-01** (HIGH, R9): Removed false `'='` check on FIELD payloads; systemd does not check this during verification
- **BUG-VERIFY-02** (LOW, R9): Added `entry_array_offsets` validation in verify_data_object; systemd's `contains_uint64(cache_entry_array_fd, ...)` check
- **VERIFY-ORPHAN-DATA** (MEDIUM, R10): Removed `total_data_count != n_data` check; systemd tolerates orphaned DATA objects not linked into any hash chain
- **VERIFY-EA-ITEM-BREAK-ON-ZERO** (LOW, R11): Changed `break` to `continue` on zero slots in EntryArray first-pass; systemd iterates all slots checking each non-zero item
- **BUG-VERIFY-EA-CHAIN-MEMBERSHIP** (MEDIUM, R12): validate entry array chain offsets in verify_entry_array against pass-1 set; systemd's `contains_uint64(cache_entry_array_fd, ...)` check

### fss.rs
- **hmac_start no-op** (MEDIUM, R1): Returns early if already running
- **hmac_put_object type dispatch** (CRITICAL, R3): Unused now dispatches on embedded type instead of erroring
- **hmac_put_object type validation** (MEDIUM, R1): Validates type, allows UNUSED pass-through
- **fsprg_evolve** (CRITICAL, R2): Tags emitted AFTER evolving, only intermediate epochs
- **fsprg_seek** (CRITICAL, R2): Fixed gen_mk/seek argument order
- **maybe_append_tag** (HIGH, R1): Implemented epoch boundary detection

---

## Remaining Divergences

### mmap_cache.rs — Architectural (intentional design difference)

qjournal uses whole-file `memmap2::Mmap`; systemd uses 8MB windowed mmap with
LRU eviction. This is a cross-platform design choice.

| ID | Severity | Issue |
|----|----------|-------|
| MMAP-01 | CRITICAL | No SIGBUS handling — truncated/corrupt files crash the process |
| MMAP-02 | CRITICAL | Whole-file mapping — no windowing for large journals |
| MMAP-03..07 | HIGH | No shared cache, categories, LRU eviction, pinning, invalidation |

**Rationale**: qjournal targets cross-platform use where SIGBUS semantics differ.
The whole-file approach is simpler and sufficient for read-only tooling on
moderate-size journals. Windowed mmap would be needed for a daemon-class reader.

### hash.rs — Performance only (no correctness issues)

| ID | Severity | Issue |
|----|----------|-------|
| HASH-01 | MEDIUM | Aligned fast-path tail uses byte-at-a-time (correct, slower) |
| HASH-02 | LOW | Missing 16-bit aligned path (correct, slower) |

**Rationale**: Rust safety rules prevent the masked-read-past-allocation trick
that systemd uses in the non-VALGRIND path. The byte-at-a-time path produces
bit-identical hash values.

### fsprg.rs — Crypto library differences

| ID | Severity | Issue |
|----|----------|-------|
| FSPRG-05 | MEDIUM | `num_prime` primality test may differ from libgcrypt |
| FSPRG-07 | MEDIUM | Missing `n.bits() == secpar` assertion after p*q |
| FSPRG-15 | MEDIUM | BigUint temporaries not zeroized on drop |

**Rationale**: FSPRG-05 is theoretically possible but extremely unlikely for true
primes at 768-bit sizes. Cross-validation with known systemd seeds is recommended.
FSPRG-15 is defense-in-depth; Rust's allocator may reuse memory but the risk is
low for non-daemon use.

### writer.rs — Remaining items

| ID | Severity | Issue |
|----|----------|-------|
| D1 | HIGH | Seqnum consumed before strict_order check in append_entry_internal |
| D3 | HIGH | E2BIG error matching is dead code (wrong error variant) |
| D6 | MEDIUM | Field linking done in caller, not inside append_data |
| D4 | MEDIUM | tail_entry_seqnum updated late (after entry write, not before) |
| D9 | LOW | Incomplete seqnum_id reconciliation for multi-source writes |

**Rationale**: D1 causes seqnum gaps when entries are rejected by strict_order.
This is a real bug but only affects the case where timestamps go backwards (rare
in practice). D3 means allocation failures abort per-data linking instead of
continuing — this affects large files near the compact size limit. D6 is an
encapsulation issue that works correctly but duplicates logic.

### reader.rs — Remaining items

| ID | Severity | Issue |
|----|----------|-------|
| R-13 | MEDIUM | Cached n_entries (stale for live-tailing) |
| R-20 | MEDIUM | entries_for_field lacks corruption recovery on array walk |

**Rationale**: R-13 is by design for a read-only single-file reader. Live-tailing
requires re-reading n_entries from the mmap'd header on each call.

### verify.rs — Remaining items

| ID | Severity | Issue |
|----|----------|-------|
| D01 | CRITICAL | No tag verification (seqnum, epoch, HMAC) for sealed journals |
| D06 | MEDIUM | No SEALED_CONTINUOUS warning |

**Rationale**: D01 requires FSPRG/HMAC crypto integration which is not yet
complete. When FSS support matures, tag verification should be added.

### fss.rs — Remaining items

| ID | Severity | Issue |
|----|----------|-------|
| FSS-01 | HIGH | hmac_put_object/header don't auto-start HMAC cycle |
| FSS-07 | MEDIUM | append_tag panics if HMAC not started (should auto-start) |
| D05 | HIGH | Missing tag sequence number tracking |
| D06 | HIGH | Missing append_first_tag (initial seal protocol) |
| D12 | MEDIUM | fs::read instead of mmap; evolved state not persisted to disk |

**Rationale**: These are all part of the incomplete FSS write-path integration.
The HMAC math and FSPRG algorithms are correct; what's missing is the orchestration
layer that ties them into the writer's append flow. This is planned future work.
