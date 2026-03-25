# qjournal vs systemd Audit Report

**Date:** 2026-03-24
**Methodology:** 75 subagents each compared Rust functions against systemd C source (from GitHub main branch or training knowledge when fetch was blocked)

---

## CRITICAL

### 1. `journal_file_allocate` — Uses `f_bfree` instead of `f_bavail` (writer.rs:2051)
The free-space check uses `f_bfree` (total free blocks including reserved) instead of `f_bavail` (free blocks available to unprivileged users). On ext4 with 5% reserved blocks, this could allow the journal to consume space reserved for root, potentially filling the disk for other processes.

### 2. `journal_file_entry_seqnum` — Missing `tail_entry_seqnum` header update (writer.rs:2021)
Systemd updates `tail_entry_seqnum` in the header inside `journal_file_entry_seqnum` itself. The Rust version defers this to `journal_file_link_entry`. If a crash occurs between entry creation and linking, `tail_entry_seqnum` won't reflect the partially-written entry, potentially causing seqnum reuse on re-open.

---

## HIGH

### 3. `journal_file_allocate` — Missing `fallocate(FALLOC_FL_KEEP_SIZE)` pre-allocation (writer.rs:2051)
Systemd uses `fallocate()` with `FALLOC_FL_KEEP_SIZE` to pre-allocate space before extending the file. The Rust version only uses `set_len()` (ftruncate). This misses the opportunity for contiguous block allocation and could lead to file fragmentation.

### 4. `journal_file_append_object` — Missing size validation against `minimum_header_size` (writer.rs:2144)
Systemd validates that the object size meets the minimum for its type before appending. The Rust version does not perform this check inside the function.

### 5. `journal_file_append_object` — Missing `journal_file_allocate` call (writer.rs:2144)
Systemd calls `journal_file_allocate()` inside `journal_file_append_object()`. The Rust version does not, relying on callers to pre-allocate.

### 6. `journal_file_entry_seqnum` — Seqnum logic differs when external seqnum provided (writer.rs:2021)
When an external seqnum is provided, the reconciliation logic between the provided value and the internal counter diverges from systemd's approach.

### 7. `find_data_object_with_hash` (reader) — Loop detection uses monotonicity check instead of counter (reader.rs:347)
The Rust reader uses `p <= prev` as loop detection. This misses forward-advancing cycles (A→B→C→A where C > B > A). Systemd uses an iteration counter with a hard limit. A corrupt file with such a cycle could cause infinite looping.

### 8. `find_data_object_with_hash` (writer) — In-memory index vs on-disk chain walk (writer.rs:2466)
The writer uses a pre-built in-memory HashMap instead of walking the on-disk hash chain. If the index is ever out of sync with disk (e.g., after crash), find would return `None` for data that exists on disk. Systemd's on-disk walk is self-healing.

### 9. `find_data_object_with_hash` (writer) — Decompression failure silently skips object (writer.rs:2466)
When comparing payloads during hash chain walk, if decompression fails, the Rust code silently skips the object instead of returning an error as systemd does.

### 10. `data_object_in_hash_table` (verify) — Missing chain-loop depth guard (verify.rs:577)
The hash chain walk uses a bare `while cur != 0` loop with no step counter. A corrupt chain with a cycle would loop forever (DoS during verification). Systemd limits chain walk depth.

### 11. `read_data_payload_raw` — LZ4 uncompressed-size prefix not range-checked (reader.rs:405)
The 8-byte LE prefix storing uncompressed size is read and used for allocation without an upper-bound check. A malicious journal could trigger an OOM by specifying an enormous size.

### 12. `verify_object` (verify) — Missing `(seqnum_id == 0) != (seqnum == 0)` XOR check on entries (verify.rs:106)
Systemd verifies that entries have consistent seqnum_id/seqnum pairs. This check is missing in the Rust verifier.

### 13. `generic_array_bisect` — `left == right` termination skips final `test_fn` validation (reader.rs:915)
When bisection converges and `m == m_original`, the Rust code skips the final `test_fn` call and goes directly to `bisect_found`. Systemd always validates the final element.

### 14. `find_field_object_with_hash` — No object type validation during chain walk (writer.rs:2427)
When walking the hash chain, the Rust code does not validate that each object encountered is actually a FIELD object. A corrupt chain pointing to a non-FIELD object could cause misinterpretation.

### 15. `journal_file_set_online` — Spurious fsync not present in systemd (writer.rs:1966)
The Rust calls `self.file.sync_all()` when transitioning to online state. Systemd's `journal_file_set_online` does NOT fsync when going online. This adds unnecessary I/O latency on every write cycle.

### 16. `journal_file_set_offline` — No background thread / no cancellation (writer.rs:1990)
Systemd spawns a background thread with a cancellable state machine for the offline transition. The Rust implementation is fully synchronous and non-cancellable, blocking the caller and missing the cancellation protocol that allows new writes to cheaply interrupt an in-progress offline.

### 17. `journal_file_link_data` — `data_hash_chain_depth` counted before new entry is linked (writer.rs:2362)
The depth walk (`count_data_chain_depth`) is called before the new tail pointer is written to the hash table, so the new entry isn't included in the count. This means `data_hash_chain_depth` is consistently understated by 1 on every non-empty-bucket insertion, which could delay rotation when chain depth exceeds `HASH_CHAIN_DEPTH_MAX`.

---

## MEDIUM

### 15. `check_object_header` — Missing `VALID64(offset)` alignment check (writer.rs:298)
Systemd checks that the object's own file offset is 8-byte aligned. The Rust version does not.

### 16. `check_object_header` — Missing `VALID64(obj_size)` alignment check (writer.rs:298)
Systemd checks that the stored object size is 8-byte aligned. The Rust version does not.

### 17. `verify_header` — Missing `file_id` null check (writer.rs:618)
Systemd rejects files with an all-zero `file_id`. The Rust version does not check this.

### 18. `verify_header` — Missing `seqnum_id` null check (writer.rs:618)
Systemd rejects files with an all-zero `seqnum_id`. The Rust version does not check this.

### 19. `verify_header` — Missing seqnum ordering check `head_entry_seqnum <= tail_entry_seqnum` (writer.rs:618)
Systemd validates that head seqnum doesn't exceed tail seqnum. Missing in qjournal.

### 20. `verify_header` — Missing `head_entry_realtime <= tail_entry_realtime` check (writer.rs:618)
Systemd validates realtime timestamp ordering in the header. Missing in qjournal.

### 21. `journal_file_link_field` — `field_hash_chain_depth` tracked inside link (writer.rs:2319)
Systemd does NOT update `field_hash_chain_depth` inside `journal_file_link_field`. The Rust version performs extra chain-depth counting on every non-empty-bucket link that systemd doesn't do at this point.

### 22. `journal_file_append_object` — `arena_size` header field not updated (writer.rs:2144)
Systemd updates `arena_size` in the header inside `journal_file_append_object`. The Rust version does not.

### 23. `link_entry_into_array` — Compact mode uses `assert!` (panic) instead of error for offset > u32::MAX (writer.rs:2847)
Systemd returns `-ERANGE` as a recoverable error. The Rust code panics.

### 24. `link_entry_into_array_plus_one` — `first_offset_ptr` write-back is conditional instead of unconditional (writer.rs:2942)
Systemd always writes back unconditionally after `link_entry_into_array`. The Rust re-reads and conditionally writes, which is semantically wrong (though unlikely to trigger in practice due to monotonically increasing offsets).

### 25. `journal_file_append_entry_internal` — Seqnum ID reconciliation is a no-op stub (writer.rs:3061)
The comment notes the seqnum ID mismatch check is skipped ("implicit — we are single-writer"). Systemd performs real seqnum ID reconciliation.

### 26. `journal_file_link_entry` — `n_entries` assigned from counter instead of incremented (writer.rs:3207)
Systemd increments `n_entries` by 1. The Rust code assigns from an in-memory counter, which could diverge if the counter gets out of sync.

### 27. `journal_file_append_entry_internal` — Realtime ordering check has no `tail_entry_realtime != 0` guard (writer.rs:3113)
Systemd only enforces `realtime >= tail_entry_realtime` when `tail_entry_realtime != 0`, to allow the first entry. The Rust version checks unconditionally, which could incorrectly reject a valid first entry if `tail_entry_realtime` happened to be non-zero from prior state.

### 28. `journal_file_rotate_suggested` — Missing file-size rotation trigger (writer.rs:3424)
The Rust version may be missing one of systemd's rotation criteria based on file size limits.

### 28. `try_compress_payload` — ZSTD: no output-size ceiling (writer.rs:2247)
Systemd enforces a maximum output size hint with `ZSTD_compressBound`. The Rust code uses streaming API without bounds.

### 29. `read_data_payload_raw` — No decompressed-output size cap for XZ or ZSTD (reader.rs:405)
Systemd limits decompressed output size. The Rust version allocates unbounded, which could be exploited by a malicious journal.

### 30. `verify_object` (verify) — Missing `entry_array_offset == 0` XOR `n_entries == 0` check for Data objects (verify.rs:106)
Systemd verifies this consistency invariant. Missing in the Rust verifier.

### 31. `verify_entry_array` — Missing object-type check on each chain entry (verify.rs:725)
Systemd validates that each entry-array object in the chain is actually an ENTRY_ARRAY type.

### 32. `verify_entry_array` — Missing minimum object-size check (verify.rs:725)
Systemd checks minimum size on each chain entry. The Rust version silently skips undersized objects.

### 33. `verify_data_hash_table` — Missing total-count verification against header `n_data` (verify.rs:608)
Systemd verifies that the total number of data objects found in the hash table matches the header's `n_data` field.

### 34. `generic_array_get` — Chain cache hit uses strict `>` instead of `>=` (reader.rs:664)
The cache hit condition differs slightly from systemd's, potentially missing cache hits.

### 35. `generic_array_get` — `Direction::Up` path `t -= k` underflow not guarded (reader.rs:664)
Could underflow when `t < k`, though this condition may not be reachable in practice.

### 36. `generic_array_bisect_for_data` — Inline `extra` entry not validated non-zero before test (reader.rs:1141)
Systemd guards the inline entry lookup. The Rust version could attempt to look up offset 0 if `extra == 0`.

### 37. `journal_file_dispose` — Random suffix width mismatch (writer.rs:4287)
The random hex suffix in the renamed file may differ in width from systemd's implementation.

### 38. `parse_verification_key` — No trailing-character check after hex seed decode (fss.rs:410)
Systemd rejects extra characters after the seed. The Rust version silently ignores them.

### 39. `JournalReader::open` — No field hash table extracted (reader.rs:128)
Systemd retains `field_hash_table_offset`/`field_hash_table_size`. The Rust reader does not, limiting field-based lookups.

### 40. `get_last_entry_monotonic_for_data` — Silent fallback when `eao == 0` and `n_entries > 1` (writer.rs:3367)
When a DATA object has `n_entries > 1` but `entry_array_offset == 0`, systemd treats this as corruption. The Rust code silently returns the first entry's monotonic timestamp as if it were the last, producing incorrect cutoff timestamps without signaling an error.

### 41. `verify_object` (verify) — Field objects not checked for `=` absence in payload (verify.rs:106)
Systemd verifies that Field object payloads (field names) do not contain `=`. The Rust verifier omits this check, allowing corrupt Field objects with `=` in the name to pass verification.

### 42. `chain_cache_put` — `CHAIN_CACHE_MAX` is 20 vs systemd's 1024 (reader.rs:51)
The chain cache is 50x smaller than systemd's, causing much more frequent eviction and slower bisection on large journals with many data objects.

### 42. `generic_array_bisect` — `bisect_goto_previous` re-walks chain backwards (reader.rs:915)
The re-walk implementation may behave differently from systemd's approach in edge cases.

---

## LOW

### 41. `check_object_header` — Redundant dead-code size check (writer.rs:298)
### 42. `verify_header` — Online state allowed for writable opens (writer.rs:618) — documented intentional
### 43. `journal_file_link_entry` — Missing atomic memory fence (writer.rs:3207)
### 44. `journal_file_link_entry` — `head_entry_seqnum` guard uses `head_entry_realtime == 0` (writer.rs:3207)
### 45. `journal_file_dispose` — `dir_fd` ignored, uses absolute paths (writer.rs:4287) — documented
### 46. `test_object_offset` — null-pointer guard returns error instead of bisection recovery (reader.rs:773)
### 47. `link_entry_into_array_plus_one` — Compact tail-cache write in wrapper instead of inner function (writer.rs:2942)
### 48. `journal_file_set_offline` — Missing `__atomic_thread_fence(SEQ_CST)` (writer.rs:1990)
### 49. `create_new_with_max_size` — Compact mode defaults to false (writer.rs:1373) — intentional, doc comment wrong
### 50. `chain_cache_put` — Early-return condition fuses two concerns (reader.rs:546)
### 51. `read_data_payload` / `read_entry_at` — Corrupt entry items silently skipped (reader.rs:482)
### 52. `journal_file_data_payload` — Redundant type check after `move_to_object` (writer.rs:2756)
### 53. `verify_entry_array` — Entry ordering check uses `<=` instead of `<` (verify.rs:725)

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 15 |
| Medium | 30 |
| Low | 13 |
| **Total** | **60** |

### Agents that could not fetch systemd source (used training knowledge instead)
~30 of 75 agents were blocked from fetching the live systemd C source via WebFetch/Bash. These agents used training knowledge of the systemd source (cutoff ~mid-2025) for comparison, which may miss very recent upstream changes. A re-audit with network access would increase confidence.

### Key risk areas
1. **Crash safety**: The `journal_file_entry_seqnum` / `tail_entry_seqnum` timing gap could cause seqnum reuse
2. **Denial of service**: Missing loop-depth guards in hash chain walks and unbounded decompression allocations
3. **Disk space**: Using `f_bfree` instead of `f_bavail` could consume reserved blocks
4. **Data integrity**: Missing alignment checks (`VALID64`) in `check_object_header` could accept malformed objects
