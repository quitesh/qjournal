# qjournal vs systemd: Remaining Divergences

Audited against systemd source over 16 rounds. All fixable correctness bugs have been resolved. The items below are intentional or deferred with justification.

## mmap_cache.rs — Architectural (intentional design difference)

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

## hash.rs — Performance only (no correctness issues)

| ID | Severity | Issue |
|----|----------|-------|
| HASH-01 | MEDIUM | Aligned fast-path tail uses byte-at-a-time (correct, slower) |
| HASH-02 | LOW | Missing 16-bit aligned path (correct, slower) |

**Rationale**: Rust safety rules prevent the masked-read-past-allocation trick
that systemd uses in the non-VALGRIND path. The byte-at-a-time path produces
bit-identical hash values.

## fsprg.rs — Crypto library differences

| ID | Severity | Issue |
|----|----------|-------|
| FSPRG-05 | MEDIUM | `num_prime` primality test may differ from libgcrypt |
| FSPRG-07 | MEDIUM | Missing `n.bits() == secpar` assertion after p*q |
| FSPRG-15 | MEDIUM | BigUint temporaries not zeroized on drop |

**Rationale**: FSPRG-05 is theoretically possible but extremely unlikely for true
primes at 768-bit sizes. Cross-validation with known systemd seeds is recommended.
FSPRG-15 is defense-in-depth; Rust's allocator may reuse memory but the risk is
low for non-daemon use.

## writer.rs

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

## reader.rs

| ID | Severity | Issue |
|----|----------|-------|
| R-13 | MEDIUM | Cached n_entries (stale for live-tailing) |
| R-20 | MEDIUM | entries_for_field lacks corruption recovery on array walk |

**Rationale**: R-13 is by design for a read-only single-file reader. Live-tailing
requires re-reading n_entries from the mmap'd header on each call.

## verify.rs

| ID | Severity | Issue |
|----|----------|-------|
| D01 | CRITICAL | No tag verification (seqnum, epoch, HMAC) for sealed journals |
| D06 | MEDIUM | No SEALED_CONTINUOUS warning |

**Rationale**: D01 requires FSPRG/HMAC crypto integration which is not yet
complete. When FSS support matures, tag verification should be added.

## fss.rs

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
