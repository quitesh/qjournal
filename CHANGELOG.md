# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-04-05

### Fixed
- Merge `SUPPORTED_WRITE`/`SUPPORTED_READ` into single `SUPPORTED` constant matching systemd's `HEADER_INCOMPATIBLE_SUPPORTED` (fixes bug where writer rejected files with compression incompat flags it itself sets).
- Fix `CHAIN_CACHE_MAX`: 1024 → 20 to match systemd.
- Remove duplicate `FSPRG_RECOMMENDED_SECPAR` from `fss.rs` (canonical definition lives in `fsprg.rs`, matching systemd's `fsprg.h`).

### Added
- Add CHANGELOG.md.

## [0.2.0] - 2026-03-29

### Changed
- Bump to 0.2.0 to reflect the scope of changes since 0.1.0.

## [0.1.1] - 2026-03-24

### Fixed
- Fix all divergences found in systemd journal-file.c audit (2 critical, 8 high, 10 medium, 5 low severity).
- Replace hand-rolled Miller-Rabin primality test with `num-prime` crate for correctness.
- Fix inaccurate security comment about `gcry_mpi_release` in FSPRG implementation.

### Changed
- Rewrite `writer.rs` and `reader.rs` as exact 1:1 ports of systemd `journal-file.c`.
- Achieve full systemd `journal-file.c` feature parity.
- Harden FSPRG crypto primitives for forward-secure sealing.
- Remove verbose security note from `fsprg.rs`.

## [0.1.0] - 2026-03-24

### Added
- Initial public release of `qjournal`.
- Cross-platform native systemd-journald compatible journal reader/writer.
- zstd compression support (default).
- Optional xz and lz4 compression support.
- Optional forward-secure sealing (FSS) via FSPRG.
- Cache per-data entry-array tail to avoid O(n^2) linked-list walk.

[0.2.1]: https://github.com/quitesh/qjournal/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/quitesh/qjournal/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/quitesh/qjournal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/quitesh/qjournal/releases/tag/v0.1.0
