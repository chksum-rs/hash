# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Removed `sha2` and `SHA2` modules.

## [0.4.3] - 2023-08-21

### Added

- Added `unstable` feature.

## [0.4.2] - 2023-08-17

### Fixed

- Fixed headers level in `CHANGELOG.md`.
- Fixed word typo in `CHANGELOG.md`.

### Changed

- Changed usage of SHA-2 modules in examples to top-level alias.
- Changed tests names and split them into many.

### Removed

- Removed `inline` feature.
- Removed `no_coverage` feature (available for nightly builds).

## [0.4.1] - 2023-08-05

### Added

- Added link to GitHub Action in `README.md`.
- Added badge to [deps.rs](https://deps.rs/) to keep dependencies up-to-date.
- Added different `README.md` for Cargo.

### Fixed

- Fixed tests code format to be rustfmt compatible.

### Changed

- Changed place of coverage badge in `README.md`.
- Changed modules to be modules aliases via `pub use`.
- Changed types to be types aliases via `pub use`.
- Changed SHA-2 tests to be split between files.

## [0.4.0] - 2023-07-26

### Added

- Added algorithms description in docs.
- Added `Digest`, `Update` and `Finalize` traits.
- Added modules aliases and module aggregator for SHA-2 family.

### Fixed

- Fixed typos in `README.md` and crate docs.
- Fixed typos in limitations section in `examples/README.md`.
- Fixed doc description for `Result` alias.
- Fixed code format to be rustfmt compatible.

### Changed

- Changed crate description.
- Changed `doc_cfg` feature with `doc_auto_cfg`.
- Changed conditional attribute `#[doc(hidden)]` to be conditionless.
- Changed build script to meet rustfmt styles guidelines.
- Changed usage examples in docs.
- Changed functions and methods to use destructive pattern.
- Changed `State` and `Update` structs to take ownership instead of reference.

### Removed

- Removed enums at top level of the crate.
- Removed `verify` functions.

## [0.3.0] - 2023-06-01

### Added

- Added `Default` trait to `State` and `Update` structs.
- Added examples (one for each hash function).

### Changed

- Changed descriptions in `README.md`.

### Removed

- Removed unnecessary `#[doc]` attributes for `Algorithm` variants.

## [0.2.2] - 2023-03-18

### Added

- Added `pub use` for `Algorithm` variants.
- Added `inline` feature.
- Added tests for `verify` methods.

### Changed

- Changed `Algorithm`, `Update`, `Finalized` and `Digest` enums as non-exhaustive.

### Removed

- Removed `anyhow` as dev-depenedency.
- Removed `criterion` as dev-depenedency.
- Removed `tempfile` as dev-depenedency.

## [0.2.1] - 2023-01-02

### Fixed

- Fixed `chksum-build` dependency.

## [0.2.0] - 2023-01-02

### Added

- Initial release.

[Unreleased]: https://github.com/ferric-bytes/chksum-hash/compare/v0.4.3...HEAD
[0.4.3]: https://github.com/ferric-bytes/chksum-hash/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/ferric-bytes/chksum-hash/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/ferric-bytes/chksum-hash/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ferric-bytes/chksum-hash/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ferric-bytes/chksum-hash/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/ferric-bytes/chksum-hash/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/ferric-bytes/chksum-hash/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ferric-bytes/chksum-hash/releases/tag/v0.2.0
