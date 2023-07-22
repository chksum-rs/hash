# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## Changed

- Changed crate description.

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

[Unreleased]: https://github.com/ferric-bytes/chksum-hash/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ferric-bytes/chksum-hash/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/ferric-bytes/chksum-hash/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/ferric-bytes/chksum-hash/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ferric-bytes/chksum-hash/releases/tag/v0.2.0
