# chksum-hash

![Build](https://img.shields.io/github/actions/workflow/status/ferric-bytes/chksum-hash/rust.yml?branch=master&style=flat-square&logo=github "Build")
[![Coverage](https://img.shields.io/codecov/c/gh/ferric-bytes/chksum-hash?style=flat-square&logo=codecov "Coverage")](https://app.codecov.io/gh/ferric-bytes/chksum-hash)
[![crates.io](https://img.shields.io/crates/v/chksum-hash?style=flat-square&logo=rust "crates.io")](https://crates.io/crates/chksum-hash)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash)
[![MSRV](https://img.shields.io/badge/MSRV-1.59.0-informational?style=flat-square "MSRV")](https://github.com/ferric-bytes/chksum-hash/blob/master/Cargo.toml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/ferric-bytes/chksum-hash?style=flat-square "LICENSE")](https://github.com/ferric-bytes/chksum-hash/blob/master/LICENSE)

Simple cryptography library that provides interface for calculating both batch and stream computation of hash digest.

## Features

* Pure Rust,
* No unsafe code,
* Configurable via Cargo features,
* Can be built without any dependencies.

## Setup

Update your `Cargo.toml` by adding entry to `dependencies` section.

```toml
[dependencies]
# ...
chksum-hash = "0.2.0"
```

Alternatively use [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand.

```sh
cargo add chksum-hash
```

## Usage

```rust
use chksum_hash as hash;

let digest = hash::new(hash::Algorithm::SHA2_256)
    .update("some")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "5c3bfbc8614adc72d3ec0e9b15a1fd1c55cee63e34af5a4ff058eb2eef7d8482"
);
```

More usage examples are available in the documentation at [docs.rs](https://docs.rs/chksum-hash).

## License

MIT