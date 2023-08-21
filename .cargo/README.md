# chksum-hash

[![GitHub](https://img.shields.io/badge/github-ferric--bytes%2Fchksum--hash-24292e?style=flat-square&logo=github "GitHub")](https://github.com/ferric-bytes/chksum-hash)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash)
[![Coverage](https://img.shields.io/codecov/c/gh/ferric-bytes/chksum-hash?style=flat-square&logo=codecov "Coverage")](https://app.codecov.io/gh/ferric-bytes/chksum-hash)
[![MSRV](https://img.shields.io/badge/MSRV-1.59.0-informational?style=flat-square "MSRV")](https://github.com/ferric-bytes/chksum-hash/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-hash/0.4.3/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-hash/0.4.3)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/ferric-bytes/chksum-hash?style=flat-square "LICENSE")](https://github.com/ferric-bytes/chksum-hash/blob/master/LICENSE)

A simple cryptography library that provides an interface for calculating hash digests using both batch and stream computation.

## Features

- Written in pure Rust
- No unsafe code
- Configurable via Cargo features
- Can be built without any dependencies

## Setup

Add the following entry to the `dependencies` section of your `Cargo.toml` file:

```toml
[dependencies]
# ...
chksum-hash = "0.4.3"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-hash
```

## Usage

Use `hash` function for batch digest calculation.

```rust
use chksum_hash::{hash, SHA2_224};

let digest = hash::<SHA2_224, _>(b"somedata");
assert_eq!(
    digest.to_hex_lowercase(),
    "a39b86d838273f5ff4879c26f85e3cb333bb44d73b24f275bad1a6c6"
);
```

Use `default` function to create hash instance for stream digest calculation.

```rust
use chksum_hash::{default, SHA2_256};

let digest = default::<SHA2_256>()
    .update("some")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "5c3bfbc8614adc72d3ec0e9b15a1fd1c55cee63e34af5a4ff058eb2eef7d8482"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-hash).

## License

MIT
