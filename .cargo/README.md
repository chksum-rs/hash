# chksum-hash

[![GitHub](https://img.shields.io/badge/github-chksum--rs%2Fhash-24292e?style=flat-square&logo=github "GitHub")](https://github.com/chksum-rs/hash)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/hash/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/hash/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash/)
[![MSRV](https://img.shields.io/badge/MSRV-1.63.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/hash/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-hash/0.5.1/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-hash/0.5.1)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/hash?style=flat-square "LICENSE")](https://github.com/chksum-rs/hash/blob/master/LICENSE)

An implementation of hash algorithms for batch and stream computation.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-hash = "0.5.1"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-hash
```

## Usage

Use the `hash` function for batch digest calculation.

```rust
use chksum_hash::md5;

let digest = md5::hash(b"example data");
assert_eq!(
    digest.to_hex_lowercase(),
    "5c71dbb287630d65ca93764c34d9aa0d"
);
```

Use `default` function to create hash instance for stream digest calculation.

```rust
use chksum_hash::sha2_384;

let digest = sha2_384::default()
    .update("example")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "ef0484e7424aa96c8f3d4910ac081d129b089435e4275b0cec9327a09959359e18c3ca55355fbc32968d20c85c379d86"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-hash/).

## Hash Algorithms

This crate provides implementations for the following hash algorithms:

* MD5
* SHA-1
* SHA-2
  * SHA-2 224
  * SHA-2 256
  * SHA-2 384
  * SHA-2 512

## License

This crate is licensed under the MIT License.
