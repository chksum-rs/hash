//! A simple cryptography library that provides an interface for calculating hash digests using both batch and stream computation.
//!
//! # Setup
//!
//! Update your `Cargo.toml` by adding entry to `dependencies` section.
//!
//! ```toml
//! [dependencies]
//! # ...
//! chksum-hash = "0.3.0"
//! ```
//!
//! Alternatively use [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand.
//!
//! ```shell
//! cargo add chksum-hash
//! ```
//!
//! # Usage example
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha256::new()
//!     .update("some")
//!     .update(b"data")
//!     .update([0, 1, 2, 3])
//!     .digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "5c3bfbc8614adc72d3ec0e9b15a1fd1c55cee63e34af5a4ff058eb2eef7d8482"
//! );
//! ```
//!
//! # Feature flags
//!
//! ## Algorithms
//!
//! * `md5`: Enables MD5 hash algorithm.
//! * `sha1`: Enables SHA-1 hash algorithm.
//! * `sha2`: Enables SHA-2 hash family algorithms.
//!   * `sha2-224`: Enables only SHA-2 224 hash algorithm.
//!   * `sha2-256`: Enables only SHA-2 256 hash algorithm.
//!   * `sha2-384`: Enables only SHA-2 384 hash algorithm.
//!   * `sha2-512`: Enables only SHA-2 512 hash algorithm.
//!
//! By default all of them are enabled.
//!
//! ## Compilation
//!
//! * `error`: Adds [`Error`] related implementations.
//! * `inline`: Adds `#[inline]` attribute to some methods on release build.
//!
//! By default all of them are enabled.
//!
//! # License
//!
//! MIT

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(nightly, feature(optimize_attribute))]
#![cfg_attr(nightly, feature(no_coverage))]
#![forbid(unsafe_code)]

#[cfg(feature = "error")]
mod error;
#[cfg(feature = "md5")]
pub mod md5;
#[cfg(feature = "sha1")]
pub mod sha1;
#[cfg(any(
    feature = "sha2-224",
    feature = "sha2-256",
    feature = "sha2-384",
    feature = "sha2-512"
))]
pub mod sha2;

#[cfg(feature = "error")]
pub use error::{Error, Result};
