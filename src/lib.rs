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
//! # Usage
//!
//! ## Batch processing
//!
//! Use `hash` function for batch digest calculation.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha224::hash(b"somedata");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "a39b86d838273f5ff4879c26f85e3cb333bb44d73b24f275bad1a6c6"
//! );
//! ```
//!
//! ## Stream processing
//!
//! Use `new` or `default` function to create hash instance for stream digest calculation.
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
//! # Algorithms
//!
//! ## MD5
//!
//! ```rust
//! use chksum_hash::md5;
//!
//! let digest = md5::hash(b"data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "8d777f385d3dfec8815d20f7496026dc"
//! );
//! ```
//!
//! Check [`md5`] module for more informations and usage examples.
//!
//! ## SHA-1
//!
//! ```rust
//! use chksum_hash::sha1;
//!
//! let digest = sha1::hash(b"data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd"
//! );
//! ```
//!
//! Check [`sha1`] module for more informations and usage examples.
//!
//! ## SHA-2
//!
//! ### SHA-2 224
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha224::hash(b"data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769"
//! );
//! ```
//!
//! Check [`sha2::sha224`] module for more informations and usage examples.
//!
//! ### SHA-2 256
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha256::hash(b"data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
//! );
//! ```
//!
//! Check [`sha2::sha256`] module for more informations and usage examples.
//!
//! ### SHA-2 384
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha384::hash(b"data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
//! );
//! ```
//!
//! Check [`sha2::sha384`] module for more informations and usage examples.
//!
//! ### SHA-2 512
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha512::hash(b"data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
//! );
//! ```
//!
//! Check [`sha2::sha512`] module for more informations and usage examples.
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
