//! This crate provides an implementation of various hash functions.
//!
//! # Setup
//!
//! To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:
//!
//! ```toml
//! [dependencies]
//! chksum-hash = "0.5.1"
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```sh
//! cargo add chksum-hash
//! ```     
//!
//! # Batch Processing
//!
//! The digest of known-size data can be calculated with the `hash` function.
//!
//! ```rust
//! use chksum_hash::sha2_224;
//!
//! let digest = sha2_224::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "90382cbfda2656313ad61fd74b32ddfa4bcc118f660bd4fba9228ced"
//! );
//! ```
//!
//! # Stream Processing
//!
//! The digest of data streams can be calculated chunk-by-chunk with a consumer created by calling the `default` function.
//!
//! ```rust
//! // Import all necessary items
//! # use std::io;
//! # use std::path::PathBuf;
//! use std::fs::File;
//! use std::io::Read;
//!
//! use chksum_hash::sha2_384;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! // Create a hash instance
//! let mut hash = sha2_384::default();
//!
//! // Open a file and create a buffer for incoming data
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//!
//! // Iterate chunk by chunk
//! while let Ok(count) = file.read(&mut buffer) {
//!     // EOF reached, exit loop
//!     if count == 0 {
//!         break;
//!     }
//!
//!     // Update the hash with data
//!     hash.update(&buffer[..count]);
//! }
//!
//! // Calculate the digest
//! let digest = hash.digest();
//! // Cast the digest to hex and compare
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Algorithms
//!
//! ## MD5
//!
//! ```rust
//! use chksum_hash::md5;
//!
//! let digest = md5::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "5c71dbb287630d65ca93764c34d9aa0d"
//! );
//! ```
//!
//! ## SHA-1
//!
//! ```rust
//! use chksum_hash::sha1;
//!
//! let digest = sha1::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "9fc42adac31303d68b444e6129f13f6093a0e045"
//! );
//! ```
//!
//! ## SHA-2 224
//!
//! ```rust
//! use chksum_hash::sha2_224;
//!
//! let digest = sha2_224::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "90382cbfda2656313ad61fd74b32ddfa4bcc118f660bd4fba9228ced"
//! );
//! ```
//!
//! ## SHA-2 256
//!
//! ```rust
//! use chksum_hash::sha2_256;
//!
//! let digest = sha2_256::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! ```
//!
//! ## SHA-2 384
//!
//! ```rust
//! use chksum_hash::sha2_384;
//!
//! let digest = sha2_384::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! ```
//!
//! ## SHA-2 512
//!
//! ```rust
//! use chksum_hash::sha2_512;
//!
//! let digest = sha2_512::hash("example data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"
//! );
//! ```
//!
//! # Features
//!
//! Cargo features are utilized to enable or disable specific hash algorithms.
//!
//! * `md5` enables MD5, accessible via the [`md5`] module.
//! * `sha1` enables SHA-1, accessible via the [`sha1`] module.
//! * `sha2-224` enables SHA-2 224, accessible via the [`sha2_224`] module.
//! * `sha2-256` enables SHA-2 256, accessible via the [`sha2_256`] module.
//! * `sha2-384` enables SHA-2 384, accessible via the [`sha2_384`] module.
//! * `sha2-512` enables SHA-2 512, accessible via the [`sha2_512`] module.
//!
//! By default, all of these features are enabled.
//!
//! To customize your setup, disable the default features and enable only those that you need in your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! chksum-hash = { version = "0.5.1", default-features = false, features = ["md5", "sha2-512"] }
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```shell
//! cargo add chksum-hash --no-default-features --features sha1,sha2-512
//! ```
//!
//! # License
//!
//! This crate is licensed under the MIT License.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]

#[doc(no_inline)]
pub use chksum_hash_core::{default, hash, Digest, Finalize, Update};
#[cfg(feature = "md5")]
#[doc(no_inline)]
pub use chksum_hash_md5 as md5;
#[cfg(feature = "sha1")]
#[doc(no_inline)]
pub use chksum_hash_sha1 as sha1;
#[cfg(feature = "sha2-224")]
#[doc(no_inline)]
pub use chksum_hash_sha2::sha2_224;
#[cfg(feature = "sha2-256")]
#[doc(no_inline)]
pub use chksum_hash_sha2::sha2_256;
#[cfg(feature = "sha2-384")]
#[doc(no_inline)]
pub use chksum_hash_sha2::sha2_384;
#[cfg(feature = "sha2-512")]
#[doc(no_inline)]
pub use chksum_hash_sha2::sha2_512;
