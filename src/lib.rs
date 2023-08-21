//! A simple cryptography library that provides an interface for calculating hash digests using both batch and stream computation.
//!
//! # Setup
//!
//! Update your `Cargo.toml` by adding entry to `dependencies` section.
//!
//! ```toml
//! [dependencies]
//! # ...
//! chksum-hash = "0.4.3"
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
//! Use [`hash`] function for batch digest calculation.
//!
//! ```rust
//! use chksum_hash::{hash, SHA2_224};
//!
//! let digest = hash::<SHA2_224, _>(b"somedata");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "a39b86d838273f5ff4879c26f85e3cb333bb44d73b24f275bad1a6c6"
//! );
//! ```
//!
//! ## Stream processing
//!
//! Use [`default`] function to create hash instance for stream digest calculation.
//!
//! ```rust
//! use chksum_hash::{default, SHA2_256};
//!
//! let digest = default::<SHA2_256>()
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
//! * `unstable`: Enables unstable options (like build script).
//!
//! By default only `error` is enabled.
//!
//! # License
//!
//! MIT

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(nightly, feature(optimize_attribute))]
#![forbid(unsafe_code)]

use std::fmt::{LowerHex, UpperHex};

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
#[cfg(feature = "sha2-224")]
pub use sha2::sha224 as sha2_224;
#[cfg(feature = "sha2-256")]
pub use sha2::sha256 as sha2_256;
#[cfg(feature = "sha2-384")]
pub use sha2::sha384 as sha2_384;
#[cfg(feature = "sha2-512")]
pub use sha2::sha512 as sha2_512;

/// Creates default hash instance.
///
/// # Example
///
/// ```rust
/// use chksum_hash::{default, SHA2};
///
/// let digest = default::<SHA2::SHA224>().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769"
/// );
/// ```
#[inline]
#[must_use]
pub fn default<T>() -> T
where
    T: Update,
{
    T::default()
}

/// Computes hash of given input.
///
/// # Example
///
/// ```rust
/// use chksum_hash::{hash, SHA2_256};
///
/// let digest = hash::<SHA2_256, _>("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
#[inline]
#[must_use]
pub fn hash<T, U>(data: U) -> T::Digest
where
    T: Update,
    U: AsRef<[u8]>,
{
    default::<T>().update(data).digest()
}

/// A digest type.
///
/// Types implementing [`Digest`] are able to be returned as a digest from function [`hash`].
pub trait Digest: AsRef<[u8]> + LowerHex + UpperHex + Eq {
    /// Returns digest bytes as a byte slice.
    #[inline]
    #[must_use]
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

/// An in-progress hash type.
///
/// Types implementing [`Update`] are able to be used as an hash algoritm in functions [`hash`] and [`default`].
pub trait Update: Default {
    /// A digest type.
    type Digest: Digest;

    /// A finalized hash type.
    type Finalize: Finalize<Digest = Self::Digest>;

    /// Processes incoming data.
    #[must_use]
    fn update<T: AsRef<[u8]>>(self, data: T) -> Self;

    /// Produces finalized state.
    #[must_use]
    fn finalize(&self) -> Self::Finalize;

    /// Produces digest.
    #[inline]
    #[must_use]
    fn digest(&self) -> Self::Digest {
        self.finalize().digest()
    }

    /// Resets state to default.
    #[must_use]
    fn reset(self) -> Self;
}

/// A finalized hash type.
pub trait Finalize {
    /// A digest type.
    type Digest: Digest;

    /// An in-progress hash type.
    type Update: Update;

    /// Produces digest.
    #[must_use]
    fn digest(&self) -> Self::Digest;

    /// Resets state to default.
    #[must_use]
    fn reset(&self) -> Self::Update;
}

/// [`md5::Update`] type alias.
///
/// # Examples
///
/// Use [`default`] function to create new hash instance.
///
/// ```rust
/// use chksum_hash::{default, MD5};
///
/// let hash = default::<MD5>();
/// ```
///
/// Use [`hash`] function to to calculate digest of given input.
///
/// ```rust
/// use chksum_hash::{hash, MD5};
///
/// let digest = hash::<MD5, _>(b"data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "8d777f385d3dfec8815d20f7496026dc"
/// );
#[cfg(feature = "md5")]
pub type MD5 = md5::Update;

/// [`sha1::Update`] type alias.
///
/// # Examples
///
/// Use [`default`] function to create new hash instance.
///
/// ```rust
/// use chksum_hash::{default, SHA1};
///
/// let hash = default::<SHA1>();
/// ```
///
/// Use [`hash`] function to to calculate digest of given input.
///
/// ```rust
/// use chksum_hash::{hash, SHA1};
///
/// let digest = hash::<SHA1, _>(b"data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd"
/// );
#[cfg(feature = "sha1")]
pub type SHA1 = sha1::Update;

/// [`sha2::sha224::Update`] type alias.
///
/// # Examples
///
/// Use [`default`] function to create new hash instance.
///
/// ```rust
/// use chksum_hash::{default, SHA2_224};
///
/// let hash = default::<SHA2_224>();
/// ```
///
/// Use [`hash`] function to to calculate digest of given input.
///
/// ```rust
/// use chksum_hash::{hash, SHA2_224};
///
/// let digest = hash::<SHA2_224, _>(b"data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769"
/// );
#[cfg(feature = "sha2-224")]
pub type SHA2_224 = sha2::sha224::Update;

/// [`sha2::sha256::Update`] type alias.
///
/// # Examples
///
/// Use [`default`] function to create new hash instance.
///
/// ```rust
/// use chksum_hash::{default, SHA2_256};
///
/// let hash = default::<SHA2_256>();
/// ```
///
/// Use [`hash`] function to to calculate digest of given input.
///
/// ```rust
/// use chksum_hash::{hash, SHA2_256};
///
/// let digest = hash::<SHA2_256, _>(b"data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
#[cfg(feature = "sha2-256")]
pub type SHA2_256 = sha2::sha256::Update;

/// [`sha2::sha384::Update`] type alias.
///
/// # Examples
///
/// Use [`default`] function to create new hash instance.
///
/// ```rust
/// use chksum_hash::{default, SHA2_384};
///
/// let hash = default::<SHA2_384>();
/// ```
///
/// Use [`hash`] function to to calculate digest of given input.
///
/// ```rust
/// use chksum_hash::{hash, SHA2_384};
///
/// let digest = hash::<SHA2_384, _>(b"data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
/// );
#[cfg(feature = "sha2-384")]
pub type SHA2_384 = sha2::sha384::Update;

/// [`sha2::sha512::Update`] type alias.
///
/// # Examples
///
/// Use [`default`] function to create new hash instance.
///
/// ```rust
/// use chksum_hash::{default, SHA2_512};
///
/// let hash = default::<SHA2_512>();
/// ```
///
/// Use [`hash`] function to to calculate digest of given input.
///
/// ```rust
/// use chksum_hash::{hash, SHA2_512};
///
/// let digest = hash::<SHA2_512, _>(b"data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
/// );
#[cfg(feature = "sha2-512")]
pub type SHA2_512 = sha2::sha512::Update;

/// Module aggregator for SHA-2 family hash functions.
#[allow(non_snake_case)]
#[cfg(any(
    feature = "sha2-224",
    feature = "sha2-256",
    feature = "sha2-384",
    feature = "sha2-512"
))]
pub mod SHA2 {
    #[cfg(feature = "sha2-224")]
    pub use crate::SHA2_224 as SHA224;
    #[cfg(feature = "sha2-256")]
    pub use crate::SHA2_256 as SHA256;
    #[cfg(feature = "sha2-384")]
    pub use crate::SHA2_384 as SHA384;
    #[cfg(feature = "sha2-512")]
    pub use crate::SHA2_512 as SHA512;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "md5")]
    #[test]
    fn default_md5_empty() {
        let digest = default::<MD5>().digest().to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

        let digest = default::<MD5>().update("").digest().to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

        let digest = default::<MD5>().update(b"").digest().to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

        let digest = default::<MD5>().update(vec![]).digest().to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[cfg(feature = "md5")]
    #[test]
    fn hash_md5_empty() {
        let digest = hash::<MD5, _>("").to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

        let digest = hash::<MD5, _>(b"").to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

        let digest = hash::<MD5, _>(vec![]).to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[cfg(feature = "md5")]
    #[test]
    fn default_md5_data() {
        let digest = default::<MD5>().update("data").digest().to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = default::<MD5>().update(b"data").digest().to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = default::<MD5>()
            .update(vec![0x64, 0x61, 0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = default::<MD5>().update("da").update("ta").digest().to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = default::<MD5>().update(b"da").update(b"ta").digest().to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = default::<MD5>()
            .update(vec![0x64, 0x61])
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = default::<MD5>().update("da").update(b"ta").digest().to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = default::<MD5>()
            .update(b"da")
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = default::<MD5>()
            .update(vec![0x64, 0x61])
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");
    }

    #[cfg(feature = "md5")]
    #[test]
    fn hash_md5_data() {
        let digest = hash::<MD5, _>("data").to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = hash::<MD5, _>(b"data").to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");

        let digest = hash::<MD5, _>(vec![0x64, 0x61, 0x74, 0x61]).to_hex_lowercase();
        assert_eq!(digest, "8d777f385d3dfec8815d20f7496026dc");
    }

    #[cfg(feature = "md5")]
    #[test]
    fn default_md5_reset() {
        let digest = default::<MD5>().update("data").reset().digest().to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

        let digest = default::<MD5>()
            .update("data")
            .finalize()
            .reset()
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn default_sha1_empty() {
        let digest = default::<SHA1>().digest().to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let digest = default::<SHA1>().update("").digest().to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let digest = default::<SHA1>().update(b"").digest().to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let digest = default::<SHA1>().update(vec![]).digest().to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn hash_sha1_empty() {
        let digest = hash::<SHA1, _>("").to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let digest = hash::<SHA1, _>(b"").to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let digest = hash::<SHA1, _>(vec![]).to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn default_sha1_data() {
        let digest = default::<SHA1>().update("data").digest().to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = default::<SHA1>().update(b"data").digest().to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = default::<SHA1>()
            .update(vec![0x64, 0x61, 0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = default::<SHA1>().update("da").update("ta").digest().to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = default::<SHA1>()
            .update(b"da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = default::<SHA1>()
            .update(vec![0x64, 0x61])
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = default::<SHA1>().update("da").update(b"ta").digest().to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = default::<SHA1>()
            .update(b"da")
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = default::<SHA1>()
            .update(vec![0x64, 0x61])
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn hash_sha1_data() {
        let digest = hash::<SHA1, _>("data").to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = hash::<SHA1, _>(b"data").to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");

        let digest = hash::<SHA1, _>(vec![0x64, 0x61, 0x74, 0x61]).to_hex_lowercase();
        assert_eq!(digest, "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn default_sha1_reset() {
        let digest = default::<SHA1>().update("data").reset().digest().to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let digest = default::<SHA1>()
            .update("data")
            .finalize()
            .reset()
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[cfg(feature = "sha2-224")]
    #[test]
    fn default_sha2_224_empty() {
        let digest = default::<SHA2_224>().digest().to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

        let digest = default::<SHA2_224>().update("").digest().to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

        let digest = default::<SHA2_224>().update(b"").digest().to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

        let digest = default::<SHA2_224>().update(vec![]).digest().to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    #[cfg(feature = "sha2-224")]
    #[test]
    fn hash_sha2_224_empty() {
        let digest = hash::<SHA2_224, _>("").to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

        let digest = hash::<SHA2_224, _>(b"").to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

        let digest = hash::<SHA2_224, _>(vec![]).to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    #[cfg(feature = "sha2-224")]
    #[test]
    fn default_sha2_224_data() {
        let digest = default::<SHA2_224>().update("data").digest().to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = default::<SHA2_224>().update(b"data").digest().to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = default::<SHA2_224>()
            .update(vec![0x64, 0x61, 0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = default::<SHA2_224>()
            .update("da")
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = default::<SHA2_224>()
            .update(b"da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = default::<SHA2_224>()
            .update(vec![0x64, 0x61])
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = default::<SHA2_224>()
            .update("da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = default::<SHA2_224>()
            .update(b"da")
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = default::<SHA2_224>()
            .update(vec![0x64, 0x61])
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");
    }

    #[cfg(feature = "sha2-224")]
    #[test]
    fn hash_sha2_224_data() {
        let digest = hash::<SHA2_224, _>("data").to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = hash::<SHA2_224, _>(b"data").to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");

        let digest = hash::<SHA2_224, _>(vec![0x64, 0x61, 0x74, 0x61]).to_hex_lowercase();
        assert_eq!(digest, "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");
    }

    #[cfg(feature = "sha2-224")]
    #[test]
    fn default_sha2_224_reset() {
        let digest = default::<SHA2_224>().update("data").reset().digest().to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

        let digest = default::<SHA2_224>()
            .update("data")
            .finalize()
            .reset()
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    #[cfg(feature = "sha2-256")]
    #[test]
    fn default_sha2_256_empty() {
        let digest = default::<SHA2_256>().digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = default::<SHA2_256>().update("").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = default::<SHA2_256>().update(b"").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = default::<SHA2_256>().update(vec![]).digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[cfg(feature = "sha2-256")]
    #[test]
    fn hash_sha2_256_empty() {
        let digest = hash::<SHA2_256, _>("").to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = hash::<SHA2_256, _>(b"").to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = hash::<SHA2_256, _>(vec![]).to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[cfg(feature = "sha2-256")]
    #[test]
    fn default_sha2_256_data() {
        let digest = default::<SHA2_256>().update("data").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = default::<SHA2_256>().update(b"data").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = default::<SHA2_256>()
            .update(vec![0x64, 0x61, 0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = default::<SHA2_256>()
            .update("da")
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = default::<SHA2_256>()
            .update(b"da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = default::<SHA2_256>()
            .update(vec![0x64, 0x61])
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = default::<SHA2_256>()
            .update("da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = default::<SHA2_256>()
            .update(b"da")
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = default::<SHA2_256>()
            .update(vec![0x64, 0x61])
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );
    }

    #[cfg(feature = "sha2-256")]
    #[test]
    fn hash_sha2_256_data() {
        let digest = hash::<SHA2_256, _>("data").to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = hash::<SHA2_256, _>(b"data").to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );

        let digest = hash::<SHA2_256, _>(vec![0x64, 0x61, 0x74, 0x61]).to_hex_lowercase();
        assert_eq!(
            digest,
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
        );
    }

    #[cfg(feature = "sha2-256")]
    #[test]
    fn default_sha2_256_reset() {
        let digest = default::<SHA2_256>().update("data").reset().digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = default::<SHA2_256>()
            .update("data")
            .finalize()
            .reset()
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[cfg(feature = "sha2-384")]
    #[test]
    fn default_sha2_384_empty() {
        let digest = default::<SHA2_384>().digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let digest = default::<SHA2_384>().update("").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let digest = default::<SHA2_384>().update(b"").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let digest = default::<SHA2_384>().update(vec![]).digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[cfg(feature = "sha2-384")]
    #[test]
    fn hash_sha2_384_empty() {
        let digest = hash::<SHA2_384, _>("").to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let digest = hash::<SHA2_384, _>(b"").to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let digest = hash::<SHA2_384, _>(vec![]).to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[cfg(feature = "sha2-384")]
    #[test]
    fn default_sha2_384_data() {
        let digest = default::<SHA2_384>().update("data").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = default::<SHA2_384>().update(b"data").digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = default::<SHA2_384>()
            .update(vec![0x64, 0x61, 0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = default::<SHA2_384>()
            .update("da")
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = default::<SHA2_384>()
            .update(b"da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = default::<SHA2_384>()
            .update(vec![0x64, 0x61])
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = default::<SHA2_384>()
            .update("da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = default::<SHA2_384>()
            .update(b"da")
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = default::<SHA2_384>()
            .update(vec![0x64, 0x61])
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );
    }

    #[cfg(feature = "sha2-384")]
    #[test]
    fn hash_sha2_384_data() {
        let digest = hash::<SHA2_384, _>("data").to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = hash::<SHA2_384, _>(b"data").to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let digest = hash::<SHA2_384, _>(vec![0x64, 0x61, 0x74, 0x61]).to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );
    }

    #[cfg(feature = "sha2-384")]
    #[test]
    fn default_sha2_384_reset() {
        let digest = default::<SHA2_384>().update("data").reset().digest().to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let digest = default::<SHA2_384>()
            .update("data")
            .finalize()
            .reset()
            .digest()
            .to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[cfg(feature = "sha2-512")]
    #[test]
    fn default_sha2_512_empty() {
        let digest = default::<SHA2_512>().digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = default::<SHA2_512>().update("").digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = default::<SHA2_512>().update(b"").digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = default::<SHA2_512>().update(vec![]).digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[cfg(feature = "sha2-512")]
    #[test]
    fn hash_sha2_512_empty() {
        let digest = hash::<SHA2_512, _>("").to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = hash::<SHA2_512, _>(b"").to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = hash::<SHA2_512, _>(vec![]).to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[cfg(feature = "sha2-512")]
    #[test]
    fn default_sha2_512_data() {
        let digest = default::<SHA2_512>().update("data").digest().to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = default::<SHA2_512>().update(b"data").digest().to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = default::<SHA2_512>()
            .update(vec![0x64, 0x61, 0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = default::<SHA2_512>()
            .update("da")
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = default::<SHA2_512>()
            .update(b"da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = default::<SHA2_512>()
            .update(vec![0x64, 0x61])
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = default::<SHA2_512>()
            .update("da")
            .update(b"ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = default::<SHA2_512>()
            .update(b"da")
            .update(vec![0x74, 0x61])
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = default::<SHA2_512>()
            .update(vec![0x64, 0x61])
            .update("ta")
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");
    }

    #[cfg(feature = "sha2-512")]
    #[test]
    fn hash_sha2_512_data() {
        let digest = hash::<SHA2_512, _>("data").to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = hash::<SHA2_512, _>(b"data").to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");

        let digest = hash::<SHA2_512, _>(vec![0x64, 0x61, 0x74, 0x61]).to_hex_lowercase();
        assert_eq!(digest, "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");
    }

    #[cfg(feature = "sha2-512")]
    #[test]
    fn default_sha2_512_reset() {
        let digest = default::<SHA2_512>().update("data").reset().digest().to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = default::<SHA2_512>()
            .update("data")
            .finalize()
            .reset()
            .digest()
            .to_hex_lowercase();
        assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }
}
