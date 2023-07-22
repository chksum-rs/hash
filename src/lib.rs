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
//! ```sh
//! cargo add chksum-hash
//! ```
//!
//! # Usage example
//!
//! ```rust
//! use chksum_hash as hash;
//!
//! let digest = hash::new(hash::SHA2_256)
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

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(nightly, feature(optimize_attribute))]
#![cfg_attr(nightly, feature(no_coverage))]
#![forbid(unsafe_code)]

use std::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use std::vec::IntoIter;

#[cfg(feature = "error")]
#[cfg_attr(docsrs, doc(cfg(feature = "error")))]
mod error;
#[cfg(feature = "md5")]
#[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
pub mod md5;
#[cfg(feature = "sha1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
pub mod sha1;
#[cfg(any(
    feature = "sha2-224",
    feature = "sha2-256",
    feature = "sha2-384",
    feature = "sha2-512"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "sha2-224",
        feature = "sha2-256",
        feature = "sha2-384",
        feature = "sha2-512"
    )))
)]
pub mod sha2;

#[cfg(feature = "error")]
pub use error::{Error, Result};

/// Represents hash algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Algorithm {
    /// MD5 hash function implemented in [`md5`] module.
    #[cfg(feature = "md5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
    MD5,
    /// SHA-1 hash function implemented in [`sha1`] module.
    #[cfg(feature = "sha1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
    SHA1,
    /// SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    #[cfg(feature = "sha2-224")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-224")))]
    SHA2_224,
    /// SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    #[cfg(feature = "sha2-256")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-256")))]
    SHA2_256,
    /// SHA-2 384 hash function implemented in [`sha2::sha384`] module.
    #[cfg(feature = "sha2-384")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-384")))]
    SHA2_384,
    /// SHA-2 512 hash function implemented in [`sha2::sha512`] module.
    #[cfg(feature = "sha2-512")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-512")))]
    SHA2_512,
}

impl Algorithm {
    /// Returns iterator through all algorithms.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn into_iter() -> IntoIter<Self> {
        let algorithms = vec![
            #[cfg(feature = "md5")]
            Self::MD5,
            #[cfg(feature = "sha1")]
            Self::SHA1,
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224,
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256,
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384,
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512,
        ];
        algorithms.into_iter()
    }

    /// Returns digest bits.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub const fn digest_bits(&self) -> usize {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5 => md5::digest::LENGTH_BITS,
            #[cfg(feature = "sha1")]
            Self::SHA1 => sha1::digest::LENGTH_BITS,
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224 => sha2::sha224::digest::LENGTH_BITS,
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256 => sha2::sha256::digest::LENGTH_BITS,
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384 => sha2::sha384::digest::LENGTH_BITS,
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512 => sha2::sha512::digest::LENGTH_BITS,
        }
    }
}

impl Display for Algorithm {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5 => write!(f, "MD5"),
            #[cfg(feature = "sha1")]
            Self::SHA1 => write!(f, "SHA-1"),
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224 => write!(f, "SHA-2 224"),
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256 => write!(f, "SHA-2 256"),
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384 => write!(f, "SHA-2 384"),
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512 => write!(f, "SHA-2 512"),
        }
    }
}

#[cfg(feature = "md5")]
pub use Algorithm::MD5;
#[cfg(feature = "sha1")]
pub use Algorithm::SHA1;
#[cfg(feature = "sha2-224")]
pub use Algorithm::SHA2_224;
#[cfg(feature = "sha2-256")]
pub use Algorithm::SHA2_256;
#[cfg(feature = "sha2-384")]
pub use Algorithm::SHA2_384;
#[cfg(feature = "sha2-512")]
pub use Algorithm::SHA2_512;

/// Represents hash digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Digest {
    /// Digest of MD5 hash function implemented in [`md5`] module.
    ///
    /// Read more - [`md5::Digest`].
    #[cfg(feature = "md5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
    MD5(md5::Digest),
    /// Digest of SHA-1 hash function implemented in [`sha1`] module.
    ///
    /// Read more - [`sha1::Digest`].
    #[cfg(feature = "sha1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
    SHA1(sha1::Digest),
    /// Digest of SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    ///
    /// Read more - [`sha2::sha224::Digest`].
    #[cfg(feature = "sha2-224")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-224")))]
    SHA2_224(sha2::sha224::Digest),
    /// Digest of SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    ///
    /// Read more - [`sha2::sha256::Digest`].
    #[cfg(feature = "sha2-256")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-256")))]
    SHA2_256(sha2::sha256::Digest),
    /// Digest of SHA-2 384 hash function implemented in [`sha2::sha384`] module.
    ///
    /// Read more - [`sha2::sha384::Digest`].
    #[cfg(feature = "sha2-384")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-384")))]
    SHA2_384(sha2::sha384::Digest),
    /// Digest of SHA-2 512 hash function implemented in [`sha2::sha512`] module.
    ///
    /// Read more - [`sha2::sha512::Digest`].
    #[cfg(feature = "sha2-512")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-512")))]
    SHA2_512(sha2::sha512::Digest),
}

impl Digest {
    /// Returns digest bytes as a byte slice.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "md5")]
            #[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
            Self::MD5(digest) => digest.as_bytes(),
            #[cfg(feature = "sha1")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
            Self::SHA1(digest) => digest.as_bytes(),
            #[cfg(feature = "sha2-224")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-224")))]
            Self::SHA2_224(digest) => digest.as_bytes(),
            #[cfg(feature = "sha2-256")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-256")))]
            Self::SHA2_256(digest) => digest.as_bytes(),
            #[cfg(feature = "sha2-384")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-384")))]
            Self::SHA2_384(digest) => digest.as_bytes(),
            #[cfg(feature = "sha2-512")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-512")))]
            Self::SHA2_512(digest) => digest.as_bytes(),
        }
    }

    /// Returns lowercase hexadecimal representation of digest.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn to_hex_lowercase(&self) -> String {
        match self {
            #[cfg(feature = "md5")]
            #[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
            Self::MD5(digest) => digest.to_hex_lowercase(),
            #[cfg(feature = "sha1")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
            Self::SHA1(digest) => digest.to_hex_lowercase(),
            #[cfg(feature = "sha2-224")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-224")))]
            Self::SHA2_224(digest) => digest.to_hex_lowercase(),
            #[cfg(feature = "sha2-256")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-256")))]
            Self::SHA2_256(digest) => digest.to_hex_lowercase(),
            #[cfg(feature = "sha2-384")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-384")))]
            Self::SHA2_384(digest) => digest.to_hex_lowercase(),
            #[cfg(feature = "sha2-512")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-512")))]
            Self::SHA2_512(digest) => digest.to_hex_lowercase(),
        }
    }

    /// Returns uppercase hexadecimal representation of digest.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn to_hex_uppercase(&self) -> String {
        match self {
            #[cfg(feature = "md5")]
            #[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
            Self::MD5(digest) => digest.to_hex_uppercase(),
            #[cfg(feature = "sha1")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
            Self::SHA1(digest) => digest.to_hex_uppercase(),
            #[cfg(feature = "sha2-224")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-224")))]
            Self::SHA2_224(digest) => digest.to_hex_uppercase(),
            #[cfg(feature = "sha2-256")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-256")))]
            Self::SHA2_256(digest) => digest.to_hex_uppercase(),
            #[cfg(feature = "sha2-384")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-384")))]
            Self::SHA2_384(digest) => digest.to_hex_uppercase(),
            #[cfg(feature = "sha2-512")]
            #[cfg_attr(docsrs, doc(cfg(feature = "sha2-512")))]
            Self::SHA2_512(digest) => digest.to_hex_uppercase(),
        }
    }
}

impl AsRef<[u8]> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(feature = "md5")]
#[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
impl From<md5::Digest> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(digest: md5::Digest) -> Self {
        Self::MD5(digest)
    }
}

#[cfg(feature = "sha1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
impl From<sha1::Digest> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(digest: sha1::Digest) -> Self {
        Self::SHA1(digest)
    }
}

#[cfg(feature = "sha2-224")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2-224")))]
impl From<sha2::sha224::Digest> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(digest: sha2::sha224::Digest) -> Self {
        Self::SHA2_224(digest)
    }
}

#[cfg(feature = "sha2-256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2-256")))]
impl From<sha2::sha256::Digest> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(digest: sha2::sha256::Digest) -> Self {
        Self::SHA2_256(digest)
    }
}

#[cfg(feature = "sha2-384")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2-384")))]
impl From<sha2::sha384::Digest> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(digest: sha2::sha384::Digest) -> Self {
        Self::SHA2_384(digest)
    }
}

#[cfg(feature = "sha2-512")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2-512")))]
impl From<sha2::sha512::Digest> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(digest: sha2::sha512::Digest) -> Self {
        Self::SHA2_512(digest)
    }
}

impl LowerHex for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha1")]
            Self::SHA1(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512(digest) => LowerHex::fmt(digest, f),
        }
    }
}

impl UpperHex for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha1")]
            Self::SHA1(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512(digest) => UpperHex::fmt(digest, f),
        }
    }
}

/// Creates new hash instance.
///
/// Check [`Update`] for more details.
#[cfg_attr(all(release, feature = "inline"), inline)]
#[must_use]
pub fn new(algorithm: Algorithm) -> Update {
    Update::new(algorithm)
}

/// Computes hash of given input.
#[cfg_attr(all(release, feature = "inline"), inline)]
#[must_use]
pub fn hash<T>(algorithm: Algorithm, data: T) -> Digest
where
    T: AsRef<[u8]>,
{
    new(algorithm).update(data).digest()
}

/// Verifies hash for given input.
#[cfg_attr(all(release, feature = "inline"), inline)]
#[must_use]
pub fn verify<T>(algorithm: Algorithm, data: T, digest: Digest) -> bool
where
    T: AsRef<[u8]>,
{
    hash(algorithm, data) == digest
}

/// Represents in-progress hash state.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Update {
    /// In-progress state of MD5 hash function implemented in [`md5`] module.
    ///
    /// Read more - [`md5::Update`].
    #[cfg(feature = "md5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
    MD5(md5::Update),
    /// In-progress state of SHA-1 hash function implemented in [`sha1`] module.
    ///
    /// Read more - [`sha1::Update`].
    #[cfg(feature = "sha1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
    SHA1(sha1::Update),
    /// In-progress state of SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    ///
    /// Read more - [`sha2::sha224::Update`].
    #[cfg(feature = "sha2-224")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-224")))]
    SHA2_224(sha2::sha224::Update),
    /// In-progress state of SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    ///
    /// Read more - [`sha2::sha256::Update`].
    #[cfg(feature = "sha2-256")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-256")))]
    SHA2_256(sha2::sha256::Update),
    /// In-progress state of SHA-2 384 hash function implemented in [`sha2::sha384`] module.
    ///
    /// Read more - [`sha2::sha384::Update`].
    #[cfg(feature = "sha2-384")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-384")))]
    SHA2_384(sha2::sha384::Update),
    /// In-progress state of SHA-2 512 hash function implemented in [`sha2::sha512`] module.
    ///
    /// Read more - [`sha2::sha512::Update`].
    #[cfg(feature = "sha2-512")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-512")))]
    SHA2_512(sha2::sha512::Update),
}

impl Update {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            #[cfg(feature = "md5")]
            Algorithm::MD5 => Self::MD5(md5::new()),
            #[cfg(feature = "sha1")]
            Algorithm::SHA1 => Self::SHA1(sha1::new()),
            #[cfg(feature = "sha2-224")]
            Algorithm::SHA2_224 => Self::SHA2_224(sha2::sha224::new()),
            #[cfg(feature = "sha2-256")]
            Algorithm::SHA2_256 => Self::SHA2_256(sha2::sha256::new()),
            #[cfg(feature = "sha2-384")]
            Algorithm::SHA2_384 => Self::SHA2_384(sha2::sha384::new()),
            #[cfg(feature = "sha2-512")]
            Algorithm::SHA2_512 => Self::SHA2_512(sha2::sha512::new()),
        }
    }

    /// Produces final digest.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn digest(&self) -> Digest {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(md5) => Digest::MD5(md5.digest()),
            #[cfg(feature = "sha1")]
            Self::SHA1(sha1) => Digest::SHA1(sha1.digest()),
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224(sha2_224) => Digest::SHA2_224(sha2_224.digest()),
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256(sha2_256) => Digest::SHA2_256(sha2_256.digest()),
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384(sha2_384) => Digest::SHA2_384(sha2_384.digest()),
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512(sha2_512) => Digest::SHA2_512(sha2_512.digest()),
        }
    }

    /// Applies padding and produces finalized state.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn finalize(&self) -> Finalize {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(md5) => Finalize::MD5(md5.finalize()),
            #[cfg(feature = "sha1")]
            Self::SHA1(sha1) => Finalize::SHA1(sha1.finalize()),
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224(sha2_224) => Finalize::SHA2_224(sha2_224.finalize()),
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256(sha2_256) => Finalize::SHA2_256(sha2_256.finalize()),
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384(sha2_384) => Finalize::SHA2_384(sha2_384.finalize()),
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512(sha2_512) => Finalize::SHA2_512(sha2_512.finalize()),
        }
    }

    /// Processes incoming data.
    ///
    /// # Performance issues
    ///
    /// To achieve maximum performance length of incoming data parts should be multiply of block length.
    ///
    /// In any other case internal buffer is used which can cause speed down the performance.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    pub fn update<T>(&mut self, data: T) -> &mut Self
    where
        T: AsRef<[u8]>,
    {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(md5) => {
                md5.update(data);
            },
            #[cfg(feature = "sha1")]
            Self::SHA1(sha1) => {
                sha1.update(data);
            },
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224(sha2_224) => {
                sha2_224.update(data);
            },
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256(sha2_256) => {
                sha2_256.update(data);
            },
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384(sha2_384) => {
                sha2_384.update(data);
            },
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512(sha2_512) => {
                sha2_512.update(data);
            },
        }
        self
    }

    /// Resets state to default without any new memory allocations.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    pub fn reset(&mut self) -> &mut Self {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(md5) => {
                md5.reset();
            },
            #[cfg(feature = "sha1")]
            Self::SHA1(sha1) => {
                sha1.reset();
            },
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224(sha2_224) => {
                sha2_224.reset();
            },
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256(sha2_256) => {
                sha2_256.reset();
            },
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384(sha2_384) => {
                sha2_384.reset();
            },
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512(sha2_512) => {
                sha2_512.reset();
            },
        }
        self
    }

    /// Verifies processed data against given digest.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn verify(&self, digest: Digest) -> bool {
        self.digest() == digest
    }
}

/// Represents finalized state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Finalize {
    /// Finalized state of MD5 hash function implemented in [`md5`] module.
    ///
    /// Read more - [`md5::Finalize`].
    #[cfg(feature = "md5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "md5")))]
    MD5(md5::Finalize),
    /// Finalized state of SHA-1 hash function implemented in [`sha1`] module.
    ///
    /// Read more - [`sha1::Finalize`].
    #[cfg(feature = "sha1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
    SHA1(sha1::Finalize),
    /// Finalized state of SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    ///
    /// Read more - [`sha2::sha224::Finalize`].
    #[cfg(feature = "sha2-224")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-224")))]
    SHA2_224(sha2::sha224::Finalize),
    /// Finalized state of SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    ///
    /// Read more - [`sha2::sha256::Finalize`].
    #[cfg(feature = "sha2-256")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-256")))]
    SHA2_256(sha2::sha256::Finalize),
    /// Finalized state of SHA-2 384 hash function implemented in [`sha2::sha384`] module.
    ///
    /// Read more - [`sha2::sha384::Finalize`].
    #[cfg(feature = "sha2-384")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-384")))]
    SHA2_384(sha2::sha384::Finalize),
    /// Finalized state of SHA-2 512 hash function implemented in [`sha2::sha512`] module.
    ///
    /// Read more - [`sha2::sha512::Finalize`].
    #[cfg(feature = "sha2-512")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha2-512")))]
    SHA2_512(sha2::sha512::Finalize),
}

impl Finalize {
    /// Produces digest.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn digest(&self) -> Digest {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(md5) => Digest::MD5(md5.digest()),
            #[cfg(feature = "sha1")]
            Self::SHA1(sha1) => Digest::SHA1(sha1.digest()),
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224(sha2_224) => Digest::SHA2_224(sha2_224.digest()),
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256(sha2_256) => Digest::SHA2_256(sha2_256.digest()),
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384(sha2_384) => Digest::SHA2_384(sha2_384.digest()),
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512(sha2_512) => Digest::SHA2_512(sha2_512.digest()),
        }
    }

    /// Resets state to default.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn reset(&self) -> Update {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(md5) => Update::MD5(md5.reset()),
            #[cfg(feature = "sha1")]
            Self::SHA1(sha1) => Update::SHA1(sha1.reset()),
            #[cfg(feature = "sha2-224")]
            Self::SHA2_224(sha2_224) => Update::SHA2_224(sha2_224.reset()),
            #[cfg(feature = "sha2-256")]
            Self::SHA2_256(sha2_256) => Update::SHA2_256(sha2_256.reset()),
            #[cfg(feature = "sha2-384")]
            Self::SHA2_384(sha2_384) => Update::SHA2_384(sha2_384.reset()),
            #[cfg(feature = "sha2-512")]
            Self::SHA2_512(sha2_512) => Update::SHA2_512(sha2_512.reset()),
        }
    }

    /// Verifies state against given digest.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn verify(&self, digest: Digest) -> bool {
        self.digest() == digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "md5")]
    #[test]
    fn test_md5() {
        assert_eq!(format!("{}", MD5), "MD5");

        let digest = new(MD5).digest();
        assert_eq!(digest.to_hex_lowercase(), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(digest.to_hex_uppercase(), "D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(verify(MD5, b"", digest), true);
        assert_eq!(format!("{digest:x}"), digest.to_hex_lowercase());
        assert_eq!(format!("{digest:X}"), digest.to_hex_uppercase());

        let digest = new(MD5).update("data").digest();
        assert_eq!(digest.to_hex_lowercase(), "8d777f385d3dfec8815d20f7496026dc");
        assert_eq!(digest.to_hex_uppercase(), "8D777F385D3DFEC8815D20F7496026DC");
        assert_eq!(new(MD5).update("data").finalize().digest(), digest);
        assert_eq!(Digest::from(md5::hash(b"data")), digest);

        let digest = new(MD5).update("data").reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(digest.to_hex_uppercase(), "D41D8CD98F00B204E9800998ECF8427E");

        let digest = new(MD5).update("data").finalize().reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(digest.to_hex_uppercase(), "D41D8CD98F00B204E9800998ECF8427E");
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn test_sha1() {
        assert_eq!(format!("{}", SHA1), "SHA-1");

        let digest = new(SHA1).digest();
        assert_eq!(digest.to_hex_lowercase(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(digest.to_hex_uppercase(), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(verify(SHA1, b"", digest), true);
        assert_eq!(format!("{digest:x}"), digest.to_hex_lowercase());
        assert_eq!(format!("{digest:X}"), digest.to_hex_uppercase());

        let digest = new(SHA1).update("data").digest();
        assert_eq!(digest.to_hex_lowercase(), "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd");
        assert_eq!(digest.to_hex_uppercase(), "A17C9AAA61E80A1BF71D0D850AF4E5BAA9800BBD");
        assert_eq!(new(SHA1).update("data").finalize().digest(), digest);
        assert_eq!(Digest::from(sha1::hash(b"data")), digest);

        let digest = new(SHA1).update("data").reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(digest.to_hex_uppercase(), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");

        let digest = new(SHA1).update("data").finalize().reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(digest.to_hex_uppercase(), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
    }

    #[cfg(feature = "sha2-224")]
    #[test]
    fn test_sha2_224() {
        assert_eq!(format!("{}", SHA2_224), "SHA-2 224");

        let digest = new(SHA2_224).digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F");
        assert_eq!(verify(SHA2_224, b"", digest), true);
        assert_eq!(format!("{digest:x}"), digest.to_hex_lowercase());
        assert_eq!(format!("{digest:X}"), digest.to_hex_uppercase());

        let digest = new(SHA2_224).update("data").digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "F4739673ACC03C424343B452787EE23DD62999A8A9F14F4250995769");
        assert_eq!(new(SHA2_224).update("data").finalize().digest(), digest);
        assert_eq!(Digest::from(sha2::sha224::hash(b"data")), digest);

        let digest = new(SHA2_224).update("data").reset().digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F");

        let digest = new(SHA2_224).update("data").finalize().reset().digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F");
    }

    #[cfg(feature = "sha2-256")]
    #[test]
    fn test_sha2_256() {
        assert_eq!(format!("{}", SHA2_256), "SHA-2 256");

        let digest = new(SHA2_256).digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
        assert_eq!(verify(SHA2_256, b"", digest), true);
        assert_eq!(format!("{digest:x}"), digest.to_hex_lowercase());
        assert_eq!(format!("{digest:X}"), digest.to_hex_uppercase());

        let digest = new(SHA2_256).update("data").digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "3A6EB0790F39AC87C94F3856B2DD2C5D110E6811602261A9A923D3BB23ADC8B7");
        assert_eq!(new(SHA2_256).update("data").finalize().digest(), digest);
        assert_eq!(Digest::from(sha2::sha256::hash(b"data")), digest);

        let digest = new(SHA2_256).update("data").reset().digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");

        let digest = new(SHA2_256).update("data").finalize().reset().digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
    }

    #[cfg(feature = "sha2-384")]
    #[test]
    fn test_sha2_384() {
        assert_eq!(format!("{}", SHA2_384), "SHA-2 384");

        let digest = new(SHA2_384).digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B");
        assert_eq!(verify(SHA2_384, b"", digest), true);
        assert_eq!(format!("{digest:x}"), digest.to_hex_lowercase());
        assert_eq!(format!("{digest:X}"), digest.to_hex_uppercase());

        let digest = new(SHA2_384).update("data").digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "2039E0F0B92728499FB88E23EBC3CFD0554B28400B0ED7B753055C88B5865C3C2AA72C6A1A9AE0A755D87900A4A6FF41");
        assert_eq!(new(SHA2_384).update("data").finalize().digest(), digest);
        assert_eq!(Digest::from(sha2::sha384::hash(b"data")), digest);

        let digest = new(SHA2_384).update("data").reset().digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B");

        let digest = new(SHA2_384).update("data").finalize().reset().digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B");
    }

    #[cfg(feature = "sha2-512")]
    #[test]
    fn test_sha2_512() {
        assert_eq!(format!("{}", SHA2_512), "SHA-2 512");

        let digest = new(SHA2_512).digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E");
        assert_eq!(verify(SHA2_512, b"", digest), true);
        assert_eq!(format!("{digest:x}"), digest.to_hex_lowercase());
        assert_eq!(format!("{digest:X}"), digest.to_hex_uppercase());

        let digest = new(SHA2_512).update("data").digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "77C7CE9A5D86BB386D443BB96390FAA120633158699C8844C30B13AB0BF92760B7E4416AEA397DB91B4AC0E5DD56B8EF7E4B066162AB1FDC088319CE6DEFC876");
        assert_eq!(new(SHA2_512).update("data").finalize().digest(), digest);
        assert_eq!(Digest::from(sha2::sha512::hash(b"data")), digest);

        let digest = new(SHA2_512).update("data").reset().digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E");

        let digest = new(SHA2_512).update("data").finalize().reset().digest();
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E");
    }
}
