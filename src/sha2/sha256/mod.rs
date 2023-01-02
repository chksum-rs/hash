//! Implementation of SHA-2 256 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! # Batch processing
//!
//! Digest of known-size data can be calculated with [`hash`] function.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha256::hash("some data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee"
//! );
//! ```
//!
//! ## Verification
//!
//! Digest of known-size data can be verified with [`verify`] function.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha256::hash("some data");
//! assert_eq!(sha2::sha256::verify("some data", digest), true);
//! assert_eq!(sha2::sha256::verify("SOME DATA", digest), false);
//! ```
//!
//! # Stream processing
//!
//! Digest of data streams can be calculated chunk-by-chunk with consumer created by calling [`new`] function.
//!
//! ```rust
//! use std::fs::File;
//! # use std::io::{self, Write};
//! use std::io::Read;
//!
//! # use tempfile::NamedTempFile;
//! use chksum_hash::sha2;
//!
//! # fn wrapper() -> io::Result<()> {
//! # let path = {
//! #     let mut file = NamedTempFile::new()?;
//! #     file.write(b"some data")?;
//! #     file.path().to_path_buf()
//! # };
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//! let mut hash = sha2::sha256::new();
//! while let Ok(count) = file.read(&mut buffer) {
//!     if count == 0 {
//!         break;
//!     }
//!
//!     hash.update(&buffer[..count]);
//! }
//! let digest = hash.digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! Check [`Update`] structure for more examples.
//!
//! ## Verification
//!
//! Digest of data stream can be verified with [`Update::verify`] or [`Finalize::verify`] methods.
//!
//! ```rust
//! use std::fs::File;
//! # use std::io::{self, Write};
//! use std::io::Read;
//!
//! # use tempfile::NamedTempFile;
//! use chksum_hash::sha2;
//!
//! # fn wrapper() -> io::Result<()> {
//! let digest_lowercase = sha2::sha256::hash("some data");
//! let digest_uppercase = sha2::sha256::hash("SOME DATA");
//!
//! # let path = {
//! #     let mut file = NamedTempFile::new()?;
//! #     file.write(b"some data")?;
//! #     file.path().to_path_buf()
//! # };
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//! let mut hash = sha2::sha256::new();
//! while let Ok(count) = file.read(&mut buffer) {
//!     if count == 0 {
//!         break;
//!     }
//!
//!     hash.update(&buffer[..count]);
//! }
//! assert_eq!(hash.verify(digest_lowercase), true);
//! assert_eq!(hash.verify(digest_uppercase), false);
//! # Ok(())
//! # }
//! ```
//!
//! ## Internal buffering
//!
//! Due to unknown size of data chunks [`Update`] structure uses internal buffer under the hood.
//!
//! Size of this buffer is at last as size of one hash block of data that is processed at once.
//!
//! To avoid buffering, which can cause performance issues, length of processed chunks must be multiply of block size.
//!
//! # Input type
//!
//! Everything that implements `AsRef<[u8]>` can be passed as an input.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha256::new()
//!     .update("str")
//!     .update(b"bytes")
//!     .update([0x75, 0x38])
//!     .digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "61466aaea66ab788a5f507ecd6061292c95e18fb9e144eab023a899aa96b59cb"
//! );
//! ```
//!
//! Since [`Digest`] implements `AsRef<[u8]>` then digests can chained to implement hash digest of hash digest.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha256::hash(sha2::sha256::hash(b"some data"));
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "149078105941cd1edda0ec5a568fc1d178661b6441831c3647d88f41f7dfc886"
//! );
//! ```

use std::slice::ChunksExact;

#[cfg_attr(docsrs, doc(hidden))] // TODO: Add documentation to this module
pub mod block;
#[cfg_attr(docsrs, doc(hidden))] // TODO: Add documentation to this module
pub mod digest;
#[cfg_attr(docsrs, doc(hidden))] // TODO: Add documentation to this module
pub mod state;

use block::Block;
pub use digest::Digest;
use state::State;

/// Creates new hash instance.
///
/// Check [`Update`] for more details.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha2;
///
/// let digest = sha2::sha256::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
#[cfg_attr(release, inline)]
#[must_use]
pub fn new() -> Update {
    Update::new()
}

/// Computes hash of given input.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha2;
///
/// let digest = sha2::sha256::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
#[cfg_attr(release, inline)]
#[must_use]
pub fn hash<T>(data: T) -> Digest
where
    T: AsRef<[u8]>,
{
    new().update(data).digest()
}

/// Verifies hash for given input.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha2;
///
/// let digest = sha2::sha256::hash("data");
/// assert_eq!(sha2::sha256::verify("data", digest), true);
/// assert_eq!(sha2::sha256::verify("DATA", digest), false);
/// ```
#[cfg_attr(release, inline)]
#[must_use]
pub fn verify<T>(data: T, digest: Digest) -> bool
where
    T: AsRef<[u8]>,
{
    hash(data) == digest
}

/// Represents in-progress hash state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Update {
    state: State,
    unprocessed: Vec<u8>,
    processed: usize,
}

impl Update {
    #[cfg_attr(release, inline)]
    #[must_use]
    fn new() -> Self {
        let state = state::new();
        let unprocessed = Vec::with_capacity(block::LENGTH_BYTES);
        let processed = 0;
        Self {
            state,
            unprocessed,
            processed,
        }
    }

    #[cfg_attr(release, inline)]
    #[must_use]
    fn update_chunks<'a>(&mut self, mut chunks: ChunksExact<'a, u8>) -> &'a [u8] {
        for chunk in chunks.by_ref() {
            let block = Block::try_from(chunk).expect("chunk length should be exact size as block");
            self.state.update(block.into());
            self.processed = self.processed.wrapping_add(block::LENGTH_BYTES);
        }
        chunks.remainder()
    }

    /// Produces final digest.
    #[cfg_attr(release, inline)]
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.finalize().digest()
    }

    /// Applies padding produces finalized state.
    #[cfg_attr(nightly, optimize(speed))]
    #[must_use]
    pub fn finalize(&self) -> Finalize {
        assert!(
            self.unprocessed.len() < block::LENGTH_BYTES,
            "unprocessed data length should be less than block length"
        );

        let length = {
            let length = (self.unprocessed.len() + self.processed) as u64;
            let length = length * 8; // convert byte-length into bits-length
            length.to_be_bytes()
        };

        let mut state = self.state;

        if (self.unprocessed.len() + 1 + length.len()) <= block::LENGTH_BYTES {
            let padding = {
                let mut padding = [0u8; block::LENGTH_BYTES];
                padding[..self.unprocessed.len()].copy_from_slice(&self.unprocessed[..self.unprocessed.len()]);
                padding[self.unprocessed.len()] = 0x80;
                padding[(block::LENGTH_BYTES - length.len())..].copy_from_slice(&length);
                padding
            };

            let block = Block::try_from(&padding[..]).expect("padding length should exact size as block");
            state.update(block.into());
        } else {
            let padding = {
                let mut padding = [0u8; block::LENGTH_BYTES * 2];
                padding[..self.unprocessed.len()].copy_from_slice(&self.unprocessed[..self.unprocessed.len()]);
                padding[self.unprocessed.len()] = 0x80;
                padding[(block::LENGTH_BYTES * 2 - length.len())..].copy_from_slice(&length);
                padding
            };

            let block = {
                Block::try_from(&padding[..block::LENGTH_BYTES]).expect("padding length should exact size as block")
            };
            state.update(block.into());

            let block = {
                Block::try_from(&padding[block::LENGTH_BYTES..]).expect("padding length should exact size as block")
            };
            state.update(block.into());
        }
        Finalize { state }
    }

    /// Processes incoming data.
    ///
    /// # Performance issues
    ///
    /// To achieve maximum performance length of incoming data parts should be multiply of block length.
    ///
    /// In any other case internal buffer is used which can cause speed down the performance.
    #[cfg_attr(nightly, optimize(speed))]
    pub fn update<T>(&mut self, data: T) -> &mut Self
    where
        T: AsRef<[u8]>,
    {
        let data = data.as_ref();
        if self.unprocessed.is_empty() {
            // internal buffer is empty
            // incoming data can be processed without buffering
            let chunks = data.chunks_exact(block::LENGTH_BYTES);
            let remainder = self.update_chunks(chunks);
            if !remainder.is_empty() {
                self.unprocessed.extend(remainder);
            }
        } else if (self.unprocessed.len() + data.len()) < block::LENGTH_BYTES {
            // no enough data even for one block
            self.unprocessed.extend(data);
        } else {
            // create first block from buffer
            // create second (and every other) block from incoming data
            assert!(
                self.unprocessed.len() < block::LENGTH_BYTES,
                "unprocessed should contain less data than one block"
            );
            let missing = block::LENGTH_BYTES - self.unprocessed.len();
            assert!(missing <= data.len(), ""); // todo add message
            let (fillment, data) = data.split_at(missing);
            let block = {
                let mut block = [0u8; block::LENGTH_BYTES];
                let (first_part, second_part) = block.split_at_mut(self.unprocessed.len());
                first_part.copy_from_slice(self.unprocessed.drain(..self.unprocessed.len()).as_slice());
                second_part[..missing].copy_from_slice(fillment);
                block
            };
            let chunks = block.chunks_exact(block::LENGTH_BYTES);
            let remainder = self.update_chunks(chunks);
            assert!(remainder.is_empty(), "chunks remainder should be empty");

            let chunks = data.chunks_exact(block::LENGTH_BYTES);
            let remainder = self.update_chunks(chunks);
            self.unprocessed.extend(remainder);
        }
        self
    }

    /// Resets values to default without any new memory allocations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash::sha2;
    ///
    /// let hash = sha2::sha256::new().update("data").finalize();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
    /// );
    /// let hash = hash.reset();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    /// );
    /// ```
    #[cfg_attr(release, inline)]
    pub fn reset(&mut self) -> &mut Self {
        self.state.reset();
        self.unprocessed.clear();
        self.processed = 0;
        self
    }

    /// Verifies processed data against given digest.
    #[cfg_attr(release, inline)]
    #[must_use]
    pub fn verify(&self, digest: Digest) -> bool {
        self.digest() == digest
    }
}

/// Represents finalized state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finalize {
    state: State,
}

impl Finalize {
    /// Produces digest.
    #[cfg_attr(release, inline)]
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.state.into()
    }

    /// Resets state to default.
    #[cfg_attr(release, inline)]
    #[must_use]
    pub fn reset(&self) -> Update {
        Update::new()
    }

    /// Verifies state against given digest.
    #[cfg_attr(release, inline)]
    #[must_use]
    pub fn verify(&self, digest: Digest) -> bool {
        self.digest() == digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let digest = new().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(verify(b"", digest), true);
    }

    #[test]
    fn test_reset() {
        let digest = new().update("data").reset().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = new().update("data").finalize().reset().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hello_world() {
        let digest = new().update("Hello World").digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        );

        let digest = new().update("Hello").update(" ").update("World").digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        );
    }

    #[test]
    fn test_rust_book() {
        let phrase = "Welcome to The Rust Programming Language, an introductory book about Rust. The Rust programming \
                      language helps you write faster, more reliable software. High-level ergonomics and low-level \
                      control are often at odds in programming language design; Rust challenges that conflict. \
                      Through balancing powerful technical capacity and a great developer experience, Rust gives you \
                      the option to control low-level details (such as memory usage) without all the hassle \
                      traditionally associated with such control.";
        let digest = hash(phrase);
        assert_eq!(
            digest.to_hex_lowercase(),
            "b2de5395f39bf32376693a9cdccc13da1d705d0eb9e9ec8c566a91f604fcc942"
        );
    }

    #[test]
    fn test_partially_filled_internal_buffer() {
        let data = vec![0u8; 64];

        let digest = new().update(&data[..60]).update(&data[60..]).digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        );

        let digest = new().update(&data[..60]).digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "5dcc1b5872dd9ff1c234501f1fefda01f664164e1583c3e1bb3dbea47588ab31"
        );
    }
}
