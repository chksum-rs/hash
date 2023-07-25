//! Implementation of SHA-1 hash function based on [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174).
//!
//! # Batch processing
//!
//! Digest of known-size data can be calculated with [`hash`] function.
//!
//! ```rust
//! use chksum_hash::sha1;
//!
//! let digest = sha1::hash("some data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "baf34551fecb48acc3da868eb85e1b6dac9de356"
//! );
//! ```
//!
//! # Stream processing
//!
//! Digest of data streams can be calculated chunk-by-chunk with consumer created by calling [`new`] function.
//!
//! ```rust
//! # use std::io;
//! # use std::path::PathBuf;
//! use std::fs::File;
//! use std::io::Read;
//!
//! use chksum_hash::sha1;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//! let mut hash = sha1::new();
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
//!     "baf34551fecb48acc3da868eb85e1b6dac9de356"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! Check [`Update`] structure for more examples.
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
//! use chksum_hash::sha1;
//!
//! let digest = sha1::new()
//!     .update("str")
//!     .update(b"bytes")
//!     .update([0x75, 0x38])
//!     .digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "dccc950173920744f2acdc30c92a552daa6ee914"
//! );
//! ```
//!
//! Since [`Digest`] implements `AsRef<[u8]>` then digests can chained to implement hash digest of hash digest.
//!
//! ```rust
//! use chksum_hash::sha1;
//!
//! let digest = sha1::hash(sha1::hash(b"some data"));
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "46eda4fc379a15b24f99ac5bcd94279fe0493cd1"
//! );
//! ```
//!
//! # Disclaimer
//!
//! SHA-1 hash function should be used only for backward compability due to security issues.
//!
//! Check [RFC 6194: Security Considerations for the SHA-0 and SHA-1 Message-Digest Algorithms](https://www.rfc-editor.org/rfc/rfc6194) for more details.

use std::slice::ChunksExact;

#[doc(hidden)] // TODO: Add documentation to this module
pub mod block;
#[doc(hidden)] // TODO: Add documentation to this module
pub mod digest;
#[doc(hidden)] // TODO: Add documentation to this module
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
/// use chksum_hash::sha1;
///
/// let digest = sha1::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd"
/// );
/// ```
#[cfg_attr(all(release, feature = "inline"), inline)]
#[must_use]
pub fn new() -> Update {
    Update::new()
}

/// Creates default hash instance.
///
/// Check [`Update`] for more details.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha1;
///
/// let digest = sha1::default().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd"
/// );
/// ```
#[cfg_attr(all(release, feature = "inline"), inline)]
#[must_use]
pub fn default() -> Update {
    Update::default()
}

/// Computes hash of given input.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha1;
///
/// let digest = sha1::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd"
/// );
/// ```
#[cfg_attr(all(release, feature = "inline"), inline)]
#[must_use]
pub fn hash<T>(data: T) -> Digest
where
    T: AsRef<[u8]>,
{
    new().update(data).digest()
}

/// Represents in-progress hash state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Update {
    state: State,
    unprocessed: Vec<u8>,
    processed: usize,
}

impl Update {
    #[cfg_attr(all(release, feature = "inline"), inline)]
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

    #[cfg_attr(all(release, feature = "inline"), inline)]
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
    #[cfg_attr(all(release, feature = "inline"), inline)]
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
    /// use chksum_hash::sha1;
    ///
    /// let hash = sha1::new().update("data").finalize();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd"
    /// );
    /// let hash = hash.reset();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    /// );
    /// ```
    #[cfg_attr(all(release, feature = "inline"), inline)]
    pub fn reset(&mut self) -> &mut Self {
        self.state.reset();
        self.unprocessed.clear();
        self.processed = 0;
        self
    }
}

impl Default for Update {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn default() -> Self {
        Self::new()
    }
}

/// Represents finalized state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finalize {
    state: State,
}

impl Finalize {
    /// Produces digest.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.state.into()
    }

    /// Resets state to default.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn reset(&self) -> Update {
        Update::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let digest = default().digest();
        assert_eq!(digest.to_hex_lowercase(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_empty() {
        let digest = new().digest();
        assert_eq!(digest.to_hex_lowercase(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_reset() {
        let digest = new().update("data").reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let digest = new().update("data").finalize().reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_hello_world() {
        let digest = new().update("Hello World").digest();
        assert_eq!(digest.to_hex_lowercase(), "0a4d55a8d778e5022fab701977c5d840bbc486d0");

        let digest = new().update("Hello").update(" ").update("World").digest();
        assert_eq!(digest.to_hex_lowercase(), "0a4d55a8d778e5022fab701977c5d840bbc486d0");
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
        assert_eq!(digest.to_hex_lowercase(), "6cb4f2c5c0fd6093247ab92ff9e0e4b675c531c1");
    }

    #[test]
    fn test_partially_filled_internal_buffer() {
        let data = vec![0u8; 64];

        let digest = new().update(&data[..60]).digest();
        assert_eq!(digest.to_hex_lowercase(), "fb3d8fb74570a077e332993f7d3d27603501b987");

        let digest = new().update(&data[..60]).update(&data[60..]).digest();
        assert_eq!(digest.to_hex_lowercase(), "c8d7d0ef0eedfa82d2ea1aa592845b9a6d4b02b7");
    }
}
