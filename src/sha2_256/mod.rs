//! Implementation of SHA-2 256 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! # Batch processing
//!
//! Digest of known-size data can be calculated with [`hash`] function.
//!
//! ```rust
//! use chksum_hash::sha2_256;
//!
//! let digest = sha2_256::hash("some data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee"
//! );
//! ```
//!
//! # Stream processing
//!
//! Digest of data streams can be calculated chunk-by-chunk with consumer created by calling [`new`] function.
//!
//! ```rust
//! // Import all necessary items
//! # use std::io;
//! # use std::path::PathBuf;
//! use std::fs::File;
//! use std::io::Read;
//!
//! use chksum_hash::sha2_256;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! // Create hash instance
//! let mut hash = sha2_256::new();
//!
//! // Open file and create buffer for incoming data
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
//!     // Update hash with data
//!     hash = hash.update(&buffer[..count]);
//! }
//!
//! // Calculate digest
//! let digest = hash.digest();
//! // Cast digest to hex and compare
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! Check [`Update`] and [`Finalize`] structures for more examples.
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
//! use chksum_hash::sha2_256;
//!
//! let digest = sha2_256::new()
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
//! Since [`Digest`] implements `AsRef<[u8]>` then digests can be chained to implement hash digest of hash digest.
//!
//! ```rust
//! use chksum_hash::sha2_256;
//!
//! let digest = sha2_256::hash(b"some data");
//! let digest = sha2_256::hash(digest);
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "149078105941cd1edda0ec5a568fc1d178661b6441831c3647d88f41f7dfc886"
//! );
//! ```

#[doc(hidden)] // TODO: Add documentation to this module
pub mod block;
#[doc(hidden)] // TODO: Add documentation to this module
pub mod digest;
#[doc(hidden)] // TODO: Add documentation to this module
pub mod state;

use block::Block;
pub use block::LENGTH_BYTES as BLOCK_LENGTH_BYTES;
pub use digest::{Digest, LENGTH_BYTES as DIGEST_LENGTH_BYTES};
use state::State;

/// Creates new hash instance.
///
/// Check [`Update`] for more details.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha2_256;
///
/// let digest = sha2_256::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
#[inline]
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
/// use chksum_hash::sha2_256;
///
/// let digest = sha2_256::default().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
#[inline]
#[must_use]
pub fn default() -> Update {
    Update::default()
}

/// Computes hash of given input.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha2_256;
///
/// let digest = sha2_256::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
/// );
/// ```
#[inline]
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
    #[inline]
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

    /// Produces final digest.
    #[inline]
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.finalize().digest()
    }

    /// Applies padding produces finalized state.
    #[cfg_attr(nightly, optimize(speed))]
    #[must_use]
    pub fn finalize(&self) -> Finalize {
        let Self {
            mut state,
            unprocessed,
            processed,
        } = self;

        assert!(
            unprocessed.len() < block::LENGTH_BYTES,
            "unprocessed data length should be less than block length"
        );

        let length = {
            let length = (unprocessed.len() + processed) as u64;
            let length = length * 8; // convert byte-length into bits-length
            length.to_be_bytes()
        };

        if (unprocessed.len() + 1 + length.len()) <= block::LENGTH_BYTES {
            let padding = {
                let mut padding = [0u8; block::LENGTH_BYTES];
                padding[..unprocessed.len()].copy_from_slice(&unprocessed[..unprocessed.len()]);
                padding[unprocessed.len()] = 0x80;
                padding[(block::LENGTH_BYTES - length.len())..].copy_from_slice(&length);
                padding
            };

            let block = Block::try_from(&padding[..]).expect("padding length should exact size as block");
            state = state.update(block.into());
        } else {
            let padding = {
                let mut padding = [0u8; block::LENGTH_BYTES * 2];
                padding[..unprocessed.len()].copy_from_slice(&unprocessed[..unprocessed.len()]);
                padding[unprocessed.len()] = 0x80;
                padding[(block::LENGTH_BYTES * 2 - length.len())..].copy_from_slice(&length);
                padding
            };

            let block = {
                Block::try_from(&padding[..block::LENGTH_BYTES]).expect("padding length should exact size as block")
            };
            state = state.update(block.into());

            let block = {
                Block::try_from(&padding[block::LENGTH_BYTES..]).expect("padding length should exact size as block")
            };
            state = state.update(block.into());
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
    #[must_use]
    pub fn update<T>(self, data: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        let Self {
            mut state,
            mut unprocessed,
            mut processed,
        } = self;
        let data = data.as_ref();

        if unprocessed.is_empty() {
            // internal buffer is empty
            // incoming data can be processed without buffering
            let mut chunks = data.chunks_exact(block::LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk).expect("chunk length should be exact size as block");
                state = state.update(block.into());
                processed = processed.wrapping_add(block::LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            if !remainder.is_empty() {
                unprocessed.extend(remainder);
            }
        } else if (unprocessed.len() + data.len()) < block::LENGTH_BYTES {
            // no enough data even for one block
            unprocessed.extend(data);
        } else {
            // create first block from buffer
            // create second (and every other) block from incoming data
            assert!(
                unprocessed.len() < block::LENGTH_BYTES,
                "unprocessed should contain less data than one block"
            );
            let missing = block::LENGTH_BYTES - unprocessed.len();
            assert!(missing <= data.len(), ""); // todo add message
            let (fillment, data) = data.split_at(missing);
            let block = {
                let mut block = [0u8; block::LENGTH_BYTES];
                let (first_part, second_part) = block.split_at_mut(unprocessed.len());
                first_part.copy_from_slice(unprocessed.drain(..unprocessed.len()).as_slice());
                second_part[..missing].copy_from_slice(fillment);
                block
            };
            let mut chunks = block.chunks_exact(block::LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk).expect("chunk length should be exact size as block");
                state = state.update(block.into());
                processed = processed.wrapping_add(block::LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            assert!(remainder.is_empty(), "chunks remainder should be empty");

            let mut chunks = data.chunks_exact(block::LENGTH_BYTES);
            for chunk in chunks.by_ref() {
                let block = Block::try_from(chunk).expect("chunk length should be exact size as block");
                state = state.update(block.into());
                processed = processed.wrapping_add(block::LENGTH_BYTES);
            }
            let remainder = chunks.remainder();
            unprocessed.extend(remainder);
        }

        Self {
            state,
            unprocessed,
            processed,
        }
    }

    /// Resets values to default without any new memory allocations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash::sha2_256;
    ///
    /// let hash = sha2_256::new().update("data").finalize();
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
    #[inline]
    #[must_use]
    pub fn reset(self) -> Self {
        let (state, unprocessed, processed) = {
            let Self {
                state, mut unprocessed, ..
            } = self;
            unprocessed.clear();
            (state.reset(), unprocessed, 0)
        };
        Self {
            state,
            unprocessed,
            processed,
        }
    }
}

impl crate::Update for Update {
    type Digest = Digest;
    type Finalize = Finalize;

    #[inline]
    fn update<T>(self, data: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        self.update(data)
    }

    #[inline]
    fn finalize(&self) -> Self::Finalize {
        self.finalize()
    }

    #[inline]
    fn reset(self) -> Self {
        self.reset()
    }
}

impl Default for Update {
    #[inline]
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
    #[inline]
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.state.into()
    }

    /// Resets state to default.
    #[inline]
    #[must_use]
    pub fn reset(&self) -> Update {
        Update::new()
    }
}

impl crate::Finalize for Finalize {
    type Digest = Digest;
    type Update = Update;

    #[inline]
    fn digest(&self) -> Self::Digest {
        self.digest()
    }

    #[inline]
    fn reset(&self) -> Self::Update {
        self.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let digest = default().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = new().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn reset() {
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
    fn hello_world() {
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
    fn rust_book() {
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
    fn zeroes() {
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
