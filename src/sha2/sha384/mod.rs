//! Implementation of SHA-2 384 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! # Batch processing
//!
//! Digest of known-size data can be calculated with [`hash`] function.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha384::hash("some data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "a9c61a162f4b572a63e6b0e2b45aef473b73027d590555966a4c09185837ff72a10191c136ec3f4614d7914d1da823f0"
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
//! use chksum_hash::sha2;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! // Create hash instance
//! let mut hash = sha2::sha384::new();
//!
//! // Open file and create buffer for incoming data
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 128];
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
//!     "a9c61a162f4b572a63e6b0e2b45aef473b73027d590555966a4c09185837ff72a10191c136ec3f4614d7914d1da823f0"
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
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha384::new()
//!     .update("str")
//!     .update(b"bytes")
//!     .update([0x75, 0x38])
//!     .digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "fdf06709928130b6c22c579287e5633a1a9fc52b944c3be878211a8fa0c22a4c7f84acc6a5e86ae7017d61ed434f04d9"
//! );
//! ```
//!
//! Since [`Digest`] implements `AsRef<[u8]>` then digests can be chained to implement hash digest of hash digest.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha384::hash(b"some data");
//! let digest = sha2::sha384::hash(digest);
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "455ea2cb1f24dea750d5f8b1dabb253415b64e82f98e4cb7070df8b67d609b888ad9a940622b1e8d528a87e53036ca46"
//! );
//! ```

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
/// use chksum_hash::sha2;
///
/// let digest = sha2::sha384::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
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
/// use chksum_hash::sha2;
///
/// let digest = sha2::sha384::default().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
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
/// use chksum_hash::sha2;
///
/// let digest = sha2::sha384::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
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
            let length = (unprocessed.len() + processed) as u128;
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
    /// use chksum_hash::sha2;
    ///
    /// let hash = sha2::sha384::new().update("data").finalize();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    /// );
    /// let hash = hash.reset();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    /// );
    /// ```
    #[cfg_attr(all(release, feature = "inline"), inline)]
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

    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn update<T>(self, data: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        self.update(data)
    }

    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn finalize(&self) -> Self::Finalize {
        self.finalize()
    }

    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn reset(self) -> Self {
        self.reset()
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

impl crate::Finalize for Finalize {
    type Digest = Digest;
    type Update = Update;

    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn digest(&self) -> Self::Digest {
        self.digest()
    }

    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn reset(&self) -> Self::Update {
        self.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let digest = default().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn test_new() {
        let digest = new().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn test_reset() {
        let digest = new().update("data").reset().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let digest = new().update("data").finalize().reset().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn test_hello_world() {
        let digest = new().update("Hello World").digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f"
        );

        let digest = new().update("Hello").update(" ").update("World").digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f"
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
            "219a81f21396aa67175bb507a6ddfb238c725c5aa61e99edf89bcfd9f119c2b00ac0614249eff0b1d41a7e98b9f9278c"
        );
    }

    #[test]
    fn test_partially_filled_internal_buffer() {
        let data = vec![0u8; 128];

        let digest = new().update(&data[..120]).digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "7212d895f4250ce1daa72e9e0caaef7132aed2e965885c55376818e45470de06fb6ebf7349c62fd342043f18010e46ac"
        );

        let digest = new().update(&data[..120]).update(&data[120..]).digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "f809b88323411f24a6f152e5e9d9d1b5466b77e0f3c7550f8b242c31b6e7b99bcb45bdecb6124bc23283db3b9fc4f5b3"
        );
    }
}
