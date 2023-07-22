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
//! ## Verification
//!
//! Digest of known-size data can be verified with [`verify`] function.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha384::hash("some data");
//! assert_eq!(sha2::sha384::verify("some data", digest), true);
//! assert_eq!(sha2::sha384::verify("SOME DATA", digest), false);
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
//! use chksum_hash::sha2;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 128];
//! let mut hash = sha2::sha384::new();
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
//!     "a9c61a162f4b572a63e6b0e2b45aef473b73027d590555966a4c09185837ff72a10191c136ec3f4614d7914d1da823f0"
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
//! # use std::io;
//! # use std::path::PathBuf;
//! use std::fs::File;
//! use std::io::Read;
//!
//! use chksum_hash::sha2;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! let digest_lowercase = sha2::sha384::hash("some data");
//! let digest_uppercase = sha2::sha384::hash("SOME DATA");
//!
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//! let mut hash = sha2::sha384::new();
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
//! Since [`Digest`] implements `AsRef<[u8]>` then digests can chained to implement hash digest of hash digest.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha384::hash(sha2::sha384::hash(b"some data"));
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "455ea2cb1f24dea750d5f8b1dabb253415b64e82f98e4cb7070df8b67d609b888ad9a940622b1e8d528a87e53036ca46"
//! );
//! ```

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

/// Verifies hash for given input.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha2;
///
/// let digest = sha2::sha384::hash("data");
/// assert_eq!(sha2::sha384::verify("data", digest), true);
/// assert_eq!(sha2::sha384::verify("DATA", digest), false);
/// ```
#[cfg_attr(all(release, feature = "inline"), inline)]
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
            let length = (self.unprocessed.len() + self.processed) as u128;
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
    pub fn reset(&mut self) -> &mut Self {
        self.state.reset();
        self.unprocessed.clear();
        self.processed = 0;
        self
    }

    /// Verifies processed data against given digest.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn verify(&self, digest: Digest) -> bool {
        self.digest() == digest
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

    #[test]
    fn test_default() {
        let digest = default().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(verify(b"", digest), true);
    }

    #[test]
    fn test_empty() {
        let digest = new().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(verify(b"", digest), true);
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
    fn test_verify() {
        let digest = new().update("data").digest();

        assert_eq!(new().update("data").verify(digest), true);
        assert_eq!(new().update(b"data").verify(digest), true);
        assert_eq!(new().verify(digest), false);

        assert_eq!(new().update("data").finalize().verify(digest), true);
        assert_eq!(new().update(b"data").finalize().verify(digest), true);
        assert_eq!(new().finalize().verify(digest), false);
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
