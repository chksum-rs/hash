//! Implementation of SHA-2 224 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! # Batch processing
//!
//! Digest of known-size data can be calculated with [`hash`] function.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha224::hash("some data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "9b3a5fec834f20c610403782024ac19eb2c7fec8537ce8e888c1920b"
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
//! use chksum_hash::sha2;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//! let mut hash = sha2::sha224::new();
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
//!     "9b3a5fec834f20c610403782024ac19eb2c7fec8537ce8e888c1920b"
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
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha224::new()
//!     .update("str")
//!     .update(b"bytes")
//!     .update([0x75, 0x38])
//!     .digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "af6ee2ebec203dbcc06e946e693bdd154dfde44aaccc978508d3ac50"
//! );
//! ```
//!
//! Since [`Digest`] implements `AsRef<[u8]>` then digests can chained to implement hash digest of hash digest.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha224::hash(sha2::sha224::hash(b"some data"));
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "1957ed4659eb6aae27b96c23d9cf7997e3a584f50bbad51fe84cde65"
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
/// let digest = sha2::sha224::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769"
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
/// let digest = sha2::sha224::default().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769"
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
/// let digest = sha2::sha224::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769"
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
    /// use chksum_hash::sha2;
    ///
    /// let hash = sha2::sha224::new().update("data").finalize();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769"
    /// );
    /// let hash = hash.reset();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
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
        assert_eq!(
            digest.to_hex_lowercase(),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn test_empty() {
        let digest = new().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn test_reset() {
        let digest = new().update("data").reset().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );

        let digest = new().update("data").finalize().reset().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn test_hello_world() {
        let digest = new().update("Hello World").digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "c4890faffdb0105d991a461e668e276685401b02eab1ef4372795047"
        );

        let digest = new().update("Hello").update(" ").update("World").digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "c4890faffdb0105d991a461e668e276685401b02eab1ef4372795047"
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
            "ed123a70f9bf57341c91260608e68ce2b483da4f5000a7db32d4e1cb"
        );
    }

    #[test]
    fn test_partially_filled_internal_buffer() {
        let data = vec![0u8; 64];

        let digest = new().update(&data[..60]).digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "3fe5b353056d4b16fce534d8de0651b38283d7ffc5b974d8b16346fe"
        );

        let digest = new().update(&data[..60]).update(&data[60..]).digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "750d81a39c18d3ce27ff3e5ece30b0088f12d8fd0450fe435326294b"
        );
    }
}
