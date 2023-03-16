//! Implementation of SHA-2 512 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! # Batch processing
//!
//! Digest of known-size data can be calculated with [`hash`] function.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha512::hash("some data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "e1645e7492f032fb62c674db75500be7b260bfc0daa965821ddb3f8a49b5d33788ee3f046744e2b95afb5c3d8f2500c549ca89d79fc6890885d28e055007424f"
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
//! let digest = sha2::sha512::hash("some data");
//! assert_eq!(sha2::sha512::verify("some data", digest), true);
//! assert_eq!(sha2::sha512::verify("SOME DATA", digest), false);
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
//! let mut hash = sha2::sha512::new();
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
//!     "e1645e7492f032fb62c674db75500be7b260bfc0daa965821ddb3f8a49b5d33788ee3f046744e2b95afb5c3d8f2500c549ca89d79fc6890885d28e055007424f"
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
//! let digest_lowercase = sha2::sha512::hash("some data");
//! let digest_uppercase = sha2::sha512::hash("SOME DATA");
//!
//! let mut file = File::open(path)?;
//! let mut buffer = vec![0; 64];
//! let mut hash = sha2::sha512::new();
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
//! let digest = sha2::sha512::new()
//!     .update("str")
//!     .update(b"bytes")
//!     .update([0x75, 0x38])
//!     .digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "46a700a6419da55a9375a63860f441134370cc83ede59e7af64a7edbbaadfbb1132a39d0bffce951b9296b5333797e5ad62e1b03469999b4e6b005a3fb49ea98"
//! );
//! ```
//!
//! Since [`Digest`] implements `AsRef<[u8]>` then digests can chained to implement hash digest of hash digest.
//!
//! ```rust
//! use chksum_hash::sha2;
//!
//! let digest = sha2::sha512::hash(sha2::sha512::hash(b"some data"));
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "e982af9db277cc3931999540e9b837807d88e2035084bf12383a2f52489b6a5201f90aaa4e72683305ea0109a459f76e3617241d086435db90a748a5b73b1d34"
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
/// let digest = sha2::sha512::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
/// );
/// ```
#[cfg_attr(all(release, feature = "inline"), inline)]
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
/// let digest = sha2::sha512::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
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
/// let digest = sha2::sha512::hash("data");
/// assert_eq!(sha2::sha512::verify("data", digest), true);
/// assert_eq!(sha2::sha512::verify("DATA", digest), false);
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
    /// let hash = sha2::sha512::new().update("data").finalize();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
    /// );
    /// let hash = hash.reset();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
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
    fn test_empty() {
        let digest = new().digest();
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        assert_eq!(verify(b"", digest), true);
    }

    #[test]
    fn test_reset() {
        let digest = new().update("data").reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = new().update("data").finalize().reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
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
        assert_eq!(digest.to_hex_lowercase(), "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");

        let digest = new().update("Hello").update(" ").update("World").digest();
        assert_eq!(digest.to_hex_lowercase(), "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");
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
        assert_eq!(digest.to_hex_lowercase(), "72a43851dd05d04f09faf88602c3a921867dd0410bd8ed2db223adc7586d93951e9d0367db023076bd0573064facebf127a0674d56d7ee4e3f0c3e334e277278");
    }

    #[test]
    fn test_partially_filled_internal_buffer() {
        let data = vec![0u8; 128];

        let digest = new().update(&data[..120]).digest();
        assert_eq!(digest.to_hex_lowercase(), "c106c47ad6eb79cd2290681cb04cb183effbd0b49402151385b2d07be966e2d50bc9db78e00bf30bb567ccdd3a1c7847260c94173ba215a0feabb0edeb643ff0");

        let digest = new().update(&data[..120]).update(&data[120..]).digest();
        assert_eq!(digest.to_hex_lowercase(), "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a552d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11");
    }
}
