//! Implementation of SHA-2 512 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//!
//! # Batch processing
//!
//! Digest of known-size data can be calculated with [`hash`] function.
//!
//! ```rust
//! use chksum_hash::sha2_512;
//!
//! let digest = sha2_512::hash("some data");
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "e1645e7492f032fb62c674db75500be7b260bfc0daa965821ddb3f8a49b5d33788ee3f046744e2b95afb5c3d8f2500c549ca89d79fc6890885d28e055007424f"
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
//! use chksum_hash::sha2_512;
//!
//! # fn wrapper(path: PathBuf) -> io::Result<()> {
//! // Create hash instance
//! let mut hash = sha2_512::new();
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
//!     "e1645e7492f032fb62c674db75500be7b260bfc0daa965821ddb3f8a49b5d33788ee3f046744e2b95afb5c3d8f2500c549ca89d79fc6890885d28e055007424f"
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
//! use chksum_hash::sha2_512;
//!
//! let digest = sha2_512::new()
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
//! Since [`Digest`] implements `AsRef<[u8]>` then digests can be chained to implement hash digest of hash digest.
//!
//! ```rust
//! use chksum_hash::sha2_512;
//!
//! let digest = sha2_512::hash(b"some data");
//! let digest = sha2_512::hash(digest);
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "e982af9db277cc3931999540e9b837807d88e2035084bf12383a2f52489b6a5201f90aaa4e72683305ea0109a459f76e3617241d086435db90a748a5b73b1d34"
//! );
//! ```

mod block;
mod digest;
pub mod state;

use block::Block;
pub use block::LENGTH_BYTES as BLOCK_LENGTH_BYTES;
pub use digest::{Digest, LENGTH_BYTES as DIGEST_LENGTH_BYTES};
#[doc(inline)]
pub use state::State;

/// Creates new hash instance.
///
/// Check [`Update`] for more details.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha2_512;
///
/// let digest = sha2_512::new().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
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
/// use chksum_hash::sha2_512;
///
/// let digest = sha2_512::default().update("data").digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
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
/// use chksum_hash::sha2_512;
///
/// let digest = sha2_512::hash("data");
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
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
    /// use chksum_hash::sha2_512;
    ///
    /// let hash = sha2_512::new().update("data").finalize();
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
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = new().digest();
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[test]
    fn reset() {
        let digest = new().update("data").reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = new().update("data").finalize().reset().digest();
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[test]
    fn hello_world() {
        let digest = new().update("Hello World").digest();
        assert_eq!(digest.to_hex_lowercase(), "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");

        let digest = new().update("Hello").update(" ").update("World").digest();
        assert_eq!(digest.to_hex_lowercase(), "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");
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
        assert_eq!(digest.to_hex_lowercase(), "72a43851dd05d04f09faf88602c3a921867dd0410bd8ed2db223adc7586d93951e9d0367db023076bd0573064facebf127a0674d56d7ee4e3f0c3e334e277278");
    }

    #[test]
    fn zeroes() {
        let data = vec![0u8; 128];

        let digest = new().update(&data[..120]).digest();
        assert_eq!(digest.to_hex_lowercase(), "c106c47ad6eb79cd2290681cb04cb183effbd0b49402151385b2d07be966e2d50bc9db78e00bf30bb567ccdd3a1c7847260c94173ba215a0feabb0edeb643ff0");

        let digest = new().update(&data[..120]).update(&data[120..]).digest();
        assert_eq!(digest.to_hex_lowercase(), "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a552d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11");
    }
}
