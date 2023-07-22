//! Implementation of SHA-2 hash functions family based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

#[allow(clippy::module_name_repetitions)]
#[cfg(feature = "sha2-224")]
pub mod sha224;
#[allow(clippy::module_name_repetitions)]
#[cfg(feature = "sha2-256")]
pub mod sha256;
#[cfg(feature = "sha2-384")]
pub mod sha384;
#[cfg(feature = "sha2-512")]
pub mod sha512;
