use std::fmt::{self, Formatter, LowerHex, UpperHex};

use super::State;
#[cfg(feature = "error")]
use crate::error::Error;

pub const LENGTH_BITS: usize = 160;
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;
pub const LENGTH_WORDS: usize = LENGTH_BYTES / 2;
pub const LENGTH_DWORDS: usize = LENGTH_WORDS / 2;
pub const LENGTH_HEX: usize = LENGTH_BYTES * 2;

/// Represents hash digest.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha1::Digest;
///
/// let digest = Digest::new([
///     0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18,
///     0x90, 0xAF, 0xD8, 0x07, 0x09,
/// ]);
/// println!("digest {:?}", digest);
/// println!("digest {:x}", digest);
/// println!("digest {:X}", digest);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; LENGTH_BYTES]);

impl Digest {
    /// Returns digest bytes as a byte slice.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates new digest from incoming bytes.
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub const fn new(digest: [u8; LENGTH_BYTES]) -> Self {
        Self(digest)
    }

    /// Returns lowercase hexadecimal representation of digest.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash::sha1::Digest;
    ///
    /// let digest = Digest::new([
    ///     0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18,
    ///     0x90, 0xAF, 0xD8, 0x07, 0x09,
    /// ]);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    /// );
    /// ```
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn to_hex_lowercase(&self) -> String {
        format!("{self:x}")
    }

    /// Returns uppercase hexadecimal representation of digest.
    ///
    /// ```rust
    /// use chksum_hash::sha1::Digest;
    ///
    /// let digest = Digest::new([
    ///     0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18,
    ///     0x90, 0xAF, 0xD8, 0x07, 0x09,
    /// ]);
    /// assert_eq!(
    ///     digest.to_hex_uppercase(),
    ///     "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
    /// );
    /// ```
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn to_hex_uppercase(&self) -> String {
        format!("{self:X}")
    }
}

impl crate::Digest for Digest {}

impl AsRef<[u8]> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; LENGTH_BYTES]> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(digest: [u8; LENGTH_BYTES]) -> Self {
        Self::new(digest)
    }
}

impl From<[u32; LENGTH_DWORDS]> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[rustfmt::skip]
    fn from([a, b, c, d, e]: [u32; LENGTH_DWORDS]) -> Self {
        let [a, b, c, d, e] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
        ];
        Self([
            a[0], a[1], a[2], a[3],
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
            e[0], e[1], e[2], e[3],
        ])
    }
}

impl From<State> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(State { a, b, c, d, e }: State) -> Self {
        Self::from([a, b, c, d, e])
    }
}

impl From<Digest> for [u8; LENGTH_BYTES] {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(Digest(digest): Digest) -> Self {
        digest
    }
}

impl LowerHex for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0x", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl UpperHex for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0X", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

#[cfg(feature = "error")]
impl TryFrom<&str> for Digest {
    type Error = Error;

    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != LENGTH_HEX {
            let error = Self::Error::InvalidLength {
                value: digest.len(),
                proper: LENGTH_HEX,
            };
            return Err(error);
        }
        let digest = [
            u32::from_str_radix(&digest[0x00..0x08], 16)?,
            u32::from_str_radix(&digest[0x08..0x10], 16)?,
            u32::from_str_radix(&digest[0x10..0x18], 16)?,
            u32::from_str_radix(&digest[0x18..0x20], 16)?,
            u32::from_str_radix(&digest[0x20..0x28], 16)?,
        ];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_bytes() {
        #[rustfmt::skip]
        let digest = [
            0xDA, 0x39, 0xA3, 0xEE,
            0x5E, 0x6B, 0x4B, 0x0D,
            0x32, 0x55, 0xBF, 0xEF,
            0x95, 0x60, 0x18, 0x90,
            0xAF, 0xD8, 0x07, 0x09,
        ];
        assert_eq!(Digest::new(digest).as_bytes(), &digest);
    }

    #[test]
    fn test_as_ref() {
        #[rustfmt::skip]
        let digest = [
            0xDA, 0x39, 0xA3, 0xEE,
            0x5E, 0x6B, 0x4B, 0x0D,
            0x32, 0x55, 0xBF, 0xEF,
            0x95, 0x60, 0x18, 0x90,
            0xAF, 0xD8, 0x07, 0x09,
        ];
        assert_eq!(Digest::new(digest).as_ref(), &digest);
    }

    #[test]
    fn test_format() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xDA, 0x39, 0xA3, 0xEE,
            0x5E, 0x6B, 0x4B, 0x0D,
            0x32, 0x55, 0xBF, 0xEF,
            0x95, 0x60, 0x18, 0x90,
            0xAF, 0xD8, 0x07, 0x09,
        ]);
        assert_eq!(format!("{digest:x}"), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(format!("{digest:#x}"), "0xda39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            format!("{digest:48x}"),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709        "
        );
        assert_eq!(
            format!("{digest:>48x}"),
            "        da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            format!("{digest:^48x}"),
            "    da39a3ee5e6b4b0d3255bfef95601890afd80709    "
        );
        assert_eq!(
            format!("{digest:<48x}"),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709        "
        );
        assert_eq!(
            format!("{digest:.^48x}"),
            "....da39a3ee5e6b4b0d3255bfef95601890afd80709...."
        );
        assert_eq!(format!("{digest:.8x}"), "da39a3ee");
        assert_eq!(format!("{digest:X}"), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(format!("{digest:#X}"), "0XDA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(
            format!("{digest:48X}"),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709        "
        );
        assert_eq!(
            format!("{digest:>48X}"),
            "        DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
        assert_eq!(
            format!("{digest:^48X}"),
            "    DA39A3EE5E6B4B0D3255BFEF95601890AFD80709    "
        );
        assert_eq!(
            format!("{digest:<48X}"),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709        "
        );
        assert_eq!(
            format!("{digest:.^48X}"),
            "....DA39A3EE5E6B4B0D3255BFEF95601890AFD80709...."
        );
        assert_eq!(format!("{digest:.8X}"), "DA39A3EE");
    }

    #[test]
    fn test_from() {
        #[rustfmt::skip]
        let digest = [
            0xDA, 0x39, 0xA3, 0xEE,
            0x5E, 0x6B, 0x4B, 0x0D,
            0x32, 0x55, 0xBF, 0xEF,
            0x95, 0x60, 0x18, 0x90,
            0xAF, 0xD8, 0x07, 0x09,
        ];
        assert_eq!(Digest::from(digest), Digest::new(digest));
        assert_eq!(<[u8; 20]>::from(Digest::new(digest)), digest);
    }

    #[test]
    fn test_to_hex() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xDA, 0x39, 0xA3, 0xEE,
            0x5E, 0x6B, 0x4B, 0x0D,
            0x32, 0x55, 0xBF, 0xEF,
            0x95, 0x60, 0x18, 0x90,
            0xAF, 0xD8, 0x07, 0x09,
        ]);
        assert_eq!(digest.to_hex_lowercase(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(digest.to_hex_uppercase(), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
    }

    #[cfg(feature = "error")]
    #[test]
    fn test_try_from() {
        assert_eq!(
            Digest::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"),
            Ok(Digest::new([
                0xDA, 0x39, 0xA3, 0xEE,
                0x5E, 0x6B, 0x4B, 0x0D,
                0x32, 0x55, 0xBF, 0xEF,
                0x95, 0x60, 0x18, 0x90,
                0xAF, 0xD8, 0x07, 0x09
            ]))
        );
        assert!(matches!(
            Digest::try_from("DA"),
            Err(Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709XX"),
            Err(Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD807XX"),
            Err(Error::ParseError(_))
        ));
    }
}
