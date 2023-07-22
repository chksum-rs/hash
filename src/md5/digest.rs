use std::fmt::{self, Formatter, LowerHex, UpperHex};

use super::State;
#[cfg(feature = "error")]
use crate::error::Error;

pub const LENGTH_BITS: usize = 128;
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;
pub const LENGTH_WORDS: usize = LENGTH_BYTES / 2;
pub const LENGTH_DWORDS: usize = LENGTH_WORDS / 2;
pub const LENGTH_HEX: usize = LENGTH_BYTES * 2;

/// Represents hash digest.
///
/// # Example
///
/// ```rust
/// use chksum_hash::md5::Digest;
///
/// #[rustfmt::skip]
/// let digest = Digest::new([
///     0xD4, 0x1D, 0x8C, 0xD9,
///     0x8F, 0x00, 0xB2, 0x04,
///     0xE9, 0x80, 0x09, 0x98,
///     0xEC, 0xF8, 0x42, 0x7E,
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
    /// use chksum_hash::md5::Digest;
    ///
    /// #[rustfmt::skip]
    /// let digest = Digest::new([
    ///     0xD4, 0x1D, 0x8C, 0xD9,
    ///     0x8F, 0x00, 0xB2, 0x04,
    ///     0xE9, 0x80, 0x09, 0x98,
    ///     0xEC, 0xF8, 0x42, 0x7E,
    /// ]);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "d41d8cd98f00b204e9800998ecf8427e"
    /// );
    /// ```
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn to_hex_lowercase(&self) -> String {
        format!("{self:x}")
    }

    /// Returns uppercase hexadecimal representation of digest.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash::md5::Digest;
    ///
    /// #[rustfmt::skip]
    /// let digest = Digest::new([
    ///     0xD4, 0x1D, 0x8C, 0xD9,
    ///     0x8F, 0x00, 0xB2, 0x04,
    ///     0xE9, 0x80, 0x09, 0x98,
    ///     0xEC, 0xF8, 0x42, 0x7E,
    /// ]);
    /// assert_eq!(
    ///     digest.to_hex_uppercase(),
    ///     "D41D8CD98F00B204E9800998ECF8427E"
    /// );
    /// ```
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[must_use]
    pub fn to_hex_uppercase(&self) -> String {
        format!("{self:X}")
    }
}

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
    fn from(digest: [u32; LENGTH_DWORDS]) -> Self {
        let [a, b, c, d] = digest;
        let [a, b, c, d] = [
            a.to_le_bytes(),
            b.to_le_bytes(),
            c.to_le_bytes(),
            d.to_le_bytes(),
        ];
        Self([
            a[0], a[1], a[2], a[3],
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
        ])
    }
}

impl From<State> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(state: State) -> Self {
        let (a, b, c, d) = (state.a, state.b, state.c, state.d);
        Self::from([a, b, c, d])
    }
}

impl From<Digest> for [u8; LENGTH_BYTES] {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(digest: Digest) -> Self {
        digest.0
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
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x0], self.0[0x1], self.0[0x2], self.0[0x3],
            self.0[0x4], self.0[0x5], self.0[0x6], self.0[0x7],
            self.0[0x8], self.0[0x9], self.0[0xA], self.0[0xB],
            self.0[0xC], self.0[0xD], self.0[0xE], self.0[0xF],
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
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x0], self.0[0x1], self.0[0x2], self.0[0x3],
            self.0[0x4], self.0[0x5], self.0[0x6], self.0[0x7],
            self.0[0x8], self.0[0x9], self.0[0xA], self.0[0xB],
            self.0[0xC], self.0[0xD], self.0[0xE], self.0[0xF],
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
        let (a, b, c, d) = (
            u32::from_str_radix(&digest[0x00..0x08], 16)?,
            u32::from_str_radix(&digest[0x08..0x10], 16)?,
            u32::from_str_radix(&digest[0x10..0x18], 16)?,
            u32::from_str_radix(&digest[0x18..0x20], 16)?,
        );
        let (a, b, c, d) = (a.swap_bytes(), b.swap_bytes(), c.swap_bytes(), d.swap_bytes());
        let digest = [a, b, c, d];
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
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ];
        assert_eq!(Digest::new(digest).as_bytes(), &digest);
    }

    #[test]
    fn test_as_ref() {
        #[rustfmt::skip]
        let digest = [
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ];
        assert_eq!(Digest::new(digest).as_ref(), &digest);
    }

    #[test]
    fn test_format() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ]);
        assert_eq!(format!("{digest:x}"), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:#x}"), "0xd41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:40x}"), "d41d8cd98f00b204e9800998ecf8427e        ");
        assert_eq!(format!("{digest:>40x}"), "        d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:^40x}"), "    d41d8cd98f00b204e9800998ecf8427e    ");
        assert_eq!(format!("{digest:<40x}"), "d41d8cd98f00b204e9800998ecf8427e        ");
        assert_eq!(format!("{digest:.^40x}"), "....d41d8cd98f00b204e9800998ecf8427e....");
        assert_eq!(format!("{digest:.8x}"), "d41d8cd9");
        assert_eq!(format!("{digest:X}"), "D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:#X}"), "0XD41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:40X}"), "D41D8CD98F00B204E9800998ECF8427E        ");
        assert_eq!(format!("{digest:>40X}"), "        D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:^40X}"), "    D41D8CD98F00B204E9800998ECF8427E    ");
        assert_eq!(format!("{digest:<40X}"), "D41D8CD98F00B204E9800998ECF8427E        ");
        assert_eq!(format!("{digest:.^40X}"), "....D41D8CD98F00B204E9800998ECF8427E....");
        assert_eq!(format!("{digest:.8X}"), "D41D8CD9");
    }

    #[test]
    fn test_from() {
        #[rustfmt::skip]
        let digest = [
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ];
        assert_eq!(Digest::from(digest), Digest::new(digest));
        assert_eq!(<[u8; 16]>::from(Digest::new(digest)), digest);
    }

    #[test]
    fn test_to_hex() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xD4, 0x1D, 0x8C, 0xD9,
            0x8F, 0x00, 0xB2, 0x04,
            0xE9, 0x80, 0x09, 0x98,
            0xEC, 0xF8, 0x42, 0x7E,
        ]);
        assert_eq!(digest.to_hex_lowercase(), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(digest.to_hex_uppercase(), "D41D8CD98F00B204E9800998ECF8427E");
    }

    #[cfg(feature = "error")]
    #[test]
    fn test_try_from() {
        assert_eq!(
            Digest::try_from("d41d8cd98f00b204e9800998ecf8427e"),
            Digest::try_from("D41D8CD98F00B204E9800998ECF8427E")
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("D41D8CD98F00B204E9800998ECF8427E"),
            Ok(Digest::new([
                0xD4, 0x1D, 0x8C, 0xD9,
                0x8F, 0x00, 0xB2, 0x04,
                0xE9, 0x80, 0x09, 0x98,
                0xEC, 0xF8, 0x42, 0x7E,
            ]))
        );
        assert!(matches!(
            Digest::try_from("D4"),
            Err(Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("D41D8CD98F00B204E9800998ECF8427EXX"),
            Err(Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("D41D8CD98F00B204E9800998ECF842XX"),
            Err(Error::ParseError(_))
        ));
    }
}
