use std::fmt::{self, Formatter, LowerHex, UpperHex};

use super::State;
#[cfg(feature = "error")]
use crate::error::Error;

pub const LENGTH_BITS: usize = 224;
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;
pub const LENGTH_WORDS: usize = LENGTH_BYTES / 2;
pub const LENGTH_DWORDS: usize = LENGTH_WORDS / 2;
pub const LENGTH_HEX: usize = LENGTH_BYTES * 2;

/// Represents hash digest.
///
/// # Example
///
/// ```rust
/// use chksum_hash::sha2::sha224::Digest;
///
/// #[rustfmt::skip]
/// let digest = Digest::new([
///     0xD1, 0x4A, 0x02, 0x8C,
///     0x2A, 0x3A, 0x2B, 0xC9,
///     0x47, 0x61, 0x02, 0xBB,
///     0x28, 0x82, 0x34, 0xC4,
///     0x15, 0xA2, 0xB0, 0x1F,
///     0x82, 0x8E, 0xA6, 0x2A,
///     0xC5, 0xB3, 0xE4, 0x2F,
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
    /// use chksum_hash::sha2::sha224::Digest;
    ///
    /// #[rustfmt::skip]
    /// let digest = Digest::new([
    ///     0xD1, 0x4A, 0x02, 0x8C,
    ///     0x2A, 0x3A, 0x2B, 0xC9,
    ///     0x47, 0x61, 0x02, 0xBB,
    ///     0x28, 0x82, 0x34, 0xC4,
    ///     0x15, 0xA2, 0xB0, 0x1F,
    ///     0x82, 0x8E, 0xA6, 0x2A,
    ///     0xC5, 0xB3, 0xE4, 0x2F,
    /// ]);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
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
    /// use chksum_hash::sha2::sha224::Digest;
    ///
    /// #[rustfmt::skip]
    /// let digest = Digest::new([
    ///     0xD1, 0x4A, 0x02, 0x8C,
    ///     0x2A, 0x3A, 0x2B, 0xC9,
    ///     0x47, 0x61, 0x02, 0xBB,
    ///     0x28, 0x82, 0x34, 0xC4,
    ///     0x15, 0xA2, 0xB0, 0x1F,
    ///     0x82, 0x8E, 0xA6, 0x2A,
    ///     0xC5, 0xB3, 0xE4, 0x2F,
    /// ]);
    /// assert_eq!(
    ///     digest.to_hex_uppercase(),
    ///     "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
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
    fn from([a, b, c, d, e, f, g]: [u32; LENGTH_DWORDS]) -> Self {
        let [a, b, c, d, e, f, g] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
            f.to_be_bytes(),
            g.to_be_bytes(),
        ];
        Self([
            a[0], a[1], a[2], a[3],
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
            e[0], e[1], e[2], e[3],
            f[0], f[1], f[2], f[3],
            g[0], g[1], g[2], g[3],
        ])
    }
}

impl From<State> for Digest {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    #[rustfmt::skip]
    fn from(State { a, b, c, d, e, f, g, .. }: State) -> Self {
        Self::from([a, b, c, d, e, f, g])
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
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
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
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
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
            u32::from_str_radix(&digest[0x28..0x30], 16)?,
            u32::from_str_radix(&digest[0x30..0x38], 16)?,
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
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ];
        assert_eq!(Digest::new(digest).as_bytes(), &digest);
    }

    #[test]
    fn test_as_ref() {
        #[rustfmt::skip]
        let digest = [
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ];
        assert_eq!(Digest::new(digest).as_ref(), &digest);
    }

    #[test]
    fn test_format() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ]);
        assert_eq!(
            format!("{digest:x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:#x}"),
            "0xd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:64x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f        "
        );
        assert_eq!(
            format!("{digest:>64x}"),
            "        d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:^64x}"),
            "    d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f    "
        );
        assert_eq!(
            format!("{digest:<64x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f        "
        );
        assert_eq!(
            format!("{digest:.^64x}"),
            "....d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f...."
        );
        assert_eq!(format!("{digest:.8x}"), "d14a028c");
        assert_eq!(
            format!("{digest:X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:#X}"),
            "0XD14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:64X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F        "
        );
        assert_eq!(
            format!("{digest:>64X}"),
            "        D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:^64X}"),
            "    D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F    "
        );
        assert_eq!(
            format!("{digest:<64X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F        "
        );
        assert_eq!(
            format!("{digest:.^64X}"),
            "....D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F...."
        );
        assert_eq!(format!("{digest:.8X}"), "D14A028C");
    }

    #[test]
    fn test_from() {
        #[rustfmt::skip]
        let digest = [
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ];
        assert_eq!(Digest::from(digest), Digest::new(digest));
        assert_eq!(<[u8; 28]>::from(Digest::new(digest)), digest);
    }

    #[test]
    fn test_to_hex() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ]);
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F");
    }

    #[cfg(feature = "error")]
    #[test]
    fn test_try_from() {
        assert_eq!(
            Digest::try_from("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F")
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"),
            Ok(Digest::new([
                0xD1, 0x4A, 0x02, 0x8C,
                0x2A, 0x3A, 0x2B, 0xC9,
                0x47, 0x61, 0x02, 0xBB,
                0x28, 0x82, 0x34, 0xC4,
                0x15, 0xA2, 0xB0, 0x1F,
                0x82, 0x8E, 0xA6, 0x2A,
                0xC5, 0xB3, 0xE4, 0x2F,
            ]))
        );
        assert!(matches!(
            Digest::try_from("D1"),
            Err(Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42FXX"),
            Err(Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E4XX"),
            Err(Error::ParseError(_))
        ));
    }
}
