use std::array::TryFromSliceError;

pub const LENGTH_BITS: usize = 512;
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;
pub const LENGTH_WORDS: usize = LENGTH_BYTES / 2;
pub const LENGTH_DWORDS: usize = LENGTH_WORDS / 2;

pub(super) struct Block([u8; LENGTH_BYTES]);

impl From<Block> for [u32; LENGTH_DWORDS] {
    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn from(block: Block) -> Self {
        [
            u32::from_be_bytes([block.0[0x00], block.0[0x01], block.0[0x02], block.0[0x03]]),
            u32::from_be_bytes([block.0[0x04], block.0[0x05], block.0[0x06], block.0[0x07]]),
            u32::from_be_bytes([block.0[0x08], block.0[0x09], block.0[0x0A], block.0[0x0B]]),
            u32::from_be_bytes([block.0[0x0C], block.0[0x0D], block.0[0x0E], block.0[0x0F]]),
            u32::from_be_bytes([block.0[0x10], block.0[0x11], block.0[0x12], block.0[0x13]]),
            u32::from_be_bytes([block.0[0x14], block.0[0x15], block.0[0x16], block.0[0x17]]),
            u32::from_be_bytes([block.0[0x18], block.0[0x19], block.0[0x1A], block.0[0x1B]]),
            u32::from_be_bytes([block.0[0x1C], block.0[0x1D], block.0[0x1E], block.0[0x1F]]),
            u32::from_be_bytes([block.0[0x20], block.0[0x21], block.0[0x22], block.0[0x23]]),
            u32::from_be_bytes([block.0[0x24], block.0[0x25], block.0[0x26], block.0[0x27]]),
            u32::from_be_bytes([block.0[0x28], block.0[0x29], block.0[0x2A], block.0[0x2B]]),
            u32::from_be_bytes([block.0[0x2C], block.0[0x2D], block.0[0x2E], block.0[0x2F]]),
            u32::from_be_bytes([block.0[0x30], block.0[0x31], block.0[0x32], block.0[0x33]]),
            u32::from_be_bytes([block.0[0x34], block.0[0x35], block.0[0x36], block.0[0x37]]),
            u32::from_be_bytes([block.0[0x38], block.0[0x39], block.0[0x3A], block.0[0x3B]]),
            u32::from_be_bytes([block.0[0x3C], block.0[0x3D], block.0[0x3E], block.0[0x3F]]),
        ]
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = TryFromSliceError;

    #[cfg_attr(all(release, feature = "inline"), inline)]
    fn try_from(block: &[u8]) -> Result<Self, Self::Error> {
        block.try_into().map(Self)
    }
}
