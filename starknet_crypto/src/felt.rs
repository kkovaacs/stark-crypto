use std::{borrow::Cow, fmt::Display};

use starknet_curve::FieldElement;

use bitvec::{order::Msb0, slice::BitSlice, view::BitView};
use starknet_curve::ff::PrimeField;

use crate::error::{HexParseError, OverflowError};

/// The Starknet elliptic curve Field Element.
///
/// Forms the basic building block of most Starknet interactions.
#[derive(Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub struct Felt([u8; 32]);

impl std::fmt::Debug for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StarkHash({})", self)
    }
}

impl std::fmt::Display for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 0xABCDEF1234567890
        write!(f, "0x{:X}", self)
    }
}

impl std::fmt::LowerHex for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|&b| write!(f, "{:02x}", b))
    }
}

impl std::fmt::UpperHex for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|&b| write!(f, "{:02X}", b))
    }
}

impl std::default::Default for Felt {
    fn default() -> Self {
        Felt::ZERO
    }
}

impl Felt {
    pub const ZERO: Felt = Felt([0u8; 32]);

    pub fn is_zero(&self) -> bool {
        self == &Felt::ZERO
    }

    /// Returns the big-endian representation of this [Felt].
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Big-endian representation of this [Felt].
    pub const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convenience function which extends [Felt::from_be_bytes] to work with slices.
    pub const fn from_be_slice(bytes: &[u8]) -> Result<Self, OverflowError> {
        if bytes.len() > 32 {
            return Err(OverflowError);
        }

        let mut buf = [0u8; 32];
        let mut index = 0;

        loop {
            if index == bytes.len() {
                break;
            }

            buf[32 - bytes.len() + index] = bytes[index];
            index += 1;
        }

        Felt::from_be_bytes(buf)
    }

    #[cfg(fuzzing)]
    pub fn from_be_bytes_orig(bytes: [u8; 32]) -> Result<Self, OverflowError> {
        // FieldElement::from_repr[_vartime] does the check in a correct way
        match FieldElement::from_repr_vartime(FieldElementRepr(bytes)) {
            Some(field_element) => Ok(Self(field_element.to_repr().0)),
            None => Err(OverflowError),
        }
    }

    pub fn random<R: rand_core::RngCore>(rng: R) -> Self {
        use starknet_curve::ff::Field;
        Felt(FieldElement::random(rng).to_repr().0)
    }

    /// Creates a [Felt] from big-endian bytes.
    ///
    /// Returns [OverflowError] if not less than the field modulus.
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, OverflowError> {
        // ff uses byteorder BigEndian::read_u64_into which uses copy_nonoverlapping(..) and
        // u64::to_be(), this is essentially the same, though would like to test conclusively

        // FIXME: in 1.63 ptr::copy_nonoverlapping became available, using it with a local [u64; 4]
        // will require the &mut in const context. using the copy_nonoverlapping should make this
        // at least more readable and no one has to wonder if all offsets are accounted for.

        #[rustfmt::skip]
        let mut limbs = [
            u64::from_ne_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            u64::from_ne_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
            u64::from_ne_bytes([
                bytes[16], bytes[17], bytes[18], bytes[19],
                bytes[20], bytes[21], bytes[22], bytes[23],
            ]),
            u64::from_ne_bytes([
                bytes[24], bytes[25], bytes[26], bytes[27],
                bytes[28], bytes[29], bytes[30], bytes[31],
            ]),
        ];

        // this is what byteorder::BigEndian::read_u64_into does after copy_nonoverlapping
        let mut index = 0;
        loop {
            if index == limbs.len() {
                break;
            }

            limbs[index] = limbs[index].to_be();
            index += 1;
        }

        // array::swap is unstable const, clippy 0.1.62 doesn't know this
        #[allow(clippy::manual_swap)]
        {
            let temp = limbs[0];
            limbs[0] = limbs[3];
            limbs[3] = temp;

            let temp = limbs[1];
            limbs[1] = limbs[2];
            limbs[2] = temp;
        }

        // this is from expansion, `const MODULUS_LIMBS: FieldElementRepr = [...];`
        let modulus = [1u64, 0u64, 0u64, 576460752303423505u64];

        let mut borrow = 0;
        let mut index = 0;

        loop {
            if index == limbs.len() {
                break;
            }
            borrow = starknet_curve::ff::derive::sbb(limbs[index], modulus[index], borrow).1;
            index += 1;
        }

        if borrow == 0 {
            // equal to or larger than modulus
            Err(OverflowError)
        } else {
            // substraction overflow; input is smaller than modulus
            Ok(Felt(bytes))
        }
    }

    /// Returns a bit view of the 251 least significant bits in MSB order.
    pub fn view_bits(&self) -> &BitSlice<Msb0, u8> {
        &self.0.view_bits()[5..]
    }

    /// Creates a [Felt] from up-to 251 bits.
    pub fn from_bits(bits: &BitSlice<Msb0, u8>) -> Result<Self, OverflowError> {
        if bits.len() > 251 {
            return Err(OverflowError);
        }

        let mut bytes = [0u8; 32];
        bytes.view_bits_mut::<Msb0>()[256 - bits.len()..].copy_from_bitslice(bits);

        Ok(Self(bytes))
    }

    /// Returns `true` if the value of [Felt] is larger than `2^251 - 1`.
    ///
    /// Every [Felt] that is used to traverse a Merkle-Patricia Tree
    /// must not exceed 251 bits, since 251 is the height of the tree.
    pub const fn has_more_than_251_bits(&self) -> bool {
        self.0[0] & 0b1111_1000 > 0
    }

    pub const fn from_u64(u: u64) -> Self {
        const_expect!(
            Self::from_be_slice(&u.to_be_bytes()),
            "64 bits is less than 251 bits"
        )
    }

    pub const fn from_u128(u: u128) -> Self {
        const_expect!(
            Self::from_be_slice(&u.to_be_bytes()),
            "128 bits is less than 251 bits"
        )
    }
}

macro_rules! const_expect {
    ($e:expr, $why:expr) => {{
        match $e {
            Ok(x) => x,
            Err(_) => panic!(concat!("Expectation failed: ", $why)),
        }
    }};
}

use const_expect;

impl From<u64> for Felt {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u128> for Felt {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl std::ops::Add for Felt {
    type Output = Felt;

    fn add(self, rhs: Self) -> Self::Output {
        let result = FieldElement::from(self) + FieldElement::from(rhs);
        Felt::from(result)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct InvalidBufferSizeError {
    expected: usize,
    actual: usize,
}

impl Display for InvalidBufferSizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Expected buffer size {}, got {}",
            self.expected, self.actual,
        ))
    }
}

impl Felt {
    /// A convenience function which parses a hex string into a [Felt].
    ///
    /// Supports both upper and lower case hex strings, as well as an
    /// optional "0x" prefix.
    pub fn from_hex_str(hex_str: &str) -> Result<Self, HexParseError> {
        fn parse_hex_digit(digit: u8) -> Result<u8, HexParseError> {
            match digit {
                b'0'..=b'9' => Ok(digit - b'0'),
                b'A'..=b'F' => Ok(digit - b'A' + 10),
                b'a'..=b'f' => Ok(digit - b'a' + 10),
                other => Err(HexParseError::InvalidNibble(other)),
            }
        }

        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        if hex_str.len() > 64 {
            return Err(HexParseError::InvalidLength {
                max: 64,
                actual: hex_str.len(),
            });
        }

        let mut buf = [0u8; 32];

        // We want the result in big-endian so reverse iterate over each pair of nibbles.
        let chunks = hex_str.as_bytes().rchunks_exact(2);

        // Handle a possible odd nibble remaining nibble.
        let odd_nibble = chunks.remainder();
        if !odd_nibble.is_empty() {
            let full_bytes = hex_str.len() / 2;
            buf[31 - full_bytes] = parse_hex_digit(odd_nibble[0])?;
        }

        for (i, c) in chunks.enumerate() {
            // Indexing c[0] and c[1] are safe since chunk-size is 2.
            buf[31 - i] = parse_hex_digit(c[0])? << 4 | parse_hex_digit(c[1])?;
        }

        let hash = Felt::from_be_bytes(buf)?;
        Ok(hash)
    }

    /// The first stage of conversion - skip leading zeros
    fn skip_zeros(&self) -> (impl Iterator<Item = &u8>, usize, usize) {
        // Skip all leading zero bytes
        let it = self.0.iter().skip_while(|&&b| b == 0);
        let num_bytes = it.clone().count();
        let skipped = self.0.len() - num_bytes;
        // The first high nibble can be 0
        let start = if self.0[skipped] < 0x10 { 1 } else { 2 };
        // Number of characters to display
        let len = start + num_bytes * 2;
        (it, start, len)
    }

    /// The second stage of conversion - map bytes to hex str
    fn it_to_hex_str<'a>(
        it: impl Iterator<Item = &'a u8>,
        start: usize,
        len: usize,
        buf: &'a mut [u8],
    ) -> &'a [u8] {
        const LUT: [u8; 16] = *b"0123456789abcdef";
        buf[0] = b'0';
        // Same small lookup table is ~25% faster than hex::encode_from_slice 🤷
        it.enumerate().for_each(|(i, &b)| {
            let idx = b as usize;
            let pos = start + i * 2;
            let x = [LUT[(idx & 0xf0) >> 4], LUT[idx & 0x0f]];
            buf[pos..pos + 2].copy_from_slice(&x);
        });
        buf[1] = b'x';
        &buf[..len]
    }

    /// A convenience function which produces a "0x" prefixed hex str slice in a given buffer `buf`
    /// from a [Felt].
    /// Panics if `self.0.len() * 2 + 2 > buf.len()`
    pub fn as_hex_str<'a>(&'a self, buf: &'a mut [u8]) -> &'a str {
        let expected_buf_len = self.0.len() * 2 + 2;
        assert!(
            buf.len() >= expected_buf_len,
            "buffer size is {}, expected at least {}",
            buf.len(),
            expected_buf_len
        );

        if !self.0.iter().any(|b| *b != 0) {
            return "0x0";
        }

        let (it, start, len) = self.skip_zeros();
        let res = Self::it_to_hex_str(it, start, len, buf);
        // Unwrap is safe because `buf` holds valid UTF8 characters.
        std::str::from_utf8(res).unwrap()
    }

    /// A convenience function which produces a "0x" prefixed hex string from a [Felt].
    pub fn to_hex_str(&self) -> Cow<'static, str> {
        if !self.0.iter().any(|b| *b != 0) {
            return Cow::from("0x0");
        }
        let (it, start, len) = self.skip_zeros();
        let mut buf = vec![0u8; len];
        Self::it_to_hex_str(it, start, len, &mut buf);
        // Unwrap is safe as the buffer contains valid utf8
        String::from_utf8(buf).unwrap().into()
    }
}
