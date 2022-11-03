use crate::felt::Felt;
use starknet_curve::{AffinePoint, FieldElement, FieldElementRepr, ProjectivePoint, PEDERSEN_P0};

use bitvec::{field::BitField, slice::BitSlice};
use starknet_curve::ff::PrimeField;

include!(concat!(env!("OUT_DIR"), "/curve_consts.rs"));

/// Computes the [Starknet Pedersen hash] on `a` and `b` using precomputed points.
///
/// [Starknet Pedersen hash]: https://docs.starknet.io/documentation/develop/Hashing/hash-functions/#definition
pub fn stark_hash(a: Felt, b: Felt) -> Felt {
    let a = FieldElement::from(a).into_bits();
    let b = FieldElement::from(b).into_bits();

    // Preprocessed material is lookup-tables for each chunk of bits
    let table_size = (1 << CURVE_CONSTS_BITS) - 1;
    let add_points = |acc: &mut ProjectivePoint, bits: &BitSlice<_, u64>, prep: &[AffinePoint]| {
        bits.chunks(CURVE_CONSTS_BITS)
            .enumerate()
            .for_each(|(i, v)| {
                let offset: usize = v.load_le();
                if offset > 0 {
                    // Table lookup at 'offset-1' in table for chunk 'i'
                    acc.add_affine(&prep[i * table_size + offset - 1]);
                }
            });
    };

    // Compute hash
    let mut acc = PEDERSEN_P0;
    add_points(&mut acc, &a[..248], &CURVE_CONSTS_P1); // Add a_low * P1
    add_points(&mut acc, &a[248..252], &CURVE_CONSTS_P2); // Add a_high * P2
    add_points(&mut acc, &b[..248], &CURVE_CONSTS_P3); // Add b_low * P3
    add_points(&mut acc, &b[248..252], &CURVE_CONSTS_P4); // Add b_high * P4

    // Convert to affine
    let result = AffinePoint::from(&acc);

    // Return x-coordinate
    Felt::from(result.x)
}

impl From<Felt> for FieldElement {
    fn from(hash: Felt) -> Self {
        debug_assert_eq!(
            std::mem::size_of::<FieldElement>(),
            std::mem::size_of::<Felt>()
        );
        Self::from_repr(FieldElementRepr(hash.to_be_bytes())).unwrap()
    }
}

impl From<FieldElement> for Felt {
    fn from(fp: FieldElement) -> Self {
        debug_assert_eq!(
            std::mem::size_of::<FieldElement>(),
            std::mem::size_of::<Felt>()
        );
        // unwrap is safe because the FieldElement and StarkHash
        // should both be smaller than the field modulus.
        Felt::from_be_bytes(fp.to_repr().0).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::error::{HexParseError, OverflowError};

    use bitvec::{bitvec, order::Msb0};
    use pretty_assertions::assert_eq;

    #[test]
    fn view_bits() {
        let one = Felt::from_hex_str("1").unwrap();

        let one = one.view_bits().to_bitvec();

        let mut expected = bitvec![0; 251];
        expected.set(250, true);
        assert_eq!(one, expected);
    }

    #[test]
    fn bits_round_trip() {
        let mut bits = bitvec![Msb0, u8; 1; 251];
        bits.set(0, false);
        bits.set(1, false);
        bits.set(2, false);
        bits.set(3, false);
        bits.set(4, false);

        let res = Felt::from_bits(&bits).unwrap();

        let x = res.view_bits();
        let y = Felt::from_bits(x).unwrap();

        assert_eq!(res, y);
    }

    #[test]
    fn hash() {
        // Test vectors from https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/pedersen_hash_test.cc
        let a = "03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb";
        let b = "0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a";
        let expected = "030e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662";

        fn parse_hex(str: &str) -> [u8; 32] {
            let mut buf = [0; 32];
            hex::decode_to_slice(str, &mut buf).unwrap();
            buf
        }

        let a = Felt::from_be_bytes(parse_hex(a)).unwrap();
        let b = Felt::from_be_bytes(parse_hex(b)).unwrap();
        let expected = Felt::from_be_bytes(parse_hex(expected)).unwrap();

        let hash = stark_hash(a, b);
        let hash2 = stark_hash(a, b);

        assert_eq!(hash, hash2);
        assert_eq!(hash, expected);
    }

    #[test]
    fn bytes_round_trip() {
        let original = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let hash = Felt::from_be_bytes(original).unwrap();
        let bytes = hash.to_be_bytes();
        assert_eq!(bytes, original);
    }

    // Prime field modulus
    const MODULUS: [u8; 32] = [
        8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    #[test]
    fn from_bytes_overflow() {
        // Field modulus
        assert_eq!(Felt::from_be_bytes(MODULUS), Err(OverflowError));
        // Field modulus - 1
        let mut max_val = MODULUS;
        max_val[31] -= 1;
        Felt::from_be_bytes(max_val).unwrap();
    }

    #[test]
    fn hash_field_round_trip() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let original = Felt::from_be_bytes(bytes).unwrap();
        let fp = FieldElement::from(original);
        let hash = Felt::from(fp);
        assert_eq!(hash, original);
    }

    mod from_be_slice {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn round_trip() {
            let original = Felt::from_hex_str("abcdef0123456789").unwrap();
            let bytes = original.to_be_bytes();
            let result = Felt::from_be_slice(&bytes[..]).unwrap();

            assert_eq!(result, original);
        }

        #[test]
        fn too_long() {
            let original = Felt::from_hex_str("abcdef0123456789").unwrap();
            let mut bytes = original.to_be_bytes().to_vec();
            bytes.push(0);
            Felt::from_be_slice(&bytes[..]).unwrap_err();
        }

        #[test]
        fn short_slice() {
            let original = Felt::from_hex_str("abcdef0123456789").unwrap();
            let bytes = original.to_be_bytes();
            let result = Felt::from_be_slice(&bytes[24..]);

            assert_eq!(result, Ok(original));
        }

        #[test]
        fn max() {
            let mut max_val = MODULUS;
            max_val[31] -= 1;
            Felt::from_be_slice(&max_val[..]).unwrap();
        }

        #[test]
        fn overflow() {
            assert_eq!(Felt::from_be_slice(&MODULUS[..]), Err(OverflowError));
        }
    }

    mod fmt {
        use crate::Felt;
        use pretty_assertions::assert_eq;

        #[test]
        fn debug() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = Felt::from_hex_str(hex_str).unwrap();
            let result = format!("{:?}", starkhash);

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);
            let expected = format!("StarkHash({})", starkhash);

            assert_eq!(result, expected);
        }

        #[test]
        fn fmt() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = Felt::from_hex_str(hex_str).unwrap();
            let result = format!("{:x}", starkhash);

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            // We don't really care which casing is used by fmt.
            assert_eq!(result.to_lowercase(), expected.to_lowercase());
        }

        #[test]
        fn lower_hex() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = Felt::from_hex_str(hex_str).unwrap();
            let result = format!("{:x}", starkhash);

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            assert_eq!(result, expected.to_lowercase());
        }

        #[test]
        fn upper_hex() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = Felt::from_hex_str(hex_str).unwrap();
            let result = format!("{:X}", starkhash);

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            assert_eq!(result, expected.to_uppercase());
        }
    }

    mod from_hex_str {
        use super::*;
        use assert_matches::assert_matches;
        use pretty_assertions::assert_eq;

        /// Test hex string with its expected [Felt].
        fn test_data() -> (&'static str, Felt) {
            let mut expected = [0; 32];
            expected[31] = 0xEF;
            expected[30] = 0xCD;
            expected[29] = 0xAB;
            expected[28] = 0xef;
            expected[27] = 0xcd;
            expected[26] = 0xab;
            expected[25] = 0x89;
            expected[24] = 0x67;
            expected[23] = 0x45;
            expected[22] = 0x23;
            expected[21] = 0x01;
            let expected = Felt::from_be_bytes(expected).unwrap();

            ("0123456789abcdefABCDEF", expected)
        }

        #[test]
        fn simple() {
            let (test_str, expected) = test_data();
            let uut = Felt::from_hex_str(test_str).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn prefix() {
            let (test_str, expected) = test_data();
            let uut = Felt::from_hex_str(&format!("0x{}", test_str)).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn leading_zeros() {
            let (test_str, expected) = test_data();
            let uut = Felt::from_hex_str(&format!("000000000{}", test_str)).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn prefix_and_leading_zeros() {
            let (test_str, expected) = test_data();
            let uut = Felt::from_hex_str(&format!("0x000000000{}", test_str)).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn invalid_nibble() {
            assert_matches!(Felt::from_hex_str("0x123z").unwrap_err(), HexParseError::InvalidNibble(n) => assert_eq!(n, b'z'))
        }

        #[test]
        fn invalid_len() {
            assert_matches!(Felt::from_hex_str(&"1".repeat(65)).unwrap_err(), HexParseError::InvalidLength{max: 64, actual: n} => assert_eq!(n, 65))
        }

        #[test]
        fn overflow() {
            // Field modulus
            let mut modulus =
                "0x800000000000011000000000000000000000000000000000000000000000001".to_string();
            assert_eq!(
                Felt::from_hex_str(&modulus).unwrap_err(),
                HexParseError::Overflow
            );
            // Field modulus - 1
            modulus.pop();
            modulus.push('0');
            Felt::from_hex_str(&modulus).unwrap();
        }
    }

    mod to_hex_str {
        use super::*;
        use pretty_assertions::assert_eq;
        const ODD: &str = "0x1234567890abcde";
        const EVEN: &str = "0x1234567890abcdef";
        const MAX: &str = "0x800000000000011000000000000000000000000000000000000000000000000";

        #[test]
        fn zero() {
            assert_eq!(Felt::ZERO.to_hex_str(), "0x0");
            let mut buf = [0u8; 66];
            assert_eq!(Felt::ZERO.as_hex_str(&mut buf), "0x0");
        }

        #[test]
        fn odd() {
            let hash = Felt::from_hex_str(ODD).unwrap();
            assert_eq!(hash.to_hex_str(), ODD);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), ODD);
        }

        #[test]
        fn even() {
            let hash = Felt::from_hex_str(EVEN).unwrap();
            assert_eq!(hash.to_hex_str(), EVEN);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), EVEN);
        }

        #[test]
        fn max() {
            let hash = Felt::from_hex_str(MAX).unwrap();
            assert_eq!(hash.to_hex_str(), MAX);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), MAX);
        }

        #[test]
        #[should_panic]
        fn buffer_too_small() {
            let mut buf = [0u8; 65];
            Felt::ZERO.as_hex_str(&mut buf);
        }
    }

    mod has_more_than_251_bits {
        use super::*;

        #[test]
        fn has_251_bits() {
            let mut bytes = [0xFFu8; 32];
            bytes[0] = 0x07;
            let h = Felt::from_be_bytes(bytes).unwrap();
            assert!(!h.has_more_than_251_bits());
        }

        #[test]
        fn has_252_bits() {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x08;
            let h = Felt::from_be_bytes(bytes).unwrap();
            assert!(h.has_more_than_251_bits());
        }
    }
}
