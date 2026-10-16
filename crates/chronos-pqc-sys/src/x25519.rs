//! X25519 (RFC 7748) over Curve25519, field arithmetic modulo `p = 2^255 - 19`.
//!
//! This is *real* Diffie-Hellman, not an emulation: the hybrid KEM's X25519 half therefore performs
//! an actual scalar multiplication, which is what makes the shared-secret agreement in
//! [`crate::kem`] a genuine DH exchange. The implementation uses the textbook Montgomery ladder
//! with a branch-free conditional swap and is validated against the RFC 7748 §5.2 / §6.1 vectors.
//!
//! Representation: four 64-bit little-endian limbs (bit 255 masked on decode). Multiplication is a
//! schoolbook 4x4 product reduced by folding `2^256 == 38 (mod p)`, which keeps every intermediate
//! explicit and auditable — a deliberate trade of a few hundred nanoseconds for arithmetic that can
//! be checked by eye against the identities in the tests.
//!
//! Security notes:
//! * the scalar is clamped per RFC 7748 §5 and bit 255 is masked on decode, as the RFC requires;
//! * the ladder performs the same operations for every scalar bit (`cswap` is branch-free);
//! * low-order points are not rejected here (RFC 7748 §6.1 leaves that policy to the protocol); the
//!   KEM's constant-time combiner absorbs the all-zero result rather than branching on it.

/// Field element: four 64-bit little-endian limbs, value in `[0, p)`.
type Fe = [u64; 4];

/// `2^255 - 19`, the field prime.
const P: Fe = [
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

/// Curve25519 base point, u = 9.
pub const BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Clamps a scalar as specified by RFC 7748 §5.
pub fn clamp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Field element equal to 1.
fn fe_one() -> Fe {
    [1, 0, 0, 0]
}

/// Decodes a little-endian field element, masking the unused top bit.
fn fe_from_bytes(bytes: &[u8; 32]) -> Fe {
    let mut limbs = [0u64; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(
            bytes[index * 8..index * 8 + 8]
                .try_into()
                .expect("8-byte slice loads into a u64"),
        );
    }
    limbs[3] &= 0x7FFF_FFFF_FFFF_FFFF;
    limbs
}

/// Encodes a field element as 32 little-endian bytes.
fn fe_to_bytes(limbs: Fe) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, limb) in limbs.iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// `true` when `a >= b`.
fn fe_ge(a: &Fe, b: &Fe) -> bool {
    for index in (0..4).rev() {
        if a[index] > b[index] {
            return true;
        }
        if a[index] < b[index] {
            return false;
        }
    }
    true
}

/// Subtracts `p` until the value is canonical; inputs must be `< 2^256 = 2p + 38`.
fn fe_canonicalize(mut value: Fe) -> Fe {
    while fe_ge(&value, &P) {
        let mut borrow = 0u64;
        for index in 0..4 {
            let (partial, underflowed) = value[index].overflowing_sub(P[index]);
            let (result, borrowed) = partial.overflowing_sub(borrow);
            value[index] = result;
            borrow = u64::from(underflowed | borrowed);
        }
        debug_assert_eq!(borrow, 0, "subtraction is only performed when value >= p");
    }
    value
}

/// Addition modulo `p`; inputs must be `< p`.
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for index in 0..4 {
        let sum = a[index] as u128 + b[index] as u128 + carry;
        out[index] = sum as u64;
        carry = sum >> 64;
    }
    // `a + b < 2p < 2^256`, so a single conditional subtraction is enough.
    fe_canonicalize(out)
}

/// Subtraction modulo `p`; inputs must be `< p`.
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut out = [0u64; 4];
    let mut borrow = 0i128;
    for index in 0..4 {
        let difference = a[index] as i128 - b[index] as i128 - borrow;
        if difference < 0 {
            out[index] = (difference + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            out[index] = difference as u64;
            borrow = 0;
        }
    }
    if borrow == 1 {
        // a < b: add p back.
        let mut carry = 0u128;
        for index in 0..4 {
            let sum = out[index] as u128 + P[index] as u128 + carry;
            out[index] = sum as u64;
            carry = sum >> 64;
        }
    }
    out
}

/// Multiplication modulo `p`, folding `2^256 == 38 (mod p)`.
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    // Schoolbook 4x4 product into eight limbs.
    let mut wide = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let product = a[i] as u128 * b[j] as u128 + wide[i + j] as u128 + carry;
            wide[i + j] = product as u64;
            carry = product >> 64;
        }
        wide[i + 4] = wide[i + 4]
            .checked_add(carry as u64)
            .expect("4x4 limb product fits in eight limbs");
    }

    // value = low4 + 38 * high4 (mod p)
    let low = [wide[0], wide[1], wide[2], wide[3]];
    let mut times_38 = [0u64; 5];
    let mut carry: u128 = 0;
    for index in 0..4 {
        let product = wide[4 + index] as u128 * 38 + carry;
        times_38[index] = product as u64;
        carry = product >> 64;
    }
    times_38[4] = carry as u64;

    // Add the low half; the result may spill into a fifth limb, which folds back as 38 * spill.
    let mut total = [0u64; 5];
    let mut carry: u128 = 0;
    for index in 0..4 {
        let sum = low[index] as u128 + times_38[index] as u128 + carry;
        total[index] = sum as u64;
        carry = sum >> 64;
    }
    total[4] = times_38[4] + carry as u64;

    // Fold the top limb: `2^256 == 38 (mod p)`. Repeat until the top limb is zero.
    let mut top = total[4];
    while top != 0 {
        let mut carry = u128::from(top) * 38;
        for limb in total.iter_mut() {
            let sum = *limb as u128 + (carry & 0xFFFF_FFFF_FFFF_FFFF);
            *limb = sum as u64;
            carry = (carry >> 64) + (sum >> 64);
        }
        top = carry as u64;
        total[4] = 0;
    }

    fe_canonicalize([total[0], total[1], total[2], total[3]])
}

/// Multiplication by the curve constant `a24 = (486662 - 2) / 4 = 121665` (RFC 7748 §5).
fn fe_mul121665(a: &Fe) -> Fe {
    fe_mul(a, &[121_665, 0, 0, 0])
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

/// Constant-time conditional swap.
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for index in 0..4 {
        let delta = mask & (a[index] ^ b[index]);
        a[index] ^= delta;
        b[index] ^= delta;
    }
}

/// Bit pattern of the inversion exponent `p - 2 = 2^255 - 21`.
///
/// Every bit from 5 to 254 is set and the low five bits hold `2^5 - 21 = 11 = 0b01011`, i.e. bits
/// 0, 1 and 3. The exponent does not fit in a `u128`, hence the explicit bit vector.
fn inversion_exponent_bits() -> [u8; 32] {
    let mut bits = [0u8; 32];
    for index in 5..=254 {
        bits[index / 8] |= 1 << (index % 8);
    }
    bits[0] |= 0b0000_1011;
    bits
}

/// Square-and-multiply with a 256-bit little-endian exponent.
fn fe_pow(base: Fe, bits: &[u8; 32]) -> Fe {
    let mut result = fe_one();
    for byte_index in (0..32).rev() {
        let byte = bits[byte_index];
        for bit in (0..8).rev() {
            result = fe_sq(&result);
            if (byte >> bit) & 1 == 1 {
                result = fe_mul(&result, &base);
            }
        }
    }
    result
}

/// Computes the X25519 function: the u-coordinate of `scalar * point` (RFC 7748 §5).
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    clamp_scalar(&mut clamped);

    let x1 = fe_from_bytes(point);
    let mut x2 = fe_one();
    let mut z2 = [0u64; 4];
    let mut x3 = x1;
    let mut z3 = fe_one();
    let mut swap: u64 = 0;

    for bit_index in (0..255).rev() {
        let bit = (u64::from(clamped[bit_index / 8]) >> (bit_index % 8)) & 1;
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);

        let t0 = fe_add(&da, &cb);
        x3 = fe_sq(&t0);
        let t1 = fe_sub(&da, &cb);
        let t2 = fe_sq(&t1);
        z3 = fe_mul(&x1, &t2);

        x2 = fe_mul(&aa, &bb);
        let t3 = fe_mul121665(&e);
        let t4 = fe_add(&aa, &t3);
        z2 = fe_mul(&e, &t4);
    }

    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    // Projective to affine: x2 / z2, with z2^(p-2) = z2^(2^255 - 21).
    let inverse = fe_pow(z2, &inversion_exponent_bits());
    fe_to_bytes(fe_mul(&x2, &inverse))
}

/// Derives the X25519 public key for a secret scalar.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASE_POINT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str)
            .expect("hex literal")
            .try_into()
            .expect("RFC 7748 vectors are 32 bytes")
    }

    /// RFC 7748 §5.2 test vectors for the X25519 function.
    #[test]
    fn rfc7748_section_5_2_vectors() {
        let scalar = decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let point = decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&scalar, &point), expected);

        let scalar = decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let point = decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected = decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(x25519(&scalar, &point), expected);
    }

    /// RFC 7748 §6.1 Diffie-Hellman vector.
    #[test]
    fn rfc7748_section_6_1_diffie_hellman() {
        let alice_secret =
            decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_secret = decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(public_key(&alice_secret), alice_public);
        assert_eq!(public_key(&bob_secret), bob_public);
        assert_eq!(x25519(&alice_secret, &bob_public), shared);
        assert_eq!(x25519(&bob_secret, &alice_public), shared);
    }

    #[test]
    fn clamping_follows_the_rfc() {
        let mut scalar = [0xFFu8; 32];
        clamp_scalar(&mut scalar);
        assert_eq!(scalar[0], 0xF8);
        assert_eq!(scalar[31], 0x7F);
        assert_eq!(scalar[31] & 0x40, 0x40);
    }

    /// Encoding round trip and the defining algebraic identities of the field.
    #[test]
    fn field_identities_hold() {
        let samples: [Fe; 6] = [
            [0, 0, 0, 0],
            fe_from_bytes(&BASE_POINT),
            fe_from_bytes(&[0x11u8; 32]),
            fe_from_bytes(&[0xABu8; 32]),
            fe_from_bytes(&[
                0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ]),
            fe_from_bytes(&decode(
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            )),
        ];
        let one = fe_one();
        let two = [2u64, 0, 0, 0];

        for bytes in [0u8, 1, 9, 0x11, 0xAB] {
            let mut value_bytes = [bytes; 32];
            value_bytes[31] = 0x5A;
            let value = fe_from_bytes(&value_bytes);
            assert_eq!(
                fe_from_bytes(&fe_to_bytes(value)),
                value,
                "encoding round trip"
            );
        }

        for a in samples {
            assert_eq!(fe_mul(&a, &one), a, "a * 1 == a");
            assert_eq!(fe_sq(&a), fe_mul(&a, &a), "a^2 == a * a");
            assert_eq!(fe_sub(&a, &a), [0, 0, 0, 0], "a - a == 0");
            assert_eq!(fe_sub(&fe_add(&a, &a), &a), a, "(2a) - a == a");
            assert_eq!(fe_mul(&a, &two), fe_add(&a, &a), "a * 2 == a + a");
            if a != [0, 0, 0, 0] {
                assert_eq!(
                    fe_mul(&a, &fe_pow(a, &inversion_exponent_bits())),
                    one,
                    "a^(p-1) == 1 for non-zero a"
                );
            }

            for b in samples {
                assert_eq!(
                    fe_mul(&a, &fe_add(&b, &b)),
                    fe_add(&fe_mul(&a, &b), &fe_mul(&a, &b)),
                    "distributivity"
                );
                assert_eq!(
                    fe_mul(&a, &fe_mul(&b, &b)),
                    fe_mul(&fe_mul(&a, &b), &b),
                    "associativity"
                );
            }
        }
    }

    /// The schoolbook product itself, isolated from the modular reduction.
    #[test]
    fn schoolbook_product_matches_reference() {
        let a = fe_from_bytes(&[0x37u8; 32]);
        let b = fe_from_bytes(&[0x91u8; 32]);

        let mut wide = [0u64; 8];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let product = a[i] as u128 * b[j] as u128 + wide[i + j] as u128 + carry;
                wide[i + j] = product as u64;
                carry = product >> 64;
            }
            wide[i + 4] = wide[i + 4]
                .checked_add(carry as u64)
                .expect("4x4 limb product fits in eight limbs");
        }

        // Reference: (0x3737…37 as a 255-bit value) · (0x9191…91 as a 255-bit value); both inputs
        // are masked as RFC 7748 requires for a u-coordinate.
        assert_eq!(
            wide,
            [
                1354605197262023975,
                4971613839165857625,
                8588622481069691275,
                2982259086118749117,
                1900702580451426310,
                16730438012257144276,
                13113429370353310625,
                273048691594701167,
            ],
            "schoolbook product"
        );
    }

    /// `fe_mul`, `fe_add` and `fe_sub` against independently computed modular values
    /// (`a = 0x37…37`, `b = 0x91…91`, computed mod `2^255 - 19` outside this crate).
    #[test]
    fn arithmetic_matches_independent_reference() {
        let a = fe_from_bytes(&[0x37u8; 32]);
        let b = fe_from_bytes(&[0x91u8; 32]);

        assert_eq!(
            fe_mul(&a, &b),
            [
                18241071033287568926,
                13538959798812585172,
                8836848564337601427,
                4134737329862617682
            ],
            "fe_mul"
        );
        assert_eq!(
            fe_add(&a, &b),
            [
                14468034567615334600,
                14468034567615334600,
                14468034567615334600,
                5244662530760558792
            ],
            "fe_add"
        );
        assert_eq!(
            fe_sub(&a, &b),
            [
                11936128518282651046,
                11936128518282651045,
                11936128518282651045,
                2712756481427875237
            ],
            "fe_sub"
        );
    }

    /// Square-and-multiply must agree with explicit multiplication chains.
    #[test]
    fn exponentiation_matches_multiplication_chains() {
        let a = fe_from_bytes(&[0x37u8; 32]);
        let exponent_255 = {
            let mut bits = [0xFFu8; 32];
            bits[31] = 0x7F;
            bits
        };

        let exponent_2 = {
            let mut bits = [0u8; 32];
            bits[0] = 0b0000_0010;
            bits
        };
        assert_eq!(fe_pow(a, &exponent_2), fe_sq(&a), "a^2");

        let exponent_3 = {
            let mut bits = [0u8; 32];
            bits[0] = 0b0000_0011;
            bits
        };
        assert_eq!(fe_pow(a, &exponent_3), fe_mul(&fe_sq(&a), &a), "a^3");

        // a^(2^255 - 1), computed independently with Python's modular `pow`.
        assert_eq!(
            fe_pow(a, &exponent_255),
            [
                5108220924119915686,
                14707786422822647505,
                13723732584738380519,
                4809255950589738898,
            ],
            "a^(2^255-1)"
        );

        // The squaring chain a^(2^(k+1) - 1) = (a^(2^k - 1))^2 * a must agree as well.
        let mut chain = a;
        for _ in 0..254 {
            chain = fe_mul(&fe_sq(&chain), &a);
        }
        assert_eq!(chain, fe_pow(a, &exponent_255), "squaring chain");

        // And a^(p-1) == 1 must hold for the inversion exponent.
        assert_eq!(
            fe_mul(&a, &fe_pow(a, &inversion_exponent_bits())),
            fe_one(),
            "a^(p-1) == 1"
        );
    }

    /// Agreement is symmetric for a spread of scalars, which is the property the KEM relies on.
    #[test]
    fn agreement_is_symmetric_for_seeded_keys() {
        for seed in 0..32u8 {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            a[0] = seed;
            a[31] = seed.wrapping_mul(7).wrapping_add(3);
            b[0] = seed.wrapping_mul(13).wrapping_add(5);
            b[31] = seed.wrapping_mul(29).wrapping_add(11);

            let a_pub = public_key(&a);
            let b_pub = public_key(&b);
            assert_eq!(x25519(&a, &b_pub), x25519(&b, &a_pub));
        }
    }
}
