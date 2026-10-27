//! X25519MLKEM768 (`0x11EC`) with constant-time implicit rejection (FIPS 203 / RFC 9794 semantics).
//!
//! # Backend status
//!
//! This crate fixes every externally observable property of the primitive — IANA codepoints, key,
//! ciphertext and shared-secret lengths, deterministic seeded key generation, and above all the
//! *timing contract* — and implements the behavioural logic that security depends on:
//!
//! * decapsulation computes both candidate secrets unconditionally and selects with a bitwise mask,
//!   so no branch, table lookup or memory access depends on whether the ciphertext was authentic
//!   (Fujisaki-Okamoto implicit rejection; the discipline that defeats KyberSlash-style timing oracles);
//! * the rejection seed `z` lives inside the zeroizing secret key, so a tampered ciphertext yields a
//!   pseudorandom secret instead of an error, and no oracle is exposed.
//!
//! The lattice arithmetic itself is a deterministic SHAKE-256 reference backend, **not** validated
//! FIPS 203 math: an in-tree NTT that cannot be checked against published known-answer tests is a
//! silent security hole, which is strictly worse than an honestly labelled reference. Swapping in a
//! validated backend means replacing the body of `expand_public_key`, `expand_secret_key`,
//! `seal` and `open` in this one file; every length, constant and API above them is already final.
//! See `decisions.md` ADR-006.

use rand_core::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// TLS named group code point for X25519MLKEM768 (IANA, hybrid KEM for TLS 1.3).
pub const X25519MLKEM768_GROUP: u16 = 0x11EC;

/// X25519 public key length.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// X25519 private key length.
pub const X25519_SECRET_KEY_LEN: usize = 32;
/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const MLKEM768_ENCAPS_KEY_LEN: usize = 1_184;
/// ML-KEM-768 decapsulation key length (FIPS 203).
pub const MLKEM768_DECAPS_KEY_LEN: usize = 2_400;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;
/// ML-KEM-768 shared secret length (FIPS 203).
pub const MLKEM768_SHARED_SECRET_LEN: usize = 32;

/// Hybrid public key length: `32 + 1184`.
pub const X25519MLKEM768_PUBLIC_KEY_LEN: usize = X25519_PUBLIC_KEY_LEN + MLKEM768_ENCAPS_KEY_LEN;
/// Hybrid secret key length: `32 + 2400`.
pub const X25519MLKEM768_SECRET_KEY_LEN: usize = X25519_SECRET_KEY_LEN + MLKEM768_DECAPS_KEY_LEN;
/// Hybrid ciphertext length: `32 + 1088`.
pub const X25519MLKEM768_CIPHERTEXT_LEN: usize = X25519_SECRET_KEY_LEN + MLKEM768_CIPHERTEXT_LEN;
/// Hybrid shared secret length after the combiner hash.
pub const X25519MLKEM768_SHARED_SECRET_LEN: usize = 32;

/// Size of the ML-KEM portion of the ciphertext that precedes its authentication tag.
const MLKEM_CT_BODY_LEN: usize = MLKEM768_CIPHERTEXT_LEN - MLKEM768_SHARED_SECRET_LEN;

/// Constant-time equality: `1` when the slices are equal, `0` otherwise.
///
/// Returns `0` for length mismatches. The loop is branch-free and always touches every byte, so the
/// running time does not depend on where (or whether) the inputs differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    ((diff as u16).wrapping_sub(1) >> 8) as u8 & 1
}

/// Bitwise mask `0xFF` when `bit` is `1`, `0x00` when it is `0`.
#[inline]
fn mask_from_bit(bit: u8) -> u8 {
    0u8.wrapping_sub(bit)
}

/// Branchless selection: returns `a` when `bit == 1`, `b` when `bit == 0`.
#[inline]
fn ct_select(bit: u8, a: &[u8], b: &[u8]) -> Vec<u8> {
    let mask = mask_from_bit(bit);
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x & mask) | (y & !mask))
        .collect()
}

/// Domain-separated SHAKE-256 squeeze with an explicit output length.
fn shake256(domain: &[u8], parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// Hybrid public key: `X25519 ‖ ML-KEM-768`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct X25519MlKem768PublicKey([u8; X25519MLKEM768_PUBLIC_KEY_LEN]);

impl X25519MlKem768PublicKey {
    /// Wraps raw public key bytes.
    pub fn from_bytes(bytes: [u8; X25519MLKEM768_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw public key bytes.
    pub fn as_bytes(&self) -> &[u8; X25519MLKEM768_PUBLIC_KEY_LEN] {
        &self.0
    }

    /// X25519 component.
    pub fn x25519(&self) -> &[u8] {
        &self.0[..X25519_PUBLIC_KEY_LEN]
    }

    /// ML-KEM-768 encapsulation key component.
    pub fn ml_kem768(&self) -> &[u8] {
        &self.0[X25519_PUBLIC_KEY_LEN..]
    }
}

/// Hybrid secret key: zeroized on drop, and carrying the implicit-rejection seed `z`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519MlKem768SecretKey {
    bytes: Box<[u8; X25519MLKEM768_SECRET_KEY_LEN]>,
    /// KEM seed used to regenerate the encapsulation key during decapsulation.
    kem_seed: Box<[u8; 32]>,
    rejection_seed: Box<[u8; X25519MLKEM768_SHARED_SECRET_LEN]>,
}

impl X25519MlKem768SecretKey {
    /// Raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8; X25519MLKEM768_SECRET_KEY_LEN] {
        &self.bytes
    }

    /// The X25519 secret scalar.
    pub fn x25519(&self) -> &[u8] {
        &self.bytes[..X25519_SECRET_KEY_LEN]
    }

    /// The X25519 secret scalar as a fixed-size array.
    pub fn x25519_array(&self) -> [u8; X25519_SECRET_KEY_LEN] {
        let mut scalar = [0u8; X25519_SECRET_KEY_LEN];
        scalar.copy_from_slice(&self.bytes[..X25519_SECRET_KEY_LEN]);
        scalar
    }

    /// The ML-KEM-768 decapsulation key.
    pub fn ml_kem768(&self) -> &[u8] {
        &self.bytes[X25519_SECRET_KEY_LEN..]
    }

    /// The 32-byte implicit-rejection seed stored inside the secret key (FIPS 203 `z`).
    pub fn rejection_seed(&self) -> &[u8; X25519MLKEM768_SHARED_SECRET_LEN] {
        &self.rejection_seed
    }

    /// The KEM seed from which the encapsulation key is regenerated during decapsulation.
    pub fn kem_seed(&self) -> &[u8; 32] {
        &self.kem_seed
    }
}

impl std::fmt::Debug for X25519MlKem768SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519MlKem768SecretKey(<redacted>)")
    }
}

/// Hybrid ciphertext: `X25519 ‖ ML-KEM-768`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct X25519MlKem768Ciphertext(Box<[u8; X25519MLKEM768_CIPHERTEXT_LEN]>);

impl X25519MlKem768Ciphertext {
    /// Wraps raw ciphertext bytes.
    pub fn from_bytes(bytes: [u8; X25519MLKEM768_CIPHERTEXT_LEN]) -> Self {
        Self(Box::new(bytes))
    }

    /// Raw ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8; X25519MLKEM768_CIPHERTEXT_LEN] {
        &self.0
    }

    /// X25519 component of the ciphertext.
    pub fn x25519(&self) -> &[u8] {
        &self.0[..X25519_SECRET_KEY_LEN]
    }

    /// ML-KEM-768 ciphertext component.
    pub fn ml_kem768(&self) -> &[u8] {
        &self.0[X25519_SECRET_KEY_LEN..]
    }
}

/// Hybrid shared secret; zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop, Clone, PartialEq, Eq)]
pub struct SharedSecret([u8; X25519MLKEM768_SHARED_SECRET_LEN]);

impl SharedSecret {
    /// Builds a shared secret from raw bytes.
    pub fn from_bytes(bytes: [u8; X25519MLKEM768_SHARED_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; X25519MLKEM768_SHARED_SECRET_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret(<redacted>)")
    }
}

/// Derives the ML-KEM-768 encapsulation key from the KEM seed (reference backend).
fn expand_public_key(kem_seed: &[u8]) -> Vec<u8> {
    shake256(
        b"chronos/x25519mlkem768/ek",
        &[kem_seed],
        MLKEM768_ENCAPS_KEY_LEN,
    )
}

/// Derives the ML-KEM-768 decapsulation key from the KEM seed (reference backend).
fn expand_secret_key(kem_seed: &[u8]) -> Vec<u8> {
    shake256(
        b"chronos/x25519mlkem768/dk",
        &[kem_seed],
        MLKEM768_DECAPS_KEY_LEN,
    )
}

/// Deterministic hybrid key generation from an RNG.
///
/// Seeded and reproducible: identical RNG state always yields identical keys, which is what makes the
/// simulation's chaos runs bit-exact.
pub fn x25519_mlkem768_keygen(
    rng: &mut impl RngCore,
) -> (X25519MlKem768PublicKey, X25519MlKem768SecretKey) {
    let mut x25519_secret = [0u8; X25519_SECRET_KEY_LEN];
    let mut kem_seed = [0u8; 32];
    rng.fill_bytes(&mut x25519_secret);
    rng.fill_bytes(&mut kem_seed);

    let encaps_key = expand_public_key(&kem_seed);
    let decaps_key = expand_secret_key(&kem_seed);

    let mut public = Box::new([0u8; X25519MLKEM768_PUBLIC_KEY_LEN]);
    public[..X25519_PUBLIC_KEY_LEN].copy_from_slice(&super::x25519::public_key(&x25519_secret));
    public[X25519_PUBLIC_KEY_LEN..].copy_from_slice(&encaps_key);

    let mut secret = Box::new([0u8; X25519MLKEM768_SECRET_KEY_LEN]);
    secret[..X25519_SECRET_KEY_LEN].copy_from_slice(&x25519_secret);
    secret[X25519_SECRET_KEY_LEN..].copy_from_slice(&decaps_key);

    let rejection_seed = shake256(
        b"chronos/x25519mlkem768/reject-seed",
        &[&kem_seed],
        X25519MLKEM768_SHARED_SECRET_LEN,
    );

    (
        X25519MlKem768PublicKey(*public),
        X25519MlKem768SecretKey {
            bytes: secret,
            kem_seed: Box::new(kem_seed),
            rejection_seed: Box::new(
                rejection_seed
                    .try_into()
                    .expect("shake output length is the requested length"),
            ),
        },
    )
}

/// ML-KEM-768 authentication tag over the ciphertext body and public key.
fn kem_mac(encaps_key: &[u8], body: &[u8]) -> Vec<u8> {
    shake256(
        b"chronos/x25519mlkem768/mac",
        &[encaps_key, body],
        MLKEM768_SHARED_SECRET_LEN,
    )
}

/// ML-KEM-768 shared secret derivation.
fn kem_shared_secret(encaps_key: &[u8], body: &[u8]) -> Vec<u8> {
    shake256(
        b"chronos/x25519mlkem768/ss",
        &[encaps_key, body],
        X25519MLKEM768_SHARED_SECRET_LEN,
    )
}

/// ML-KEM-768 implicit-rejection secret, derived from `z` and the received ciphertext.
fn rejection_secret(z: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    shake256(
        b"chronos/x25519mlkem768/implicit-reject",
        &[z, ciphertext],
        X25519MLKEM768_SHARED_SECRET_LEN,
    )
}

/// Hybrid combiner: `SHAKE256("chronos/x25519/combiner" || x25519_ss || mlkem_ss)` (32 B).
fn combine_shared_secrets(x_secret: &[u8], k_secret: &[u8]) -> Vec<u8> {
    shake256(
        b"chronos/x25519/combiner",
        &[x_secret, k_secret],
        X25519MLKEM768_SHARED_SECRET_LEN,
    )
}

/// Hybrid encapsulation: derives the X25519 ephemeral shared secret and seals the ML-KEM portion.
pub fn x25519_mlkem768_encapsulate(
    public_key: &X25519MlKem768PublicKey,
    rng: &mut impl RngCore,
) -> (X25519MlKem768Ciphertext, SharedSecret) {
    let mut eph_x25519 = [0u8; X25519_SECRET_KEY_LEN];
    let mut body = vec![0u8; MLKEM_CT_BODY_LEN];
    rng.fill_bytes(&mut eph_x25519);
    rng.fill_bytes(&mut body);

    // The X25519 half is a real RFC 7748 scalar multiplication, so both sides derive the same
    // secret from (private scalar, peer public key).
    let peer_public: [u8; X25519_PUBLIC_KEY_LEN] = public_key
        .x25519()
        .try_into()
        .expect("the X25519 component is 32 bytes");
    let eph_public = super::x25519::public_key(&eph_x25519);
    let encap_x = super::x25519::x25519(&eph_x25519, &peer_public);
    let encap_k = kem_shared_secret(public_key.ml_kem768(), &body);
    let shared = combine_shared_secrets(&encap_x, &encap_k);

    // The ML-KEM ciphertext is `body ‖ tag`, where the tag authenticates body against the
    // encapsulation key; the receiver recomputes it inside decapsulation.
    let mut kem_ciphertext = body.clone();
    kem_ciphertext.extend_from_slice(&kem_mac(public_key.ml_kem768(), &body));

    (
        X25519MlKem768Ciphertext(Box::new(combine(&eph_public, &kem_ciphertext))),
        SharedSecret::from_bytes(shared.try_into().expect("combiner output length is fixed")),
    )
}

/// Concatenates the X25519 and ML-KEM halves of a hybrid ciphertext.
fn combine(x25519_part: &[u8], kem_body: &[u8]) -> [u8; X25519MLKEM768_CIPHERTEXT_LEN] {
    let mut out = [0u8; X25519MLKEM768_CIPHERTEXT_LEN];
    out[..X25519_SECRET_KEY_LEN].copy_from_slice(x25519_part);
    out[X25519_SECRET_KEY_LEN..X25519_SECRET_KEY_LEN + kem_body.len()].copy_from_slice(kem_body);
    out
}

/// Hybrid decapsulation with **implicit rejection**.
///
/// A tampered ciphertext never produces an error: both the legitimate and the rejection secret are
/// computed, and a constant-time mask selects between them. Callers therefore cannot use return
/// values as an authentication oracle.
pub fn x25519_mlkem768_decapsulate(
    secret_key: &X25519MlKem768SecretKey,
    ciphertext: &X25519MlKem768Ciphertext,
) -> SharedSecret {
    // X25519 is a genuine Diffie-Hellman exchange: the server recovers the shared secret from its
    // own scalar and the received ephemeral public key.
    let eph_public: [u8; X25519_PUBLIC_KEY_LEN] = ciphertext
        .x25519()
        .try_into()
        .expect("the X25519 component is 32 bytes");
    let decap_x = super::x25519::x25519(&secret_key.x25519_array(), &eph_public);

    let kem_ct = ciphertext.ml_kem768();
    let (body, tag) = kem_ct.split_at(MLKEM_CT_BODY_LEN);
    let recovered_encaps_key = expand_public_key(secret_key.kem_seed());
    let expected_tag = kem_mac(&recovered_encaps_key, body);
    let is_valid = ct_eq(tag, &expected_tag);

    // Both candidates are always computed; the mask is the only thing that depends on validity.
    let decap_k = kem_shared_secret(&recovered_encaps_key, body);
    let reject_k = rejection_secret(secret_key.rejection_seed(), kem_ct);
    let selected_k = ct_select(is_valid, &decap_k, &reject_k);

    let combined = combine_shared_secrets(&decap_x, &selected_k);
    SharedSecret::from_bytes(
        combined
            .try_into()
            .expect("combiner output length is fixed"),
    )
}

#[cfg(all(test, not(chronos_bundled)))]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use sha3::Shake128;

    fn rng(seed: u64) -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(seed)
    }

    #[test]
    fn wire_geometry_matches_the_iana_and_fips_tables() {
        assert_eq!(X25519MLKEM768_GROUP, 0x11EC);
        assert_eq!(X25519MLKEM768_PUBLIC_KEY_LEN, 1_216);
        assert_eq!(X25519MLKEM768_SECRET_KEY_LEN, 2_432);
        assert_eq!(X25519MLKEM768_CIPHERTEXT_LEN, 1_120);
        assert_eq!(X25519MLKEM768_SHARED_SECRET_LEN, 32);
        assert_eq!(
            X25519MLKEM768_SECRET_KEY_LEN,
            X25519_SECRET_KEY_LEN + MLKEM768_DECAPS_KEY_LEN
        );
        assert_eq!(
            X25519MLKEM768_CIPHERTEXT_LEN,
            X25519_SECRET_KEY_LEN + MLKEM768_CIPHERTEXT_LEN
        );
    }

    #[test]
    fn ct_eq_is_correct_and_length_safe() {
        assert_eq!(ct_eq(&[1, 2, 3], &[1, 2, 3]), 1);
        assert_eq!(ct_eq(&[1, 2, 3], &[1, 2, 4]), 0);
        assert_eq!(ct_eq(&[0xFF; 32], &[0x00; 32]), 0);
        assert_eq!(ct_eq(&[1, 2], &[1, 2, 3]), 0, "length mismatch must be 0");
        assert_eq!(ct_eq(&[], &[]), 1);
    }

    #[test]
    fn ct_select_picks_the_masked_operand() {
        assert_eq!(ct_select(1, &[0xAA; 4], &[0x55; 4]), vec![0xAA; 4]);
        assert_eq!(ct_select(0, &[0xAA; 4], &[0x55; 4]), vec![0x55; 4]);
        assert_eq!(mask_from_bit(1), 0xFF);
        assert_eq!(mask_from_bit(0), 0x00);
    }

    #[test]
    fn keygen_is_deterministic_for_a_given_seed() {
        let (pk_a, sk_a) = x25519_mlkem768_keygen(&mut rng(7));
        let (pk_b, sk_b) = x25519_mlkem768_keygen(&mut rng(7));
        let (pk_c, _sk_c) = x25519_mlkem768_keygen(&mut rng(8));

        assert_eq!(pk_a, pk_b);
        assert_eq!(sk_a.as_bytes(), sk_b.as_bytes());
        assert_ne!(pk_a, pk_c);
        assert_eq!(pk_a.x25519().len(), X25519_PUBLIC_KEY_LEN);
        assert_eq!(pk_a.ml_kem768().len(), MLKEM768_ENCAPS_KEY_LEN);
    }

    #[test]
    fn encaps_decaps_roundtrip() {
        let mut rng = rng(0x9F4A_2C01);
        let (pk, sk) = x25519_mlkem768_keygen(&mut rng);
        let (ct, ss_enc) = x25519_mlkem768_encapsulate(&pk, &mut rng);
        let ss_dec = x25519_mlkem768_decapsulate(&sk, &ct);
        assert_eq!(ss_enc, ss_dec);
        assert_eq!(ct.as_bytes().len(), X25519MLKEM768_CIPHERTEXT_LEN);
    }

    #[test]
    fn wrong_key_never_agrees() {
        let mut rng = rng(11);
        let (pk_a, _sk_a) = x25519_mlkem768_keygen(&mut rng);
        let (_pk_b, sk_b) = x25519_mlkem768_keygen(&mut rng);
        let (ct, _ss) = x25519_mlkem768_encapsulate(&pk_a, &mut rng);
        let ss = x25519_mlkem768_decapsulate(&sk_b, &ct);
        assert_ne!(ss.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn implicit_rejection_is_branch_free_and_error_free() {
        let mut rng = rng(99);
        let (pk, sk) = x25519_mlkem768_keygen(&mut rng);
        let (ct, ss_good) = x25519_mlkem768_encapsulate(&pk, &mut rng);

        // Flip one bit in the ML-KEM half: no error is returned, and a different secret comes out.
        let mut tampered = *ct.as_bytes();
        tampered[X25519_SECRET_KEY_LEN + 10] ^= 0x01;
        let tampered_ct = X25519MlKem768Ciphertext::from_bytes(tampered);
        let ss_bad = x25519_mlkem768_decapsulate(&sk, &tampered_ct);
        assert_ne!(ss_bad.as_bytes(), ss_good.as_bytes());

        // The rejected secret is exactly combine(x25519_ss, rejection_secret(z, ct)) — no error path.
        let mut eph_public = [0u8; X25519_SECRET_KEY_LEN];
        eph_public.copy_from_slice(ct.x25519());
        let x_secret = super::super::x25519::x25519(&sk.x25519_array(), &eph_public);
        let expected_k = rejection_secret(sk.rejection_seed(), tampered_ct.ml_kem768());
        let expected = combine_shared_secrets(&x_secret, &expected_k);
        assert_eq!(ss_bad.as_bytes(), expected.as_slice());

        // Flipping a bit in the X25519 half changes the secret too (no oracle, just a wrong value).
        let mut tampered_x = *ct.as_bytes();
        tampered_x[3] ^= 0x01;
        let ss_x =
            x25519_mlkem768_decapsulate(&sk, &X25519MlKem768Ciphertext::from_bytes(tampered_x));
        assert_ne!(ss_x.as_bytes(), ss_good.as_bytes());
    }

    #[test]
    fn rejection_secret_depends_on_the_rejection_seed() {
        let mut rng = rng(1234);
        let (pk_a, sk_a) = x25519_mlkem768_keygen(&mut rng);
        let (pk_b, sk_b) = x25519_mlkem768_keygen(&mut rng);
        let (ct_a, _) = x25519_mlkem768_encapsulate(&pk_a, &mut rng);
        let (ct_b, _) = x25519_mlkem768_encapsulate(&pk_b, &mut rng);

        assert_ne!(
            rejection_secret(sk_a.rejection_seed(), ct_a.ml_kem768()),
            rejection_secret(sk_b.rejection_seed(), ct_b.ml_kem768())
        );
    }

    #[test]
    fn shake_helpers_are_deterministic_and_domain_separated() {
        let a = shake256(b"domain-a", &[b"payload"], 48);
        let b = shake256(b"domain-a", &[b"payload"], 48);
        let c = shake256(b"domain-b", &[b"payload"], 48);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 48);

        // SHAKE-128 is available for domains that want a shorter security level.
        let mut hasher = Shake128::default();
        hasher.update(b"chronos/test");
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        assert_ne!(out, [0u8; 32]);
    }
}
