//! ML-DSA-44 (`0x0904`) and ML-DSA-65 (`0x0905`): FIPS 204 wire geometry, 64-byte SHAKE256
//! external-μ pre-hashing, and cooperative restartable signing.
//!
//! # Backend status
//!
//! The same rule as [`crate::kem`]: every externally observable property — codepoints, key and
//! signature lengths, deterministic seeded key generation, the external-μ construction, the
//! rejection-sampling loop shape and its one-round-per-poll contract — is exact and tested; the
//! lattice arithmetic is a deterministic SHAKE-256 reference backend rather than validated FIPS 204
//! math, and must be swapped before any real deployment (`decisions.md` ADR-006).
//!
//! The two behaviours that exist precisely because they are hard to retrofit are implemented for
//! real here:
//!
//! * **External-μ** (FIPS 204 §6.2) is a streaming hasher: `tr = SHAKE256(pk, 64)` then
//!   `μ = SHAKE256(tr ‖ 0x00 ‖ ctx_len ‖ ctx ‖ message, 64)`, fed incrementally so a multi-megabyte
//!   message never lands in a buffer.
//! * **Restartable signing** models rejection sampling as a state machine: each
//!   [`RestartableSignContext::step`] performs exactly one sampling attempt and reports `Pending` or
//!   `Ready`, so an async driver can yield instead of stalling a reactor for 100 µs+.

use rand_core::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// TLS code point for ML-DSA-44 (FIPS 204).
pub const ML_DSA_44_GROUP: u16 = 0x0904;
/// TLS code point for ML-DSA-65 (FIPS 204).
pub const ML_DSA_65_GROUP: u16 = 0x0905;

/// ML-DSA-44 public key length.
pub const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1_312;
/// ML-DSA-44 private key length.
pub const ML_DSA_44_SECRET_KEY_LEN: usize = 2_560;
/// ML-DSA-44 signature length.
pub const ML_DSA_44_SIGNATURE_LEN: usize = 2_420;

/// ML-DSA-65 public key length.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1_952;
/// ML-DSA-65 private key length.
pub const ML_DSA_65_SECRET_KEY_LEN: usize = 4_032;
/// ML-DSA-65 signature length.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3_309;

/// Length of the 64-byte SHAKE256 digest used for `tr` and external `μ`.
pub const EXTERNAL_MU_LEN: usize = 64;

/// Acceptance threshold of the reference rejection sampler (~50 % acceptance, so the loop really
/// iterates; the exact rates in FIPS 204 are gamma-bound driven).
const REJECTION_THRESHOLD: u8 = 0x80;

/// Offsets inside an emitted signature: `[ctr:u32be][tag:8][body:..]`.
const SIGNATURE_CTR_LEN: usize = 4;
const SIGNATURE_TAG_LEN: usize = 8;
const SIGNATURE_BODY_LEN: usize = ML_DSA_65_SIGNATURE_LEN - SIGNATURE_CTR_LEN - SIGNATURE_TAG_LEN;

/// Domain-separated SHAKE-256 squeeze.
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

/// ML-DSA-65 public key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MlDsa65PublicKey(Box<[u8; ML_DSA_65_PUBLIC_KEY_LEN]>);

impl MlDsa65PublicKey {
    /// Raw public key bytes.
    pub fn as_bytes(&self) -> &[u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        &self.0
    }

    /// The 64-byte key hash `tr = SHAKE256(pk, 64)` (FIPS 204 §6.2).
    pub fn key_hash(&self) -> [u8; EXTERNAL_MU_LEN] {
        let mut hasher = Shake256::default();
        hasher.update(&self.0[..]);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; EXTERNAL_MU_LEN];
        reader.read(&mut out);
        out
    }
}

/// ML-DSA-65 private key; zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65SecretKey(Box<[u8; ML_DSA_65_SECRET_KEY_LEN]>);

impl MlDsa65SecretKey {
    /// Raw private key bytes.
    pub fn as_bytes(&self) -> &[u8; ML_DSA_65_SECRET_KEY_LEN] {
        &self.0
    }

    /// Seed material at the head of the private key.
    pub fn seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.0[..32]);
        seed
    }
}

impl std::fmt::Debug for MlDsa65SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa65SecretKey(<redacted>)")
    }
}

/// ML-DSA-65 signature: `ctr ‖ tag ‖ body`.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa65Signature(Box<[u8; ML_DSA_65_SIGNATURE_LEN]>);

impl MlDsa65Signature {
    /// Wraps raw signature bytes (for example a signature received on the wire).
    pub fn from_bytes(bytes: [u8; ML_DSA_65_SIGNATURE_LEN]) -> Self {
        Self(Box::new(bytes))
    }

    /// Raw signature bytes.
    pub fn as_bytes(&self) -> &[u8; ML_DSA_65_SIGNATURE_LEN] {
        &self.0
    }

    /// Sampling counter of the attempt that produced the signature.
    pub fn counter(&self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// Integrity tag binding the signature to the public key and message.
    pub fn tag(&self) -> &[u8] {
        &self.0[SIGNATURE_CTR_LEN..SIGNATURE_CTR_LEN + SIGNATURE_TAG_LEN]
    }

    /// Signature body.
    pub fn body(&self) -> &[u8] {
        &self.0[SIGNATURE_CTR_LEN + SIGNATURE_TAG_LEN..]
    }
}

impl std::fmt::Debug for MlDsa65Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsa65Signature(counter={}, len={})",
            self.counter(),
            ML_DSA_65_SIGNATURE_LEN
        )
    }
}

/// ML-DSA-44 geometry, exposed for size assertions and protocol negotiation tables.
pub mod ml_dsa_44 {
    /// Public key length (FIPS 204).
    pub const PUBLIC_KEY_LEN: usize = 1_312;
    /// Private key length (FIPS 204).
    pub const SECRET_KEY_LEN: usize = 2_560;
    /// Signature length (FIPS 204).
    pub const SIGNATURE_LEN: usize = 2_420;

    /// Derives the deterministic 44-parameter public key from a seed (reference backend).
    pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; PUBLIC_KEY_LEN] {
        let derived = super::shake256(b"chronos/mldsa44/pk", &[seed], PUBLIC_KEY_LEN);
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(&derived);
        out
    }

    /// Derives the deterministic 44-parameter private key from a seed (reference backend).
    pub fn secret_key_from_seed(seed: &[u8; 32]) -> [u8; SECRET_KEY_LEN] {
        let derived = super::shake256(b"chronos/mldsa44/sk", &[seed], SECRET_KEY_LEN);
        let mut out = [0u8; SECRET_KEY_LEN];
        out.copy_from_slice(&derived);
        out
    }
}

/// Deterministic ML-DSA-65 key generation from an RNG.
pub fn ml_dsa_65_keygen(rng: &mut impl RngCore) -> (MlDsa65PublicKey, MlDsa65SecretKey) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let pk = shake256(b"chronos/mldsa65/pk", &[&seed], ML_DSA_65_PUBLIC_KEY_LEN);
    let mut sk = shake256(b"chronos/mldsa65/sk", &[&seed], ML_DSA_65_SECRET_KEY_LEN);
    sk[..32].copy_from_slice(&seed);

    let mut pk_bytes = Box::new([0u8; ML_DSA_65_PUBLIC_KEY_LEN]);
    pk_bytes.copy_from_slice(&pk);
    let mut sk_bytes = Box::new([0u8; ML_DSA_65_SECRET_KEY_LEN]);
    sk_bytes.copy_from_slice(&sk);

    (MlDsa65PublicKey(pk_bytes), MlDsa65SecretKey(sk_bytes))
}

/// Streaming SHAKE256 external-μ hasher (FIPS 204 §6.2).
///
/// ```text
/// tr = SHAKE256(pk, 64)
/// μ  = SHAKE256(tr ‖ 0x00 ‖ ctx_len ‖ ctx ‖ message, 64)
/// ```
///
/// The context is fixed at construction (FIPS 204 caps it at 255 bytes); the message is streamed.
#[derive(Clone)]
pub struct ExternalMuHasher {
    state: Shake256,
    finished: bool,
}

impl ExternalMuHasher {
    /// Creates a hasher bound to the key hash `tr` and a signing context.
    pub fn new(tr: &[u8; EXTERNAL_MU_LEN], ctx: &[u8]) -> Result<Self, MuContextError> {
        if ctx.len() > u8::MAX as usize {
            return Err(MuContextError::ContextTooLong {
                len: ctx.len(),
                max: u8::MAX as usize,
            });
        }
        let mut state = Shake256::default();
        state.update(tr);
        state.update(&[0x00]);
        state.update(&[ctx.len() as u8]);
        state.update(ctx);
        Ok(Self {
            state,
            finished: false,
        })
    }

    /// Feeds the next message chunk; may be called any number of times.
    pub fn update(&mut self, chunk: &[u8]) {
        self.state.update(chunk);
    }

    /// Squeezes the 64-byte `μ` and consumes the hasher.
    pub fn finalize(mut self) -> [u8; EXTERNAL_MU_LEN] {
        let mut reader = self.state.finalize_xof();
        let mut out = [0u8; EXTERNAL_MU_LEN];
        reader.read(&mut out);
        self.finished = true;
        out
    }

    /// One-shot convenience wrapper.
    pub fn digest(
        tr: &[u8; EXTERNAL_MU_LEN],
        ctx: &[u8],
        message: &[u8],
    ) -> Result<[u8; EXTERNAL_MU_LEN], MuContextError> {
        let mut hasher = Self::new(tr, ctx)?;
        hasher.update(message);
        Ok(hasher.finalize())
    }
}

impl std::fmt::Debug for ExternalMuHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExternalMuHasher(finished={})", self.finished)
    }
}

/// Failure modes of the external-μ construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MuContextError {
    /// FIPS 204 limits the signing context to 255 bytes.
    #[error("external-mu context is {len} bytes, FIPS 204 allows at most {max}")]
    ContextTooLong {
        /// Provided length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
}

/// Reference-backend signature body for a given attempt counter.
fn signature_body(
    seed: &[u8; 32],
    mu: &[u8; EXTERNAL_MU_LEN],
    counter: u32,
) -> [u8; SIGNATURE_BODY_LEN] {
    let derived = shake256(
        b"chronos/mldsa65/sig",
        &[seed, mu, &counter.to_be_bytes()],
        SIGNATURE_BODY_LEN,
    );
    let mut body = [0u8; SIGNATURE_BODY_LEN];
    body.copy_from_slice(&derived);
    body
}

/// Integrity tag binding `(pk, μ, counter, body)`.
fn signature_tag(
    pk: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
    mu: &[u8; EXTERNAL_MU_LEN],
    counter: u32,
    body: &[u8],
) -> [u8; SIGNATURE_TAG_LEN] {
    let derived = shake256(
        b"chronos/mldsa65/tag",
        &[pk, mu, &counter.to_be_bytes(), body],
        SIGNATURE_TAG_LEN,
    );
    let mut tag = [0u8; SIGNATURE_TAG_LEN];
    tag.copy_from_slice(&derived);
    tag
}

/// Assembles a signature from an accepted attempt.
fn assemble_signature(
    pk: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
    mu: &[u8; EXTERNAL_MU_LEN],
    counter: u32,
    body: &[u8; SIGNATURE_BODY_LEN],
) -> MlDsa65Signature {
    let tag = signature_tag(pk, mu, counter, body);
    let mut bytes = Box::new([0u8; ML_DSA_65_SIGNATURE_LEN]);
    bytes[..SIGNATURE_CTR_LEN].copy_from_slice(&counter.to_be_bytes());
    bytes[SIGNATURE_CTR_LEN..SIGNATURE_CTR_LEN + SIGNATURE_TAG_LEN].copy_from_slice(&tag);
    bytes[SIGNATURE_CTR_LEN + SIGNATURE_TAG_LEN..].copy_from_slice(body);
    MlDsa65Signature(bytes)
}

/// One rejection-sampling attempt: returns `true` when the candidate is accepted.
///
/// The acceptance test models the FIPS 204 norm-bound checks (`|z|∞ < γ1 − β`, `|r0|∞ < γ2 − β`) by
/// drawing a nonce-dependent word and rejecting roughly half of them, which is what makes the
/// restartable loop genuinely iterate.
fn rejection_attempt(seed: &[u8; 32], mu: &[u8; EXTERNAL_MU_LEN], counter: u32) -> bool {
    let word = shake256(
        b"chronos/mldsa65/rej",
        &[seed, mu, &counter.to_be_bytes()],
        1,
    );
    word[0] < REJECTION_THRESHOLD
}

/// Signs the 64-byte `μ` in one call (the blocking convenience path).
pub fn ml_dsa_65_sign(
    secret_key: &MlDsa65SecretKey,
    mu: &[u8; EXTERNAL_MU_LEN],
) -> MlDsa65Signature {
    let seed = secret_key.seed();
    let mut context = RestartableSignContext::new(&seed, mu);
    loop {
        if let SignPollResult::Ready(signature) = context.step() {
            return signature;
        }
    }
}

/// Verifies a signature over `μ`.
pub fn ml_dsa_65_verify(
    public_key: &MlDsa65PublicKey,
    mu: &[u8; EXTERNAL_MU_LEN],
    signature: &MlDsa65Signature,
) -> bool {
    let counter = signature.counter();
    let body = signature.body();
    let expected = signature_tag(public_key.as_bytes(), mu, counter, body);
    crate::kem::ct_eq(signature.tag(), &expected) == 1
}

/// Outcome of one cooperative signing step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignPollResult {
    /// The candidate for this attempt was rejected; more attempts are required.
    Pending {
        /// 1-based attempt index that was just rejected.
        attempt: u32,
    },
    /// An attempt was accepted and the signature is complete.
    Ready(MlDsa65Signature),
}

/// Cooperative signing state machine.
///
/// Each [`Self::step`] runs exactly one sampling attempt, so a caller driving an async reactor can
/// `yield_now()` between attempts instead of blocking the worker for the whole rejection loop.
#[derive(Debug, Clone)]
pub struct RestartableSignContext {
    seed: [u8; 32],
    mu: [u8; EXTERNAL_MU_LEN],
    public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    next_counter: u32,
    attempts_taken: u32,
}

impl RestartableSignContext {
    /// Creates a context for signing `mu` with the given seed.
    pub fn new(seed: &[u8; 32], mu: &[u8; EXTERNAL_MU_LEN]) -> Self {
        let pk = ml_dsa_44_free_public_key(seed);
        Self {
            seed: *seed,
            mu: *mu,
            public_key: pk,
            next_counter: 0,
            attempts_taken: 0,
        }
    }

    /// Number of attempts executed so far.
    pub fn attempts_taken(&self) -> u32 {
        self.attempts_taken
    }

    /// The message digest this context signs.
    pub fn mu(&self) -> &[u8; EXTERNAL_MU_LEN] {
        &self.mu
    }

    /// Runs exactly one rejection-sampling attempt.
    pub fn step(&mut self) -> SignPollResult {
        let counter = self.next_counter;
        self.attempts_taken += 1;
        self.next_counter += 1;

        if rejection_attempt(&self.seed, &self.mu, counter) {
            let body = signature_body(&self.seed, &self.mu, counter);
            SignPollResult::Ready(assemble_signature(
                &self.public_key,
                &self.mu,
                counter,
                &body,
            ))
        } else {
            SignPollResult::Pending {
                attempt: self.attempts_taken,
            }
        }
    }
}

/// Derives the public key a restartable context must tag against.
fn ml_dsa_44_free_public_key(seed: &[u8; 32]) -> [u8; ML_DSA_65_PUBLIC_KEY_LEN] {
    let derived = shake256(b"chronos/mldsa65/pk", &[seed], ML_DSA_65_PUBLIC_KEY_LEN);
    let mut out = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
    out.copy_from_slice(&derived);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn rng(seed: u64) -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(seed)
    }

    fn sample_message(seed: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        rng(seed).fill_bytes(&mut out);
        out
    }

    #[test]
    fn wire_geometry_matches_fips_204() {
        assert_eq!(ML_DSA_44_GROUP, 0x0904);
        assert_eq!(ML_DSA_65_GROUP, 0x0905);
        assert_eq!(ML_DSA_44_PUBLIC_KEY_LEN, 1_312);
        assert_eq!(ML_DSA_44_SECRET_KEY_LEN, 2_560);
        assert_eq!(ML_DSA_44_SIGNATURE_LEN, 2_420);
        assert_eq!(ML_DSA_65_PUBLIC_KEY_LEN, 1_952);
        assert_eq!(ML_DSA_65_SECRET_KEY_LEN, 4_032);
        assert_eq!(ML_DSA_65_SIGNATURE_LEN, 3_309);
        assert_eq!(EXTERNAL_MU_LEN, 64);
        assert_eq!(ml_dsa_44::PUBLIC_KEY_LEN, ML_DSA_44_PUBLIC_KEY_LEN);
    }

    #[test]
    fn keygen_is_deterministic_and_correctly_sized() {
        let (pk_a, sk_a) = ml_dsa_65_keygen(&mut rng(42));
        let (pk_b, sk_b) = ml_dsa_65_keygen(&mut rng(42));
        let (pk_c, _sk_c) = ml_dsa_65_keygen(&mut rng(43));

        assert_eq!(pk_a, pk_b);
        assert_eq!(sk_a.as_bytes(), sk_b.as_bytes());
        assert_ne!(pk_a, pk_c);
        assert_eq!(pk_a.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(sk_a.as_bytes().len(), ML_DSA_65_SECRET_KEY_LEN);
        assert_eq!(pk_a.key_hash().len(), EXTERNAL_MU_LEN);
    }

    #[test]
    fn external_mu_matches_a_one_shot_reference() {
        let mut rng = rng(7);
        let (pk, _sk) = ml_dsa_65_keygen(&mut rng);
        let tr = pk.key_hash();
        let message = sample_message(11, 4_096);

        let mut streaming = ExternalMuHasher::new(&tr, b"chronos-ctx").unwrap();
        for chunk in message.chunks(317) {
            streaming.update(chunk);
        }
        let streamed = streaming.finalize();

        let one_shot = ExternalMuHasher::digest(&tr, b"chronos-ctx", &message).unwrap();
        assert_eq!(streamed, one_shot, "chunking must not change the digest");

        // Reference: SHAKE256(tr || 0x00 || ctx_len || ctx || message, 64)
        let mut hasher = Shake256::default();
        hasher.update(&tr);
        hasher.update(&[0x00]);
        hasher.update(&[b"chronos-ctx".len() as u8]);
        hasher.update(b"chronos-ctx");
        hasher.update(&message);
        let mut reader = hasher.finalize_xof();
        let mut expected = [0u8; EXTERNAL_MU_LEN];
        reader.read(&mut expected);
        assert_eq!(streamed, expected);

        // A different context must produce a different digest.
        let other = ExternalMuHasher::digest(&tr, b"chronos-ctx2", &message).unwrap();
        assert_ne!(streamed, other);
    }

    #[test]
    fn external_mu_rejects_oversized_contexts() {
        let mut rng = rng(5);
        let (pk, _sk) = ml_dsa_65_keygen(&mut rng);
        let tr = pk.key_hash();
        assert!(ExternalMuHasher::new(&tr, &vec![b'x'; 255]).is_ok());
        assert!(matches!(
            ExternalMuHasher::new(&tr, &vec![b'x'; 256]),
            Err(MuContextError::ContextTooLong { len: 256, max: 255 })
        ));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = rng(0x9F4A_2C01);
        let (pk, sk) = ml_dsa_65_keygen(&mut rng);
        let tr = pk.key_hash();
        let mu = ExternalMuHasher::digest(&tr, b"chronos", b"landmark checkpoint").unwrap();

        let signature = ml_dsa_65_sign(&sk, &mu);
        assert_eq!(signature.as_bytes().len(), ML_DSA_65_SIGNATURE_LEN);
        assert!(ml_dsa_65_verify(&pk, &mu, &signature));

        // Wrong message, wrong key and tampered bytes all fail.
        assert!(!ml_dsa_65_verify(&pk, &[0u8; EXTERNAL_MU_LEN], &signature));
        let (_pk_other, _sk_other) = ml_dsa_65_keygen(&mut rng);
        assert!(!ml_dsa_65_verify(&_pk_other, &mu, &signature));

        let mut tampered = signature.as_bytes().to_vec();
        tampered[ML_DSA_65_SIGNATURE_LEN - 1] ^= 0x01;
        let tampered_sig = MlDsa65Signature(Box::new(
            tampered
                .try_into()
                .expect("same length as the original signature"),
        ));
        assert!(!ml_dsa_65_verify(&pk, &mu, &tampered_sig));
    }

    #[test]
    fn restartable_signing_iterates_and_agrees_with_the_blocking_path() {
        let mut rng = rng(3);
        let (pk, sk) = ml_dsa_65_keygen(&mut rng);
        let tr = pk.key_hash();
        let mu = ExternalMuHasher::digest(&tr, b"ctx", b"message").unwrap();

        let blocking = ml_dsa_65_sign(&sk, &mu);

        let mut pending_seen = 0u32;
        let mut iterations = 0u32;
        let mut context = RestartableSignContext::new(&sk.seed(), &mu);
        let cooperative = loop {
            iterations += 1;
            assert!(iterations < 64, "rejection loop must terminate quickly");
            match context.step() {
                SignPollResult::Pending { .. } => pending_seen += 1,
                SignPollResult::Ready(signature) => break signature,
            }
        };

        assert_eq!(
            cooperative, blocking,
            "both paths must produce the same signature"
        );
        assert_eq!(context.attempts_taken(), iterations);
        assert!(context.attempts_taken() >= 1);
        assert_eq!(pending_seen, iterations - 1);
        assert!(ml_dsa_65_verify(&pk, &mu, &cooperative));
    }

    #[test]
    fn rejection_sampling_really_rejects_sometimes() {
        let mut rng = rng(0x5EED);
        let (pk, sk) = ml_dsa_65_keygen(&mut rng);
        let tr = pk.key_hash();

        let mut pending_total = 0u32;
        let mut max_attempts = 0u32;
        for i in 0..1_000u64 {
            let mu = ExternalMuHasher::digest(&tr, b"ctx", &i.to_be_bytes()).unwrap();
            let mut context = RestartableSignContext::new(&sk.seed(), &mu);
            let mut attempts = 0u32;
            loop {
                attempts += 1;
                assert!(attempts < 64, "unreasonable rejection streak");
                if let SignPollResult::Ready(_) = context.step() {
                    break;
                }
                pending_total += 1;
            }
            max_attempts = max_attempts.max(attempts);
        }
        assert!(
            pending_total > 0,
            "rejection sampling must reject at least once"
        );
        assert!(
            max_attempts >= 2,
            "expected at least one signature needing a retry"
        );
    }

    #[test]
    fn signatures_are_deterministic_for_a_given_key_and_message() {
        let mut rng = rng(21);
        let (pk, sk) = ml_dsa_65_keygen(&mut rng);
        let tr = pk.key_hash();
        let mu = ExternalMuHasher::digest(&tr, b"ctx", b"same").unwrap();
        let a = ml_dsa_65_sign(&sk, &mu);
        let b = ml_dsa_65_sign(&sk, &mu);
        assert_eq!(a, b);
        assert_eq!(a.counter(), b.counter());
    }

    #[test]
    fn ml_dsa_44_geometry_is_available_for_negotiation() {
        let seed = [0x11u8; 32];
        let pk = ml_dsa_44::public_key_from_seed(&seed);
        let sk = ml_dsa_44::secret_key_from_seed(&seed);
        assert_eq!(pk.len(), 1_312);
        assert_eq!(sk.len(), 2_560);
        assert_ne!(pk, ml_dsa_44::public_key_from_seed(&[0x22u8; 32]));
    }
}
