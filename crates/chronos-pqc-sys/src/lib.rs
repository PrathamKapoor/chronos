//! # chronos-pqc-sys
//!
//! Post-quantum primitives for ChronosMTC with **exact wire geometry** and the behavioural contracts
//! that security actually depends on:
//!
//! | Primitive | Codepoint | Public | Secret | Ciphertext / Signature | Shared secret / digest |
//! |---|---|---|---|---|---|
//! | X25519MLKEM768 | `0x11EC` | 1,216 B | 2,432 B | 1,120 B | 32 B |
//! | ML-DSA-44 | `0x0904` | 1,312 B | 2,560 B | 2,420 B | 64 B `μ` |
//! | ML-DSA-65 | `0x0905` | 1,952 B | 4,032 B | 3,309 B | 64 B `μ` |
//!
//! Three properties are implemented for real rather than asserted:
//!
//! 1. **Constant-time implicit rejection** (`kem`): decapsulation always computes both candidate
//!    secrets and selects between them with a bitwise mask, so nothing observable depends on whether
//!    the ciphertext was authentic.
//! 2. **Streaming external-μ** (`mldsa`): `SHAKE256(tr ‖ 0x00 ‖ ctx_len ‖ ctx ‖ message, 64)` fed
//!    incrementally, so a large message never has to be buffered.
//! 3. **Restartable signing** (`mldsa`): `RestartableSignContext::step()` performs exactly one
//!    rejection-sampling attempt, so an async driver can yield instead of stalling.
//!
//! # Backend status
//!
//! The lattice arithmetic in this crate is a deterministic SHAKE-256 **reference backend**, not
//! validated FIPS 203/204 mathematics. Every externally observable property is exact (codepoints,
//! lengths, determinism, constant-time selection, external-μ, restartable rejection sampling), and the
//! arithmetic is confined to two files so a validated backend can replace it without touching a
//! single caller. See `decisions.md` ADR-006 and the module docs of [`kem`] / [`mldsa`].
//!
//! Secret-key types are zeroized on drop, and no `unsafe` block exists in the crate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod kem;
pub mod mldsa;
pub mod x25519;

pub use kem::{
    ct_eq, x25519_mlkem768_decapsulate, x25519_mlkem768_encapsulate, x25519_mlkem768_keygen,
    SharedSecret, X25519MlKem768Ciphertext, X25519MlKem768PublicKey, X25519MlKem768SecretKey,
    MLKEM768_CIPHERTEXT_LEN, MLKEM768_DECAPS_KEY_LEN, MLKEM768_ENCAPS_KEY_LEN,
    X25519MLKEM768_CIPHERTEXT_LEN, X25519MLKEM768_GROUP, X25519MLKEM768_PUBLIC_KEY_LEN,
    X25519MLKEM768_SECRET_KEY_LEN, X25519MLKEM768_SHARED_SECRET_LEN,
};
pub use mldsa::{
    ml_dsa_44, ml_dsa_65_keygen, ml_dsa_65_sign, ml_dsa_65_verify, ExternalMuHasher,
    MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, MuContextError, RestartableSignContext,
    SignPollResult, EXTERNAL_MU_LEN, ML_DSA_44_GROUP, ML_DSA_44_PUBLIC_KEY_LEN,
    ML_DSA_44_SECRET_KEY_LEN, ML_DSA_44_SIGNATURE_LEN, ML_DSA_65_GROUP, ML_DSA_65_PUBLIC_KEY_LEN,
    ML_DSA_65_SECRET_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};

/// Post-quantum algorithms supported by the stack, with their TLS code points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Algorithm {
    /// Hybrid X25519 + ML-KEM-768 key establishment.
    X25519MlKem768,
    /// ML-DSA-44 signatures.
    MlDsa44,
    /// ML-DSA-65 signatures.
    MlDsa65,
}

impl Algorithm {
    /// TLS code point of this algorithm.
    pub fn codepoint(&self) -> u16 {
        match self {
            Self::X25519MlKem768 => X25519MLKEM768_GROUP,
            Self::MlDsa44 => ML_DSA_44_GROUP,
            Self::MlDsa65 => ML_DSA_65_GROUP,
        }
    }

    /// Resolves a TLS code point back to an algorithm.
    pub fn from_codepoint(codepoint: u16) -> Option<Self> {
        match codepoint {
            X25519MLKEM768_GROUP => Some(Self::X25519MlKem768),
            ML_DSA_44_GROUP => Some(Self::MlDsa44),
            ML_DSA_65_GROUP => Some(Self::MlDsa65),
            _ => None,
        }
    }

    /// Signature length in bytes for signature algorithms, `None` for key establishment.
    pub fn signature_len(&self) -> Option<usize> {
        match self {
            Self::MlDsa44 => Some(ML_DSA_44_SIGNATURE_LEN),
            Self::MlDsa65 => Some(ML_DSA_65_SIGNATURE_LEN),
            Self::X25519MlKem768 => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn codepoints_round_trip() {
        for algorithm in [
            Algorithm::X25519MlKem768,
            Algorithm::MlDsa44,
            Algorithm::MlDsa65,
        ] {
            assert_eq!(
                Algorithm::from_codepoint(algorithm.codepoint()),
                Some(algorithm)
            );
        }
        assert_eq!(Algorithm::from_codepoint(0x1301), None);
        assert_eq!(Algorithm::MlDsa44.signature_len(), Some(2_420));
        assert_eq!(Algorithm::MlDsa65.signature_len(), Some(3_309));
        assert_eq!(Algorithm::X25519MlKem768.signature_len(), None);
    }

    #[test]
    fn key_exchange_and_signature_pipeline() {
        let mut rng = ChaCha8Rng::seed_from_u64(0x9F4A_2C01);

        let (pk, sk) = x25519_mlkem768_keygen(&mut rng);
        let (ct, client_secret) = x25519_mlkem768_encapsulate(&pk, &mut rng);
        let server_secret = x25519_mlkem768_decapsulate(&sk, &ct);
        assert_eq!(client_secret, server_secret);

        let (sign_pk, sign_sk) = ml_dsa_65_keygen(&mut rng);
        let tr = sign_pk.key_hash();
        let mu = ExternalMuHasher::digest(&tr, b"chronos", client_secret.as_bytes()).unwrap();
        let signature = ml_dsa_65_sign(&sign_sk, &mu);
        assert!(ml_dsa_65_verify(&sign_pk, &mu, &signature));
    }
}
