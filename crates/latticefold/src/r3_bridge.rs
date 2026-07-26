//! R3 — provable share encryption under the recipient's individual key.
//!
//! Plan.md R3: `ct0 = pk0_ind * u + e0 + Delta * (share digits)`,
//! `ct1 = pk1_ind * u + e1`, affine in the witness, run over the
//! share-transport BFV instance. This module makes the relation real:
//!
//! - **Transport.** Shares move as their base-B decomposition DIGITS (the
//!   same digits the R2 commitments bind), so the transport plaintext modulus
//!   is `t_share = 2^16` and the R3 witness is uniformly short. Encryption is
//!   `fhe.rs`'s own [`PublicKey::try_encrypt_extended`], which returns the
//!   full witness `(u, e1, e2)`; decryption is the real
//!   [`SecretKey::try_decrypt`].
//! - **Proof.** Per transport prime `p_j`, the native relation
//!   `ct0 = pk0 * u + e1 + delta * digit`, `ct1 = pk1 * u + e2` with
//!   `delta = (-t_share)^{-1} mod p_j` (fhe.rs's BEHZ-style plaintext
//!   embedding, with `Q mod t = 1` for this chain). All fhe.rs-sampled
//!   witnesses are small signed values, handled by the balanced
//!   decomposition.
//! - **Folding.** Instances across the dealer x digit axis fold per
//!   transport prime — the axis where the Noir design spent 432 C3 proofs
//!   per committee round.

use std::{error::Error, sync::Arc};

use cyclotomic_rings::rings::{
    N4096S0ChallengeSet, N4096S0Field, N4096S0RingNTT, N4096S0RingPoly, N4096S1ChallengeSet,
    N4096S1Field, N4096S1RingNTT, N4096S1RingPoly, N8192S0ChallengeSet, N8192S0Field,
    N8192S0RingNTT, N8192S0RingPoly, N8192S1ChallengeSet, N8192S1Field, N8192S1RingNTT,
    N8192S1RingPoly,
};
use fhe::bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_rand::rng;
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder};
use stark_rings::cyclotomic_ring::CRT;
use stark_rings_linalg::SparseMatrix;

use crate::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::{
        linearization::{
            LFLinearizationProver, LFLinearizationVerifier, LinearizationProver,
            LinearizationVerifier,
        },
        NIFSProver, NIFSVerifier,
    },
    transcript::{poseidon::PoseidonTranscript, Transcript},
    vdkg_params::{R3_MODULI, R3_PLAINTEXT_MODULUS},
};

const KAPPA: usize = 4;

/// Decomposition parameters for the 63-bit share-transport rings.
#[derive(Clone)]
pub struct R3Params;

impl DecompositionParams for R3Params {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    const K: usize = 64;
}

/// Encode a signed digit coefficient as a plaintext-space value.
pub fn digit_encode(digit: i64) -> u64 {
    digit.rem_euclid(R3_PLAINTEXT_MODULUS as i64) as u64
}

/// Recover a signed digit coefficient from a decoded plaintext value.
pub fn digit_decode(value: u64) -> i64 {
    let t = R3_PLAINTEXT_MODULUS as i64;
    let value = value as i64 % t;
    if value > t / 2 {
        value - t
    } else {
        value
    }
}

/// `delta = (-t_share)^{-1} mod p`: fhe.rs's plaintext embedding scalar for
/// this chain (`Q mod t = 1`, so `m_scaled = center(m) * delta`).
pub fn embedding_delta(prime: u64) -> u64 {
    let t = R3_PLAINTEXT_MODULUS as u128;
    let p = prime as u128;
    let neg_t = (p - t % p) % p;
    // Fermat inversion; the transport moduli are prime.
    let mut result = 1u128;
    let mut base = neg_t;
    let mut exponent = p - 2;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base % p;
        }
        base = base * base % p;
        exponent >>= 1;
    }
    result as u64
}

/// One recipient individual-BFV transport instance for the digit-form R3
/// chain.
pub struct R3Transport {
    params: Arc<bfv::BfvParameters>,
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl R3Transport {
    /// Build the transport instance at the given ring degree.
    pub fn new(degree: usize) -> Result<Self, Box<dyn Error>> {
        let params: Arc<bfv::BfvParameters> = bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(R3_PLAINTEXT_MODULUS)
            .set_moduli(&R3_MODULI)
            .set_variance(10)
            .build_arc()?;
        let mut key_rng = rng();
        let secret_key = SecretKey::random(&params, &mut key_rng);
        let public_key = PublicKey::new(&secret_key, &mut key_rng);
        Ok(Self {
            params,
            secret_key,
            public_key,
        })
    }

    pub fn degree(&self) -> usize {
        self.params.degree()
    }

    /// The recipient's individual public key as per-prime coefficient rows in
    /// coefficient form: `[pk0, pk1][prime][coefficient]`.
    pub fn pk_coefficients(&self) -> [Vec<Vec<u64>>; 2] {
        let rows = |index: usize| {
            self.public_key.c[index]
                .clone()
                .into_power_basis()
                .coefficients()
                .rows()
                .into_iter()
                .map(|row| row.to_vec())
                .collect::<Vec<_>>()
        };
        [rows(0), rows(1)]
    }

    /// Per-prime coefficient rows of a ciphertext component in coefficient
    /// form.
    pub fn ciphertext_coefficients(ct: &Ciphertext, index: usize) -> Vec<Vec<u64>> {
        ct[index]
            .clone()
            .into_power_basis()
            .coefficients()
            .rows()
            .into_iter()
            .map(|row| row.to_vec())
            .collect()
    }

    /// Per-prime coefficient rows of an fhe.rs witness polynomial (`u`, `e1`,
    /// or `e2`) in coefficient form.
    pub fn witness_coefficients(poly: &Poly<PowerBasis>) -> Vec<Vec<u64>> {
        poly.coefficients()
            .rows()
            .into_iter()
            .map(|row| row.to_vec())
            .collect()
    }

    /// Encrypt one digit polynomial with fhe.rs's extended encryption,
    /// returning the ciphertext and the full witness `(u, e1, e2)`.
    pub fn encrypt_digit(
        &self,
        digit: &[u64],
    ) -> Result<(Ciphertext, Poly<PowerBasis>, Poly<PowerBasis>, Poly<PowerBasis>), Box<dyn Error>>
    {
        let plaintext = Plaintext::try_encode(digit, Encoding::poly(), &self.params)?;
        let mut encryption_rng = rng();
        let (ciphertext, u, e1, e2) = self
            .public_key
            .try_encrypt_extended(&plaintext, &mut encryption_rng)?;
        Ok((
            ciphertext,
            u.into_power_basis(),
            e1.into_power_basis(),
            e2.into_power_basis(),
        ))
    }

    /// Decrypt a ciphertext and decode the digit polynomial.
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<Vec<u64>, Box<dyn Error>> {
        let plaintext = self.secret_key.try_decrypt(ct)?;
        Ok(Vec::<u64>::try_decode(&plaintext, Encoding::poly())?)
    }
}

macro_rules! define_r3_track {
    ($module:ident, $ring:ty, $poly:ty, $field:ty, $challenge_set:ty, $prime:expr, $degree:expr) => {
        pub mod $module {
            use super::*;

            type R3Transcript = PoseidonTranscript<$ring, $challenge_set>;

            pub const PRIME: u64 = $prime;
            pub const DEGREE: usize = $degree;

            /// Coefficient vector (raw, possibly canonical-negative) -> native
            /// NTT ring element.
            pub fn coeffs_to_ntt(coeffs: &[u64]) -> Result<$ring, Box<dyn Error>> {
                if coeffs.len() != DEGREE {
                    return Err(format!(
                        "polynomial has {} coefficients, expected {DEGREE}",
                        coeffs.len()
                    )
                    .into());
                }
                let polynomial = <$poly>::from(
                    coeffs
                        .iter()
                        .map(|&c| <$field>::from(c))
                        .collect::<Vec<_>>(),
                );
                Ok(CRT::elementwise_crt(vec![polynomial])[0])
            }

            /// Signed (i64) coefficient vector -> native NTT ring element.
            pub fn signed_to_ntt(coeffs: &[i64]) -> Result<$ring, Box<dyn Error>> {
                let unsigned = coeffs
                    .iter()
                    .map(|&c| {
                        if c < 0 {
                            (PRIME as i128 + c as i128) as u64
                        } else {
                            c as u64
                        }
                    })
                    .collect::<Vec<_>>();
                coeffs_to_ntt(&unsigned)
            }

            // z = [ct0, ct1, one, u, e1, e2, m]
            const CT0: usize = 0;
            const CT1: usize = 1;
            const ONE: usize = 2;
            const U: usize = 3;
            const E1: usize = 4;
            const E2: usize = 5;
            const M: usize = 6;
            const R3_ROWS: usize = 32; // >= 4 * L = 20 committed limbs

            fn r3_r1cs(pk0: &$ring, pk1: &$ring, delta: $ring) -> R1CS<$ring> {
                let one = <$ring>::from(1u128);
                let mut a_rows = vec![vec![]; R3_ROWS];
                a_rows[0] = vec![
                    (one, CT0),
                    (-*pk0, U),
                    (-one, E1),
                    (-delta, M),
                ];
                a_rows[1] = vec![(one, CT1), (-*pk1, U), (-one, E2)];
                let mut b_rows = vec![vec![]; R3_ROWS];
                b_rows[0] = vec![(one, ONE)];
                b_rows[1] = vec![(one, ONE)];
                R1CS::<$ring> {
                    l: 2,
                    A: SparseMatrix { nrows: R3_ROWS, ncols: 7, coeffs: a_rows },
                    B: SparseMatrix { nrows: R3_ROWS, ncols: 7, coeffs: b_rows },
                    C: SparseMatrix {
                        nrows: R3_ROWS,
                        ncols: 7,
                        coeffs: vec![vec![]; R3_ROWS],
                    },
                }
            }

            pub fn r3_context(
                pk0: &$ring,
                pk1: &$ring,
            ) -> (CCS<$ring>, AjtaiCommitmentScheme<$ring>) {
                let delta = <$ring>::from(embedding_delta(PRIME) as u128);
                (
                    CCS::from_r1cs(r3_r1cs(pk0, pk1, delta), R3_ROWS),
                    AjtaiCommitmentScheme::from_domain::<R3Transcript>(
                        &format!("vdkg/r3/p{}/N{}", PRIME, DEGREE),
                        KAPPA,
                        4 * R3Params::L,
                        DEGREE,
                    ),
                )
            }

            /// Build one R3 instance from the fhe.rs ciphertext and witness
            /// coefficient rows for this prime, plus the signed digit
            /// polynomial.
            #[allow(clippy::too_many_arguments)]
            pub fn r3_instance(
                ct0: &$ring,
                ct1: &$ring,
                u: $ring,
                e1: $ring,
                e2: $ring,
                m: $ring,
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
            ) -> Result<(CCCS<$ring>, Witness<$ring>), Box<dyn Error>> {
                let z = vec![*ct0, *ct1, <$ring>::from(1u128), u, e1, e2, m];
                ccs.check_relation(&z)?;

                let witness = Witness::from_w_ccs::<R3Params>(vec![u, e1, e2, m]);
                let cm = CCCS {
                    cm: witness.commit::<R3Params>(scheme)?,
                    x_ccs: vec![*ct0, *ct1],
                };
                Ok((cm, witness))
            }

            /// Prove a batch of R3 instances (linearization for each, then
            /// fold the batch into one accumulator). The per-fold verifier
            /// self-check is deferred by default (`DKG_VERIFY_FOLDS=1` to
            /// re-enable).
            pub fn prove_and_fold_r3(
                instances: &[(CCCS<$ring>, Witness<$ring>)],
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
                tag: u64,
            ) -> Result<(), Box<dyn Error>> {
                let tags = vec![tag; instances.len()];
                prove_and_fold_r3_tagged(instances, ccs, scheme, &tags)
            }

            /// As [`prove_and_fold_r3`], but with one metadata `tag` per
            /// instance, so each instance's linearization is bound to its own
            /// (sender, recipient, channel/limb) domain. Each `tag` packs
            /// `sender + 2^16·recipient + 2^32·channel` (the
            /// `fhe_bridge::metadata_domain` layout); the fields are absorbed
            /// separately so each is individually bound. The shared fold
            /// transcript absorbs every tag in instance order.
            pub fn prove_and_fold_r3_tagged(
                instances: &[(CCCS<$ring>, Witness<$ring>)],
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
                tags: &[u64],
            ) -> Result<(), Box<dyn Error>> {
                if instances.is_empty() {
                    return Err("no R3 instances to prove".into());
                }
                if tags.len() != instances.len() {
                    return Err(format!(
                        "expected one metadata tag per instance ({} tags for {} instances)",
                        tags.len(),
                        instances.len()
                    )
                    .into());
                }
                let verify_folds = std::env::var_os("DKG_VERIFY_FOLDS").is_some();

                let absorb_label = |transcript: &mut R3Transcript| {
                    for &tag in tags {
                        for value in [tag & 0xFFFF, (tag >> 16) & 0xFFFF, tag >> 32] {
                            transcript.absorb(&<$ring>::from(value as u128));
                        }
                    }
                };
                // Binary fold tree: same total fold count as the sequential
                // chain, but log2(n) depth with independent, parallel nodes
                // (and independently verifiable proofs per node).
                crate::nifs::tree::fold_tree::<$ring, R3Params, R3Transcript>(
                    instances,
                    ccs,
                    scheme,
                    &absorb_label,
                    !verify_folds,
                )?;
                Ok(())
            }
        }
    };
}

define_r3_track!(
    n8192_s0, N8192S0RingNTT, N8192S0RingPoly, N8192S0Field, N8192S0ChallengeSet,
    R3_MODULI[0], 8192
);
define_r3_track!(
    n8192_s1, N8192S1RingNTT, N8192S1RingPoly, N8192S1Field, N8192S1ChallengeSet,
    R3_MODULI[1], 8192
);
define_r3_track!(
    n4096_s0, N4096S0RingNTT, N4096S0RingPoly, N4096S0Field, N4096S0ChallengeSet,
    R3_MODULI[0], 4096
);
define_r3_track!(
    n4096_s1, N4096S1RingNTT, N4096S1RingPoly, N4096S1Field, N4096S1ChallengeSet,
    R3_MODULI[1], 4096
);
