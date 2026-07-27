//! Native end-to-end VDKG flow over the threshold RNS channels and the
//! reconstruction prime P, following the `plan.md` relations R1..R7,
//! generic over the parameter set ([`VdkgParams`]):
//!
//! - **P1 DKG.** Every dealer proves R1 (`pk0_i = -a * sk_i + e_i`, with the
//!   smudging noise `e_sm,i` inside the same short witness), shares both
//!   secrets per channel (`generate_channel_sharing`, the plan's native
//!   per-channel formulation of R2) with GRS-syndrome R2 proofs, transports
//!   the recipient's shares through the proven R3 path (each share's
//!   R2-committed digits encrypted with `fhe.rs` extended encryption, proven
//!   per transport prime and folded — see [`crate::r3_bridge`]), and the
//!   recipient opens every received share in the metadata-bound R4 relation,
//!   folded per channel with NIFS (reusing [`crate::fhe_bridge`]).
//! - **P2 aggregation (R5).** `pk0_agg = sum pk0_i` is public; the Ajtai
//!   homomorphism check `sum Com(w_i) == Com(sum w_i)` is free, and the
//!   aggregate is additionally checked against the R1 relation shape.
//! - **P3 user encryption (Ruser).** A user encrypts a plaintext `m` under the
//!   aggregated key: `ct0 = pk0_agg * u + e0 + Delta * m`, `ct1 = a * u + e1`,
//!   proven natively per channel. The encryption randomness is sampled once
//!   and shared across channels (short), so the per-channel ciphertexts are
//!   CRT-consistent.
//! - **P4 threshold decryption.** Each of the first T parties proves R6
//!   (`d_j = ct0 + ct1 * sk_share_j + e_sm_share_j`) over its aggregated R4
//!   shares, folded per channel; the T decryption shares are Lagrange-
//!   interpolated per channel and the P-track R7 relations prove the CRT
//!   reconstruction (quotient witnesses `u = u_l + s_l * q_l`) and the decode
//!   (`u = Delta * m + e`, centered rounding witness) natively in the P ring,
//!   both range-enforced by tight witness decompositions (§9.3 margin in
//!   `vdkg_params::r7_margin_holds`), recovering the user plaintext.
//!
//! Production distributions: secrets, errors, and smudging noise are sampled
//! with the pinned fhe.rs TRBFV distributions ([`crate::samples`]) — ternary
//! `sk`, CBD errors, λ=50 smudging noise (wide: committed in R1 as balanced
//! limbs, shared as per-channel residues) — and the R7 decode uses the
//! centered-noise form `u = Delta * m + e` with `|e| <= Delta/2`.
//!
//! Deliberate demonstration simplifications (documented, never silent):
//!
//! - Cross-relation equality-of-openings (the R1<->R2 secret anchor, the
//!   R2->R4 share binding, and Ruser's cross-channel `Com(m)` consistency) are
//!   example-side assertions, exactly as in the other slices; verifier-bound
//!   equality proofs remain the known gap listed in `DKG_SLICES.md`.

use std::error::Error;

use ark_ff::{Field, PrimeField};
use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};
use cyclotomic_rings::rings::{
    N16384PChallengeSet, N16384PField, N16384PRingNTT, N16384PRingPoly, N16384Q0ChallengeSet,
    N16384Q0Field, N16384Q0RingNTT, N16384Q0RingPoly, N16384Q1ChallengeSet, N16384Q1Field,
    N16384Q1RingNTT, N16384Q1RingPoly, N16384Q2ChallengeSet, N16384Q2Field, N16384Q2RingNTT,
    N16384Q2RingPoly, N16384Q3ChallengeSet, N16384Q3Field, N16384Q3RingNTT, N16384Q3RingPoly,
    N4096PChallengeSet, N4096PField, N4096PRingNTT, N4096PRingPoly, N4096Q0ChallengeSet,
    N4096Q0Field, N4096Q0RingNTT, N4096Q0RingPoly, N4096Q1ChallengeSet, N4096Q1Field,
    N4096Q1RingNTT, N4096Q1RingPoly, N4096Q2ChallengeSet, N4096Q2Field, N4096Q2RingNTT,
    N4096Q2RingPoly, N4096Q3ChallengeSet, N4096Q3Field, N4096Q3RingNTT, N4096Q3RingPoly,
};
use num_bigint::{BigInt, BigUint};
use stark_rings::{
    cyclotomic_ring::{CRT, ICRT},
    PolyRing,
};
use stark_rings_linalg::SparseMatrix;

use crate::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    fhe_bridge::{
        generate_channel_sharing, ChannelSharings, CommitteeConfig,
    },
    samples::{balanced_limbs, sample_dealer, smudging_max_bits, DealerSamples},
    nifs::{
        linearization::{
            LFLinearizationProver, LFLinearizationVerifier, LinearizationProver,
            LinearizationVerifier,
        },
        NIFSProver, NIFSVerifier,
    },
    transcript::{poseidon::PoseidonTranscript, Transcript},
    vdkg_params::{
        DemoParams, ProdParams, VdkgParams, DEMO_R7_CRT_B, DEMO_R7_CRT_L, DEMO_R7_DECODE_B,
        DEMO_R7_DECODE_L, PROD_R7_CRT_B, PROD_R7_CRT_L, PROD_R7_DECODE_B, PROD_R7_DECODE_L,
    },
};

const KAPPA: usize = 4;

#[derive(Clone)]
struct DemoR4Params;

impl DecompositionParams for DemoR4Params {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    // The q channels are 34-bit fields; retain enough binary limbs for signed
    // field representatives and the public-input decomposition used by NIFS.
    const K: usize = 35;
}

/// Demo (d=4096) R7 CRT-quotient witness decomposition (tight): capacity 2^67
/// over the ~2^66.3 quotient witnesses. The margin accounting and the derived
/// extraction slack are in `vdkg_params` (see `r7_margin_holds`).
#[derive(Clone)]
struct DemoR7CrtParams;

impl DecompositionParams for DemoR7CrtParams {
    const B: u128 = DEMO_R7_CRT_B;
    const L: usize = DEMO_R7_CRT_L;
    const B_SMALL: usize = 2;
    // log2(B); the R7 track is decide-directly, so the fold-only K is
    // documentary (a fold would additionally need K to cover the public
    // inputs, and is ruled out by the fold-slack analysis in vdkg_params).
    const K: usize = 17;
}

/// Demo (d=4096) R7 decode-noise witness decomposition (tight): capacity 2^83
/// over the ~2^74 centered noise, enforced bound 2^84 - 1 < Delta - E_true.
#[derive(Clone)]
struct DemoR7DecodeParams;

impl DecompositionParams for DemoR7DecodeParams {
    const B: u128 = DEMO_R7_DECODE_B;
    const L: usize = DEMO_R7_DECODE_L;
    const B_SMALL: usize = 2;
    // log2(B); see DemoR7CrtParams.
    const K: usize = 12;
}

#[derive(Clone)]
struct ProdR4Params;

impl DecompositionParams for ProdR4Params {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    // The q channels are 61-bit fields; retain enough binary limbs for signed
    // field representatives and the public-input decomposition used by NIFS.
    const K: usize = 66;
}

/// Production (d=16384) R7 CRT-quotient witness decomposition (tight):
/// capacity ~2^116 over the Q/q_l quotient witnesses; enforced bound
/// 2^117 - 1.
#[derive(Clone)]
struct ProdR7CrtParams;

impl DecompositionParams for ProdR7CrtParams {
    const B: u128 = PROD_R7_CRT_B;
    const L: usize = PROD_R7_CRT_L;
    const B_SMALL: usize = 2;
    // log2(B); see DemoR7CrtParams.
    const K: usize = 11;
}

/// Production (d=16384) R7 decode-noise witness decomposition (tight):
/// capacity 2^149 over the ~2^145.6 centered noise; enforced bound
/// 2^150 - 1 < Delta - E_true (headroom ~16x).
#[derive(Clone)]
struct ProdR7DecodeParams;

impl DecompositionParams for ProdR7DecodeParams {
    const B: u128 = PROD_R7_DECODE_B;
    const L: usize = PROD_R7_DECODE_L;
    const B_SMALL: usize = 2;
    // log2(B); see DemoR7CrtParams.
    const K: usize = 11;
}

/// Sample a polynomial with small non-negative coefficients in `[0, bound)`.
fn sample_short_poly<P: VdkgParams>(bound: u64, rng: &mut impl rand::Rng) -> Vec<u64> {
    (0..P::DEGREE).map(|_| rng.next_u64() % bound).collect()
}

/// Sample a smudging-noise polynomial in `[3N, 6N)` per coefficient. The shift
/// dominates the worst-case negative wrap terms of the negacyclic product
/// noises (`-2 * H * N`), keeping the decode witness positive.
fn sample_smudging_poly<P: VdkgParams>(rng: &mut impl rand::Rng) -> Vec<u64> {
    let n = P::DEGREE as u64;
    (0..P::DEGREE)
        .map(|_| 3 * n + rng.next_u64() % (3 * n))
        .collect()
}

/// Sum transported share polynomials coefficient-wise, mod `modulus`.
fn sum_transported<P: VdkgParams>(shares: &[Vec<u64>], modulus: u64) -> Vec<u64> {
    let mut sum = vec![0u64; P::DEGREE];
    for share in shares {
        for (acc, &value) in sum.iter_mut().zip(share) {
            *acc += value;
            if *acc >= modulus {
                *acc -= modulus;
            }
        }
    }
    sum
}

macro_rules! define_flow_channel {
    ($module:ident, $params:ty, $decomp:ty, $bridge:ident, $ring:ty, $poly:ty, $field:ty, $challenge_set:ty, $channel:expr) => {
        pub mod $module {
            use super::*;

            type ChannelTranscript = PoseidonTranscript<$ring, $challenge_set>;

            pub const CHANNEL: usize = $channel;

            pub fn modulus() -> u64 {
                <$params as VdkgParams>::THRESHOLD_MODULI[CHANNEL]
            }

            fn degree() -> usize {
                <$params as VdkgParams>::DEGREE
            }

            fn scalar_ring(value: $field) -> $ring {
                <$ring>::from(value.into_bigint().as_ref()[0] as u128)
            }

            /// Domain-separate a transcript by the committee configuration,
            /// the channel, and a per-relation tag (dealer/party id).
            fn absorb_config(
                transcript: &mut ChannelTranscript,
                config: &CommitteeConfig,
                tag: u64,
            ) {
                for value in [
                    config.session_id,
                    config.committee_n as u64,
                    config.honest_h as u64,
                    config.threshold_t as u64,
                    CHANNEL as u64,
                    tag,
                ] {
                    transcript.absorb(&<$ring>::from(value as u128));
                }
            }

            /// Coefficient vector -> native NTT ring element.
            pub fn coeffs_to_ntt(coeffs: &[u64]) -> Result<$ring, Box<dyn Error>> {
                if coeffs.len() != degree() {
                    return Err(format!(
                        "polynomial has {} coefficients, expected {}",
                        coeffs.len(),
                        degree()
                    )
                    .into());
                }
                if coeffs.iter().any(|&coefficient| coefficient >= modulus()) {
                    return Err("polynomial is not in the channel threshold domain".into());
                }
                let polynomial = <$poly>::from(
                    coeffs
                        .iter()
                        .copied()
                        .map(<$field>::from)
                        .collect::<Vec<_>>(),
                );
                Ok(CRT::elementwise_crt(vec![polynomial])[0])
            }

            /// Native NTT ring element -> coefficient vector.
            pub fn ntt_to_coeffs(value: $ring) -> Vec<u64> {
                ICRT::elementwise_icrt(vec![value])[0]
                    .coeffs()
                    .iter()
                    .map(|coefficient| coefficient.into_bigint().as_ref()[0])
                    .collect()
            }

            /// Signed (i64) coefficient vector -> canonical u64 vector mod q_l.
            pub fn signed_to_canonical(coeffs: &[i64]) -> Vec<u64> {
                let modulus = modulus() as i128;
                coeffs
                    .iter()
                    .map(|&c| (((c as i128) % modulus + modulus) % modulus) as u64)
                    .collect()
            }

            fn pow_mod_u128(mut base: u128, mut exponent: u128, modulus: u128) -> u128 {
                let mut result = 1u128;
                base %= modulus;
                while exponent != 0 {
                    if exponent & 1 == 1 {
                        result = result * base % modulus;
                    }
                    base = base * base % modulus;
                    exponent >>= 1;
                }
                result
            }

            fn fermat_inverse_u128(value: u128, modulus: u128) -> u128 {
                pow_mod_u128(value, modulus - 2, modulus)
            }

            /// Signed (i64) coefficient vector -> native NTT ring element.
            pub fn signed_to_ntt(coeffs: &[i64]) -> Result<$ring, Box<dyn Error>> {
                coeffs_to_ntt(&signed_to_canonical(coeffs))
            }

            /// Lagrange-at-zero coefficients for the given evaluation points
            /// as scalar ring elements.
            pub fn lagrange_scalars(points: &[u64]) -> Vec<$ring> {
                let fields = points
                    .iter()
                    .map(|&point| <$field>::from(point))
                    .collect::<Vec<_>>();
                fields
                    .iter()
                    .enumerate()
                    .map(|(index, &point)| {
                        let multiplier = fields
                            .iter()
                            .enumerate()
                            .filter(|(other, _)| *other != index)
                            .fold(<$field>::ONE, |acc, (_, &other)| {
                                acc * other * (other - point).inverse().unwrap()
                            });
                        scalar_ring(multiplier)
                    })
                    .collect()
            }

            // -- R1: pk0 = -a * sk + e --------------------------------------
            // z = [pk0, one, sk, e, esm_limb_0..esm_limb_{K-1}]
            //
            // The smudging noise is wide (~2^74 at lambda=50/z=1), so it is
            // committed as ESM_LIMBS balanced base-B limbs (plan §9.2), each
            // individually short.
            const ESM_LIMBS: usize = 6;
            const R1_PK0: usize = 0;
            const R1_ONE: usize = 1;
            const R1_SK: usize = 2;
            const R1_E: usize = 3;
            const R1_COLS: usize = 4 + ESM_LIMBS;
            const R1_ROWS: usize = 64; // >= (2 + 6) * L = 40 committed limbs

            fn r1_r1cs(a: &$ring) -> R1CS<$ring> {
                let one = <$ring>::from(1u128);
                let mut a_rows = vec![vec![]; R1_ROWS];
                a_rows[0] = vec![(one, R1_PK0), (*a, R1_SK), (-one, R1_E)];
                let mut b_rows = vec![vec![]; R1_ROWS];
                b_rows[0] = vec![(one, R1_ONE)];
                R1CS::<$ring> {
                    l: 1,
                    A: SparseMatrix { nrows: R1_ROWS, ncols: R1_COLS, coeffs: a_rows },
                    B: SparseMatrix { nrows: R1_ROWS, ncols: R1_COLS, coeffs: b_rows },
                    C: SparseMatrix {
                        nrows: R1_ROWS,
                        ncols: R1_COLS,
                        coeffs: vec![vec![]; R1_ROWS],
                    },
                }
            }

            /// Prove one dealer's R1 contribution on this channel; returns the
            /// public `pk0`, the committed instance, and the witness (which
            /// includes the smudging-noise limbs).
            pub fn prove_r1(
                dealer_id: u64,
                a: &$ring,
                sk: $ring,
                e: $ring,
                esm_limbs: &[$ring],
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
                config: &CommitteeConfig,
            ) -> Result<($ring, CCCS<$ring>, Witness<$ring>), Box<dyn Error>> {
                if esm_limbs.len() != ESM_LIMBS {
                    return Err(format!(
                        "expected {ESM_LIMBS} smudging limbs, got {}",
                        esm_limbs.len()
                    )
                    .into());
                }
                let pk0 = -*a * sk + e;
                let mut z = vec![pk0, <$ring>::from(1u128), sk, e];
                z.extend_from_slice(esm_limbs);
                ccs.check_relation(&z)?;

                let mut witness_vec = vec![sk, e];
                witness_vec.extend_from_slice(esm_limbs);
                let witness = Witness::from_w_ccs::<$decomp>(witness_vec);
                let cm = CCCS {
                    cm: witness.commit::<$decomp>(scheme)?,
                    x_ccs: vec![pk0],
                };

                let mut prover_transcript = ChannelTranscript::default();
                absorb_config(&mut prover_transcript, config, dealer_id);
                let (prover_lcccs, proof) =
                    LFLinearizationProver::<$ring, ChannelTranscript>::prove(
                        &cm,
                        &witness,
                        &mut prover_transcript,
                        ccs,
                    )?;
                let mut verifier_transcript = ChannelTranscript::default();
                absorb_config(&mut verifier_transcript, config, dealer_id);
                let verifier_lcccs = LFLinearizationVerifier::<$ring, ChannelTranscript>::verify(
                    &cm,
                    &proof,
                    &mut verifier_transcript,
                    ccs,
                )?;
                assert_eq!(prover_lcccs, verifier_lcccs, "R1 linearization mismatch");
                assert_eq!(
                    verifier_lcccs.x_w,
                    vec![pk0],
                    "R1 verifier output was not bound to the dealer's pk0"
                );
                Ok((pk0, cm, witness))
            }

            // -- Ruser: ct0 = pk0_agg * u + e0 + Delta * m, ct1 = a * u + e1 -
            // z = [ct0, ct1, one, u, e0, e1, m]
            const RUSER_CT0: usize = 0;
            const RUSER_CT1: usize = 1;
            const RUSER_ONE: usize = 2;
            const RUSER_U: usize = 3;
            const RUSER_E0: usize = 4;
            const RUSER_E1: usize = 5;
            const RUSER_M: usize = 6;
            const RUSER_ROWS: usize = 32; // >= 4 * L = 20 committed limbs

            fn ruser_r1cs(a: &$ring, pk0_agg: &$ring, delta: $ring) -> R1CS<$ring> {
                let one = <$ring>::from(1u128);
                let mut a_rows = vec![vec![]; RUSER_ROWS];
                a_rows[0] = vec![
                    (one, RUSER_CT0),
                    (-*pk0_agg, RUSER_U),
                    (-one, RUSER_E0),
                    (-delta, RUSER_M),
                ];
                a_rows[1] = vec![(one, RUSER_CT1), (-*a, RUSER_U), (-one, RUSER_E1)];
                let mut b_rows = vec![vec![]; RUSER_ROWS];
                b_rows[0] = vec![(one, RUSER_ONE)];
                b_rows[1] = vec![(one, RUSER_ONE)];
                R1CS::<$ring> {
                    l: 2,
                    A: SparseMatrix { nrows: RUSER_ROWS, ncols: 7, coeffs: a_rows },
                    B: SparseMatrix { nrows: RUSER_ROWS, ncols: 7, coeffs: b_rows },
                    C: SparseMatrix {
                        nrows: RUSER_ROWS,
                        ncols: 7,
                        coeffs: vec![vec![]; RUSER_ROWS],
                    },
                }
            }

            /// Prove the user encryption under the aggregated threshold key on
            /// this channel; returns the public ciphertext `(ct0, ct1)`.
            pub fn prove_ruser(
                a: &$ring,
                pk0_agg: &$ring,
                u: $ring,
                e0: $ring,
                e1: $ring,
                m: $ring,
                config: &CommitteeConfig,
            ) -> Result<($ring, $ring), Box<dyn Error>> {
                let delta_big = <$params as VdkgParams>::delta() % modulus();
                let delta_scalar: u64 = delta_big.try_into().map_err(|_| "delta overflow")?;
                let delta = <$ring>::from(delta_scalar as u128);
                let ccs = CCS::from_r1cs(ruser_r1cs(a, pk0_agg, delta), RUSER_ROWS);
                let scheme = AjtaiCommitmentScheme::from_domain::<ChannelTranscript>(
                    &format!("vdkg/ruser/q{}/N{}", CHANNEL, degree()),
                    KAPPA,
                    4 * <$decomp>::L,
                    degree(),
                );

                let ct0 = *pk0_agg * u + e0 + delta * m;
                let ct1 = *a * u + e1;
                let z = vec![ct0, ct1, <$ring>::from(1u128), u, e0, e1, m];
                ccs.check_relation(&z)?;

                let witness = Witness::from_w_ccs::<$decomp>(vec![u, e0, e1, m]);
                let cm = CCCS {
                    cm: witness.commit::<$decomp>(&scheme)?,
                    x_ccs: vec![ct0, ct1],
                };

                let mut prover_transcript = ChannelTranscript::default();
                absorb_config(&mut prover_transcript, config, u64::MAX);
                let (prover_lcccs, proof) =
                    LFLinearizationProver::<$ring, ChannelTranscript>::prove(
                        &cm,
                        &witness,
                        &mut prover_transcript,
                        &ccs,
                    )?;
                let mut verifier_transcript = ChannelTranscript::default();
                absorb_config(&mut verifier_transcript, config, u64::MAX);
                let verifier_lcccs = LFLinearizationVerifier::<$ring, ChannelTranscript>::verify(
                    &cm,
                    &proof,
                    &mut verifier_transcript,
                    &ccs,
                )?;
                assert_eq!(prover_lcccs, verifier_lcccs, "Ruser linearization mismatch");
                assert_eq!(
                    verifier_lcccs.x_w,
                    vec![ct0, ct1],
                    "Ruser verifier output was not bound to the ciphertext"
                );
                Ok((ct0, ct1))
            }

            // -- R6: d = ct0 + ct1 * sk_share + e_sm_share -------------------
            // z = [ct0, ct1, d, one, sk_share, e_sm_share]
            const R6_CT0: usize = 0;
            const R6_D: usize = 2;
            const R6_ONE: usize = 3;
            const R6_SK: usize = 4;
            const R6_ESM: usize = 5;
            const R6_ROWS: usize = 16; // >= 2 * L = 10 committed limbs

            fn r6_r1cs(ct1: &$ring) -> R1CS<$ring> {
                let one = <$ring>::from(1u128);
                let mut a_rows = vec![vec![]; R6_ROWS];
                a_rows[0] = vec![
                    (one, R6_D),
                    (-one, R6_CT0),
                    (-*ct1, R6_SK),
                    (-one, R6_ESM),
                ];
                let mut b_rows = vec![vec![]; R6_ROWS];
                b_rows[0] = vec![(one, R6_ONE)];
                R1CS::<$ring> {
                    l: 3,
                    A: SparseMatrix { nrows: R6_ROWS, ncols: 6, coeffs: a_rows },
                    B: SparseMatrix { nrows: R6_ROWS, ncols: 6, coeffs: b_rows },
                    C: SparseMatrix {
                        nrows: R6_ROWS,
                        ncols: 6,
                        coeffs: vec![vec![]; R6_ROWS],
                    },
                }
            }

            /// Build one party's R6 decryption-share instance on this channel;
            /// returns the public share `d`, the committed instance, and the
            /// witness (the full-range aggregated shares, digit-decomposed by
            /// the witness construction as in R2/R4).
            pub fn r6_instance(
                ct0: &$ring,
                ct1: &$ring,
                sk_share: $ring,
                e_sm_share: $ring,
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
            ) -> Result<($ring, CCCS<$ring>, Witness<$ring>), Box<dyn Error>> {
                let d = *ct0 + *ct1 * sk_share + e_sm_share;
                let z = vec![*ct0, *ct1, d, <$ring>::from(1u128), sk_share, e_sm_share];
                ccs.check_relation(&z)?;

                let witness = Witness::from_w_ccs::<$decomp>(vec![sk_share, e_sm_share]);
                let cm = CCCS {
                    cm: witness.commit::<$decomp>(scheme)?,
                    x_ccs: vec![*ct0, *ct1, d],
                };
                Ok((d, cm, witness))
            }

            /// Prove the T parties' R6 instances and fold them into one
            /// accumulator for this channel, as a binary fold tree (same
            /// total fold count as the sequential chain, log2(T) depth).
            /// The per-node verifier self-check is deferred by default and
            /// re-enabled with `DKG_VERIFY_FOLDS=1`.
            pub fn prove_and_fold_r6(
                instances: &[(CCCS<$ring>, Witness<$ring>)],
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
                config: &CommitteeConfig,
            ) -> Result<(), Box<dyn Error>> {
                let verify_folds = std::env::var_os("DKG_VERIFY_FOLDS").is_some();

                // Bind every node to the committee config and, in order, to
                // the 1-based party ids of the leaves (party 1..=T).
                let absorb_label = |transcript: &mut ChannelTranscript| {
                    absorb_config(transcript, config, 0xE6);
                    for party in 1..=instances.len() as u64 {
                        transcript.absorb(&<$ring>::from(party as u128));
                    }
                };
                crate::nifs::tree::fold_tree::<$ring, $decomp, ChannelTranscript>(
                    instances,
                    ccs,
                    scheme,
                    &absorb_label,
                    !verify_folds,
                )?;
                Ok(())
            }

            /// Sum the `party`-th shares of every dealer, coefficient-wise,
            /// mod q_l. `party` is 1-based.
            fn aggregate_native(sharings: &ChannelSharings, party: usize) -> Vec<u64> {
                let mut aggregate = vec![0u64; degree()];
                for dealer_shares in &sharings.shares {
                    for (acc, &value) in aggregate.iter_mut().zip(&dealer_shares[party - 1]) {
                        *acc += value;
                        if *acc >= modulus() {
                            *acc -= modulus();
                        }
                    }
                }
                aggregate
            }

            /// Run this channel's R1 phase for the committee and export the
            /// C5 wrapper vectors (real aggregated witness, aggregate
            /// commitment, CRS, digest, and off-circuit challenges).
            pub fn export_c5_track(
                samples: &[DealerSamples],
                config: &CommitteeConfig,
            ) -> Result<crate::wrapper_export::C5TrackExport, Box<dyn Error>> {
                let mut rng = StdRng::seed_from_u64(
                    config.session_id ^ ((CHANNEL as u64 + 1) << 40),
                );
                let a = <$ring>::rand(&mut rng);
                let r1_ccs = CCS::from_r1cs(r1_r1cs(&a), R1_ROWS);
                let r1_scheme = AjtaiCommitmentScheme::from_domain::<ChannelTranscript>(
                    &format!("vdkg/r1/q{}/N{}", CHANNEL, degree()),
                    KAPPA,
                    (2 + ESM_LIMBS) * <$decomp>::L,
                    degree(),
                );

                let mut pk0_agg = <$ring>::from(0u128);
                let mut cm_acc: Option<crate::commitment::Commitment<$ring>> = None;
                let mut sk_acc = vec![0i64; degree()];
                let mut e_acc = vec![0i64; degree()];
                let mut esm_limbs_acc = vec![vec![0i64; degree()]; ESM_LIMBS];
                let mut digit_sums = vec![vec![0i64; degree()]; (2 + ESM_LIMBS) * <$decomp>::L];

                for (index, dealer) in samples.iter().enumerate() {
                    let limb_polys: Vec<Vec<i64>> = (0..degree())
                        .map(|c| balanced_limbs(&dealer.e_sm[c], ESM_LIMBS))
                        .collect();
                    let mut esm_limbs: Vec<$ring> = Vec::with_capacity(ESM_LIMBS);
                    for limb in 0..ESM_LIMBS {
                        let poly: Vec<i64> = limb_polys.iter().map(|l| l[limb]).collect();
                        for (acc, &d) in esm_limbs_acc[limb].iter_mut().zip(&poly) {
                            *acc += d;
                        }
                        esm_limbs.push(signed_to_ntt(&poly)?);
                    }
                    let (pk0, cm, witness) = prove_r1(
                        index as u64 + 1,
                        &a,
                        signed_to_ntt(&dealer.sk)?,
                        signed_to_ntt(&dealer.e)?,
                        &esm_limbs,
                        &r1_ccs,
                        &r1_scheme,
                        config,
                    )?;
                    pk0_agg = pk0_agg + pk0;
                    cm_acc = Some(match cm_acc {
                        None => cm.cm,
                        Some(acc) => acc + &cm.cm,
                    });
                    for (acc, &c) in sk_acc.iter_mut().zip(&dealer.sk) {
                        *acc += c;
                    }
                    for (acc, &c) in e_acc.iter_mut().zip(&dealer.e) {
                        *acc += c;
                    }
                    // The committed digit sums the aggregate commitment binds.
                    for (j, poly) in witness.f_coeff.iter().enumerate() {
                        for (acc, c) in digit_sums[j].iter_mut().zip(poly.coeffs()) {
                            let v = c.into_bigint().as_ref()[0] as i64;
                            *acc += if v > modulus() as i64 / 2 {
                                v - modulus() as i64
                            } else {
                                v
                            };
                        }
                    }
                }

                // §6.2 rank-1 outer commitment of the aggregate commitment.
                let cm_acc = cm_acc.expect("at least one dealer");
                let outer_scheme = AjtaiCommitmentScheme::from_domain::<ChannelTranscript>(
                    &format!("vdkg/outer/q{}/N{}", CHANNEL, degree()),
                    1,
                    KAPPA * <$decomp>::L,
                    degree(),
                );
                let digest_witness =
                    Witness::from_w_ccs::<$decomp>(cm_acc.as_ref().to_vec());
                let digest = outer_scheme.commit_ntt(&digest_witness.f)?;

                // Evaluation-point challenge gamma for the coefficient-domain
                // opening check (off-circuit, digest-derived; gamma^N != -1).
                let tag = format!("vdkg/c5/q{}/N{}", CHANNEL, degree());
                let r_sz = crate::wrapper_challenge::derive_field_challenges::<$ring, $challenge_set>(
                    &tag,
                    digest.as_ref(),
                    1,
                )[0];
                let r_lin = crate::wrapper_challenge::derive_field_challenges::<$ring, $challenge_set>(
                    &format!("{tag}/lin"),
                    digest.as_ref(),
                    4,
                );
                let rho = crate::wrapper_challenge::derive_field_challenges::<$ring, $challenge_set>(
                    &format!("{tag}/rho"),
                    digest.as_ref(),
                    1,
                )[0];
                let gamma = crate::wrapper_challenge::derive_field_challenges::<$ring, $challenge_set>(
                    &format!("{tag}/gamma"),
                    digest.as_ref(),
                    1,
                )[0];

                // ---- Evaluation bundle for the coefficient-domain opening
                // check (plan §10's small final arithmetic step).
                let eval_poly = |coeffs: &[u64], x: u64| -> u64 {
                    let mut acc = 0u128;
                    for &c in coeffs.iter().rev() {
                        acc = (acc * x as u128 + c as u128) % modulus() as u128;
                    }
                    acc as u64
                };
                let gamma_u = gamma.into_bigint().as_ref()[0];
                let gamma_n_plus_1 =
                    (pow_mod_u128(gamma_u as u128, degree() as u128, modulus() as u128) + 1)
                        % modulus() as u128;
                let gamma_n_plus_1_inv =
                    fermat_inverse_u128(gamma_n_plus_1, modulus() as u128) as u64;

                // Ajtai matrix entries evaluated at gamma (iNTT to coefficient
                // form, then Horner).
                let a_gamma: Vec<Vec<u64>> = r1_scheme
                    .matrix()
                    .vals
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|element| eval_poly(&ntt_to_coeffs(*element), gamma_u))
                            .collect()
                    })
                    .collect();

                // Quotient sums per row: Q_ij(gamma) = (A_ij(gamma) f_ij(gamma)
                // - R_ij(gamma)) / (gamma^N + 1), R_ij the X^N+1-reduced
                // product.
                let digit_ntts: Vec<$ring> = digit_sums
                    .iter()
                    .map(|digits| signed_to_ntt(digits).expect("digit NTT"))
                    .collect();
                let f_gamma: Vec<u64> = digit_sums
                    .iter()
                    .map(|digits| {
                        let canonical = signed_to_canonical(digits);
                        eval_poly(&canonical, gamma_u)
                    })
                    .collect();
                let mut q_sum_gamma = vec![0u64; KAPPA];
                for (i, row) in r1_scheme.matrix().vals.iter().enumerate() {
                    let mut acc = 0u128;
                    for (j, element) in row.iter().enumerate() {
                        let r_ntt = *element * digit_ntts[j];
                        let r_coeffs = ntt_to_coeffs(r_ntt);
                        let r_gamma = eval_poly(&r_coeffs, gamma_u) as u128;
                        let term = (a_gamma[i][j] as u128 * f_gamma[j] as u128
                            + modulus() as u128
                            - r_gamma)
                            * gamma_n_plus_1_inv as u128
                            % modulus() as u128;
                        acc = (acc + term) % modulus() as u128;
                    }
                    q_sum_gamma[i] = acc as u64;
                }

                // cm(gamma) per row (iNTT of the NTT-form commitment + Horner).
                let cm_gamma: Vec<u64> = cm_acc
                    .as_ref()
                    .iter()
                    .map(|element| eval_poly(&ntt_to_coeffs(*element), gamma_u))
                    .collect();

                // R1-row evals at gamma.
                let a_gamma_crs = eval_poly(&ntt_to_coeffs(a), gamma_u);
                let sk_canonical = signed_to_canonical(&sk_acc);
                let e_canonical = signed_to_canonical(&e_acc);
                let sk_gamma = eval_poly(&sk_canonical, gamma_u) as u128;
                let e_gamma = eval_poly(&e_canonical, gamma_u) as u128;
                let pk0_coeffs = ntt_to_coeffs(pk0_agg);
                let pk0_gamma = eval_poly(&pk0_coeffs, gamma_u) as u128;
                let q_r1_gamma = ((a_gamma_crs as u128 * sk_gamma
                    + modulus() as u128
                    - ((e_gamma + modulus() as u128 - pk0_gamma) % modulus() as u128))
                    % modulus() as u128)
                    * gamma_n_plus_1_inv as u128
                    % modulus() as u128;

                let to_u64 = |c: $field| c.into_bigint().as_ref()[0];
                let (psi, omega) = crate::vdkg_params::ntt_roots::<$params>(CHANNEL);
                Ok(crate::wrapper_export::C5TrackExport {
                    channel: CHANNEL,
                    modulus: modulus(),
                    psi,
                    omega,
                    a_coeffs: ntt_to_coeffs(a),
                    a_ntt: a.into_coeffs().into_iter().map(to_u64).collect(),
                    sk_acc,
                    e_acc,
                    esm_limbs_acc,
                    digit_sums,
                    cm_acc_ntt: cm_acc
                        .as_ref()
                        .iter()
                        .map(|element| element.into_coeffs().into_iter().map(to_u64).collect())
                        .collect(),
                    pk0_agg: pk0_agg.into_coeffs().into_iter().map(to_u64).collect(),
                    digest_ntt: digest
                        .as_ref()
                        .iter()
                        .flat_map(|element| element.into_coeffs().into_iter().map(to_u64))
                        .collect(),
                    r_sz: r_sz.into_bigint().as_ref()[0],
                    r_lin: r_lin.into_iter().map(to_u64).collect(),
                    rho: rho.into_bigint().as_ref()[0],
                    gamma: gamma_u,
                    f_gamma,
                    a_gamma,
                    q_sum_gamma,
                    cm_gamma,
                    a_gamma_crs,
                    pk0_gamma: pk0_gamma as u64,
                    q_r1_gamma: q_r1_gamma as u64,
                })
            }


            /// Run this channel's P1 -> P4 share of the full flow, returning
            /// the interpolated residue polynomial for the P reconstruction
            /// track.
            ///
            /// The user encryption randomness `(u, e0, e1)` is sampled once
            /// for the whole flow and shared across channels (short, so the
            /// per-channel encryptions are CRT-consistent and the decryption
            /// noise is a single small integer polynomial).
            #[allow(clippy::too_many_arguments)]
            pub fn flow(
                samples: &[DealerSamples],
                sk_sharings: &ChannelSharings,
                esm_sharings: &ChannelSharings,
                transport: &crate::r3_bridge::R3Transport,
                user_randomness: &[Vec<u64>; 3],
                message: &[u64],
                config: &CommitteeConfig,
            ) -> Result<Vec<u64>, Box<dyn Error>> {
                let mut rng = StdRng::seed_from_u64(
                    config.session_id ^ ((CHANNEL as u64 + 1) << 40),
                );
                // The public CRS element `a` for this channel.
                let a = <$ring>::rand(&mut rng);

                // ---- P1/R1: dealer threshold-key + smudging contributions.
                let r1_ccs = CCS::from_r1cs(r1_r1cs(&a), R1_ROWS);
                let r1_scheme = AjtaiCommitmentScheme::from_domain::<ChannelTranscript>(
                    &format!("vdkg/r1/q{}/N{}", CHANNEL, degree()),
                    KAPPA,
                    (2 + ESM_LIMBS) * <$decomp>::L,
                    degree(),
                );
                let mut pk0s = Vec::with_capacity(samples.len());
                let mut r1_commitments = Vec::with_capacity(samples.len());
                let mut r1_witnesses = Vec::with_capacity(samples.len());
                let mut sk_ntts = Vec::with_capacity(samples.len());
                let mut e_ntts = Vec::with_capacity(samples.len());
                for (index, dealer) in samples.iter().enumerate() {
                    // R1 <-> R2 anchor (example-side): the sharing secret on
                    // this channel is exactly the R1 secret key (canonically
                    // reduced; the fhe.rs ternary/CBD samples are signed).
                    let sk_canonical = signed_to_canonical(&dealer.sk);
                    assert_eq!(
                        sk_sharings.secrets[index], sk_canonical,
                        "R1/R2 anchor: sharing secret does not match the R1 secret key"
                    );
                    // The wide smudging noise is committed as balanced limbs;
                    // check the recomposition against the residues shared in R2.
                    let limb_polys: Vec<Vec<i64>> = (0..degree())
                        .map(|c| balanced_limbs(&dealer.e_sm[c], ESM_LIMBS))
                        .collect();
                    let mut esm_limbs: Vec<$ring> = Vec::with_capacity(ESM_LIMBS);
                    for limb in 0..ESM_LIMBS {
                        let poly: Vec<i64> = limb_polys.iter().map(|l| l[limb]).collect();
                        esm_limbs.push(signed_to_ntt(&poly)?);
                    }
                    let sk_ntt = signed_to_ntt(&dealer.sk)?;
                    let e_ntt = signed_to_ntt(&dealer.e)?;
                    let (pk0, cm, witness) = prove_r1(
                        index as u64 + 1,
                        &a,
                        sk_ntt,
                        e_ntt,
                        &esm_limbs,
                        &r1_ccs,
                        &r1_scheme,
                        config,
                    )?;
                    pk0s.push(pk0);
                    r1_commitments.push(cm);
                    r1_witnesses.push(witness);
                    sk_ntts.push(sk_ntt);
                    e_ntts.push(e_ntt);
                }
                println!(
                    "[q{CHANNEL}] P1/R1: {} dealer contribution proofs verified",
                    samples.len()
                );

                // ---- P1/R2 + R3 + R4: GRS sharing proofs, proven R3 digit
                // transport of the recipient's shares, folded metadata-bound
                // openings (reusing the fhe_bridge committee path). The sk
                // and e_sm tracks are independent, so they run concurrently.
                const FLOW_STACK_SIZE: usize = 1 << 30;
                let (decoded_sk, decoded_esm) = std::thread::scope(|scope| {
                    let sk_handle = std::thread::Builder::new()
                        .stack_size(FLOW_STACK_SIZE)
                        .spawn_scoped(scope, || {
                            crate::fhe_bridge::$bridge::fold_committee_r4(
                                transport, sk_sharings, config, 0,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .expect("failed to spawn sk track thread");
                    let esm_result = crate::fhe_bridge::$bridge::fold_committee_r4(
                        transport,
                        esm_sharings,
                        config,
                        1,
                    )
                    .map_err(|e| e.to_string());
                    (
                        sk_handle
                            .join()
                            .unwrap_or_else(|_| Err("sk track thread panicked".to_string())),
                        esm_result,
                    )
                });
                let decoded_sk = decoded_sk?;
                let decoded_esm = decoded_esm?;
                println!(
                    "[q{CHANNEL}] P1/R2+R3+R4: {} sharings (sk + e_sm) proven, transported, folded",
                    sk_sharings.secrets.len()
                );

                // ---- P2/R5: aggregate the threshold public key. The
                // commitment sum is free by Ajtai homomorphism; the aggregate
                // key is additionally tied to the R1 relation shape.
                let pk0_agg = pk0s
                    .iter()
                    .fold(<$ring>::from(0u128), |acc, pk0| acc + *pk0);
                let digit_sum = (0..r1_witnesses[0].f.len())
                    .map(|j| {
                        r1_witnesses
                            .iter()
                            .fold(<$ring>::from(0u128), |acc, witness| acc + witness.f[j])
                    })
                    .collect::<Vec<_>>();
                let commitment_sum = r1_commitments
                    .iter()
                    .skip(1)
                    .fold(r1_commitments[0].cm.clone(), |acc, cm| acc + &cm.cm);
                assert_eq!(
                    r1_scheme.commit_ntt(&digit_sum)?,
                    commitment_sum,
                    "R5 Ajtai homomorphism check failed"
                );
                let sk_sum = sk_ntts
                    .iter()
                    .fold(<$ring>::from(0u128), |acc, value| acc + *value);
                let e_sum = e_ntts
                    .iter()
                    .fold(<$ring>::from(0u128), |acc, value| acc + *value);
                assert_eq!(
                    pk0_agg,
                    -a * sk_sum + e_sum,
                    "R5 aggregate key does not match the R1 witnesses"
                );
                println!(
                    "[q{CHANNEL}] P2/R5: pk0_agg over {} contributions (homomorphic sum ok)",
                    pk0s.len()
                );

                // ---- P3/Ruser: user encryption under the aggregated key.
                let u = coeffs_to_ntt(&user_randomness[0])?;
                let e0 = coeffs_to_ntt(&user_randomness[1])?;
                let e1 = coeffs_to_ntt(&user_randomness[2])?;
                let m = coeffs_to_ntt(message)?;
                let (ct0, ct1) = prove_ruser(&a, &pk0_agg, u, e0, e1, m, config)?;
                println!("[q{CHANNEL}] P3/Ruser: user ciphertext proven under pk_agg");

                // ---- P4/R6: decryption shares for the first T parties.
                let r6_ccs = CCS::from_r1cs(r6_r1cs(&ct1), R6_ROWS);
                let r6_scheme = AjtaiCommitmentScheme::from_domain::<ChannelTranscript>(
                    &format!("vdkg/r6/q{}/N{}", CHANNEL, degree()),
                    KAPPA,
                    2 * <$decomp>::L,
                    degree(),
                );
                let mut decryption_shares = Vec::with_capacity(config.threshold_t);
                let mut instances = Vec::with_capacity(config.threshold_t);
                for party in 1..=config.threshold_t {
                    let sk_share = aggregate_native(sk_sharings, party);
                    let esm_share = aggregate_native(esm_sharings, party);
                    if party == config.recipient_id {
                        // The transported (R3/R4) shares of the designated
                        // recipient must equal the natively aggregated ones.
                        assert_eq!(
                            sk_share,
                            sum_transported::<$params>(&decoded_sk, modulus()),
                            "R4 aggregate mismatch for the transported recipient (sk)"
                        );
                        assert_eq!(
                            esm_share,
                            sum_transported::<$params>(&decoded_esm, modulus()),
                            "R4 aggregate mismatch for the transported recipient (e_sm)"
                        );
                    }
                    let (d, cm, witness) = r6_instance(
                        &ct0,
                        &ct1,
                        coeffs_to_ntt(&sk_share)?,
                        coeffs_to_ntt(&esm_share)?,
                        &r6_ccs,
                        &r6_scheme,
                    )?;
                    decryption_shares.push(d);
                    instances.push((cm, witness));
                }
                prove_and_fold_r6(&instances, &r6_ccs, &r6_scheme, config)?;
                println!(
                    "[q{CHANNEL}] P4/R6: {} decryption shares proven and folded",
                    instances.len()
                );

                // ---- P4/R7 (channel side): Lagrange interpolation at zero.
                let points = (1..=config.threshold_t as u64).collect::<Vec<_>>();
                let lambdas = lagrange_scalars(&points);
                let u_ntt = decryption_shares
                    .iter()
                    .zip(&lambdas)
                    .fold(<$ring>::from(0u128), |acc, (d, lambda)| {
                        acc + *lambda * *d
                    });
                Ok(ntt_to_coeffs(u_ntt))
            }
        }
    };
}

macro_rules! define_p_track {
    ($module:ident, $params:ty, $pcrt:ty, $pdec:ty, $pring:ty, $ppoly:ty, $pfield:ty, $pcs:ty) => {
        /// Reconstruction-track R7 over the P ring: CRT recombination with
        /// quotient witnesses plus the BFV decode, proven natively as TWO
        /// decide-directly instances with SEPARATE tight decompositions
        /// (plan §5-R7 steps 3-4, §9.3):
        ///
        /// * the CRT instance binds `u` to the public channel residues via
        ///   the quotient witnesses `u = u_l + s_l * q_l`, the quotients
        ///   range-enforced by the tight decomposition `$pcrt` (capacity
        ///   ~Q/q_l, enforced bound B'^L' - 1);
        /// * the decode instance binds `u = Delta * m + e` with the centered
        ///   rounding witness `e` range-enforced by the tight decomposition
        ///   `$pdec` (capacity >= E_true, enforced bound < Delta - E_true).
        ///
        /// Both proofs run on ONE transcript (the decode proof's challenges
        /// depend on the CRT proof), and the shared `u` is bound across the
        /// two verifier outputs. The plaintext `m` is a PUBLIC input of the
        /// decode instance; the range `m < t` is validated publicly (it is
        /// the protocol output), which replaces the former prover-side
        /// assert — the balanced decomposition cannot express the exact
        /// asymmetric range [0, t) anyway. Neither instance is folded: at
        /// the byte challenge set the fold slack (~2^13.6) would breach the
        /// 2^10 envelope and empty the decode Delta-window (derivation in
        /// vdkg_params::R7_EXTRACTION_SLACK).
        pub mod $module {
            use super::*;

            type PTranscript = PoseidonTranscript<$pring, $pcs>;

            // CRT instance: z = [u, u0, u1, u2, u3, one, r0, t1, t2, t3, s0..s3]
            const IDX_U: usize = 0;
            const IDX_U0: usize = 1;
            const IDX_U1: usize = 2;
            const IDX_U2: usize = 3;
            const IDX_U3: usize = 4;
            const CRT_ONE: usize = 5;
            const IDX_R0: usize = 6;
            const IDX_T1: usize = 7;
            const IDX_T2: usize = 8;
            const IDX_T3: usize = 9;
            const IDX_S0: usize = 10;
            const IDX_S1: usize = 11;
            const IDX_S2: usize = 12;
            const IDX_S3: usize = 13;
            const CRT_COLS: usize = 14;
            // >= 8 * L' committed limbs, padded to a power of two.
            const CRT_ROWS: usize = (8 * <$pcrt>::L).next_power_of_two();

            // Decode instance: z = [u, m, one, e]
            const DEC_U: usize = 0;
            const DEC_M: usize = 1;
            const DEC_ONE: usize = 2;
            const DEC_E: usize = 3;
            const DEC_COLS: usize = 4;
            // >= L'' committed limbs, padded to a power of two.
            const DEC_ROWS: usize = (<$pdec>::L).next_power_of_two();

            /// Build a P-ring element from wide-integer coefficients.
            pub fn p_ring_big(coeffs: &[BigUint]) -> Result<$pring, Box<dyn Error>> {
                let polynomial = <$ppoly>::from(
                    coeffs
                        .iter()
                        .map(|c| <$pfield>::from(c.clone()))
                        .collect::<Vec<_>>(),
                );
                Ok(CRT::elementwise_crt(vec![polynomial])[0])
            }

            /// Build a P-ring element from signed integer coefficients
            /// (negatives are represented as field negations; the balanced
            /// decomposition treats them as small signed values).
            pub fn p_ring_signed(coeffs: &[BigInt]) -> Result<$pring, Box<dyn Error>> {
                let polynomial = <$ppoly>::from(
                    coeffs
                        .iter()
                        .map(|c| {
                            let (sign, mag) = c.clone().into_parts();
                            let f = <$pfield>::from(mag);
                            if sign == num_bigint::Sign::Minus {
                                -f
                            } else {
                                f
                            }
                        })
                        .collect::<Vec<_>>(),
                );
                Ok(CRT::elementwise_crt(vec![polynomial])[0])
            }

            /// Build a P-ring element from u128 coefficients.
            pub fn p_ring_u128(coeffs: &[u128]) -> Result<$pring, Box<dyn Error>> {
                let polynomial = <$ppoly>::from(
                    coeffs
                        .iter()
                        .copied()
                        .map(<$pfield>::from)
                        .collect::<Vec<_>>(),
                );
                Ok(CRT::elementwise_crt(vec![polynomial])[0])
            }

            /// Balanced capacity `(B/2) * (B^L - 1)/(B - 1)` of a tight
            /// decomposition: the largest honestly decomposable magnitude.
            fn tight_capacity<B: DecompositionParams>() -> BigUint {
                let base = BigUint::from(B::B);
                (base.clone() >> 1)
                    * ((base.pow(B::L as u32) - BigUint::from(1u64))
                        / (base - BigUint::from(1u64)))
            }

            /// The R7 CRT-reconstruction relation as an R1CS (Garner
            /// recombination plus one quotient-witness row per channel).
            pub fn r7_crt_r1cs() -> R1CS<$pring> {
                let [q0, q1, q2, q3] = <$params as VdkgParams>::THRESHOLD_MODULI;
                let q0 = <$pring>::from(q0 as u128);
                let q1 = <$pring>::from(q1 as u128);
                let q2 = <$pring>::from(q2 as u128);
                let q3 = <$pring>::from(q3 as u128);
                let q0q1 = q0 * q1;
                let q0q1q2 = q0q1 * q2;
                let one = <$pring>::from(1u128);

                let mut a_rows = vec![vec![]; CRT_ROWS];
                // Garner recombination: u = r0 + q0*t1 + q0*q1*t2 + q0*q1*q2*t3.
                a_rows[0] = vec![
                    (one, IDX_U),
                    (-one, IDX_R0),
                    (-q0, IDX_T1),
                    (-q0q1, IDX_T2),
                    (-q0q1q2, IDX_T3),
                ];
                // Quotient witnesses binding u to the public channel residues:
                // u = u_l + s_l * q_l with s_l < Q / q_l, range-enforced by
                // the tight decomposition of the committed witness digits.
                a_rows[1] = vec![(one, IDX_U), (-one, IDX_U0), (-q0, IDX_S0)];
                a_rows[2] = vec![(one, IDX_U), (-one, IDX_U1), (-q1, IDX_S1)];
                a_rows[3] = vec![(one, IDX_U), (-one, IDX_U2), (-q2, IDX_S2)];
                a_rows[4] = vec![(one, IDX_U), (-one, IDX_U3), (-q3, IDX_S3)];

                let mut b_rows = vec![vec![]; CRT_ROWS];
                for row in b_rows.iter_mut().take(5) {
                    *row = vec![(one, CRT_ONE)];
                }
                R1CS::<$pring> {
                    l: 5,
                    A: SparseMatrix { nrows: CRT_ROWS, ncols: CRT_COLS, coeffs: a_rows },
                    B: SparseMatrix { nrows: CRT_ROWS, ncols: CRT_COLS, coeffs: b_rows },
                    C: SparseMatrix {
                        nrows: CRT_ROWS,
                        ncols: CRT_COLS,
                        coeffs: vec![vec![]; CRT_ROWS],
                    },
                }
            }

            /// The R7 decode relation as an R1CS: u = Delta * m + e with
            /// e = u - Delta * m the CENTERED noise in (-Delta/2, Delta/2),
            /// range-enforced by the tight decomposition (enforced bound
            /// < Delta - E_true so a wrong m admits no witness).
            pub fn r7_decode_r1cs() -> R1CS<$pring> {
                let delta = <$pring>::from(<$pfield>::from(<$params as VdkgParams>::delta()));
                let one = <$pring>::from(1u128);

                let mut a_rows = vec![vec![]; DEC_ROWS];
                a_rows[0] = vec![(one, DEC_U), (-delta, DEC_M), (-one, DEC_E)];
                let mut b_rows = vec![vec![]; DEC_ROWS];
                b_rows[0] = vec![(one, DEC_ONE)];
                R1CS::<$pring> {
                    l: 2,
                    A: SparseMatrix { nrows: DEC_ROWS, ncols: DEC_COLS, coeffs: a_rows },
                    B: SparseMatrix { nrows: DEC_ROWS, ncols: DEC_COLS, coeffs: b_rows },
                    C: SparseMatrix {
                        nrows: DEC_ROWS,
                        ncols: DEC_COLS,
                        coeffs: vec![vec![]; DEC_ROWS],
                    },
                }
            }

            /// Fermat inversion of a u128 value modulo a channel prime.
            pub fn fermat_inverse(value: u128, modulus: u128) -> u128 {
                let mut result = 1u128;
                let mut base = value % modulus;
                let mut exponent = modulus - 2;
                while exponent != 0 {
                    if exponent & 1 == 1 {
                        result = result * base % modulus;
                    }
                    base = base * base % modulus;
                    exponent >>= 1;
                }
                result
            }

            /// Prove the R7 CRT reconstruction and decode of the four
            /// per-channel interpolated residue polynomials, returning the
            /// decoded plaintext coefficients.
            pub fn prove_r7(
                residues: &[Vec<u64>; 4],
                config: &CommitteeConfig,
            ) -> Result<Vec<u64>, Box<dyn Error>> {
                let [q0, q1, q2, q3] = <$params as VdkgParams>::THRESHOLD_MODULI.map(u128::from);
                let q0q1 = q0 * q1;
                let q0q1q2 = BigUint::from(q0q1) * BigUint::from(q2);
                let q3_big = BigUint::from(q3);
                let delta = <$params as VdkgParams>::delta();
                let t = <$params as VdkgParams>::THRESHOLD_PLAINTEXT as u128;
                let degree = <$params as VdkgParams>::DEGREE;

                let mut u = Vec::with_capacity(degree);
                let mut garner_t1 = Vec::with_capacity(degree);
                let mut garner_t2 = Vec::with_capacity(degree);
                let mut garner_t3 = Vec::with_capacity(degree);
                let mut quotient_s0 = Vec::with_capacity(degree);
                let mut quotient_s1 = Vec::with_capacity(degree);
                let mut quotient_s2 = Vec::with_capacity(degree);
                let mut quotient_s3 = Vec::with_capacity(degree);
                let mut message = Vec::with_capacity(degree);
                let mut rounding = Vec::with_capacity(degree);

                // Honest-execution completeness guards: the tight
                // decompositions commit only witnesses within their balanced
                // capacity, so check before decomposing (an out-of-capacity
                // witness would otherwise panic inside the decomposition).
                // These are NOT the soundness mechanism: the range
                // enforcement comes from the committed digit decomposition
                // itself plus the §9.3 margin (`r7_margin_holds`), so a
                // cheating prover gains nothing by skipping these guards.
                let capacity_crt = tight_capacity::<$pcrt>();
                let capacity_dec = tight_capacity::<$pdec>();

                for coefficient in 0..degree {
                    let residue = [
                        residues[0][coefficient],
                        residues[1][coefficient],
                        residues[2][coefficient],
                        residues[3][coefficient],
                    ];
                    // Garner reconstruction; the final channel's prefix
                    // product q0*q1*q2 exceeds u128 at production sizes, so
                    // the wide tail is BigUint throughout.
                    let r0 = residue[0] as u128;
                    let t1 = (residue[1] as u128 + q1 - r0 % q1) * fermat_inverse(q0, q1) % q1;
                    let x01 = r0 + q0 * t1;
                    let t2 = (residue[2] as u128 + q2 - x01 % q2)
                        * fermat_inverse(q0q1 % q2, q2)
                        % q2;
                    let x012 = BigUint::from(x01) + BigUint::from(q0q1) * BigUint::from(t2);
                    let q0q1q2_mod_q3: u128 = (&q0q1q2 % &q3_big)
                        .try_into()
                        .map_err(|_| "q0q1q2 mod q3 exceeds u128")?;
                    let x012_mod_q3: u128 = (&x012 % &q3_big)
                        .try_into()
                        .map_err(|_| "x012 mod q3 exceeds u128")?;
                    let t3 = (residue[3] as u128 + q3 - x012_mod_q3)
                        * fermat_inverse(q0q1q2_mod_q3, q3)
                        % q3;
                    let value = &x012 + &q0q1q2 * BigUint::from(t3);

                    // s0 = t1 + q1*t2 + q1*q2*t3 (so u = u0 + s0*q0).
                    quotient_s0.push(
                        BigUint::from(t1 + q1 * t2) + BigUint::from(q1 * q2) * BigUint::from(t3),
                    );
                    quotient_s1.push(
                        (value.clone() - residue[1] as u128) / q1,
                    );
                    quotient_s2.push(
                        (value.clone() - residue[2] as u128) / q2,
                    );
                    quotient_s3.push(
                        (value.clone() - residue[3] as u128) / &q3_big,
                    );
                    garner_t1.push(t1);
                    garner_t2.push(t2);
                    garner_t3.push(t3);

                    let half = &delta / 2u64;
                    let m_big = (&value + &half) / &delta;
                    // Centered (signed) rounding witness in (-Delta/2, Delta/2).
                    let half_int = BigInt::from(half.clone());
                    let e_signed = BigInt::from(value.clone() + &half)
                        - BigInt::from(&delta * &m_big)
                        - &half_int;
                    if m_big >= BigUint::from(t) {
                        return Err(format!(
                            "decode failure at coefficient {coefficient}: decoded plaintext out of range"
                        )
                        .into());
                    }
                    if num_traits::Signed::abs(&e_signed) > BigInt::from(capacity_dec.clone()) {
                        return Err(format!(
                            "decode failure at coefficient {coefficient}: centered rounding witness exceeds the tight decomposition capacity"
                        )
                        .into());
                    }
                    u.push(value);
                    message.push(
                        m_big
                            .try_into()
                            .map_err(|_| "decoded plaintext exceeds the message space")?,
                    );
                    rounding.push(e_signed);
                }
                // CRT quotient completeness guard (all coefficients).
                for (name, quotients) in [
                    ("s0", &quotient_s0),
                    ("s1", &quotient_s1),
                    ("s2", &quotient_s2),
                    ("s3", &quotient_s3),
                ] {
                    if quotients.iter().any(|quotient| quotient >= &capacity_crt) {
                        return Err(format!(
                            "CRT quotient witness {name} exceeds the tight decomposition capacity"
                        )
                        .into());
                    }
                }

                let residue_u128 = |channel: usize| {
                    residues[channel]
                        .iter()
                        .map(|&value| value as u128)
                        .collect::<Vec<_>>()
                };
                let u_r = p_ring_big(&u)?;
                let u0_r = p_ring_u128(&residue_u128(0))?;
                let u1_r = p_ring_u128(&residue_u128(1))?;
                let u2_r = p_ring_u128(&residue_u128(2))?;
                let u3_r = p_ring_u128(&residue_u128(3))?;
                let m_r = p_ring_u128(
                    &message
                        .iter()
                        .map(|&value| value as u128)
                        .collect::<Vec<_>>(),
                )?;
                let witness_crt = vec![
                    u0_r, // r0 = u mod q0 is the channel-0 residue itself
                    p_ring_u128(&garner_t1)?,
                    p_ring_u128(&garner_t2)?,
                    p_ring_u128(&garner_t3)?,
                    p_ring_big(&quotient_s0)?,
                    p_ring_big(&quotient_s1)?,
                    p_ring_big(&quotient_s2)?,
                    p_ring_big(&quotient_s3)?,
                ];
                let witness_dec = vec![p_ring_signed(&rounding)?];

                let ccs_crt = CCS::from_r1cs(r7_crt_r1cs(), CRT_ROWS);
                let ccs_dec = CCS::from_r1cs(r7_decode_r1cs(), DEC_ROWS);
                let z_crt = [
                    &[u_r, u0_r, u1_r, u2_r, u3_r, <$pring>::from(1u128)][..],
                    &witness_crt[..],
                ]
                .concat();
                let z_dec = [
                    &[u_r, m_r, <$pring>::from(1u128)][..],
                    &witness_dec[..],
                ]
                .concat();
                if std::env::var_os("DKG_DEBUG_R7").is_some() {
                    let delta_ring = <$pring>::from(<$pfield>::from(
                        <$params as VdkgParams>::delta(),
                    ));
                    let row_dec = u_r - delta_ring * m_r - witness_dec[0];
                    let nonzero = ICRT::elementwise_icrt(vec![row_dec])[0]
                        .coeffs()
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| c.into_bigint().0[0] != 0 || c.into_bigint().0[1] != 0)
                        .map(|(i, c)| (i, c.into_bigint().to_string()))
                        .take(5)
                        .collect::<Vec<_>>();
                    eprintln!("[r7-debug] decode-row nonzero coeffs (first 5): {nonzero:?}");
                }
                ccs_crt.check_relation(&z_crt)?;
                ccs_dec.check_relation(&z_dec)?;

                let scheme_crt = AjtaiCommitmentScheme::from_domain::<PTranscript>(
                    &format!("vdkg/r7crt/P/N{}", <$params as VdkgParams>::DEGREE),
                    KAPPA,
                    8 * <$pcrt>::L,
                    <$params as VdkgParams>::DEGREE,
                );
                let scheme_dec = AjtaiCommitmentScheme::from_domain::<PTranscript>(
                    &format!("vdkg/r7dec/P/N{}", <$params as VdkgParams>::DEGREE),
                    KAPPA,
                    <$pdec>::L,
                    <$params as VdkgParams>::DEGREE,
                );
                let witness_crt = Witness::from_w_ccs::<$pcrt>(witness_crt);
                let witness_dec = Witness::from_w_ccs::<$pdec>(witness_dec);
                let cm_crt = CCCS {
                    cm: witness_crt.commit::<$pcrt>(&scheme_crt)?,
                    x_ccs: vec![u_r, u0_r, u1_r, u2_r, u3_r],
                };
                let cm_dec = CCCS {
                    cm: witness_dec.commit::<$pdec>(&scheme_dec)?,
                    x_ccs: vec![u_r, m_r],
                };

                let absorb = |transcript: &mut PTranscript| {
                    for value in [
                        config.session_id,
                        config.committee_n as u64,
                        config.honest_h as u64,
                        config.threshold_t as u64,
                        0xE7,
                    ] {
                        transcript.absorb(&<$pring>::from(value as u128));
                    }
                };
                // One transcript for both instances: the CRT instance is
                // proven first, so the decode proof's challenges depend on
                // the whole CRT proof (cross-binding); the commitment and
                // public input of each instance are absorbed by the shared
                // linearization code (no double-absorb here).
                let mut prover_transcript = PTranscript::default();
                absorb(&mut prover_transcript);
                let (prover_lcccs_crt, proof_crt) =
                    LFLinearizationProver::<$pring, PTranscript>::prove(
                        &cm_crt,
                        &witness_crt,
                        &mut prover_transcript,
                        &ccs_crt,
                    )?;
                let (prover_lcccs_dec, proof_dec) =
                    LFLinearizationProver::<$pring, PTranscript>::prove(
                        &cm_dec,
                        &witness_dec,
                        &mut prover_transcript,
                        &ccs_dec,
                    )?;
                let mut verifier_transcript = PTranscript::default();
                absorb(&mut verifier_transcript);
                let verifier_lcccs_crt =
                    LFLinearizationVerifier::<$pring, PTranscript>::verify(
                        &cm_crt,
                        &proof_crt,
                        &mut verifier_transcript,
                        &ccs_crt,
                    )?;
                let verifier_lcccs_dec =
                    LFLinearizationVerifier::<$pring, PTranscript>::verify(
                        &cm_dec,
                        &proof_dec,
                        &mut verifier_transcript,
                        &ccs_dec,
                    )?;
                assert_eq!(prover_lcccs_crt, verifier_lcccs_crt, "R7 CRT linearization mismatch");
                assert_eq!(
                    prover_lcccs_dec, verifier_lcccs_dec,
                    "R7 decode linearization mismatch"
                );
                assert_eq!(
                    verifier_lcccs_crt.x_w,
                    vec![u_r, u0_r, u1_r, u2_r, u3_r],
                    "R7 CRT verifier output was not bound to the public reconstruction"
                );
                assert_eq!(
                    verifier_lcccs_dec.x_w,
                    vec![u_r, m_r],
                    "R7 decode verifier output was not bound to the public decode"
                );
                // Public-input validation of the plaintext range: m is the
                // protocol output, so m < t is checked by every consumer of
                // this artifact (replacing the former prover-side assert).
                if message.iter().any(|&coefficient| coefficient >= t as u64) {
                    return Err("decoded plaintext outside the message space".into());
                }
                Ok(message)
            }
        }
    };
}

macro_rules! define_run_full_flow {
    ($params:ty, $q0:ident, $q1:ident, $q2:ident, $q3:ident, $p:ident) => {
        /// Run the complete P1 -> P4 protocol over all four RNS channels plus
        /// the P reconstruction track, returning the decrypted plaintext
        /// coefficients.
        ///
        /// Requires `config.recipient_id <= config.threshold_t` so the party
        /// whose shares are really transported (and folded through R4) is one
        /// of the T reconstructing parties.
        pub fn run_full_flow(
            config: &CommitteeConfig,
            message: &[u64],
        ) -> Result<Vec<u64>, Box<dyn Error>> {
            config.validate()?;
            crate::fhe_bridge::ensure_large_rayon_stack();
            if config.recipient_id > config.threshold_t {
                return Err(
                    "the transported recipient must be one of the T reconstructing parties \
                     (recipient <= threshold)"
                        .into(),
                );
            }
            if message.len() != <$params as VdkgParams>::DEGREE {
                return Err(format!(
                    "message has {} coefficients, expected {}",
                    message.len(),
                    <$params as VdkgParams>::DEGREE
                )
                .into());
            }
            if message
                .iter()
                .any(|&coefficient| coefficient >= <$params as VdkgParams>::THRESHOLD_PLAINTEXT)
            {
                return Err("message does not fit the threshold plaintext modulus".into());
            }

            // OS CSPRNG: the Shamir sharing coefficients and the user
            // encryption randomness below are secret protocol randomness and
            // must not come from a deterministic public seed.
            let mut rng = ark_std::rand::rngs::OsRng;
            let dealers = config.honest_h;
            // Real fhe.rs production distributions: ternary sk, CBD errors,
            // TRBFV smudging noise at lambda=50 (wide: limb-decomposed in R1,
            // shared as per-channel residues in R2).
            let samples = (0..dealers)
                .map(|_| sample_dealer::<$params>(config.honest_h, 1))
                .collect::<Result<Vec<DealerSamples>, _>>()?;
            let smudge_bits = smudging_max_bits(&samples);
            println!(
                "[setup] H={dealers} dealers sampled via fhe.rs TRBFV (lambda=50, smudging max {smudge_bits} bits)"
            );

            // Channel-native sharings (plan.md R2 is per channel); the four
            // channel sharings of one short secret are CRT-consistent. The
            // smudging noise exceeds one channel, so it is shared as its
            // per-channel CRT residues.
            let sk_sharings = (0..4)
                .map(|channel| {
                    let modulus = <$params as VdkgParams>::THRESHOLD_MODULI[channel] as i128;
                    let secrets = samples
                        .iter()
                        .map(|dealer| {
                            dealer
                                .sk
                                .iter()
                                .map(|&c| (((c as i128) % modulus + modulus) % modulus) as u64)
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    generate_channel_sharing::<$params>(&secrets, config, channel, &mut rng)
                })
                .collect::<Vec<_>>();
            let esm_sharings = (0..4)
                .map(|channel| {
                    let modulus = <$params as VdkgParams>::THRESHOLD_MODULI[channel];
                    let secrets = samples
                        .iter()
                        .map(|dealer| {
                            dealer
                                .e_sm
                                .iter()
                                .map(|c| {
                                    let residue = c % BigInt::from(modulus);
                                    let (_, residue) = residue.into_parts();
                                    residue.iter_u64_digits().next().unwrap_or(0)
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    generate_channel_sharing::<$params>(&secrets, config, channel, &mut rng)
                })
                .collect::<Vec<_>>();
            // User encryption randomness, shared across channels (short, so
            // the per-channel ciphertexts are CRT-consistent).
            let user_randomness = [
                sample_short_poly::<$params>(2, &mut rng),
                sample_short_poly::<$params>(2, &mut rng),
                sample_short_poly::<$params>(2, &mut rng),
            ];

            // One recipient individual key shared across all channels (R0:
            // the same key is referenced by every R3 proof on every channel).
            let transport = crate::r3_bridge::R3Transport::new(
                <$params as VdkgParams>::DEGREE,
            )?;

            // The four channels share only read-only data, so their proof
            // chains run concurrently. The fold chains are deep, so give each
            // channel thread a large stack.
            const FLOW_STACK_SIZE: usize = 1 << 30;
            let (residues_q0, residues_q1, residues_q2, residues_q3) = std::thread::scope(|scope| {
                let handle_q0 = std::thread::Builder::new()
                    .stack_size(FLOW_STACK_SIZE)
                    .spawn_scoped(scope, || {
                        $q0::flow(
                            &samples,
                            &sk_sharings[0],
                            &esm_sharings[0],
                            &transport,
                            &user_randomness,
                            message,
                            config,
                        )
                        .map_err(|e| e.to_string())
                    })
                    .expect("failed to spawn q0 flow thread");
                let handle_q1 = std::thread::Builder::new()
                    .stack_size(FLOW_STACK_SIZE)
                    .spawn_scoped(scope, || {
                        $q1::flow(
                            &samples,
                            &sk_sharings[1],
                            &esm_sharings[1],
                            &transport,
                            &user_randomness,
                            message,
                            config,
                        )
                        .map_err(|e| e.to_string())
                    })
                    .expect("failed to spawn q1 flow thread");
                let handle_q2 = std::thread::Builder::new()
                    .stack_size(FLOW_STACK_SIZE)
                    .spawn_scoped(scope, || {
                        $q2::flow(
                            &samples,
                            &sk_sharings[2],
                            &esm_sharings[2],
                            &transport,
                            &user_randomness,
                            message,
                            config,
                        )
                        .map_err(|e| e.to_string())
                    })
                    .expect("failed to spawn q2 flow thread");
                let handle_q3 = std::thread::Builder::new()
                    .stack_size(FLOW_STACK_SIZE)
                    .spawn_scoped(scope, || {
                        $q3::flow(
                            &samples,
                            &sk_sharings[3],
                            &esm_sharings[3],
                            &transport,
                            &user_randomness,
                            message,
                            config,
                        )
                        .map_err(|e| e.to_string())
                    })
                    .expect("failed to spawn q3 flow thread");
                (
                    handle_q0.join().unwrap_or_else(|_| Err("q0 flow thread panicked".to_string())),
                    handle_q1.join().unwrap_or_else(|_| Err("q1 flow thread panicked".to_string())),
                    handle_q2.join().unwrap_or_else(|_| Err("q2 flow thread panicked".to_string())),
                    handle_q3.join().unwrap_or_else(|_| Err("q3 flow thread panicked".to_string())),
                )
            });
            let residues = [residues_q0?, residues_q1?, residues_q2?, residues_q3?];

            println!("[P] P4/R7: proving CRT reconstruction + decode on the P track");
            // The P ring keeps large degree-N, multi-limb elements on the
            // stack; run the R7 prover on a dedicated big-stack thread.
            let committee = *config;
            let recovered = std::thread::Builder::new()
                .stack_size(FLOW_STACK_SIZE)
                .spawn(move || $p::prove_r7(&residues, &committee).map_err(|e| e.to_string()))
                .expect("failed to spawn P track thread")
                .join()
                .unwrap_or_else(|_| Err("P track thread panicked".to_string()))?;
            if recovered != message {
                return Err("threshold decryption did not recover the user message".into());
            }
            Ok(recovered)
        }
    };
}

pub mod demo_flow {
    use super::*;

    define_flow_channel!(
        q0, DemoParams, DemoR4Params, demo_q0, N4096Q0RingNTT, N4096Q0RingPoly, N4096Q0Field,
        N4096Q0ChallengeSet, 0
    );
    define_flow_channel!(
        q1, DemoParams, DemoR4Params, demo_q1, N4096Q1RingNTT, N4096Q1RingPoly, N4096Q1Field,
        N4096Q1ChallengeSet, 1
    );
    define_flow_channel!(
        q2, DemoParams, DemoR4Params, demo_q2, N4096Q2RingNTT, N4096Q2RingPoly, N4096Q2Field,
        N4096Q2ChallengeSet, 2
    );
    define_flow_channel!(
        q3, DemoParams, DemoR4Params, demo_q3, N4096Q3RingNTT, N4096Q3RingPoly, N4096Q3Field,
        N4096Q3ChallengeSet, 3
    );
    define_p_track!(
        p_track, DemoParams, DemoR7CrtParams, DemoR7DecodeParams, N4096PRingNTT,
        N4096PRingPoly, N4096PField, N4096PChallengeSet
    );
    define_run_full_flow!(DemoParams, q0, q1, q2, q3, p_track);
}

pub mod prod_flow {
    use super::*;

    define_flow_channel!(
        q0, ProdParams, ProdR4Params, prod_q0, N16384Q0RingNTT, N16384Q0RingPoly,
        N16384Q0Field, N16384Q0ChallengeSet, 0
    );
    define_flow_channel!(
        q1, ProdParams, ProdR4Params, prod_q1, N16384Q1RingNTT, N16384Q1RingPoly,
        N16384Q1Field, N16384Q1ChallengeSet, 1
    );
    define_flow_channel!(
        q2, ProdParams, ProdR4Params, prod_q2, N16384Q2RingNTT, N16384Q2RingPoly,
        N16384Q2Field, N16384Q2ChallengeSet, 2
    );
    define_flow_channel!(
        q3, ProdParams, ProdR4Params, prod_q3, N16384Q3RingNTT, N16384Q3RingPoly,
        N16384Q3Field, N16384Q3ChallengeSet, 3
    );
    define_p_track!(
        p_track, ProdParams, ProdR7CrtParams, ProdR7DecodeParams, N16384PRingNTT,
        N16384PRingPoly, N16384PField, N16384PChallengeSet
    );
    define_run_full_flow!(ProdParams, q0, q1, q2, q3, p_track);
}

pub use demo_flow::run_full_flow;
pub use prod_flow::run_full_flow as run_full_flow_prod;

#[cfg(test)]
mod tests {
    use super::*;

    /// Standalone check of the R7 relation on one known-good coefficient set
    /// (fast: no committee, no committee threads).
    #[test]
    fn r7_decode_row_is_consistent() {
        // The R7 machinery keeps degree-N, multi-limb P-ring elements on the
        // stack; run on a large-stack thread like the full flow does.
        std::thread::Builder::new()
            .stack_size(1 << 30)
            .spawn(|| {
                // Known-good coefficient set (demo set): a centered SIGNED
                // rounding witness e = -2^70, inside the tight decode
                // decomposition capacity 2^83 (the previous synthetic noise
                // ~Delta/2 encoded the OLD unsound acceptance region; the
                // tight decomposition enforces |e| << Delta/2 so a wrong
                // plaintext admits no witness).
                let config = CommitteeConfig::default();
                let [q0, q1, q2, q3] = DemoParams::THRESHOLD_MODULI;
                let delta = DemoParams::delta();
                let m_true = 7u128;
                let noise = 1u128 << 70;
                let u = &delta * m_true - &noise; // e = u - delta*m_true = -2^70
                // residues u mod q_l
                let u_big = u.clone();
                let residues = [
                    (u_big.clone() % q0).iter_u64_digits().next().unwrap_or(0),
                    (u_big.clone() % q1).iter_u64_digits().next().unwrap_or(0),
                    (u_big.clone() % q2).iter_u64_digits().next().unwrap_or(0),
                    (u_big.clone() % q3).iter_u64_digits().next().unwrap_or(0),
                ];
                let mut res = residues.map(|r| vec![0u64; DemoParams::DEGREE]);
                res[0][0] = residues[0];
                res[1][0] = residues[1];
                res[2][0] = residues[2];
                res[3][0] = residues[3];
                // prove_r7 must accept and decode m_true at coefficient 0 (others are 0).
                let decoded = demo_flow::p_track::prove_r7(&res, &config).expect("prove_r7 failed");
                assert_eq!(decoded[0], m_true as u64);
                assert!(decoded[1..].iter().all(|&m| m == 0));
            })
            .expect("failed to spawn R7 test thread")
            .join()
            .expect("R7 test thread panicked");
    }

    /// Negative test: a FORGED u_global (off by one from the CRT value of
    /// the public residues) and a forged plaintext (off by one) each close
    /// the bare mod-P relations with prover-chosen FULL-RANGE witnesses —
    /// and each is rejected by the tight decomposition, demonstrating that
    /// the range enforcement (not the mod-P equality) is load-bearing.
    #[test]
    fn r7_forged_witnesses_are_rejected_by_tight_decomposition() {
        std::thread::Builder::new()
            .stack_size(1 << 30)
            .spawn(|| {
                use demo_flow::p_track::*;

                let [q0, q1, q2, q3] = DemoParams::THRESHOLD_MODULI.map(u128::from);
                let p_mod = BigUint::parse_bytes(DEMO_RECONSTRUCTION_MODULUS.as_bytes(), 10)
                    .expect("P constant must be decimal");
                let delta = DemoParams::delta();
                let capacity = |base: u128, limbs: usize| {
                    let base = BigUint::from(base);
                    (base.clone() >> 1)
                        * ((base.pow(limbs as u32) - BigUint::from(1u64))
                            / (base - BigUint::from(1u64)))
                };
                let capacity_crt = capacity(DEMO_R7_CRT_B, DEMO_R7_CRT_L);
                let capacity_dec = capacity(DEMO_R7_DECODE_B, DEMO_R7_DECODE_L);

                // Honest value u = Delta*5 + 42, its residues, and the
                // forgery u' = u + 1 (inconsistent with the residues).
                let u = &delta * 5u128 + 42u128;
                let residues = [
                    u.clone() % q0,
                    u.clone() % q1,
                    u.clone() % q2,
                    u.clone() % q3,
                ];
                let forged = &u + 1u64;
                assert!(
                    [q0, q1, q2, q3]
                        .iter()
                        .any(|&ql| (forged.clone() - (&u % ql)) % ql != BigUint::from(0u64)),
                    "u + 1 must be inconsistent with at least one residue"
                );

                // --- (i) CRT forgery closes mod P with full-range quotients.
                let forged_quotients: Vec<BigUint> = [q0, q1, q2, q3]
                    .iter()
                    .zip(&residues)
                    .map(|(&ql, residue)| {
                        let ql_big = BigUint::from(ql);
                        let inverse = ql_big.modpow(&(&p_mod - 2u64), &p_mod);
                        (forged.clone() - residue) * inverse % &p_mod
                    })
                    .collect();
                // Full-range: the forged quotients exceed the tight capacity
                // (the honest Q/q_l bound ~2^66) for at least one channel.
                assert!(
                    forged_quotients.iter().any(|fq| fq >= &capacity_crt),
                    "forged quotients must exceed the tight decomposition capacity"
                );
                // Honest quotients fit (sanity).
                for (&ql, residue) in [q0, q1, q2, q3].iter().zip(&residues) {
                    assert!((&u - residue) / ql < capacity_crt, "honest quotient fits");
                }

                // The bare CRT relation closes over R_P with the forged
                // witnesses — only the decomposition catches it.
                // (demo: CRT_ROWS = next_pow2(8*6) = 64.)
                let ccs_crt = CCS::from_r1cs(r7_crt_r1cs(), 64);
                let one = p_ring_u128(&[1]).unwrap();
                // Garner digits of the forgery (recomputed honestly).
                let r0_f = forged.clone() % q0;
                let t1_f = (forged.clone() % q1 + q1 - r0_f.clone() % q1)
                    * BigUint::from(fermat_inverse(q0, q1))
                    % q1;
                let x01_f = r0_f.clone() + q0 * &t1_f;
                let t2_f = (forged.clone() % q2 + q2 - x01_f.clone() % q2)
                    * BigUint::from(fermat_inverse(q0 * q1 % q2, q2))
                    % q2;
                let x012_f = x01_f + BigUint::from(q0 * q1) * &t2_f;
                let q0q1q2 = BigUint::from(q0 * q1) * BigUint::from(q2);
                let q0q1q2_mod_q3: u128 = (&q0q1q2 % q3).try_into().unwrap();
                let x012_mod_q3: u128 = (&x012_f % q3).try_into().unwrap();
                let t3_f = (forged.clone() % q3 + q3 - x012_mod_q3)
                    * BigUint::from(fermat_inverse(q0q1q2_mod_q3, q3))
                    % q3;
                assert_eq!(
                    &x012_f + &q0q1q2 * &t3_f,
                    forged.clone(),
                    "Garner digits must reconstruct the forgery"
                );
                let z_forged = vec![
                    p_ring_big(&[forged.clone()]).unwrap(),
                    p_ring_big(&[residues[0].clone()]).unwrap(),
                    p_ring_big(&[residues[1].clone()]).unwrap(),
                    p_ring_big(&[residues[2].clone()]).unwrap(),
                    p_ring_big(&[residues[3].clone()]).unwrap(),
                    one,
                    p_ring_big(&[r0_f]).unwrap(),
                    p_ring_big(&[t1_f]).unwrap(),
                    p_ring_big(&[t2_f]).unwrap(),
                    p_ring_big(&[t3_f]).unwrap(),
                    p_ring_big(&[forged_quotients[0].clone()]).unwrap(),
                    p_ring_big(&[forged_quotients[1].clone()]).unwrap(),
                    p_ring_big(&[forged_quotients[2].clone()]).unwrap(),
                    p_ring_big(&[forged_quotients[3].clone()]).unwrap(),
                ];
                assert!(
                    ccs_crt.check_relation(&z_forged).is_ok(),
                    "mod-P relation closes for forged quotients (vacuity without range enforcement)"
                );

                // --- (ii) Decode forgery: m' = m + 1 forces e' = e - Delta.
                let forged_m = 6u128;
                let e_forged =
                    BigInt::from(u.clone()) - BigInt::from(&delta * BigUint::from(forged_m));
                assert!(
                    num_traits::Signed::abs(&e_forged) > BigInt::from(capacity_dec.clone()),
                    "forged decode witness must exceed the tight capacity"
                );
                // (demo: DEC_ROWS = next_pow2(7) = 8.)
                let ccs_dec = CCS::from_r1cs(r7_decode_r1cs(), 8);
                let z_dec_forged = vec![
                    p_ring_big(&[u.clone()]).unwrap(),
                    p_ring_u128(&[forged_m]).unwrap(),
                    p_ring_u128(&[1]).unwrap(),
                    p_ring_signed(&[e_forged]).unwrap(),
                ];
                assert!(
                    ccs_dec.check_relation(&z_dec_forged).is_ok(),
                    "mod-P decode row closes for the forged plaintext (vacuity)"
                );
            })
            .expect("failed to spawn R7 negative-test thread")
            .join()
            .expect("R7 negative-test thread panicked");
    }

    /// Production-set smoke test of the R7 P track (251-bit reconstruction
    /// prime): two nonzero coefficients with signed rounding witnesses inside
    /// the tight decode capacity, decoded through the P-ring NTT and both
    /// tight decompositions.
    #[test]
    fn r7_prod_decode_smoke() {
        std::thread::Builder::new()
            .stack_size(1 << 30)
            .spawn(|| {
                let config = CommitteeConfig::default();
                let [q0, q1, q2, q3] = ProdParams::THRESHOLD_MODULI;
                let delta = ProdParams::delta();
                // Coefficient 0: negative noise; coefficient 1: large
                // positive noise (still inside the tight capacity 2^149).
                let u0: BigUint = &delta * 3u128 - (BigUint::from(1u64) << 100);
                let u1: BigUint = &delta * 5u128 + (BigUint::from(1u64) << 140);
                let mut res = [
                    vec![0u64; ProdParams::DEGREE],
                    vec![0u64; ProdParams::DEGREE],
                    vec![0u64; ProdParams::DEGREE],
                    vec![0u64; ProdParams::DEGREE],
                ];
                for (channel, modulus) in [q0, q1, q2, q3].into_iter().enumerate() {
                    res[channel][0] = (u0.clone() % modulus)
                        .iter_u64_digits()
                        .next()
                        .unwrap_or(0);
                    res[channel][1] = (u1.clone() % modulus)
                        .iter_u64_digits()
                        .next()
                        .unwrap_or(0);
                }
                let decoded =
                    prod_flow::p_track::prove_r7(&res, &config).expect("prove_r7 failed");
                assert_eq!(decoded[0], 3);
                assert_eq!(decoded[1], 5);
                assert!(decoded[2..].iter().all(|&m| m == 0));
            })
            .expect("failed to spawn R7 production smoke-test thread")
            .join()
            .expect("R7 production smoke-test thread panicked");
    }

    use crate::vdkg_params::{
        DEMO_RECONSTRUCTION_MODULUS, DEMO_R7_CRT_B, DEMO_R7_CRT_L, DEMO_R7_DECODE_B,
        DEMO_R7_DECODE_L, DEMO_THRESHOLD_MODULI, DEMO_THRESHOLD_PLAINTEXT_MODULUS,
    };

    /// Native (proof-free) replication of the P3/P4 decryption arithmetic on
    /// the N=4096 parameter set: encrypt under the aggregate key, compute T
    /// decryption shares, interpolate, CRT-combine, and decode. Used to
    /// isolate flow bugs from the proof machinery.
    #[test]
    fn native_decryption_roundtrip() {
        let config = CommitteeConfig {
            committee_n: 3,
            honest_h: 3,
            threshold_t: 2,
            recipient_id: 2,
            session_id: 0,
        };
        let mut rng = ark_std::test_rng();
        let dealers = config.honest_h;
        let sk = (0..dealers)
            .map(|_| sample_short_poly::<DemoParams>(2, &mut rng))
            .collect::<Vec<_>>();
        let e = (0..dealers)
            .map(|_| sample_short_poly::<DemoParams>(2, &mut rng))
            .collect::<Vec<_>>();
        let e_sm = (0..dealers)
            .map(|_| sample_smudging_poly::<DemoParams>(&mut rng))
            .collect::<Vec<_>>();
        let message = (0..DemoParams::DEGREE)
            .map(|c| (7 + 31 * c as u64) % DEMO_THRESHOLD_PLAINTEXT_MODULUS)
            .collect::<Vec<_>>();
        // User encryption randomness, shared across channels.
        let user_u = sample_short_poly::<DemoParams>(2, &mut rng);
        let user_e0 = sample_short_poly::<DemoParams>(2, &mut rng);
        let user_e1 = sample_short_poly::<DemoParams>(2, &mut rng);

        let mut residues: [Vec<u64>; 4] = [vec![], vec![], vec![], vec![]];
        for channel in 0..4 {
            let modulus = DEMO_THRESHOLD_MODULI[channel];
            let sk_sharings =
                generate_channel_sharing::<DemoParams>(&sk, &config, channel, &mut rng);
            let esm_sharings =
                generate_channel_sharing::<DemoParams>(&e_sm, &config, channel, &mut rng);

            // Schoolbook negacyclic multiplication mod q_l.
            let mul = |x: &[u64], y: &[u64]| -> Vec<u64> {
                let q = modulus as u128;
                let mut out = vec![0u128; DemoParams::DEGREE];
                for (i, &xi) in x.iter().enumerate() {
                    for (j, &yj) in y.iter().enumerate() {
                        let target = i + j;
                        let value = xi as u128 * yj as u128;
                        if target < DemoParams::DEGREE {
                            out[target] = (out[target] + value) % q;
                        } else {
                            let slot = target - DemoParams::DEGREE;
                            out[slot] = (out[slot] + q - value % q) % q;
                        }
                    }
                }
                out.iter().map(|&v| v as u64).collect()
            };
            let add = |x: &[u64], y: &[u64]| -> Vec<u64> {
                x.iter()
                    .zip(y)
                    .map(|(&a, &b)| {
                        let s = a + b;
                        if s >= modulus {
                            s - modulus
                        } else {
                            s
                        }
                    })
                    .collect()
            };

            // a: fixed "CRS" stand-in, short so the noise accounting below
            // matches the flow's.
            let a = sample_short_poly::<DemoParams>(2, &mut rng);

            let sk_sum = (0..DemoParams::DEGREE)
                .map(|c| sk.iter().fold(0u64, |acc, s| acc + s[c]))
                .collect::<Vec<_>>();
            let e_sum = (0..DemoParams::DEGREE)
                .map(|c| e.iter().fold(0u64, |acc, s| acc + s[c]))
                .collect::<Vec<_>>();
            let esm_sum = (0..DemoParams::DEGREE)
                .map(|c| e_sm.iter().fold(0u64, |acc, s| acc + s[c]) % modulus)
                .collect::<Vec<_>>();

            let neg_a_s = mul(&a, &sk_sum)
                .iter()
                .map(|&v| if v == 0 { 0 } else { modulus - v })
                .collect::<Vec<_>>();
            let pk_agg = add(&neg_a_s, &e_sum);

            let delta_big = DemoParams::delta() % modulus;
            let delta_l: u64 = delta_big.try_into().unwrap();
            let ct0 = add(
                &add(&mul(&pk_agg, &user_u), &user_e0),
                &message
                    .iter()
                    .map(|&mc| (mc as u128 * delta_l as u128 % modulus as u128) as u64)
                    .collect::<Vec<_>>(),
            );
            let ct1 = add(&mul(&a, &user_u), &user_e1);

            // R6 shares for the first T parties + interpolation (native).
            let points = (1..=config.threshold_t as u64).collect::<Vec<_>>();
            let inv = |x: u64| -> u64 {
                let mut result = 1u128;
                let mut base = x as u128;
                let mut exp = modulus - 2;
                while exp != 0 {
                    if exp & 1 == 1 {
                        result = result * base % modulus as u128;
                    }
                    base = base * base % modulus as u128;
                    exp >>= 1;
                }
                result as u64
            };
            let lambdas = points
                .iter()
                .enumerate()
                .map(|(i, &point)| {
                    points
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .fold(1u64, |acc, (_, &other)| {
                            let den = if other > point {
                                other - point
                            } else {
                                modulus - (point - other)
                            };
                            (other as u128 * inv(den) as u128 % modulus as u128) as u64
                        })
                })
                .collect::<Vec<_>>();

            let mut u_interp = vec![0u64; DemoParams::DEGREE];
            for (party, &lambda) in (1..=config.threshold_t).zip(&lambdas) {
                let mut sk_share = vec![0u64; DemoParams::DEGREE];
                let mut esm_share = vec![0u64; DemoParams::DEGREE];
                for dealer in 0..dealers {
                    for c in 0..DemoParams::DEGREE {
                        sk_share[c] = (sk_share[c] + sk_sharings.shares[dealer][party - 1][c])
                            % modulus;
                        esm_share[c] = (esm_share[c] + esm_sharings.shares[dealer][party - 1][c])
                            % modulus;
                    }
                }
                let d = add(&add(&ct0, &mul(&ct1, &sk_share)), &esm_share);
                for (acc, &dv) in u_interp.iter_mut().zip(&d) {
                    let term = (dv as u128 * lambda as u128 % modulus as u128) as u64;
                    *acc += term;
                    if *acc >= modulus {
                        *acc -= modulus;
                    }
                }
            }

            // Direct check: u == ct0 + ct1 * S + E_sm == Delta*m + noise (mod q_l)
            let noise_poly = add(
                &add(&mul(&e_sum, &user_u), &user_e0),
                &add(&mul(&user_e1, &sk_sum), &esm_sum),
            );
            let expected = add(
                &message
                    .iter()
                    .map(|&mc| (mc as u128 * delta_l as u128 % modulus as u128) as u64)
                    .collect::<Vec<_>>(),
                &noise_poly,
            );
            assert_eq!(u_interp, expected, "channel {channel}: u != Delta*m + noise");
            residues[channel] = u_interp;
        }

        // CRT + decode natively (Garner; the four-channel prefix product
        // q0*q1*q2 exceeds u128 at the tail, so the wide tail is BigUint).
        let [q0, q1, q2, q3] = DEMO_THRESHOLD_MODULI.map(u128::from);
        let delta = DemoParams::delta();
        for c in 0..16 {
            let r0 = residues[0][c] as u128;
            let t1 = (residues[1][c] as u128 + q1 - r0 % q1)
                * demo_flow::p_track::fermat_inverse(q0, q1)
                % q1;
            let x01 = r0 + q0 * t1;
            let t2 = (residues[2][c] as u128 + q2 - x01 % q2)
                * demo_flow::p_track::fermat_inverse((q0 * q1) % q2, q2)
                % q2;
            let x012 = BigUint::from(x01) + BigUint::from(q0 * q1) * BigUint::from(t2);
            let q0q1q2 = BigUint::from(q0 * q1) * BigUint::from(q2);
            let q3_big = BigUint::from(q3);
            let x012_mod_q3: u128 = (&x012 % &q3_big).try_into().unwrap();
            let q0q1q2_mod_q3: u128 = (&q0q1q2 % &q3_big).try_into().unwrap();
            let t3 = (residues[3][c] as u128 + q3 - x012_mod_q3)
                * demo_flow::p_track::fermat_inverse(q0q1q2_mod_q3, q3)
                % q3;
            let value = x012 + q0q1q2 * BigUint::from(t3);
            let m = &value / &delta;
            let noise = &value - &delta * &m;
            assert!(
                noise <= &delta / 2u64,
                "coefficient {c}: noise {noise} exceeds Delta/2"
            );
            assert_eq!(
                m,
                BigUint::from(message[c]),
                "coefficient {c} decoded wrong"
            );
        }
    }
}
