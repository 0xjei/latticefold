//! Native end-to-end VDKG flow over the threshold RNS channels and the
//! reconstruction prime P, following the `plan.md` relations R1..R7,
//! generic over the parameter set ([`VdkgParams`]):
//!
//! - **P1 DKG.** Every dealer proves R1 (`pk0_i = -a * sk_i + e_i`, with the
//!   smudging noise `e_sm,i` inside the same short witness), shares both
//!   secrets per channel (`generate_channel_sharing`, the plan's native
//!   per-channel formulation of R2) with GRS-syndrome R2 proofs, transports
//!   the recipient's shares with real `fhe.rs` BFV (R3 data plane), and the
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
//!   interpolated per channel and the P-track R7 relation proves the CRT
//!   reconstruction (quotient witnesses `u = u_l + s_l * q_l`) and the decode
//!   (`u = Delta * m + e`, bounded positive rounding witness) natively in the
//!   P ring, recovering the user plaintext.
//!
//! Deliberate demonstration simplifications (documented, never silent):
//!
//! - Secrets and errors are sampled with small NON-NEGATIVE coefficients
//!   (`{0,1}` for `sk/e/u/e0/e1`, smudging noise in `[3N, 6N)`) so the R7
//!   decode witness is a positive bounded integer and no centered/balanced
//!   handling is required. The smudging shift dominates the (possibly
//!   negative) negacyclic wrap terms of the product noises, so
//!   `0 < e < 8 * H * N << Delta / 2` coefficient-wise and the decode identity
//!   holds over the integers. The relation shapes are unaffected.
//! - Cross-relation equality-of-openings (the R1<->R2 secret anchor, the
//!   R2->R4 share binding, and Ruser's cross-channel `Com(m)` consistency) are
//!   example-side assertions, exactly as in the other slices; verifier-bound
//!   equality proofs remain the known gap listed in `DKG_SLICES.md`.

use std::error::Error;

use ark_ff::{Field, PrimeField};
use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};
use cyclotomic_rings::rings::{
    N4096PChallengeSet, N4096PField, N4096PRingNTT, N4096PRingPoly, N4096Q0ChallengeSet,
    N4096Q0Field, N4096Q0RingNTT, N4096Q0RingPoly, N4096Q1ChallengeSet, N4096Q1Field,
    N4096Q1RingNTT, N4096Q1RingPoly, N4096Q2ChallengeSet, N4096Q2Field, N4096Q2RingNTT,
    N4096Q2RingPoly, N8192PChallengeSet, N8192PField, N8192PRingNTT, N8192PRingPoly,
    N8192Q0ChallengeSet, N8192Q0Field, N8192Q0RingNTT, N8192Q0RingPoly, N8192Q1ChallengeSet,
    N8192Q1Field, N8192Q1RingNTT, N8192Q1RingPoly, N8192Q2ChallengeSet, N8192Q2Field,
    N8192Q2RingNTT, N8192Q2RingPoly,
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
        generate_channel_sharing, ChannelSharings, CommitteeConfig, ShareTransport,
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
    vdkg_params::{N4096Params, N8192Params, VdkgParams},
};

const KAPPA: usize = 4;

#[derive(Clone)]
struct FlowParams;

impl DecompositionParams for FlowParams {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    // The q channels are 34-bit fields; retain enough binary limbs for signed
    // field representatives and the public-input decomposition used by NIFS.
    const K: usize = 35;
}

#[derive(Clone)]
struct PFlowParams;

impl DecompositionParams for PFlowParams {
    const B: u128 = 1 << 15;
    const L: usize = 7;
    const B_SMALL: usize = 2;
    // P is a 104-bit field; retain enough binary limbs for signed field
    // representatives and the public-input decomposition.
    const K: usize = 105;
}

#[derive(Clone)]
struct Flow8192Params;

impl DecompositionParams for Flow8192Params {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    // The q channels are 58-bit fields.
    const K: usize = 59;
}

#[derive(Clone)]
struct PFlow8192Params;

impl DecompositionParams for PFlow8192Params {
    const B: u128 = 1 << 15;
    // The shifted decode witness reaches Delta (~154 bits), so retain enough
    // base-B limbs for it and the CRT quotient witnesses (~116 bits).
    const L: usize = 11;
    const B_SMALL: usize = 2;
    // P is a 176-bit field.
    const K: usize = 177;
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
            /// accumulator for this channel. The per-fold NIFS verifier
            /// self-check is deferred by default (as in the R4 fold chain) and
            /// re-enabled with `DKG_VERIFY_FOLDS=1`.
            pub fn prove_and_fold_r6(
                instances: &[(CCCS<$ring>, Witness<$ring>)],
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
                config: &CommitteeConfig,
            ) -> Result<(), Box<dyn Error>> {
                let verify_folds = std::env::var_os("DKG_VERIFY_FOLDS").is_some();

                let (cm0, witness0) = &instances[0];
                let mut bootstrap_prover = ChannelTranscript::default();
                absorb_config(&mut bootstrap_prover, config, 0xE6);
                let (mut accumulator, _) =
                    LFLinearizationProver::<$ring, ChannelTranscript>::prove(
                        cm0,
                        witness0,
                        &mut bootstrap_prover,
                        ccs,
                    )?;
                let mut accumulator_witness = witness0.clone();

                let mut fold_prover = ChannelTranscript::default();
                let mut fold_verifier = ChannelTranscript::default();
                absorb_config(&mut fold_prover, config, 0xE6);
                absorb_config(&mut fold_verifier, config, 0xE6);
                for (index, (cm_i, witness_i)) in instances.iter().enumerate().skip(1) {
                    let (new_accumulator, new_witness, proof) =
                        NIFSProver::<$ring, $decomp, ChannelTranscript>::prove(
                            &accumulator,
                            &accumulator_witness,
                            cm_i,
                            witness_i,
                            &mut fold_prover,
                            ccs,
                            scheme,
                        )?;
                    if verify_folds {
                        let verified_accumulator =
                            NIFSVerifier::<$ring, $decomp, ChannelTranscript>::verify(
                                &accumulator,
                                cm_i,
                                &proof,
                                &mut fold_verifier,
                                ccs,
                            )?;
                        assert_eq!(
                            new_accumulator, verified_accumulator,
                            "R6 fold mismatch at {index}"
                        );
                    }
                    accumulator = new_accumulator;
                    accumulator_witness = new_witness;
                }
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
                transport: &ShareTransport<$params>,
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

                // ---- P1/R2 + R3 + R4: GRS sharing proofs, real BFV
                // transport of the recipient's shares, folded metadata-bound
                // openings (reusing the fhe_bridge committee path).
                let decoded_sk =
                    crate::fhe_bridge::$bridge::fold_committee_r4(transport, sk_sharings, config)?;
                let decoded_esm = crate::fhe_bridge::$bridge::fold_committee_r4(
                    transport,
                    esm_sharings,
                    config,
                )?;
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
    ($module:ident, $params:ty, $pdecomp:ty, $pring:ty, $ppoly:ty, $pfield:ty, $pcs:ty) => {
        /// Reconstruction-track R7 over the P ring: CRT recombination with
        /// quotient witnesses plus the BFV decode, proven natively.
        pub mod $module {
            use super::*;

            type PTranscript = PoseidonTranscript<$pring, $pcs>;

            // z = [u, u0, u1, u2, m, one, r0, t1, t2, s0, s1, s2, e]
            const IDX_U: usize = 0;
            const IDX_U0: usize = 1;
            const IDX_U1: usize = 2;
            const IDX_U2: usize = 3;
            const IDX_M: usize = 4;
            const IDX_ONE: usize = 5;
            const IDX_R0: usize = 6;
            const IDX_T1: usize = 7;
            const IDX_T2: usize = 8;
            const IDX_S0: usize = 9;
            const IDX_S1: usize = 10;
            const IDX_S2: usize = 11;
            const IDX_E: usize = 12;
            const R7_COLS: usize = 13;
            // >= 7 * L committed limbs, padded to a power of two.
            const R7_ROWS: usize = (7 * <$pdecomp>::L).next_power_of_two();

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

            /// The R7 relation (interpolation/CRT/decode) as an R1CS.
            pub fn r7_r1cs() -> R1CS<$pring> {
                let [q0, q1, q2] = <$params as VdkgParams>::THRESHOLD_MODULI;
                let q0 = <$pring>::from(q0 as u128);
                let q1 = <$pring>::from(q1 as u128);
                let q2 = <$pring>::from(q2 as u128);
                let q0q1 = q0 * q1;
                let delta = <$pring>::from(<$pfield>::from(<$params as VdkgParams>::delta()));
                let one = <$pring>::from(1u128);

                let mut a_rows = vec![vec![]; R7_ROWS];
                // Garner recombination: u = r0 + q0 * t1 + q0 * q1 * t2.
                a_rows[0] = vec![(one, IDX_U), (-one, IDX_R0), (-q0, IDX_T1), (-q0q1, IDX_T2)];
                // Quotient witnesses binding u to the public channel residues:
                // u = u_l + s_l * q_l with s_l < Q / q_l.
                a_rows[1] = vec![(one, IDX_U), (-one, IDX_U0), (-q0, IDX_S0)];
                a_rows[2] = vec![(one, IDX_U), (-one, IDX_U1), (-q1, IDX_S1)];
                a_rows[3] = vec![(one, IDX_U), (-one, IDX_U2), (-q2, IDX_S2)];
                // Decode for signed (centered) noise: u = Delta * m + e with
                // e = u - Delta * m the CENTERED noise in (-Delta/2, Delta/2)
                // (represented as a signed field element; balanced
                // decomposition handles it).
                a_rows[4] = vec![(one, IDX_U), (-delta, IDX_M), (-one, IDX_E)];

                let mut b_rows = vec![vec![]; R7_ROWS];
                for row in b_rows.iter_mut().take(5) {
                    *row = vec![(one, IDX_ONE)];
                }
                R1CS::<$pring> {
                    l: 5,
                    A: SparseMatrix { nrows: R7_ROWS, ncols: R7_COLS, coeffs: a_rows },
                    B: SparseMatrix { nrows: R7_ROWS, ncols: R7_COLS, coeffs: b_rows },
                    C: SparseMatrix {
                        nrows: R7_ROWS,
                        ncols: R7_COLS,
                        coeffs: vec![vec![]; R7_ROWS],
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

            /// Prove the R7 CRT reconstruction and decode of the three
            /// per-channel interpolated residue polynomials, returning the
            /// decoded plaintext coefficients.
            pub fn prove_r7(
                residues: &[Vec<u64>; 3],
                config: &CommitteeConfig,
            ) -> Result<Vec<u64>, Box<dyn Error>> {
                let [q0, q1, q2] = <$params as VdkgParams>::THRESHOLD_MODULI.map(u128::from);
                let q0q1 = q0 * q1;
                let delta = <$params as VdkgParams>::delta();
                let t = <$params as VdkgParams>::THRESHOLD_PLAINTEXT as u128;
                let degree = <$params as VdkgParams>::DEGREE;

                let mut u = Vec::with_capacity(degree);
                let mut garner_t1 = Vec::with_capacity(degree);
                let mut garner_t2 = Vec::with_capacity(degree);
                let mut quotient_s0 = Vec::with_capacity(degree);
                let mut quotient_s1 = Vec::with_capacity(degree);
                let mut quotient_s2 = Vec::with_capacity(degree);
                let mut message = Vec::with_capacity(degree);
                let mut rounding = Vec::with_capacity(degree);

                for coefficient in 0..degree {
                    let residue = [
                        residues[0][coefficient],
                        residues[1][coefficient],
                        residues[2][coefficient],
                    ];
                    // Garner reconstruction with u128 intermediate digits; only
                    // the final value needs a wide integer.
                    let r0 = residue[0] as u128;
                    let t1 = (residue[1] as u128 + q1 - r0 % q1) * fermat_inverse(q0, q1) % q1;
                    let x01 = r0 + q0 * t1;
                    let t2 = (residue[2] as u128 + q2 - x01 % q2)
                        * fermat_inverse(q0q1 % q2, q2)
                        % q2;
                    let value = BigUint::from(x01) + BigUint::from(q0q1) * BigUint::from(t2);

                    quotient_s0.push(t1 + q1 * t2);
                    quotient_s1.push(
                        (value.clone() - residue[1] as u128) / q1,
                    );
                    quotient_s2.push(
                        (value.clone() - residue[2] as u128) / q2,
                    );
                    garner_t1.push(t1);
                    garner_t2.push(t2);

                    let half = &delta / 2u64;
                    let m_big = (&value + &half) / &delta;
                    // Centered (signed) rounding witness in (-Delta/2, Delta/2).
                    let half_int = BigInt::from(half.clone());
                    let e_signed = BigInt::from(value.clone() + &half)
                        - BigInt::from(&delta * &m_big)
                        - &half_int;
                    if num_traits::Signed::abs(&e_signed) > half_int || m_big >= BigUint::from(t) {
                        return Err(format!(
                            "decode failure at coefficient {coefficient}: centered rounding witness out of range"
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
                let m_r = p_ring_u128(
                    &message
                        .iter()
                        .map(|&value| value as u128)
                        .collect::<Vec<_>>(),
                )?;
                let witness_r = vec![
                    u0_r, // r0 = u mod q0 is the channel-0 residue itself
                    p_ring_u128(&garner_t1)?,
                    p_ring_u128(&garner_t2)?,
                    p_ring_u128(&quotient_s0)?,
                    p_ring_big(&quotient_s1)?,
                    p_ring_big(&quotient_s2)?,
                    p_ring_signed(&rounding)?,
                ];

                let ccs = CCS::from_r1cs(r7_r1cs(), R7_ROWS);
                let z = [
                    &[u_r, u0_r, u1_r, u2_r, m_r, <$pring>::from(1u128)][..],
                    &witness_r[..],
                ]
                .concat();
                if std::env::var_os("DKG_DEBUG_R7").is_some() {
                    let half_ring = <$pring>::from(<$pfield>::from(
                        <$params as VdkgParams>::delta() / 2u64,
                    ));
                    let delta_ring = <$pring>::from(<$pfield>::from(
                        <$params as VdkgParams>::delta(),
                    ));
                    let row4 = u_r + half_ring - delta_ring * m_r - witness_r[6];
                    let row4_coeffs = ICRT::elementwise_icrt(vec![row4])[0].coeffs().to_vec();
                    let nonzero = row4_coeffs
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| c.into_bigint().0[0] != 0 || c.into_bigint().0[1] != 0)
                        .map(|(i, c)| (i, c.into_bigint().to_string()))
                        .take(5)
                        .collect::<Vec<_>>();
                    eprintln!("[r7-debug] row4 nonzero coeffs (first 5): {nonzero:?}");
                    let u0c = ICRT::elementwise_icrt(vec![u_r])[0].coeffs()[0].into_bigint();
                    let m0c = ICRT::elementwise_icrt(vec![m_r])[0].coeffs()[0].into_bigint();
                    let e0c = ICRT::elementwise_icrt(vec![witness_r[6]])[0].coeffs()[0]
                        .into_bigint();
                    eprintln!("[r7-debug] u[0]={u0c} m[0]={m0c} e[0]={e0c}");
                    let c = |r: $pring, i: usize| {
                        ICRT::elementwise_icrt(vec![r])[0].coeffs()[i].into_bigint()
                    };
                    eprintln!(
                        "[r7-debug] u[1]={} m[1]={} e[1]={} half_ring[0]={} half_ring[1]={} delta_ring[1]={}",
                        c(u_r, 1),
                        c(m_r, 1),
                        c(witness_r[6], 1),
                        c(half_ring, 0),
                        c(half_ring, 1),
                        c(delta_ring, 1)
                    );
                }
                ccs.check_relation(&z)?;

                let scheme = AjtaiCommitmentScheme::from_domain::<PTranscript>(
                    &format!("vdkg/r7/P/N{}", <$params as VdkgParams>::DEGREE),
                    KAPPA,
                    7 * <$pdecomp>::L,
                    <$params as VdkgParams>::DEGREE,
                );
                let witness = Witness::from_w_ccs::<$pdecomp>(witness_r);
                let cm = CCCS {
                    cm: witness.commit::<$pdecomp>(&scheme)?,
                    x_ccs: vec![u_r, u0_r, u1_r, u2_r, m_r],
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
                let mut prover_transcript = PTranscript::default();
                absorb(&mut prover_transcript);
                let (prover_lcccs, proof) = LFLinearizationProver::<$pring, PTranscript>::prove(
                    &cm,
                    &witness,
                    &mut prover_transcript,
                    &ccs,
                )?;
                let mut verifier_transcript = PTranscript::default();
                absorb(&mut verifier_transcript);
                let verifier_lcccs = LFLinearizationVerifier::<$pring, PTranscript>::verify(
                    &cm,
                    &proof,
                    &mut verifier_transcript,
                    &ccs,
                )?;
                assert_eq!(prover_lcccs, verifier_lcccs, "R7 linearization mismatch");
                assert_eq!(
                    verifier_lcccs.x_w,
                    vec![u_r, u0_r, u1_r, u2_r, m_r],
                    "R7 verifier output was not bound to the public reconstruction"
                );
                Ok(message)
            }
        }
    };
}

macro_rules! define_run_full_flow {
    ($params:ty, $q0:ident, $q1:ident, $q2:ident, $p:ident) => {
        /// Run the complete P1 -> P4 protocol over all three RNS channels plus
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

            let mut rng = ark_std::test_rng();
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

            // Channel-native sharings (plan.md R2 is per channel); the three
            // channel sharings of one short secret are CRT-consistent. The
            // smudging noise exceeds one channel, so it is shared as its
            // per-channel CRT residues.
            let sk_sharings = (0..3)
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
            let esm_sharings = (0..3)
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

            let transport = ShareTransport::<$params>::new()?;

            // The three channels share only read-only data, so their proof
            // chains run concurrently. The fold chains are deep, so give each
            // channel thread a large stack.
            const FLOW_STACK_SIZE: usize = 1 << 30;
            let (residues_q0, residues_q1, residues_q2) = std::thread::scope(|scope| {
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
                (
                    handle_q0.join().unwrap_or_else(|_| Err("q0 flow thread panicked".to_string())),
                    handle_q1.join().unwrap_or_else(|_| Err("q1 flow thread panicked".to_string())),
                    handle_q2.join().unwrap_or_else(|_| Err("q2 flow thread panicked".to_string())),
                )
            });
            let residues = [residues_q0?, residues_q1?, residues_q2?];

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

pub mod n4096_flow {
    use super::*;

    define_flow_channel!(
        q0, N4096Params, FlowParams, q0, N4096Q0RingNTT, N4096Q0RingPoly, N4096Q0Field,
        N4096Q0ChallengeSet, 0
    );
    define_flow_channel!(
        q1, N4096Params, FlowParams, q1, N4096Q1RingNTT, N4096Q1RingPoly, N4096Q1Field,
        N4096Q1ChallengeSet, 1
    );
    define_flow_channel!(
        q2, N4096Params, FlowParams, q2, N4096Q2RingNTT, N4096Q2RingPoly, N4096Q2Field,
        N4096Q2ChallengeSet, 2
    );
    define_p_track!(
        p_track, N4096Params, PFlowParams, N4096PRingNTT, N4096PRingPoly, N4096PField,
        N4096PChallengeSet
    );
    define_run_full_flow!(N4096Params, q0, q1, q2, p_track);
}

pub mod n8192_flow {
    use super::*;

    define_flow_channel!(
        q0, N8192Params, Flow8192Params, n8192_q0, N8192Q0RingNTT, N8192Q0RingPoly,
        N8192Q0Field, N8192Q0ChallengeSet, 0
    );
    define_flow_channel!(
        q1, N8192Params, Flow8192Params, n8192_q1, N8192Q1RingNTT, N8192Q1RingPoly,
        N8192Q1Field, N8192Q1ChallengeSet, 1
    );
    define_flow_channel!(
        q2, N8192Params, Flow8192Params, n8192_q2, N8192Q2RingNTT, N8192Q2RingPoly,
        N8192Q2Field, N8192Q2ChallengeSet, 2
    );
    define_p_track!(
        p_track, N8192Params, PFlow8192Params, N8192PRingNTT, N8192PRingPoly, N8192PField,
        N8192PChallengeSet
    );
    define_run_full_flow!(N8192Params, q0, q1, q2, p_track);
}

pub use n4096_flow::run_full_flow;
pub use n8192_flow::run_full_flow as run_full_flow_n8192;

#[cfg(test)]
mod tests {
    use super::*;

    /// Standalone check of the R7 relation on one known-good coefficient set
    /// (fast: no committee, no committee threads).
    #[test]
    fn r7_decode_row_is_consistent() {
        // Values from a real flow debug print (N=4096 set).
        let config = CommitteeConfig::default();
        let [q0, q1, q2] = N4096Params::THRESHOLD_MODULI;
        let delta = N4096Params::delta();
        let half = &delta / 2u64;
        let m_true = 7u128;
        let noise = 12345u128;
        let u = &delta * m_true + noise - &half; // u + half = delta*m_true + noise
        // residues u mod q_l
        let u_big = u.clone();
        let residues = [
            (u_big.clone() % q0).iter_u64_digits().next().unwrap_or(0),
            (u_big.clone() % q1).iter_u64_digits().next().unwrap_or(0),
            (u_big.clone() % q2).iter_u64_digits().next().unwrap_or(0),
        ];
        let mut res = residues.map(|r| vec![0u64; N4096Params::DEGREE]);
        res[0][0] = residues[0];
        res[1][0] = residues[1];
        res[2][0] = residues[2];
        // prove_r7 must accept and decode m_true at coefficient 0 (others are 0).
        let decoded = n4096_flow::p_track::prove_r7(&res, &config).expect("prove_r7 failed");
        assert_eq!(decoded[0], m_true as u64);
        assert!(decoded[1..].iter().all(|&m| m == 0));
    }

    use crate::vdkg_params::{
        N4096_THRESHOLD_PLAINTEXT_MODULUS, N4096_THRESHOLD_MODULI,
    };
    use stark_rings::cyclotomic_ring::ICRT;

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
            .map(|_| sample_short_poly::<N4096Params>(2, &mut rng))
            .collect::<Vec<_>>();
        let e = (0..dealers)
            .map(|_| sample_short_poly::<N4096Params>(2, &mut rng))
            .collect::<Vec<_>>();
        let e_sm = (0..dealers)
            .map(|_| sample_smudging_poly::<N4096Params>(&mut rng))
            .collect::<Vec<_>>();
        let message = (0..N4096Params::DEGREE)
            .map(|c| (7 + 31 * c as u64) % N4096_THRESHOLD_PLAINTEXT_MODULUS)
            .collect::<Vec<_>>();
        // User encryption randomness, shared across channels.
        let user_u = sample_short_poly::<N4096Params>(2, &mut rng);
        let user_e0 = sample_short_poly::<N4096Params>(2, &mut rng);
        let user_e1 = sample_short_poly::<N4096Params>(2, &mut rng);

        let mut residues: [Vec<u64>; 3] = [vec![], vec![], vec![]];
        for channel in 0..3 {
            let modulus = N4096_THRESHOLD_MODULI[channel];
            let sk_sharings =
                generate_channel_sharing::<N4096Params>(&sk, &config, channel, &mut rng);
            let esm_sharings =
                generate_channel_sharing::<N4096Params>(&e_sm, &config, channel, &mut rng);

            // Schoolbook negacyclic multiplication mod q_l.
            let mul = |x: &[u64], y: &[u64]| -> Vec<u64> {
                let q = modulus as u128;
                let mut out = vec![0u128; N4096Params::DEGREE];
                for (i, &xi) in x.iter().enumerate() {
                    for (j, &yj) in y.iter().enumerate() {
                        let target = i + j;
                        let value = xi as u128 * yj as u128;
                        if target < N4096Params::DEGREE {
                            out[target] = (out[target] + value) % q;
                        } else {
                            let slot = target - N4096Params::DEGREE;
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
            let a = sample_short_poly::<N4096Params>(2, &mut rng);

            let sk_sum = (0..N4096Params::DEGREE)
                .map(|c| sk.iter().fold(0u64, |acc, s| acc + s[c]))
                .collect::<Vec<_>>();
            let e_sum = (0..N4096Params::DEGREE)
                .map(|c| e.iter().fold(0u64, |acc, s| acc + s[c]))
                .collect::<Vec<_>>();
            let esm_sum = (0..N4096Params::DEGREE)
                .map(|c| e_sm.iter().fold(0u64, |acc, s| acc + s[c]) % modulus)
                .collect::<Vec<_>>();

            let neg_a_s = mul(&a, &sk_sum)
                .iter()
                .map(|&v| if v == 0 { 0 } else { modulus - v })
                .collect::<Vec<_>>();
            let pk_agg = add(&neg_a_s, &e_sum);

            let delta_big = N4096Params::delta() % modulus;
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

            let mut u_interp = vec![0u64; N4096Params::DEGREE];
            for (party, &lambda) in (1..=config.threshold_t).zip(&lambdas) {
                let mut sk_share = vec![0u64; N4096Params::DEGREE];
                let mut esm_share = vec![0u64; N4096Params::DEGREE];
                for dealer in 0..dealers {
                    for c in 0..N4096Params::DEGREE {
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

        // CRT + decode natively (Garner, u128 intermediates for N=4096).
        let [q0, q1, q2] = N4096_THRESHOLD_MODULI.map(u128::from);
        let delta = N4096Params::delta();
        for c in 0..16 {
            let r0 = residues[0][c] as u128;
            let t1 = (residues[1][c] as u128 + q1 - r0 % q1)
                * n4096_flow::p_track::fermat_inverse(q0, q1)
                % q1;
            let x01 = r0 + q0 * t1;
            let t2 = (residues[2][c] as u128 + q2 - x01 % q2)
                * n4096_flow::p_track::fermat_inverse((q0 * q1) % q2, q2)
                % q2;
            let value = BigUint::from(x01) + BigUint::from(q0 * q1) * BigUint::from(t2);
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
