//! Slice 6: relation **R7** (Lagrange interpolation, CRT reconstruction, decode).
//!
//! This is the one relation that needs NO zero-knowledge (every d_i is already
//! public) and the one that CANNOT stay within a single RNS track — CRT
//! reconstruction mixes all channels — so it runs once on a dedicated track over
//! a large prime P > Q, and it is where QUOTIENT WITNESSES reappear (the range
//! checks avoided everywhere else).
//!
//! Structure demonstrated here (single Goldilocks track standing in for the P
//! track):
//!   1. Lagrange interpolation  u_l = Σ_i L_i(0) · d_i   — public affine, no witness.
//!   2. CRT reconstruction step u_global = u_l + r · q_l  — `r` is a QUOTIENT
//!      WITNESS bounded by ~Q/q_l, whose bound is enforced by LatticeFold's
//!      native range-proof machinery (not a foreign-field bit-decomposition).
//!
//! No-wraparound requirement: P must exceed u_global and every r·q_l cross term
//! (plus LatticeFold's extraction slack) so the R_P-native identity matches the
//! intended integer identity. Here values are kept small so no wraparound
//! occurs; the margin is DERIVED explicitly in `dkg_r7_crt.rs` and validated
//! for production in `vdkg_params::r7_margin_holds` (§9.3). The decomposition
//! below is deliberately NON-vacuous (B^L = 2^60 < P = 2^64): the earlier
//! B^L = 2^75 > P parameters let every residue decompose short, so any forged
//! u_global admitted valid quotient witnesses.
//!
//! Run with: cargo run --release --example dkg_r7

use ark_ff::{Field, PrimeField};
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::{
        linearization::{LFLinearizationProver, LinearizationProver},
        NIFSProver, NIFSVerifier,
    },
    transcript::poseidon::PoseidonTranscript,
};
use stark_rings::cyclotomic_ring::models::goldilocks::Fq;
use stark_rings_linalg::SparseMatrix;

type RqNTT = GoldilocksRingNTT;
type CS = GoldilocksChallengeSet;
type T = PoseidonTranscript<RqNTT, CS>;

#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    const B: u128 = 1 << 15;
    // 4 limbs: B^L = 2^60 < Goldilocks P = 2^64 (non-vacuous decomposition).
    const L: usize = 4;
    const B_SMALL: usize = 2;
    const K: usize = 15;
}

/// Witness = quotient r.
const WIT_LEN: usize = 1;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

/// Reconstruction consumes exactly the threshold T=27 decryption shares (of N=100).
const T_PARTIES: usize = 27; // T
/// Stand-in RNS modulus q_l for the CRT quotient step (kept small: no wraparound).
const Q_L: u128 = 1024;

// z = [u_l, u_global, one, r], l = 2.
const IDX_UL: usize = 0;
const IDX_UGLOBAL: usize = 1;
const IDX_ONE: usize = 2;
const IDX_R: usize = 3;
const N_COLS: usize = 4;

fn scalar_ring(c: Fq) -> RqNTT {
    RqNTT::from(c.into_bigint().as_ref()[0] as u128)
}

/// CRT reconstruction R1CS: `u_global - u_l - q_l * r = 0`.
#[allow(non_snake_case)]
fn r7_r1cs(q_l: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let neg_one = -one;
    let a0 = vec![(one, IDX_UGLOBAL), (neg_one, IDX_UL), (-*q_l, IDX_R)];
    let A = SparseMatrix {
        nrows: 1,
        ncols: N_COLS,
        coeffs: vec![a0],
    };
    let B = SparseMatrix {
        nrows: 1,
        ncols: N_COLS,
        coeffs: vec![vec![(one, IDX_ONE)]],
    };
    let C = SparseMatrix {
        nrows: 1,
        ncols: N_COLS,
        coeffs: vec![vec![]],
    };
    R1CS::<RqNTT> { l: 2, A, B, C }
}

fn main() {
    println!("LatticeFold VDKG — R7 Lagrange interpolation + CRT reconstruction");
    println!("Reconstructing from {T_PARTIES} shares | stand-in q_l={Q_L}, Goldilocks P track");

    let mut rng = ark_std::test_rng();

    // --- Step 1: PUBLIC Lagrange interpolation u_l = Σ L_i(0) * d_i -----------
    // Party indices 1..T; Lagrange-at-0 weights L_i(0) = Π_{j≠i} x_j/(x_j - x_i).
    let xs: Vec<Fq> = (1..=T_PARTIES as u64).map(Fq::from).collect();
    let lagrange0: Vec<Fq> = xs
        .iter()
        .enumerate()
        .map(|(i, &xi)| {
            xs.iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .fold(Fq::from(1u64), |acc, (_, &xj)| {
                    acc * xj * (xj - xi).inverse().unwrap()
                })
        })
        .collect();
    // Small public decryption shares d_i.
    let ds: Vec<Fq> = (0..T_PARTIES).map(|k| Fq::from((k as u64) + 3)).collect();
    let u_l_fq: Fq = lagrange0
        .iter()
        .zip(&ds)
        .fold(Fq::from(0u64), |acc, (&l, &d)| acc + l * d);
    println!("\n(1) PUBLIC interpolation: u_l = Σ L_i(0)*d_i computed off-witness (no proof) ✓");

    // --- Step 2: CRT reconstruction with QUOTIENT WITNESS r -------------------
    // Choose a quotient r and set u_global = u_l + r*q_l (small: no wraparound).
    let u_l = scalar_ring(u_l_fq);
    let r_val: u128 = 5; // quotient witness, bounded ~ Q/q_l in a real run
    let q_l = RqNTT::from(Q_L);
    let r = RqNTT::from(r_val);
    let u_global = u_l + q_l * r;

    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r7_r1cs(&q_l), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // z = [u_l, u_global, one, r]
    let z = vec![u_l, u_global, RqNTT::from(1u128), r];
    ccs.check_relation(&z)
        .expect("CRT reconstruction relation not satisfied");
    println!(
        "(2) CRT step u_global = u_l + r*q_l enforced; r is the quotient witness (range-proven) ✓"
    );

    let wit = Witness::from_w_ccs::<DP>(vec![r]);
    let cm = CCCS {
        cm: wit.commit::<DP>(&scheme).unwrap(),
        x_ccs: vec![u_l, u_global],
    };

    // Bootstrap + one fold to exercise the full pipeline incl. the norm/range proof on r.
    let mut bootstrap = PoseidonTranscript::<RqNTT, CS>::default();
    let (acc, _) = LFLinearizationProver::<_, T>::prove(&cm, &wit, &mut bootstrap, &ccs)
        .expect("bootstrap failed");

    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let (folded, _, proof) = NIFSProver::<RqNTT, DP, T>::prove(
        &acc,
        &wit,
        &cm,
        &wit,
        &mut prover_transcript,
        &ccs,
        &scheme,
    )
    .expect("folding prover failed");
    let verified =
        NIFSVerifier::<RqNTT, DP, T>::verify(&acc, &cm, &proof, &mut verifier_transcript, &ccs)
            .expect("folding verifier failed");
    assert_eq!(folded, verified, "accumulator mismatch");

    println!("\nReconstruction proof folded & verified (P track).");
    println!("Decode step (centered form u = Δ·m + e, |e| ≤ Δ/2) is the same shape:");
    println!("another bounded rounding/quotient witness — intrinsic to integer division, not a backend artifact.");
    println!(
        "\nNo-wraparound: P must exceed u_global and all r*q_l terms + the DERIVED extraction slack (§9.3)."
    );
}
