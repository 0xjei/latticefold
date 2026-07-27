//! Slice 2 of the lattice-based VDKG design: relation **R2** (Shamir sharing of
//! a contribution), with the batched Reed–Solomon check and digit decomposition.
//!
//! A dealer shares a ring-valued secret. Writing the sharing polynomial with
//! ring-element coefficients `s_0,...,s_T` (`s_0` = the short secret, the rest
//! uniform), the share to point `a_k` is
//!
//!     Y[k] = Σ_j a_k^j · s_j        (a_k^j are public SCALARS in Z_q).
//!
//! Because the evaluation points are scalars, `Y[1..n]` is a Reed–Solomon
//! codeword *coefficient-wise*: every one of the N ring coefficients is an
//! independent RS-codeword symbol under the same points. The design's key move
//! is that the parity check is therefore a SINGLE ring-level equation per row,
//!
//!     H_l · Y_l = 0        (H_l scalar entries acting on ring elements),
//!
//! not N separate field checks. We use the generalized-RS dual multipliers
//! `u_k = 1 / Π_{j≠k}(a_k − a_j)` so parity rows `H[r][k] = u_k · a_k^r` satisfy
//! `Σ_k u_k a_k^m = 0` for `m ≤ n−2` (the divided-difference identity), which
//! makes `H·Y = 0` hold for every degree-≤T sharing.
//!
//! Scalars embed as CONSTANT ring elements, so `H[r][k]·Y[k]` scales each
//! coefficient independently (no X^N+1 cross-coefficient mixing) — this is
//! exactly why the batching is sound. The whole relation is affine in the
//! witness. Shares are full-range, so `Witness::from_w_ccs` carries them via
//! their radix-B digit decomposition and the norm proof binds the digits.
//!
//! Goldilocks stands in for a real RNS prime q_l (custom-`Ring` work deferred).
//!
//! Run with:
//!   cargo run --release --example dkg_r2

use std::time::Instant;

use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::UniformRand;
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

// ---- Concrete instantiation ------------------------------------------------

type RqNTT = GoldilocksRingNTT;
type CS = GoldilocksChallengeSet;
type T = PoseidonTranscript<RqNTT, CS>;

#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    const K: usize = 15;
}

/// Committee N=100, threshold T=27: a dealer Shamir-shares to all N recipients with
/// a degree-(T−1) polynomial, so any T shares reconstruct. RS codeword dimension
/// k = T; PARITY = n − k parity rows.
const SHARES: usize = 100; // n = N recipients
const T_DEG: usize = 26; // polynomial degree = T − 1
const PARITY: usize = SHARES - (T_DEG + 1); // n − T = 73

/// Witness = the SHARES ring elements Y[1..n].
const WIT_LEN: usize = SHARES;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

/// Number of honest dealers whose R2 sharings are folded (H of N=100).
const DEALERS: usize = 51; // H

// z layout = [one, Y_0..Y_{n-1}], l = 0.
const IDX_ONE: usize = 0;
const N_COLS: usize = 1 + SHARES;

/// Scalar `Fq` embedded as the constant ring element (constant polynomial).
fn scalar_ring(c: Fq) -> RqNTT {
    let limbs = c.into_bigint();
    RqNTT::from(limbs.as_ref()[0] as u128)
}

/// Public evaluation points a_1..a_n (distinct, nonzero scalars).
fn eval_points() -> Vec<Fq> {
    (1..=SHARES as u64).map(Fq::from).collect()
}

/// GRS dual multipliers u_k = 1 / Π_{j≠k}(a_k − a_j).
fn dual_multipliers(a: &[Fq]) -> Vec<Fq> {
    a.iter()
        .enumerate()
        .map(|(k, &ak)| {
            let prod = a
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != k)
                .fold(Fq::ONE, |acc, (_, &aj)| acc * (ak - aj));
            prod.inverse().expect("distinct points => nonzero product")
        })
        .collect()
}

/// Build the batched-RS parity R1CS: PARITY rows, each enforcing
/// `Σ_k H[r][k]·Y[k] = 0` with `H[r][k] = u_k·a_k^r` (as constant ring elements).
#[allow(non_snake_case)]
fn rs_r1cs(a: &[Fq], u: &[Fq]) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);

    let mut A_rows = Vec::with_capacity(PARITY);
    let mut B_rows = Vec::with_capacity(PARITY);
    let mut C_rows = Vec::with_capacity(PARITY);

    for r in 0..PARITY {
        let mut a_row = Vec::with_capacity(SHARES);
        for k in 0..SHARES {
            // H[r][k] = u_k * a_k^r  (computed in Fq, then embedded).
            let h = u[k] * a[k].pow([r as u64]);
            a_row.push((scalar_ring(h), 1 + k)); // Y[k] at column 1+k
        }
        A_rows.push(a_row);
        B_rows.push(vec![(one, IDX_ONE)]); // select the constant 1
        C_rows.push(vec![]); // zero
    }

    R1CS::<RqNTT> {
        l: 0,
        A: SparseMatrix {
            nrows: PARITY,
            ncols: N_COLS,
            coeffs: A_rows,
        },
        B: SparseMatrix {
            nrows: PARITY,
            ncols: N_COLS,
            coeffs: B_rows,
        },
        C: SparseMatrix {
            nrows: PARITY,
            ncols: N_COLS,
            coeffs: C_rows,
        },
    }
}

/// One dealer's sharing: sample the sharing polynomial's ring coefficients and
/// evaluate at every point to form the shares Y[k].
fn deal_shares(a: &[Fq], rng: &mut impl ark_std::rand::Rng) -> Vec<RqNTT> {
    // s_0 = the short secret; s_1..s_T uniform (making shares full-range).
    let mut s = vec![short_ring(rng)];
    for _ in 0..T_DEG {
        s.push(RqNTT::rand(rng));
    }
    a.iter()
        .map(|&ak| {
            (0..=T_DEG).fold(RqNTT::from(0u128), |acc, j| {
                acc + scalar_ring(ak.pow([j as u64])) * s[j]
            })
        })
        .collect()
}

/// A short ring element (ternary constant-heavy secret): here just a small
/// scalar, sufficient to stand in for the short DKG secret s_0.
fn short_ring(rng: &mut impl ark_std::rand::Rng) -> RqNTT {
    RqNTT::from(rng.gen_range(0..3u128))
}

fn dealer_instance(
    a: &[Fq],
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    let shares = deal_shares(a, rng);

    // z = [one, Y_0..Y_{n-1}]; verify the batched RS parity check holds.
    let mut z = vec![RqNTT::from(1u128)];
    z.extend(shares.iter().copied());
    ccs.check_relation(&z)
        .expect("batched Reed-Solomon parity check H*Y = 0 failed");

    let wit = Witness::from_w_ccs::<DP>(shares);
    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: vec![],
    };
    (cm, wit)
}

fn main() {
    println!("LatticeFold VDKG — R2 Shamir sharing (batched Reed-Solomon)");
    println!("SHARES(n)={SHARES} T={T_DEG} PARITY rows={PARITY} | Goldilocks stand-in for q_l");
    println!("KAPPA={KAPPA} WIT_LEN={WIT_LEN} N={N}");
    println!(
        "(batched: {PARITY} ring-level constraints replace {} scalar checks)",
        PARITY
            * <cyclotomic_rings::rings::GoldilocksRingPoly as stark_rings::PolyRing>::dimension()
    );

    let mut rng = ark_std::test_rng();
    let a = eval_points();
    let u = dual_multipliers(&a);

    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(rs_r1cs(&a, &u), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // Bootstrap the accumulator from dealer 0.
    let (cm_0, wit_0) = dealer_instance(&a, &ccs, &scheme, &mut rng);
    let mut w_acc = wit_0;
    let mut bootstrap = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) = LFLinearizationProver::<_, T>::prove(&cm_0, &w_acc, &mut bootstrap, &ccs)
        .expect("failed to bootstrap accumulator");

    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();

    println!("\nFolding {DEALERS} dealers' R2 sharings...");
    let start = Instant::now();
    let mut last_proof = None;

    // Dealer 0 is already represented by the bootstrap accumulator.
    for dealer in 1..DEALERS {
        let (cm_i, wit_i) = dealer_instance(&a, &ccs, &scheme, &mut rng);

        let (new_acc, new_w_acc, proof) = NIFSProver::<RqNTT, DP, T>::prove(
            &acc,
            &w_acc,
            &cm_i,
            &wit_i,
            &mut prover_transcript,
            &ccs,
            &scheme,
        )
        .expect("folding prover failed");

        let verified_acc = NIFSVerifier::<RqNTT, DP, T>::verify(
            &acc,
            &cm_i,
            &proof,
            &mut verifier_transcript,
            &ccs,
        )
        .expect("folding verifier failed");

        assert_eq!(
            new_acc, verified_acc,
            "accumulator mismatch at dealer {dealer}"
        );

        acc = new_acc;
        w_acc = new_w_acc;
        println!(
            "  dealer {:>2}/{DEALERS} sharing folded & verified",
            dealer + 1
        );
        last_proof = Some(proof);
    }

    let elapsed = start.elapsed();
    println!("\nAll {DEALERS} R2 sharings folded & verified in {elapsed:?}");
    println!("Average per dealer: {:?}", elapsed / DEALERS as u32);

    if let Some(proof) = last_proof {
        let mut buf = Vec::new();
        proof.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        println!(
            "Per-sharing fold proof size (compressed): {}",
            humansize::format_size(buf.len(), humansize::BINARY)
        );
    }

    println!("\nResult: batched RS validity proved as {PARITY} ring-level constraints (not {} field checks), shares carried as bound digits.", PARITY * <cyclotomic_rings::rings::GoldilocksRingPoly as stark_rings::PolyRing>::dimension());
}
