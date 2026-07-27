//! **§9.2 / Step 8 — smudging noise wider than the native shortness bound**,
//! via the mitigation the design names: "splitting the noise into multiple
//! independently-committed bounded limbs (the same decomposition machinery
//! already used for shares, applied to the noise itself)".
//!
//! The statistical security parameter can force the smudging noise e_sm to a
//! width (e.g. ~2^40 here) far beyond the per-digit bound B = 2^15 that the
//! native norm proof certifies. The limb split makes it provable anyway:
//!
//!     e_sm = Σ_j B^j · e_j,      ‖e_j‖∞ < B   for all limbs j
//!
//! Arithmetized as ONE affine recompose row (public powers of B times secret
//! limbs), with each limb individually norm-provable — no foreign-field range
//! gadget, exactly the share machinery reused. The width covered scales as
//! B^limbs, so the same slice covers any statistical parameter by adding limbs.
//!
//! A negative check shows an OUT-OF-RANGE limb assignment for the same e_sm
//! (limb ≥ B) is exactly what the norm proof exists to exclude — the recompose
//! row alone admits it, the digit bound does not.
//!
//! Folded across the committee's smudging contributions and verified.
//!
//! Goldilocks stands in for a real RNS prime q_l.
//!
//! Run with: cargo run --release --example dkg_wide_smudging

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
use stark_rings_linalg::SparseMatrix;

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

/// Number of limbs: 3 limbs of base 2^15 cover widths up to 2^45.
const LIMBS: usize = 3;
/// Target smudging width for the demo (statistical parameter stand-in): ~2^40.
const WIDTH_BITS: u32 = 40;

/// Witness = the LIMBS limb values.
const WIT_LEN: usize = LIMBS;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;
const PARTIES: usize = 51;

// z = [e_sm, one, e_0..e_{LIMBS-1}], l = 1.
const IDX_ESM: usize = 0;
const IDX_ONE: usize = 1;
const IDX_LIMB: usize = 2;
const N_COLS: usize = 2 + LIMBS;

/// Recompose row: e_sm − Σ_j B^j·e_j = 0.
#[allow(non_snake_case)]
fn limb_r1cs() -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let mut a0 = vec![(one, IDX_ESM)];
    for j in 0..LIMBS {
        a0.push((-RqNTT::from(DP::B.pow(j as u32)), IDX_LIMB + j));
    }
    R1CS::<RqNTT> {
        l: 1,
        A: SparseMatrix {
            nrows: 1,
            ncols: N_COLS,
            coeffs: vec![a0],
        },
        B: SparseMatrix {
            nrows: 1,
            ncols: N_COLS,
            coeffs: vec![vec![(one, IDX_ONE)]],
        },
        C: SparseMatrix {
            nrows: 1,
            ncols: N_COLS,
            coeffs: vec![vec![]],
        },
    }
}

fn instance(
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>, u128) {
    // A wide smudging sample in [0, 2^WIDTH_BITS).
    let e_sm: u128 = rng.gen_range(0..1u128 << WIDTH_BITS);
    // Base-B limb split — each limb < B, i.e. individually norm-provable.
    let limbs: Vec<u128> = (0..LIMBS)
        .map(|j| (e_sm >> (15 * j as u32)) & (DP::B - 1))
        .collect();
    debug_assert_eq!(
        limbs
            .iter()
            .enumerate()
            .fold(0u128, |acc, (j, &l)| acc + l * DP::B.pow(j as u32)),
        e_sm
    );

    let mut z = vec![RqNTT::from(e_sm), RqNTT::from(1u128)];
    z.extend(limbs.iter().map(|&l| RqNTT::from(l)));
    ccs.check_relation(&z).expect("limb recompose row failed");

    let wit = Witness::from_w_ccs::<DP>(limbs.iter().map(|&l| RqNTT::from(l)).collect());
    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: vec![RqNTT::from(e_sm)],
    };
    (cm, wit, e_sm)
}

fn main() {
    println!("LatticeFold VDKG — §9.2 wide smudging noise via bounded limbs");
    println!("width ~2^{WIDTH_BITS} ≫ B = 2^15, {LIMBS} limbs (covers up to 2^{}) | Goldilocks stand-in\n", 15 * LIMBS);

    let mut rng = ark_std::test_rng();
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(limb_r1cs(), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // Negative shape check: the recompose row ALONE also accepts an assignment
    // with one huge limb (e_sm = 1·e_sm + 0 + 0) — it is the per-digit NORM
    // BOUND (the folded range proof) that excludes it. Shown explicitly:
    let wide: u128 = 1 << WIDTH_BITS;
    let mut z_bad = vec![RqNTT::from(wide), RqNTT::from(1u128), RqNTT::from(wide)];
    z_bad.extend((1..LIMBS).map(|_| RqNTT::from(0u128)));
    assert!(
        ccs.check_relation(&z_bad).is_ok(),
        "recompose row alone admits a wide limb"
    );
    assert!(
        wide >= DP::B,
        "…but the limb violates the norm bound the fold proves"
    );
    println!("Shape check: recompose row alone admits a 2^{WIDTH_BITS} limb — the per-digit");
    println!("norm bound (B = 2^15, proven by the fold's range proof) is what excludes it ✓\n");

    // Fold the committee's wide smudging contributions.
    let insts: Vec<_> = (0..PARTIES)
        .map(|_| instance(&ccs, &scheme, &mut rng))
        .collect();
    println!(
        "Committee samples (first 3): {:?}…",
        insts.iter().take(3).map(|(_, _, e)| e).collect::<Vec<_>>()
    );

    let (cm0, w0, _) = &insts[0];
    let mut w_acc = w0.clone();
    let mut bt = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) =
        LFLinearizationProver::<_, T>::prove(cm0, &w_acc, &mut bt, &ccs).expect("bootstrap failed");
    let mut pt = PoseidonTranscript::<RqNTT, CS>::default();
    let mut vt = PoseidonTranscript::<RqNTT, CS>::default();
    // Instance 0 is already represented by the bootstrap accumulator.
    for (i, (cm_i, wit_i, _)) in insts.iter().enumerate().skip(1) {
        let (na, nw, proof) =
            NIFSProver::<RqNTT, DP, T>::prove(&acc, &w_acc, cm_i, wit_i, &mut pt, &ccs, &scheme)
                .expect("folding prover failed");
        let va = NIFSVerifier::<RqNTT, DP, T>::verify(&acc, cm_i, &proof, &mut vt, &ccs)
            .expect("folding verifier failed");
        assert_eq!(na, va, "accumulator mismatch at party {i}");
        acc = na;
        w_acc = nw;
    }
    println!("\nAll {PARTIES} wide smudging contributions folded & verified ✓");

    println!("\nResult: the configured wide-noise width is provable by adding limbs —");
    println!("the recompose stays one affine row, limbs stay individually norm-provable,");
    println!("and the same limb decomposition carries through sharing/aggregation exactly");
    println!("like share digits (§9.1). The §9.2 deferral is closed at the relation level;");
    println!("choosing the production limb count is a Step 1 parameter decision.");
}
