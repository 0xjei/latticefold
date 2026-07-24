//! Slice 4: relation **R5** (threshold public-key aggregation).
//!
//! `pk0_agg = Σ_i pk0_i`, `pk1_agg = a` — a computation over exclusively PUBLIC
//! values, needing no hiding. Per the design, the sum itself is verifiable by
//! anyone from the published commitments via Ajtai homomorphism (FREE), and it
//! is nonetheless wrapped in a thin decided proof so a client can retrieve the
//! aggregated key + a compact validity proof in one step without redoing the
//! L×|A| summation.
//!
//! This example shows (a) homomorphism on the *digit vectors* and (b) a single
//! folded opening proof for a separately recomputed public aggregate. Because
//! radix decomposition has carries, the former is not automatically a proof
//! that the latter's canonical digit decomposition is the aggregate. A carry
//! relation is still required to link those two representations.
//!
//! Goldilocks stands in for a real RNS prime q_l.
//!
//! Run with: cargo run --release --example dkg_r5

use ark_std::UniformRand;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{r1cs::R1CS, Witness, CCCS, CCS},
    commitment::{AjtaiCommitmentScheme, Commitment},
    decomposition_parameters::DecompositionParams,
    nifs::linearization::{
        LFLinearizationProver, LFLinearizationVerifier, LinearizationProver, LinearizationVerifier,
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

const WIT_LEN: usize = 1;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;
const PARTIES: usize = 51; // H honest of N=100 (T=27 threshold)
const N_COLS: usize = 2;

/// Trivial opening relation (the aggregation itself is public; the proof only
/// certifies a valid opening for compact client retrieval).
#[allow(non_snake_case)]
fn opening_r1cs() -> R1CS<RqNTT> {
    let empty = || SparseMatrix {
        nrows: 1,
        ncols: N_COLS,
        coeffs: vec![vec![]],
    };
    R1CS::<RqNTT> {
        l: 0,
        A: empty(),
        B: empty(),
        C: empty(),
    }
}

fn main() {
    println!("LatticeFold VDKG — R5 threshold public-key aggregation");
    println!("pk0_agg = Σ pk0_i (public), pk1_agg = a | {PARTIES} parties, Goldilocks stand-in");

    let mut rng = ark_std::test_rng();
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(opening_r1cs(), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // Each party's PUBLIC pk0_i, committed.
    let parties: Vec<(RqNTT, Witness<RqNTT>, Commitment<RqNTT>)> = (0..PARTIES)
        .map(|_| {
            let pk0 = RqNTT::rand(&mut rng);
            let wit = Witness::from_w_ccs::<DP>(vec![pk0]);
            let cm = wit.commit::<DP>(&scheme).unwrap();
            (pk0, wit, cm)
        })
        .collect();

    // (a) FREE: Σ Com(f_i) == Com(Σ f_i) on the committed digit witnesses.
    let n = parties[0].1.f.len();
    let f_sum: Vec<RqNTT> = (0..n)
        .map(|j| {
            parties
                .iter()
                .fold(RqNTT::from(0u128), |acc, p| acc + p.1.f[j])
        })
        .collect();
    let com_of_digit_sum = scheme.commit_ntt(&f_sum).unwrap();
    let sum_of_coms: Commitment<RqNTT> = parties
        .iter()
        .skip(1)
        .fold(parties[0].2.clone(), |acc, p| acc + &p.2);
    assert_eq!(
        com_of_digit_sum, sum_of_coms,
        "pk aggregation homomorphism broken"
    );

    let pk0_agg: RqNTT = parties.iter().fold(RqNTT::from(0u128), |acc, p| acc + p.0);
    let canonical_agg = Witness::from_w_ccs::<DP>(vec![pk0_agg]);
    let canonical_agg_cm = canonical_agg.commit::<DP>(&scheme).unwrap();
    println!("\n(a) FREE: Σ Com(digits(pk0_i)) == Com(Σ digits(pk0_i))  ✓  (no circuit)");
    println!("    canonical Com(Σ pk0_i) is {} to this digit-sum commitment; carries need a separate proof.",
        if canonical_agg_cm == sum_of_coms { "equal" } else { "not equal" });
    println!("    pk1_agg = a (the shared CRS element), no computation needed");

    // (b) Thin decided proof: one opening the client can fetch alongside pk_agg.
    let agg_wit = Witness::from_w_ccs::<DP>(vec![pk0_agg]);
    let agg_cm = CCCS {
        cm: agg_wit.commit::<DP>(&scheme).unwrap(),
        x_ccs: vec![],
    };
    let mut transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let (_lcccs, proof) =
        LFLinearizationProver::<_, T>::prove(&agg_cm, &agg_wit, &mut transcript, &ccs)
            .expect("decided proof for pk_agg failed");
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    LFLinearizationVerifier::<_, T>::verify(&agg_cm, &proof, &mut verifier_transcript, &ccs)
        .expect("decided proof for pk_agg did not verify");
    println!("(b) Thin decided proof over the public pk0_agg opening produced ✓");

    println!("\nResult: aggregation is public/free; the on-chain artifact is a compact");
    println!("(double) commitment to pk_agg plus this decided proof — the full polynomial");
    println!("is served over broadcast and checked locally by recomputing its commitment.");
    println!("A production implementation must also prove the digit-carry link when it");
    println!("derives pk_agg from per-party committed digit decompositions.");
}
