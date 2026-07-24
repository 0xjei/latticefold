//! Slice 0 of the lattice-based VDKG design: relation **R1** (threshold-key /
//! smudging-noise contribution), folded across parties within one RNS channel.
//!
//! R1 constraint, per party `i`, over the ring `R_q` (native identity, no
//! quotient witnesses):
//!
//!     pk0_i = -a * sk_i + e_i   (mod q, mod X^N + 1)
//!
//! where `a` is a public CRS ring element and `sk_i, e_i, e_sm_i` are *short*
//! secret witnesses. The relation is affine in the witness: `a` is public, so `a*sk_i`
//! is a public-ring-element times a secret — it lives as a ring coefficient in
//! the constraint matrix, giving native `R_q` multiplication with no
//! decomposition or range-check machinery for the modular reduction itself.
//! Shortness of `sk_i, e_i, e_sm_i` is enforced by LatticeFold's native norm proof.
//!
//! This exercises two of the design's load-bearing claims against real code:
//!   1. an affine native-`R_q` relation with an Ajtai-committed short witness,
//!   2. folding many parties' same-shaped R1 instances into one accumulator
//!      (the "across parties, within a channel" aggregation axis).
//!
//! It uses the Goldilocks ring as a STAND-IN for a real RNS prime q_l, so the
//! custom-`Ring`-per-q_l work is deferred: swapping the ring later is a type
//! substitution, not a redesign.
//!
//! Run with:
//!   cargo run --release --example dkg_r1

use std::time::Instant;

use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::UniformRand;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT, GoldilocksRingPoly};
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
use stark_rings::cyclotomic_ring::{models::goldilocks::Fq, CRT};
use stark_rings_linalg::SparseMatrix;

// ---- Concrete instantiation ------------------------------------------------

type RqNTT = GoldilocksRingNTT;
type RqPoly = GoldilocksRingPoly;
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

/// R1 witness is (sk_i, e_i, e_sm_i): three ring elements. `e_sm_i` is not
/// used by the public-key equation, but proving it here binds its shortness
/// before it is shared and consumed by R6.
const WIT_LEN: usize = 3;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

/// DKG committee: N=100 parties, H=51 honest (authorized set A), T=27 threshold.
/// R1 folds the honest parties' contributions.
const PARTIES: usize = 51; // H

// z layout = [statement, one, witness] = [pk0, 1, sk, e, e_sm]
const IDX_PK0: usize = 0;
const IDX_ONE: usize = 1;
const IDX_SK: usize = 2;
const IDX_E: usize = 3;
const N_COLS: usize = 5;

/// Build the single-row R1CS enforcing `e - a*sk - pk0 = 0` as `A z ∘ B z = C z`
/// with `A z = L(z)`, `B z = 1`, `C z = 0`. The public CRS element `a` is baked
/// in as a ring-valued matrix coefficient.
#[allow(non_snake_case)]
fn r1_r1cs(a: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let neg_one = -one;
    let neg_a = -*a;

    // A: L(z) = 1*e + (-a)*sk + (-1)*pk0
    let A = SparseMatrix {
        nrows: 1,
        ncols: N_COLS,
        coeffs: vec![vec![(neg_a, IDX_SK), (one, IDX_E), (neg_one, IDX_PK0)]],
    };
    // B: selects the constant `1`.
    let B = SparseMatrix {
        nrows: 1,
        ncols: N_COLS,
        coeffs: vec![vec![(one, IDX_ONE)]],
    };
    // C: zero.
    let C = SparseMatrix {
        nrows: 1,
        ncols: N_COLS,
        coeffs: vec![vec![]],
    };

    R1CS::<RqNTT> { l: 1, A, B, C }
}

/// Sample a short ring element: coefficients in {-1, 0, 1} (ternary secret),
/// built in the coefficient representation then mapped to the NTT form.
fn short_element(rng: &mut impl ark_std::rand::Rng) -> RqNTT {
    let dim = <RqPoly as stark_rings::PolyRing>::dimension();
    let coeffs: Vec<Fq> = (0..dim)
        .map(|_| match rng.gen_range(0..3) {
            0 => Fq::from(0u64),
            1 => Fq::from(1u64),
            _ => -Fq::from(1u64),
        })
        .collect();
    let poly = RqPoly::from(coeffs);
    CRT::elementwise_crt(vec![poly])[0]
}

/// One party's R1 instance: sample short (sk, e), compute the public pk0.
fn party_instance(
    a: &RqNTT,
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    let sk = short_element(rng);
    let e = short_element(rng);
    let e_sm = short_element(rng);
    // Native R_q identity: pk0 = -a*sk + e.
    let pk0 = e - *a * sk;

    // Sanity check against the CCS with z = [pk0, 1, sk, e, e_sm].
    let z = vec![pk0, RqNTT::from(1u128), sk, e, e_sm];
    ccs.check_relation(&z)
        .expect("R1 assignment does not satisfy pk0 = -a*sk + e");

    let wit = Witness::from_w_ccs::<DP>(vec![sk, e, e_sm]);
    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: vec![pk0],
    };
    (cm, wit)
}

fn main() {
    println!("LatticeFold VDKG — R1 contribution, folded across {PARTIES} parties");
    println!("Relation: pk0_i = -a*sk_i + e_i  (native R_q, Goldilocks stand-in for q_l)");
    println!("KAPPA={KAPPA} WIT_LEN={WIT_LEN} N={N}");

    let mut rng = ark_std::test_rng();

    // Public CRS element `a`, shared by all parties, baked into the fixed CCS.
    let a = RqNTT::rand(&mut rng);
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r1_r1cs(&a), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // Bootstrap the accumulator by linearizing party 0's contribution.
    let (cm_0, wit_0) = party_instance(&a, &ccs, &scheme, &mut rng);
    let mut w_acc = wit_0;
    let mut bootstrap = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) = LFLinearizationProver::<_, T>::prove(&cm_0, &w_acc, &mut bootstrap, &ccs)
        .expect("failed to bootstrap accumulator");

    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();

    println!("\nFolding {PARTIES} party contributions...");
    let start = Instant::now();
    let mut last_proof = None;

    // Party 0 is already represented by the bootstrap accumulator. Fold only
    // the remaining instances so the final accumulator represents exactly
    // PARTIES contributions.
    for party in 1..PARTIES {
        let (cm_i, wit_i) = party_instance(&a, &ccs, &scheme, &mut rng);

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
            "prover/verifier accumulator mismatch at party {party}"
        );

        acc = new_acc;
        w_acc = new_w_acc;
        println!(
            "  party {:>2}/{PARTIES} R1 contribution folded & verified",
            party + 1
        );
        last_proof = Some(proof);
    }

    let elapsed = start.elapsed();
    println!("\nAll {PARTIES} R1 contributions folded & verified in {elapsed:?}");
    println!("Average per party: {:?}", elapsed / PARTIES as u32);

    if let Some(proof) = last_proof {
        let mut buf = Vec::new();
        proof.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        println!(
            "Per-contribution fold proof size (compressed): {}",
            humansize::format_size(buf.len(), humansize::BINARY)
        );
    }

    println!(
        "\nFinal accumulator = one folded LCCCS attesting all {PARTIES} parties' R1 contributions."
    );
}
