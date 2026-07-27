//! Sequential IVC-style folding of 1024 Ajtai-committed steps over a *real*
//! arithmetic step circuit.
//!
//! The step relation is the canonical cubic constraint
//!
//!     y = x^3 + x + 5
//!
//! (the same R1CS used in Vitalik's QAP write-up), expressed here as the
//! rank-1 constraint system returned by `get_test_r1cs` and converted to a
//! folding-ready CCS with `CCS::from_r1cs_padded`. Every step:
//!
//!   1. picks a real input `x`, computes the satisfying assignment
//!      `z = (x, 1, y, x^2, x^3, x^3 + x)` and checks `ccs.check_relation(z)`,
//!   2. commits the step witness with the Ajtai commitment scheme,
//!   3. folds the resulting committed instance into the running accumulator via
//!      `NIFSProver`, and verifies that fold step with `NIFSVerifier`.
//!
//! A single Fiat-Shamir transcript is threaded through the whole chain, exactly
//! as an IVC prover/verifier would. This is the native LatticeFold verification
//! path (there is no on-chain decider in this codebase).
//!
//! Run with:
//!   cargo run --release --example fold_1024

use std::time::Instant;

use ark_serialize::{CanonicalSerialize, Compress};
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{
        r1cs::{get_test_z_split, to_F_matrix, R1CS},
        Arith, Witness, CCCS, CCS,
    },
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::{
        linearization::{LFLinearizationProver, LinearizationProver},
        NIFSProver, NIFSVerifier,
    },
    transcript::poseidon::PoseidonTranscript,
};

// ---- Concrete instantiation ------------------------------------------------

type RqNTT = GoldilocksRingNTT;
type CS = GoldilocksChallengeSet;
type T = PoseidonTranscript<RqNTT, CS>;

/// Decomposition parameters (Goldilocks defaults from examples/README.md).
#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    const K: usize = 15;
}

/// The cubic R1CS `y = x^3 + x + 5` has: 1 public input (x), the constant, and
/// 4 witness wires => wit_len = 4. The Ajtai matrix commits `wit_len * L` ring
/// elements.
const WIT_LEN: usize = 4;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

/// Number of sequential folding steps.
const STEPS: usize = 1024;

/// The real R1CS for `y = x^3 + x + 5` (Vitalik's QAP example), matching the
/// `z = (io, 1, w)` assignment produced by `get_test_z_split`.
#[allow(non_snake_case)]
fn cubic_r1cs() -> R1CS<RqNTT> {
    let A = to_F_matrix::<RqNTT>(vec![
        vec![1, 0, 0, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 0],
        vec![1, 0, 0, 0, 1, 0],
        vec![0, 5, 0, 0, 0, 1],
    ]);
    let B = to_F_matrix::<RqNTT>(vec![
        vec![1, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0],
        vec![0, 1, 0, 0, 0, 0],
        vec![0, 1, 0, 0, 0, 0],
    ]);
    let C = to_F_matrix::<RqNTT>(vec![
        vec![0, 0, 0, 1, 0, 0],
        vec![0, 0, 0, 0, 1, 0],
        vec![0, 0, 0, 0, 0, 1],
        vec![0, 0, 1, 0, 0, 0],
    ]);
    R1CS::<RqNTT> { l: 1, A, B, C }
}

/// Build the committed CCCS instance + witness for one step with input `x`.
fn step_instance(
    x: usize,
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    // z = (one, x_ccs, w_ccs) for the relation y = x^3 + x + 5.
    let (one, x_ccs, w_ccs) = get_test_z_split::<RqNTT>(x);

    // Sanity: the assignment really satisfies the constraint system.
    // LatticeFold reconstructs z as [statement, one, witness] (see
    // `Arith::get_z_vector`), matching the (io, 1, w) layout of get_test_z.
    let mut z = x_ccs.clone();
    z.push(one);
    z.extend(w_ccs.clone());
    ccs.check_relation(&z)
        .expect("step assignment does not satisfy y = x^3 + x + 5");

    let wit = Witness::from_w_ccs::<DP>(w_ccs);
    let cm_i = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs,
    };
    (cm_i, wit)
}

fn main() {
    println!("LatticeFold sequential folding — {STEPS} steps of y = x^3 + x + 5");
    println!("Ring: Goldilocks | KAPPA={KAPPA} WIT_LEN={WIT_LEN} N={N}");
    println!(
        "Decomposition: B={} L={} B_SMALL={} K={}",
        DP::B,
        DP::L,
        DP::B_SMALL,
        DP::K
    );

    // Fixed real step circuit (cubic R1CS -> folding-ready CCS) and Ajtai scheme.
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(cubic_r1cs(), N, DP::L);
    let mut rng = ark_std::test_rng();
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // A small varying input per step keeps the cubic arithmetic bounded while
    // producing genuinely distinct real instances.
    let input_at = |step: usize| (step % 250) + 1;

    // Bootstrap the accumulator by linearizing the first committed instance.
    let (cm_0, wit_0) = step_instance(input_at(0), &ccs, &scheme);
    let mut w_acc = wit_0;
    let mut bootstrap_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) =
        LFLinearizationProver::<_, T>::prove(&cm_0, &w_acc, &mut bootstrap_transcript, &ccs)
            .expect("failed to bootstrap accumulator");

    // One transcript per party, threaded through the entire IVC chain.
    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();

    println!("\nFolding {STEPS} steps...");
    let start = Instant::now();
    let mut last_proof = None;

    // Step 0 is already represented by the bootstrap accumulator.
    for step in 1..STEPS {
        let (cm_i, wit_i) = step_instance(input_at(step), &ccs, &scheme);

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
            "prover/verifier accumulator mismatch at step {step}"
        );

        acc = new_acc;
        w_acc = new_w_acc;

        if (step + 1) % 128 == 0 {
            println!("  step {:>4}/{STEPS} folded & verified", step + 1);
        }
        last_proof = Some(proof);
    }

    let elapsed = start.elapsed();
    println!("\nAll {STEPS} steps folded and verified in {elapsed:?}");
    println!("Average per step: {:?}", elapsed / STEPS as u32);

    if let Some(proof) = last_proof {
        let mut buf = Vec::new();
        proof.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        println!(
            "Per-step fold proof size (compressed): {}",
            humansize::format_size(buf.len(), humansize::BINARY)
        );
    }

    println!("\nFinal accumulator is the single folded LCCCS attesting all {STEPS} steps.");
}
