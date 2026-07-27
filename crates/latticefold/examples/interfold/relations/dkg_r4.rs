//! Slice 1 of the lattice-based VDKG design: relation **R4** (share receipt and
//! aggregation), for one recipient over one RNS channel.
//!
//! R4 has two parts, and the point of this example is that they live in two
//! different cost classes — exactly the "free vs. proof-required" split of §4.2:
//!
//!   (a) FREE linear link — aggregation. The recipient's aggregated share is
//!       `agg = Σ_a V_{a→i}` over the sending set. By Ajtai homomorphism,
//!       `Com(agg) = Σ_a Com(V_{a→i})` holds unconditionally as ring algebra, so
//!       anyone verifies the aggregation from the published commitments with NO
//!       circuit. This example checks that equality directly on `Commitment`s.
//!
//!   (b) PROOF-required link — openings. What still needs a proof is knowledge
//!       of a short-digit opening `V_{a→i}` matching each sender's commitment.
//!       That is LatticeFold's foundational commitment-opening relation,
//!       unmodified — here each received share is a committed CCS instance and
//!       all of them are folded into one accumulator.
//!
//! Shares are full-range (a Shamir share is ~uniform mod q_l), so — per §6/§9.1
//! — each is carried as its base-`b` digit decomposition; `Witness::from_w_ccs`
//! performs exactly that radix-B gadget decomposition before committing, and the
//! norm proof binds the digits.
//!
//! Goldilocks stands in for a real RNS prime q_l (custom-`Ring` work deferred).
//!
//! Run with:
//!   cargo run --release --example dkg_r4

use std::time::Instant;

use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::UniformRand;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::{AjtaiCommitmentScheme, Commitment},
    decomposition_parameters::DecompositionParams,
    nifs::{
        linearization::{LFLinearizationProver, LinearizationProver},
        NIFSProver, NIFSVerifier,
    },
    transcript::poseidon::PoseidonTranscript,
};
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

/// One received share `V_{a→i}` is carried as a single ring element (its digit
/// decomposition is performed inside `Witness::from_w_ccs`).
const WIT_LEN: usize = 1;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

/// Number of honest senders whose shares this recipient aggregates (H of N=100).
const SENDERS: usize = 51; // H

// z layout = [one, V]. The opening relation puts no constraint on the witness
// beyond the commitment binding + native norm bound, so the CCS is the trivial
// satisfiable relation `0 = 0`.
const N_COLS: usize = 2;

/// Trivial R1CS `0*... = 0`: knowledge of a short opening `V` to the commitment
/// is what the fold proves; there is no algebraic constraint to add (R4 is an
/// unmodified commitment-opening relation).
#[allow(non_snake_case)]
fn opening_r1cs() -> R1CS<RqNTT> {
    let empty = || SparseMatrix {
        nrows: 1,
        ncols: N_COLS,
        coeffs: vec![vec![]],
    };
    // A z = 0, B z = 0, C z = 0  ->  0 ∘ 0 = 0 holds for any witness.
    R1CS::<RqNTT> {
        l: 0,
        A: empty(),
        B: empty(),
        C: empty(),
    }
}

/// A received share as a committed CCS instance. Returns the instance, its
/// witness, the raw share ring element, and its commitment.
fn received_share(
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>, RqNTT, Commitment<RqNTT>) {
    // A Shamir share is ~uniform mod q_l -> sample a full-range ring element.
    let v = RqNTT::rand(rng);

    let z = vec![RqNTT::from(1u128), v];
    ccs.check_relation(&z)
        .expect("trivial opening relation failed");

    let wit = Witness::from_w_ccs::<DP>(vec![v]);
    let cm = wit.commit::<DP>(scheme).unwrap();
    let cccs = CCCS {
        cm: cm.clone(),
        x_ccs: vec![],
    };
    (cccs, wit, v, cm)
}

fn main() {
    println!("LatticeFold VDKG — R4 receipt & aggregation for one recipient");
    println!("Aggregating {SENDERS} received shares over one channel (Goldilocks stand-in)");
    println!("KAPPA={KAPPA} WIT_LEN={WIT_LEN} N={N}");

    let mut rng = ark_std::test_rng();
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(opening_r1cs(), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // Generate all received shares (instance, witness, raw value, commitment).
    let shares: Vec<_> = (0..SENDERS)
        .map(|_| received_share(&ccs, &scheme, &mut rng))
        .collect();

    // ---- (a) FREE linear link: verify aggregation via Ajtai homomorphism ----
    // KEY SUBTLETY (design §6/§9.1): the Ajtai commitment is over the radix-B
    // *digit decomposition* `f`, and digit decomposition is NON-linear (carries).
    // So the homomorphism lives on the committed digits, not on a re-decomposition
    // of the recomposed value: Σ Com(f_a) = Com(Σ f_a), and the linear recompose
    // sends Σ f_a back to the aggregated share Σ V_a. (Σ f_a is generally no longer
    // a *canonical* short decomposition — which is exactly why aggregation shifts
    // cost downstream, per the design's R4/R6 note.)
    let n = shares[0].1.f.len();
    let f_sum: Vec<RqNTT> = (0..n)
        .map(|j| {
            shares
                .iter()
                .fold(RqNTT::from(0u128), |acc, s| acc + s.1.f[j])
        })
        .collect();
    let com_of_digit_sum = scheme.commit_ntt(&f_sum).unwrap();

    // ...vs. summing the published commitments with no circuit at all.
    let sum_of_coms: Commitment<RqNTT> = shares
        .iter()
        .skip(1)
        .fold(shares[0].3.clone(), |acc, s| acc + &s.3);

    assert_eq!(
        com_of_digit_sum, sum_of_coms,
        "Ajtai homomorphism broken: Com(Σ f) != Σ Com(f)"
    );
    // recompose is linear, so recompose(Σ f) = Σ recompose(f_a) = Σ V_a — the
    // aggregated share — with no further commitment work.
    println!("\n(a) FREE aggregation check: Σ Com(f) == Com(Σ f)  ✓  (no circuit)");

    // ---- (b) PROOF-required link: fold the opening proofs ------------------
    let (cm_0, wit_0, _, _) = &shares[0];
    let mut w_acc = wit_0.clone();
    let mut bootstrap = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) = LFLinearizationProver::<_, T>::prove(cm_0, &w_acc, &mut bootstrap, &ccs)
        .expect("failed to bootstrap accumulator");

    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();

    println!("\n(b) Folding {SENDERS} share-opening proofs...");
    let start = Instant::now();
    let mut last_proof = None;

    // Share 0 is already represented by the bootstrap accumulator.
    for (idx, (cm_i, wit_i, _, _)) in shares.iter().enumerate().skip(1) {
        let (new_acc, new_w_acc, proof) = NIFSProver::<RqNTT, DP, T>::prove(
            &acc,
            &w_acc,
            cm_i,
            wit_i,
            &mut prover_transcript,
            &ccs,
            &scheme,
        )
        .expect("folding prover failed");

        let verified_acc = NIFSVerifier::<RqNTT, DP, T>::verify(
            &acc,
            cm_i,
            &proof,
            &mut verifier_transcript,
            &ccs,
        )
        .expect("folding verifier failed");

        assert_eq!(new_acc, verified_acc, "accumulator mismatch at share {idx}");

        acc = new_acc;
        w_acc = new_w_acc;
        println!("  share {:>2}/{SENDERS} opening folded & verified", idx + 1);
        last_proof = Some(proof);
    }

    let elapsed = start.elapsed();
    println!("\nAll {SENDERS} openings folded & verified in {elapsed:?}");
    println!("Average per share: {:?}", elapsed / SENDERS as u32);

    if let Some(proof) = last_proof {
        let mut buf = Vec::new();
        proof.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        println!(
            "Per-opening fold proof size (compressed): {}",
            humansize::format_size(buf.len(), humansize::BINARY)
        );
    }

    println!(
        "\nResult: aggregation verified for free from commitments; the only proof \
         needed was knowledge of each short opening (folded into one LCCCS)."
    );
}
