//! **Cheater isolation in the folding pipeline** (§2.3 / §4.1 / §7): the design
//! follows Urban–Rambaud — every party's contribution carries a proof, and any
//! party whose proof fails verification is DISCARDED from the authorized set —
//! while preserving the property that the all-honest common case pays no
//! search cost.
//!
//! Demonstrated on R1 with the honest set of 51 (of N=100) where party #25 CHEATS: it publishes
//! a pk0 that does not match any short (sk, e) it knows (its instance does not
//! satisfy the CCS). The aggregator folds contributions sequentially:
//!
//!   * honest parties: fold proof verifies, accumulator advances;
//!   * the cheater: its fold step FAILS (prover error or verifier rejection —
//!     both are handled); crucially the accumulator is only advanced on
//!     success, so a failed step leaves the accumulated state UNTOUCHED;
//!   * the cheater's index is identified exactly (no tree search — each fold
//!     step names its instance), the party is discarded, folding continues;
//!   * final result: one accumulator attesting exactly the 50 honest parties,
//!     plus the identified cheater set {25}.
//!
//! This is the sequential-arity version of the design's fold tree: with the
//! public NIFS API (acc + 1 per step), isolation is per-step and O(1); the
//! L-ary tree of §7 generalizes the same discard logic to batched arities.
//!
//! Run with: cargo run --release --example dkg_cheater_isolation

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

const WIT_LEN: usize = 2;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;
const PARTIES: usize = 51;
const CHEATER: usize = 25;

#[allow(non_snake_case)]
fn r1_r1cs(a: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    R1CS::<RqNTT> {
        l: 1,
        A: SparseMatrix {
            nrows: 1,
            ncols: 4,
            coeffs: vec![vec![(-*a, 2), (one, 3), (-one, 0)]],
        },
        B: SparseMatrix {
            nrows: 1,
            ncols: 4,
            coeffs: vec![vec![(one, 1)]],
        },
        C: SparseMatrix {
            nrows: 1,
            ncols: 4,
            coeffs: vec![vec![]],
        },
    }
}

/// A party's contribution. Honest: pk0 = -a·sk + e. Cheater: a pk0 it has no
/// witness for (e.g. copied/garbled) — the instance does NOT satisfy the CCS.
fn contribution(
    a: &RqNTT,
    honest: bool,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    let sk = RqNTT::from(rng.gen_range(0..3u128));
    let e = RqNTT::from(rng.gen_range(0..3u128));
    let pk0 = if honest {
        e - *a * sk
    } else {
        RqNTT::rand(rng)
    };
    let wit = Witness::from_w_ccs::<DP>(vec![sk, e]);
    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: vec![pk0],
    };
    (cm, wit)
}

fn main() {
    println!("LatticeFold VDKG — cheater isolation in the R1 fold ({PARTIES} parties, #{CHEATER} cheats)\n");

    let mut rng = ark_std::test_rng();
    let a = RqNTT::rand(&mut rng);
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r1_r1cs(&a), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let parties: Vec<_> = (0..PARTIES)
        .map(|i| contribution(&a, i != CHEATER, &scheme, &mut rng))
        .collect();
    // Sanity: the cheater's instance really is unsatisfiable.
    {
        let (cm, wit) = &parties[CHEATER];
        let mut z = vec![cm.x_ccs[0], RqNTT::from(1u128)];
        z.extend(wit.w_ccs.iter().copied());
        assert!(
            ccs.check_relation(&z).is_err(),
            "cheater must be unsatisfiable"
        );
    }

    // Bootstrap from party 0 (honest).
    let (cm0, w0) = &parties[0];
    let mut w_acc = w0.clone();
    let mut bt = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) =
        LFLinearizationProver::<_, T>::prove(cm0, &w_acc, &mut bt, &ccs).expect("bootstrap failed");

    let mut pt = PoseidonTranscript::<RqNTT, CS>::default();
    let mut vt = PoseidonTranscript::<RqNTT, CS>::default();
    let mut folded = 0usize;
    let mut discarded: Vec<usize> = Vec::new();

    // Party 0 is already represented by the bootstrap accumulator.
    for (i, (cm_i, wit_i)) in parties.iter().enumerate().skip(1) {
        // Transcript forks so a failed step cannot desynchronize the survivors.
        let mut pt_try = pt.clone();
        let mut vt_try = vt.clone();
        let step = NIFSProver::<RqNTT, DP, T>::prove(
            &acc,
            &w_acc,
            cm_i,
            wit_i,
            &mut pt_try,
            &ccs,
            &scheme,
        );
        let ok = match step {
            Err(_) => false, // prover cannot even produce a proof for the junk instance
            Ok((na, nw, proof)) => {
                match NIFSVerifier::<RqNTT, DP, T>::verify(&acc, cm_i, &proof, &mut vt_try, &ccs) {
                    Err(_) => false, // proof produced but rejected
                    Ok(va) => {
                        assert_eq!(na, va, "accumulator mismatch at party {i}");
                        acc = na;
                        w_acc = nw;
                        pt = pt_try;
                        vt = vt_try;
                        true
                    }
                }
            }
        };
        if ok {
            folded += 1;
            println!("  party {i}: fold verified ✓");
        } else {
            discarded.push(i);
            println!("  party {i}: fold FAILED ✗  → identified, discarded (accumulator untouched)");
        }
    }

    assert_eq!(
        discarded,
        vec![CHEATER],
        "exactly the cheater must be discarded"
    );
    // `folded` counts post-bootstrap steps; party 0 is already in `acc`.
    assert_eq!(
        folded,
        PARTIES - 2,
        "all remaining honest parties must fold"
    );

    println!(
        "\nResult: {} honest contributions folded into ONE accumulator; cheating",
        folded + 1
    );
    println!("party #{CHEATER} identified at its own fold step (O(1), no tree search) and");
    println!("discarded from the authorized set, per the Urban–Rambaud discard rule the");
    println!("design adopts (§2.3). The all-honest path pays zero isolation overhead.");
}
