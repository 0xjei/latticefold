//! Step 7 (in-repo part): extract the DECIDER STATEMENT for a folded track.
//!
//! The on-chain wrapper itself (LatticeFold decider -> Solidity) does NOT exist —
//! no tooling compiles a lattice-relation decider to an EVM verifier (§10). But
//! the part of Step 7 that IS in-repo is "decide each of the L+1 tracks down to a
//! small, fixed-size statement" — the compact object a wrapper would take as
//! input. This example folds a track and prints exactly that statement (the
//! final `LCCCS` accumulator) and its serialized size, so the wrapper's input
//! cost can be measured independently of building the wrapper.
//!
//! What a wrapper must check about this statement (§7.1): a commitment opening,
//! a norm bound, and evaluation consistency — the SAME shape for every track,
//! differing only in the modulus. Here we quantify the statement; the checks are
//! the (unimplemented, external) wrapper circuit.
//!
//! Run with: cargo run --release --example dkg_decider_statement

use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::UniformRand;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{r1cs::R1CS, Witness, CCCS, CCS, LCCCS},
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

const WIT_LEN: usize = 3;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;
const INSTANCES: usize = 51; // H honest of N=100 (T=27)

#[allow(non_snake_case)]
fn r1cs(a: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    R1CS::<RqNTT> {
        l: 1,
        A: SparseMatrix {
            nrows: 1,
            ncols: 5,
            coeffs: vec![vec![(-*a, 2), (one, 3), (-one, 0)]],
        },
        B: SparseMatrix {
            nrows: 1,
            ncols: 5,
            coeffs: vec![vec![(one, 1)]],
        },
        C: SparseMatrix {
            nrows: 1,
            ncols: 5,
            coeffs: vec![vec![]],
        },
    }
}

fn inst(
    a: &RqNTT,
    ccs: &CCS<RqNTT>,
    s: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    let sk = RqNTT::from(rng.gen_range(0..3u128));
    let e = RqNTT::from(rng.gen_range(0..3u128));
    let e_sm = RqNTT::from(rng.gen_range(0..3u128));
    let pk0 = e - *a * sk;
    let wit = Witness::from_w_ccs::<DP>(vec![sk, e, e_sm]);
    let cm = CCCS {
        cm: wit.commit::<DP>(s).unwrap(),
        x_ccs: vec![pk0],
    };
    let _ = ccs;
    (cm, wit)
}

fn field_bytes<Ser: CanonicalSerialize>(x: &Ser) -> usize {
    let mut b = Vec::new();
    x.serialize_with_mode(&mut b, Compress::Yes).unwrap();
    b.len()
}

fn main() {
    println!("Step 7 (in-repo) — decider statement for one folded track\n");

    let mut rng = ark_std::test_rng();
    let a = RqNTT::rand(&mut rng);
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r1cs(&a), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let insts: Vec<_> = (0..INSTANCES)
        .map(|_| inst(&a, &ccs, &scheme, &mut rng))
        .collect();
    let (cm0, w0) = &insts[0];
    let mut w_acc = w0.clone();
    let mut bt = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _): (LCCCS<RqNTT>, _) =
        LFLinearizationProver::<_, T>::prove(cm0, &w_acc, &mut bt, &ccs).unwrap();
    let mut pt = PoseidonTranscript::<RqNTT, CS>::default();
    let mut vt = PoseidonTranscript::<RqNTT, CS>::default();
    // Instance 0 is already represented by the bootstrap accumulator.
    for (cm_i, wit_i) in insts.iter().skip(1) {
        let (na, nw, proof) =
            NIFSProver::<RqNTT, DP, T>::prove(&acc, &w_acc, cm_i, wit_i, &mut pt, &ccs, &scheme)
                .unwrap();
        let verified =
            NIFSVerifier::<RqNTT, DP, T>::verify(&acc, cm_i, &proof, &mut vt, &ccs).unwrap();
        assert_eq!(na, verified, "prover/verifier accumulator mismatch");
        acc = na;
        w_acc = nw;
    }

    println!("Folded {INSTANCES} instances into one accumulator (LCCCS). Its decider statement:");
    println!(
        "  r   (sumcheck challenge)     : {:>3} ring elems, {:>5} B",
        acc.r.len(),
        field_bytes(&acc.r)
    );
    println!(
        "  v   (linearized CCS eval)    : {:>3} ring elems, {:>5} B",
        acc.v.len(),
        field_bytes(&acc.v)
    );
    println!(
        "  cm  (Ajtai commitment)       : {:>3} ring elems, {:>5} B",
        acc.cm.as_ref().len(),
        field_bytes(&acc.cm)
    );
    println!(
        "  u   (M_j z evals at r)       : {:>3} ring elems, {:>5} B",
        acc.u.len(),
        field_bytes(&acc.u)
    );
    println!(
        "  x_w (CCS statement)          : {:>3} ring elems, {:>5} B",
        acc.x_w.len(),
        field_bytes(&acc.x_w)
    );
    println!(
        "  h   (z constant term)        : {:>3} ring elem , {:>5} B",
        1,
        field_bytes(&acc.h)
    );

    let total = field_bytes(&acc.r)
        + field_bytes(&acc.v)
        + field_bytes(&acc.cm)
        + field_bytes(&acc.u)
        + field_bytes(&acc.x_w)
        + field_bytes(&acc.h);
    println!("\n  TOTAL decider statement      : {total} B  (fixed-size — independent of the {INSTANCES} folded instances)");
    println!("\nThis is the compact per-track object a wrapper (Noir/Barretenberg or STARK) would");
    println!("verify (commitment opening + norm bound + eval consistency). Combining the L+1");
    println!("tracks and emitting a Solidity verifier is the external, unbuilt Step 7 wrapper.");
}
