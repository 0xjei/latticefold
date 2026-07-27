//! Slice 3 of the lattice-based VDKG design: BFV encryption relations **R3**
//! (encrypt a share under a recipient's individual key) and **Ruser** (user
//! encryption under the threshold key) — structurally identical, the GRECO
//! replacement.
//!
//! Relation (per channel), fully affine in the witness:
//!
//!     ct0 = pk0 * u + e0 + Δ * m
//!     ct1 = pk1 * u + e1
//!
//! `pk0, pk1` (public keys) and `Δ` (scaling constant) are public; `u, e0, e1`
//! are short encryption randomness/errors and `m` is the message (a recomposed
//! short share for R3, the user plaintext for Ruser). Because the keys are
//! public, `pk*·u` is public-ring-element × secret — affine, embedded as ring
//! coefficients, with NO quotient witnesses for the modular reduction.
//!
//! This is the axis the design flags for high-arity folding gains: R3 runs
//! |A|·(|A|−1) times, so we fold a batch of encryption instances into one
//! accumulator and report throughput.
//!
//! Goldilocks stands in for a real RNS prime q_l (custom-`Ring` work deferred).
//!
//! Run with:
//!   cargo run --release --example dkg_r3_ruser

use std::time::Instant;

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

/// Witness = (u, e0, e1, m).
const WIT_LEN: usize = 4;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

/// Honest set H=51 of N=100; R3 encrypts each honest party's share to every other
/// honest party => |A|·(|A|−1) = H·(H−1) = 2550 instances (the high-arity axis).
const H: usize = 51;
const INSTANCES: usize = H * (H - 1); // 2550

// z = [ct0, ct1, one, u, e0, e1, m], l = 2.
const IDX_CT0: usize = 0;
const IDX_CT1: usize = 1;
const IDX_ONE: usize = 2;
const IDX_U: usize = 3;
const IDX_E0: usize = 4;
const IDX_E1: usize = 5;
const IDX_M: usize = 6;
const N_COLS: usize = 7;

/// Encryption R1CS: two affine constraints (ct0, ct1) with public `pk0,pk1,Δ`
/// baked in as ring coefficients.
#[allow(non_snake_case)]
fn enc_r1cs(pk0: &RqNTT, pk1: &RqNTT, delta: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let neg_one = -one;

    // ct0 - pk0*u - e0 - Δ*m = 0
    let a0 = vec![
        (one, IDX_CT0),
        (-*pk0, IDX_U),
        (neg_one, IDX_E0),
        (-*delta, IDX_M),
    ];
    // ct1 - pk1*u - e1 = 0
    let a1 = vec![(one, IDX_CT1), (-*pk1, IDX_U), (neg_one, IDX_E1)];

    let A = SparseMatrix {
        nrows: 2,
        ncols: N_COLS,
        coeffs: vec![a0, a1],
    };
    let B = SparseMatrix {
        nrows: 2,
        ncols: N_COLS,
        coeffs: vec![vec![(one, IDX_ONE)], vec![(one, IDX_ONE)]],
    };
    let C = SparseMatrix {
        nrows: 2,
        ncols: N_COLS,
        coeffs: vec![vec![], vec![]],
    };

    R1CS::<RqNTT> { l: 2, A, B, C }
}

fn short(rng: &mut impl ark_std::rand::Rng) -> RqNTT {
    RqNTT::from(rng.gen_range(0..3u128))
}

fn enc_instance(
    pk0: &RqNTT,
    pk1: &RqNTT,
    delta: &RqNTT,
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    let u = short(rng);
    let e0 = short(rng);
    let e1 = short(rng);
    let m = short(rng);
    // Native R_q BFV encryption.
    let ct0 = *pk0 * u + e0 + *delta * m;
    let ct1 = *pk1 * u + e1;

    // z = [ct0, ct1, one, u, e0, e1, m]
    let z = vec![ct0, ct1, RqNTT::from(1u128), u, e0, e1, m];
    ccs.check_relation(&z)
        .expect("encryption relation not satisfied");

    let wit = Witness::from_w_ccs::<DP>(vec![u, e0, e1, m]);
    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: vec![ct0, ct1],
    };
    (cm, wit)
}

fn main() {
    println!("LatticeFold VDKG — R3 / Ruser encryption (GRECO replacement)");
    println!("Relation: ct0 = pk0*u + e0 + Δ*m,  ct1 = pk1*u + e1  (native R_q)");
    println!("Folding {INSTANCES} encryption instances | KAPPA={KAPPA} WIT_LEN={WIT_LEN} N={N}");

    let mut rng = ark_std::test_rng();

    // Public key (pk1 = CRS a; pk0 arbitrary public) and scaling constant Δ.
    let pk1 = RqNTT::rand(&mut rng);
    let pk0 = RqNTT::rand(&mut rng);
    let delta = RqNTT::from(7u128); // RNS-friendly per-channel scaling constant

    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(enc_r1cs(&pk0, &pk1, &delta), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let (cm_0, wit_0) = enc_instance(&pk0, &pk1, &delta, &ccs, &scheme, &mut rng);
    let mut w_acc = wit_0;
    let mut bootstrap = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) = LFLinearizationProver::<_, T>::prove(&cm_0, &w_acc, &mut bootstrap, &ccs)
        .expect("failed to bootstrap accumulator");

    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();

    println!("\nFolding {INSTANCES} instances (high-arity axis)...");
    let start = Instant::now();
    let mut last_proof = None;

    // Instance 0 is already represented by the bootstrap accumulator.
    for i in 1..INSTANCES {
        let (cm_i, wit_i) = enc_instance(&pk0, &pk1, &delta, &ccs, &scheme, &mut rng);
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
            "accumulator mismatch at instance {i}"
        );
        acc = new_acc;
        w_acc = new_w_acc;
        if (i + 1) % 4 == 0 {
            println!(
                "  {:>2}/{INSTANCES} encryption instances folded & verified",
                i + 1
            );
        }
        last_proof = Some(proof);
    }

    let elapsed = start.elapsed();
    println!("\nAll {INSTANCES} encryption instances folded & verified in {elapsed:?}");
    println!(
        "Throughput: {:?}/instance ({:.1} instances/s)",
        elapsed / INSTANCES as u32,
        INSTANCES as f64 / elapsed.as_secs_f64()
    );

    if let Some(proof) = last_proof {
        let mut buf = Vec::new();
        proof.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        println!(
            "Per-instance fold proof size (compressed): {}",
            humansize::format_size(buf.len(), humansize::BINARY)
        );
    }

    println!("\nNote: Ruser is the same relation under (pk_agg); its extra requirement is a");
    println!("commit-once message `m` referenced by all L per-channel instances (cross-channel");
    println!("consistency) — the same commit-once/reference-many pattern used for sk_i.");
}
