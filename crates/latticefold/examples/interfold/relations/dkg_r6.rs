//! Slice 5: relation **R6** (decryption-share computation).
//!
//!     d_i = ct0 + ct1 * sk_i^share + e_sm_i^share      (mod q_l)
//!
//! `ct0, ct1` are public, full-range ciphertext components; `sk_i^share` and
//! `e_sm_i^share` are the party's aggregated (full-range) secret-key and
//! smudging-noise shares — carried via their digit decomposition, exactly as in
//! R2/R4. `ct1` is public × secret-digit-linear-combination, so the whole
//! relation stays affine. `d_i` needs no norm bound and no fresh commitment: it
//! is the public output of a linear map on an already-committed short-digit
//! witness, broadcast in the clear (smudging noise hides the share).
//!
//! Goldilocks stands in for a real RNS prime q_l.
//!
//! Run with: cargo run --release --example dkg_r6

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

/// Witness = (sk_share, e_sm_share), both full-range.
const WIT_LEN: usize = 2;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;
const PARTIES: usize = 51; // H honest parties compute decryption shares (N=100, T=27)

// z = [ct0, ct1, d, one, sk, e_sm], l = 3. (ct1 at column 1 enters the
// constraint as a coefficient, not as a referenced variable.)
const IDX_CT0: usize = 0;
const IDX_D: usize = 2;
const IDX_ONE: usize = 3;
const IDX_SK: usize = 4;
const IDX_ESM: usize = 5;
const N_COLS: usize = 6;

/// R6 R1CS: `d - ct0 - ct1*sk - e_sm = 0`, affine (ct1 public ring coefficient).
#[allow(non_snake_case)]
fn r6_r1cs(ct1: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let neg_one = -one;
    let a0 = vec![
        (one, IDX_D),
        (neg_one, IDX_CT0),
        (-*ct1, IDX_SK),
        (neg_one, IDX_ESM),
    ];
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
    R1CS::<RqNTT> { l: 3, A, B, C }
}

fn party_instance(
    ct0: &RqNTT,
    ct1: &RqNTT,
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    // Aggregated shares are full-range (sum of ~uniform shares).
    let sk = RqNTT::rand(rng);
    let e_sm = RqNTT::rand(rng);
    let d = *ct0 + *ct1 * sk + e_sm;

    let z = vec![*ct0, *ct1, d, RqNTT::from(1u128), sk, e_sm];
    ccs.check_relation(&z)
        .expect("R6 decryption-share relation not satisfied");

    let wit = Witness::from_w_ccs::<DP>(vec![sk, e_sm]);
    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: vec![*ct0, *ct1, d],
    };
    (cm, wit)
}

fn main() {
    println!("LatticeFold VDKG — R6 decryption-share computation");
    println!("d_i = ct0 + ct1*sk_i^share + e_sm_i^share | {PARTIES} parties, Goldilocks stand-in");

    let mut rng = ark_std::test_rng();
    // Public, full-range ciphertext to decrypt.
    let ct0 = RqNTT::rand(&mut rng);
    let ct1 = RqNTT::rand(&mut rng);

    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r6_r1cs(&ct1), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let (cm_0, wit_0) = party_instance(&ct0, &ct1, &ccs, &scheme, &mut rng);
    let mut w_acc = wit_0;
    let mut bootstrap = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) = LFLinearizationProver::<_, T>::prove(&cm_0, &w_acc, &mut bootstrap, &ccs)
        .expect("failed to bootstrap accumulator");

    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();

    println!("\nFolding {PARTIES} decryption-share proofs...");
    let start = Instant::now();
    let mut last_proof = None;

    // Party 0 is already represented by the bootstrap accumulator.
    for i in 1..PARTIES {
        let (cm_i, wit_i) = party_instance(&ct0, &ct1, &ccs, &scheme, &mut rng);
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
        assert_eq!(new_acc, verified_acc, "accumulator mismatch at party {i}");
        acc = new_acc;
        w_acc = new_w_acc;
        println!(
            "  party {:>2}/{PARTIES} decryption share folded & verified",
            i + 1
        );
        last_proof = Some(proof);
    }

    let elapsed = start.elapsed();
    println!("\nAll {PARTIES} decryption-share proofs folded & verified in {elapsed:?}");
    println!("Average per party: {:?}", elapsed / PARTIES as u32);
    if let Some(proof) = last_proof {
        let mut buf = Vec::new();
        proof.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        println!(
            "Per-share fold proof size (compressed): {}",
            humansize::format_size(buf.len(), humansize::BINARY)
        );
    }

    println!("\nResult: each d_i is a public linear image of already-committed short digits;");
    println!("norm bounds inherited from R2/R4, no fresh commitment for d_i.");
}
