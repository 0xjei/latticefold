//! **R1 on the REAL q_l ring — the stand-in is gone.**
//!
//! Every DKG slice so far ran on Goldilocks "standing in for a real RNS prime
//! q_l", with the promise that swapping the ring later is a type substitution,
//! not a redesign. This slice cashes that promise: it is `dkg_r1.rs` with the
//! types swapped to the custom `InterfoldRingNTT` — the ring over
//!
//!     q = 1125899909038081   (51 bits)
//!
//! which is simultaneously NTT-friendly for BFV (q ≡ 1 mod 2N, N = 8192) and
//! LatticeFold-congruent (q ≡ 1 + 2t mod 4t, t = 2^14): the q_0 of the RNS
//! chain derived and verified by `dkg_ring_model.rs`, implemented as a full
//! `stark-rings` model (fork `0xjei/stark-rings#interfold`, per the orphan-rule constraint) with
//! `SuitableRing`/challenge-set/Poseidon wiring in `cyclotomic-rings`.
//!
//! Everything else — the relation, the folding, the verification — is
//! IDENTICAL to `dkg_r1.rs`. That is the point.
//!
//! Run with: cargo run --release --example dkg_r1_native

use std::time::Instant;

use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::UniformRand;
use cyclotomic_rings::rings::{InterfoldChallengeSet, InterfoldRingNTT, InterfoldRingPoly};
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
use stark_rings::cyclotomic_ring::{models::interfold::Fq, CRT};
use stark_rings_linalg::SparseMatrix;

// ---- Concrete instantiation: the REAL q_l ring -----------------------------

type RqNTT = InterfoldRingNTT;
type RqPoly = InterfoldRingPoly;
type CS = InterfoldChallengeSet;
type T = PoseidonTranscript<RqNTT, CS>;

#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    // q ≈ 2^50.0: B^L = (2^14)^4 = 2^56 ≥ q. K carries 4 extra binary positions
    // over log2(B) (the FrogDP pattern in latticefold's own presets): the
    // accumulated witness handed to the small-radix decomposition has norm that
    // can brush past B during folding, and the balanced decomposition needs
    // room for it.
    const B: u128 = 1 << 14;
    const L: usize = 4;
    const B_SMALL: usize = 2;
    const K: usize = 18;
}

/// R1 witness is (sk_i, e_i, e_sm_i): three ring elements. `e_sm_i` is
/// committed and norm-proven before it is shared and used by R6.
const WIT_LEN: usize = 3;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;
const PARTIES: usize = 51; // H honest of N=100 (T=27)

// z layout = [pk0, 1, sk, e, e_sm]
const IDX_PK0: usize = 0;
const IDX_ONE: usize = 1;
const IDX_SK: usize = 2;
const IDX_E: usize = 3;
const N_COLS: usize = 5;

#[allow(non_snake_case)]
fn r1_r1cs(a: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    R1CS::<RqNTT> {
        l: 1,
        A: SparseMatrix {
            nrows: 1,
            ncols: N_COLS,
            coeffs: vec![vec![(-*a, IDX_SK), (one, IDX_E), (-one, IDX_PK0)]],
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

/// Sample a short ring element: ternary coefficients, built in coefficient form
/// then CRT'd to the NTT form — identical to the Goldilocks slice.
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

fn party_instance(
    a: &RqNTT,
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    let sk = short_element(rng);
    let e = short_element(rng);
    let e_sm = short_element(rng);
    let pk0 = e - *a * sk;

    let z = vec![pk0, RqNTT::from(1u128), sk, e, e_sm];
    ccs.check_relation(&z)
        .expect("R1 assignment does not satisfy pk0 = -a*sk + e on the native ring");

    let wit = Witness::from_w_ccs::<DP>(vec![sk, e, e_sm]);
    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: vec![pk0],
    };
    (cm, wit)
}

fn main() {
    println!("LatticeFold VDKG — R1 on the NATIVE q_l ring (no stand-in)");
    println!("q = 1125899909038081 (51-bit, NTT-friendly ∧ LatticeFold-congruent)");
    println!("Relation: pk0_i = -a*sk_i + e_i | {PARTIES} parties | KAPPA={KAPPA} N={N}");

    let mut rng = ark_std::test_rng();

    let a = RqNTT::rand(&mut rng);
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r1_r1cs(&a), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let (cm_0, wit_0) = party_instance(&a, &ccs, &scheme, &mut rng);
    let mut w_acc = wit_0;
    let mut bootstrap = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) = LFLinearizationProver::<_, T>::prove(&cm_0, &w_acc, &mut bootstrap, &ccs)
        .expect("failed to bootstrap accumulator");

    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();

    println!("\nFolding {PARTIES} party contributions on the native ring...");
    let start = Instant::now();
    let mut last_proof = None;

    // Party 0 is already represented by the bootstrap accumulator.
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
            "accumulator mismatch at party {party}"
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

    println!("\nResult: the 'type substitution, not a redesign' promise is now a fact —");
    println!("this file differs from dkg_r1.rs ONLY in its type aliases and decomposition");
    println!("base. The custom ring (stark-rings fork, model `interfold`) closes");
    println!("plan §12.2 for the power-of-two-t parameter point; the odd-t production");
    println!("chains still need the §8.1 extension-field variant of the same model.");
}
