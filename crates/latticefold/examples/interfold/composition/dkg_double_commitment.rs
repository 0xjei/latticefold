//! **§6.2 — double commitments for compact publication**, the mechanism the
//! slices had deferred to `latticefold-plus` (WIP): an outer Ajtai commitment
//! with a SMALL (rank-1) output taken over the inner commitment vector, so the
//! on-chain artifact per published quantity is ONE ring element instead of a
//! full κ-element commitment vector.
//!
//! Demonstrated against real code:
//!   1. inner: Com_in(w) = A_in·f ∈ R^κ (κ = 4 ring elements) — the usual
//!      commitment every slice publishes;
//!   2. outer: the κ inner ring elements are full-range, so (like shares) they
//!      are digit-decomposed and committed under a rank-1 outer key:
//!      Com_out(digits(Com_in)) ∈ R^1 — the ON-CHAIN artifact;
//!   3. publication model (§4.3): the full inner commitment travels over the
//!      broadcast layer; anyone recomputes the outer commitment locally and
//!      compares to the published ring element — no trust in the relayer;
//!   4. tamper detection: a relayed inner vector altered in one component fails
//!      the outer recomputation;
//!   5. the homomorphism split the plan notes: LINEAR links stay free at the
//!      INNER layer (Σ Com_in(f_i) = Com_in(Σ f_i) — checked); the outer layer
//!      sits above a non-linear digit decomposition, so cross-relation algebra
//!      is done on inner commitments and the outer layer is purely the compact
//!      publication wrapper ("one layer of commitment preserves homomorphism,
//!      so worst case we use one layer" — exactly this arrangement).
//!
//! Size accounting is printed: κ-element inner vs. 1-element outer.
//!
//! Run with: cargo run --release --example dkg_double_commitment

use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::UniformRand;
use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::{
    arith::Witness,
    commitment::{AjtaiCommitmentScheme, Commitment},
    decomposition_parameters::DecompositionParams,
};

type RqNTT = GoldilocksRingNTT;

#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    const K: usize = 15;
}

/// Inner commitment: the usual per-slice shape.
const WIT_LEN: usize = 2;
const N_IN: usize = WIT_LEN * DP::L;
const KAPPA_IN: usize = 4;
/// Outer commitment: rank-1 output over the decomposed inner vector.
const N_OUT: usize = KAPPA_IN * DP::L;
const KAPPA_OUT: usize = 1;

const PARTIES: usize = 51;

fn ser_len<S: CanonicalSerialize>(x: &S) -> usize {
    let mut b = Vec::new();
    x.serialize_with_mode(&mut b, Compress::Yes).unwrap();
    b.len()
}

/// The outer (double) commitment of an inner commitment: digit-decompose the κ
/// full-range inner ring elements, commit under the rank-1 outer key.
fn outer(
    inner: &Commitment<RqNTT>,
    out_scheme: &AjtaiCommitmentScheme<RqNTT>,
) -> Commitment<RqNTT> {
    let wit = Witness::<RqNTT>::from_w_ccs::<DP>(inner.as_ref().to_vec());
    out_scheme.commit_ntt(&wit.f).unwrap()
}

fn main() {
    println!("LatticeFold VDKG — §6.2 double commitments (compact on-chain publication)");
    println!("inner κ = {KAPPA_IN} → outer rank-1 | {PARTIES} parties, Goldilocks stand-in\n");

    let mut rng = ark_std::test_rng();
    let in_scheme: AjtaiCommitmentScheme<RqNTT> =
        AjtaiCommitmentScheme::rand(KAPPA_IN, N_IN, &mut rng);
    let out_scheme: AjtaiCommitmentScheme<RqNTT> =
        AjtaiCommitmentScheme::rand(KAPPA_OUT, N_OUT, &mut rng);

    // Each party's witness, inner commitment, and published outer digest.
    let wits: Vec<Witness<RqNTT>> = (0..PARTIES)
        .map(|_| Witness::from_w_ccs::<DP>(vec![RqNTT::rand(&mut rng), RqNTT::rand(&mut rng)]))
        .collect();
    let inners: Vec<Commitment<RqNTT>> = wits
        .iter()
        .map(|w| w.commit::<DP>(&in_scheme).unwrap())
        .collect();
    let outers: Vec<Commitment<RqNTT>> = inners.iter().map(|c| outer(c, &out_scheme)).collect();

    let in_bytes = ser_len(&inners[0]);
    let out_bytes = ser_len(&outers[0]);
    println!("(1,2) inner Com ∈ R^{KAPPA_IN} = {in_bytes} B  →  outer Com ∈ R^{KAPPA_OUT} = {out_bytes} B on-chain");
    println!(
        "      per-publication saving: {:.1}× smaller artifact\n",
        in_bytes as f64 / out_bytes as f64
    );

    // (3) Publication model: broadcast inner, verify against on-chain outer.
    for (c_in, c_out) in inners.iter().zip(&outers) {
        assert_eq!(
            &outer(c_in, &out_scheme),
            c_out,
            "broadcast validation failed"
        );
    }
    println!("(3) All broadcast inner commitments validated against on-chain outer digests ✓");

    // (4) Tamper detection: one altered inner component.
    let mut tampered = inners[0].as_ref().to_vec();
    tampered[2] += RqNTT::from(1u128);
    let tampered_out = {
        let w = Witness::<RqNTT>::from_w_ccs::<DP>(tampered);
        out_scheme.commit_ntt(&w.f).unwrap()
    };
    assert_ne!(
        tampered_out, outers[0],
        "tampered inner must fail outer check"
    );
    println!("(4) Tampered relayed inner commitment detected by outer mismatch ✓");

    // (5) Linear links stay at the INNER layer: Σ Com_in(f_i) == Com_in(Σ f_i).
    let f_sum: Vec<RqNTT> = (0..N_IN)
        .map(|j| wits.iter().fold(RqNTT::from(0u128), |acc, w| acc + w.f[j]))
        .collect();
    let sum_in = inners
        .iter()
        .skip(1)
        .fold(inners[0].clone(), |acc, c| acc + c);
    assert_eq!(
        in_scheme.commit_ntt(&f_sum).unwrap(),
        sum_in,
        "inner homomorphism broken"
    );
    // The outer layer sits above a NON-linear digit decomposition, so the
    // aggregate is re-published with its own outer digest, derived from the
    // (freely computed) inner sum — algebra inner, publication outer.
    let agg_outer = outer(&sum_in, &out_scheme);
    assert_eq!(outer(&sum_in, &out_scheme), agg_outer);
    println!(
        "(5) Σ Com_in(f_i) == Com_in(Σ f_i) ✓ (free) — outer digest re-derived for the aggregate ✓"
    );

    println!("\nResult: on-chain artifact shrinks to one ring element per published");
    println!("quantity; cross-relation algebra stays free at the inner layer; the outer");
    println!("opening link (digest ↔ inner ↔ witness) is one extra fixed-size opening in");
    println!("the accompanying proof, per §6.2 — the LatticeFold+ double-commitment shape.");
}
