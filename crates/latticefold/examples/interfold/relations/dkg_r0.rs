//! Slice for relation **R0** (individual key commitment) — the one relation the
//! pipeline previously skipped.
//!
//! Per the design, R0 has NO witness and NO proof: each party's individual BFV
//! key pair `(pk0_ind, pk1_ind)` is public data, and R0's entire job is to pin
//! it per channel with an Ajtai commitment that later relations (R3's "encrypt
//! under the recipient's key") are intended to reference. Well-formedness is
//! NOT proved here; the end-to-end R3/R4 key-reference and discard flow remains
//! unimplemented.
//!
//! What this slice demonstrates, against real code:
//!   1. publication: `Com_l(pk0_ind), Com_l(pk1_ind)` computed and "published";
//!   2. the downstream reference pattern: anyone holding the broadcast key can
//!      recompute the commitment locally and check it against the published one
//!      (the §4.3 broadcast-vs-on-chain validation, no trust in the relayer);
//!   3. tamper detection: a relayed key that differs in ONE coefficient fails
//!      the recomputation check.
//!
//! Goldilocks stands in for a real RNS prime q_l.
//!
//! Run with: cargo run --release --example dkg_r0

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

/// Each key component committed on its own: WIT_LEN = 1 ring element.
const WIT_LEN: usize = 1;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;
const PARTIES: usize = 100; // full committee N=100 — every party pins its keys

/// Commit one public ring element the way every downstream slice does: via its
/// deterministic radix-B digit decomposition (`Witness::from_w_ccs`).
fn commit_value(v: RqNTT, scheme: &AjtaiCommitmentScheme<RqNTT>) -> Commitment<RqNTT> {
    Witness::<RqNTT>::from_w_ccs::<DP>(vec![v])
        .commit::<DP>(scheme)
        .unwrap()
}

fn main() {
    println!("LatticeFold VDKG — R0 individual key commitment (no witness, no proof)");
    println!("{PARTIES} parties pin (pk0_ind, pk1_ind) per channel | Goldilocks stand-in\n");

    let mut rng = ark_std::test_rng();
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // Each party's public individual key pair, and the published commitments.
    let keys: Vec<(RqNTT, RqNTT)> = (0..PARTIES)
        .map(|_| (RqNTT::rand(&mut rng), RqNTT::rand(&mut rng)))
        .collect();
    let published: Vec<(Commitment<RqNTT>, Commitment<RqNTT>)> = keys
        .iter()
        .map(|(pk0, pk1)| (commit_value(*pk0, &scheme), commit_value(*pk1, &scheme)))
        .collect();
    println!("(1) Published Com_l(pk0_ind), Com_l(pk1_ind) for all {PARTIES} parties ✓");

    // Downstream reference (e.g. an R3 sender fetching a recipient's key over
    // broadcast): recompute the commitment locally, compare with the published one.
    for ((pk0, pk1), (c0, c1)) in keys.iter().zip(&published) {
        assert_eq!(
            &commit_value(*pk0, &scheme),
            c0,
            "pk0_ind reference check failed"
        );
        assert_eq!(
            &commit_value(*pk1, &scheme),
            c1,
            "pk1_ind reference check failed"
        );
    }
    println!("(2) Broadcast keys validated against published commitments (recompute-locally) ✓");

    // Tamper detection: flip one coefficient of a relayed pk0 and re-check.
    let tampered = keys[0].0 + RqNTT::from(1u128);
    assert_ne!(
        commit_value(tampered, &scheme),
        published[0].0,
        "tampered key must NOT match the published commitment"
    );
    println!("(3) Tampered relay (one-coefficient change) detected by commitment mismatch ✓");

    println!("\nResult: R0 needs no circuit and no proof — its on-chain artifact per the");
    println!("design is 'none required'; the commitments simply pin the keys later relations");
    println!("(R3) reference; end-to-end malformed-key discard remains to be wired.");
}
