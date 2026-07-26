//! **R7 step 4 — the DECODE, in-CCS**: the final piece of R7 (§5-R7.4), which
//! the CRT slices stopped short of: recovering the plaintext from the
//! reconstructed u_global as a PROVEN relation with its bounded rounding
//! witness — "an intrinsic feature of arithmetizing integer division, not an
//! artifact of the backend."
//!
//! BFV decode in the CENTERED form (matching the production flow and the
//! corrected plan §5-R7 step 4 — the earlier `t·u_global + floor(Q/2) =
//! m·Q + v` form arithmetizes `t·u_global ≈ 2^194 > P`, blowing the margin):
//!
//!     u_global = Δ·m + e,     Δ = ⌊Q/t⌋,   |e| ≤ Δ/2 (centered noise),
//!
//! with `m` (the plaintext) PUBLIC — its range m < t is validated publicly as
//! the protocol output — and the signed rounding witness `e` SECRET,
//! range-enforced by a TIGHT witness decomposition: the balanced capacity C
//! covers the honest noise, while the enforced bound stays below Δ so a WRONG
//! plaintext m' ≠ m forces |e'| = |e ± Δ| ≥ Δ − |e| beyond what can be
//! committed. The mod-P row alone does NOT exclude a forged m (any full-range
//! e' closes it); the tight decomposition is what rejects the forgery.
//!
//! §9.3 margin: every term of u − Δ·m − e = 0, times the extraction slack,
//! stays under P — checked numerically (slack derived as in dkg_r7_crt.rs:
//! S = 2 decide-directly). Two decode instances are proven and verified on
//! one shared transcript, mirroring the production P-track structure.
//!
//! Goldilocks stands in for the reconstruction prime P.
//!
//! Run with: cargo run --release --example dkg_r7_decode

use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::linearization::{LFLinearizationProver, LinearizationProver},
    transcript::poseidon::PoseidonTranscript,
};
use stark_rings_linalg::SparseMatrix;

type RqNTT = GoldilocksRingNTT;
type CS = GoldilocksChallengeSet;
type T = PoseidonTranscript<RqNTT, CS>;

/// Tight decode-witness decomposition: balanced capacity
/// C = (B/2)(B^L−1)/(B−1) = 2184 covers the honest centered noise (tiny),
/// while the enforced bound S·C = 4368 < Δ = 69570 excludes a wrong
/// plaintext. B^L = 2^12 ≪ P — non-vacuous. (L = 3 is required: with L = 4
/// the enforced bound 69904 overshoots Δ — the Δ-window is why the decode
/// witness needs its own decomposition, tighter than the quotients'.)
#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    const B: u128 = 16;
    const L: usize = 3;
    const B_SMALL: usize = 2;
    const K: usize = 4;
}

/// Same toy RNS chain as dkg_r7_circuit: Q = Π q_l.
const QLS: [u128; 3] = [101, 103, 107];
/// Plaintext modulus t (power-of-two style toy — dkg_params covers the real t).
const T_PT: u128 = 16;
/// Extraction slack, derived (dkg_r7_crt.rs): decide-directly path.
const SLACK: u128 = 2;
/// Goldilocks modulus (the stand-in P).
const P_MOD: u128 = 0xFFFF_FFFF_0000_0001;

/// Witness = e. The plaintext m is a public output in the CCS statement.
const WIT_LEN: usize = 1;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

// z = [u_global, m, one, e], l = 2.
const IDX_UG: usize = 0;
const IDX_M: usize = 1;
const IDX_ONE: usize = 2;
const IDX_E: usize = 3;
const N_COLS: usize = 4;

/// Balanced capacity of the tight decomposition: (B/2)(B^L − 1)/(B − 1).
const fn balanced_capacity() -> u128 {
    (DP::B / 2) * (DP::B.pow(DP::L as u32) - 1) / (DP::B - 1)
}

/// Decode row: u_global − Δ·m − e = 0.
#[allow(non_snake_case)]
fn decode_r1cs(delta: u128) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let a0 = vec![
        (one, IDX_UG),
        (-RqNTT::from(delta), IDX_M),
        (-one, IDX_E),
    ];
    R1CS::<RqNTT> {
        l: 2,
        A: SparseMatrix {
            nrows: 1,
            ncols: N_COLS,
            coeffs: vec![a0],
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

fn main() {
    let big_q: u128 = QLS.iter().product();
    let delta = big_q / T_PT;
    println!("LatticeFold VDKG — R7 step 4: DECODE in-CCS, centered form (P track)");
    println!("u_global = Δ·m + e  |  t = {T_PT}, Δ = {delta}, Q = {big_q}, Goldilocks stand-in for P\n");

    let mut rng = ark_std::test_rng();

    // A BFV-shaped u_global: u = Δ·m0 + e with small centered noise e.
    let m0: u128 = 11; // the plaintext, < t
    let e: i128 = 5; // centered decryption noise, |e| << Δ/2
    let u_global = (delta * m0) as i128 + e;
    assert!((u_global as u128) < big_q, "CRT output must be canonical in [0, Q)");

    // Public-input validation of the plaintext range (m is the output).
    assert!(m0 < T_PT, "plaintext output must be canonical in [0, t)");
    // The tight decomposition covers the honest noise (completeness) and its
    // enforced bound excludes a wrong plaintext (soundness): wrong m' forces
    // |e'| ≥ Δ − |e| > B^L − 1.
    let capacity = balanced_capacity();
    assert!((e.unsigned_abs()) < capacity, "honest noise must fit");
    let enforced = SLACK * capacity;
    assert!(
        enforced < delta - e.unsigned_abs(),
        "Delta-window: enforced bound S*C must stay below Δ - |e|"
    );
    println!("Encoded m0 = {m0} (Δ = {delta}, centered noise e = {e}) → u_global = {u_global}");
    println!(
        "Tight decomposition: capacity C = {capacity}, enforced ≤ S·C = {enforced} < Δ = {delta} ✓"
    );

    // §9.3 margin: |u − Δ·m − e| ≤ u + Δ·m + S·C < P, checked numerically.
    let max_term = (u_global as u128) + delta * m0 + enforced;
    assert!(max_term < P_MOD, "no-wraparound margin violated");
    println!("§9.3 margin: u + Δ·m + S·C = {max_term} < P checked numerically ✓\n");

    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(decode_r1cs(delta), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let e_ring = if e < 0 {
        -RqNTT::from(e.unsigned_abs())
    } else {
        RqNTT::from(e.unsigned_abs())
    };
    let z = vec![
        RqNTT::from(u_global as u128),
        RqNTT::from(m0),
        RqNTT::from(1u128),
        e_ring,
    ];
    ccs.check_relation(&z)
        .expect("decode relation not satisfied");
    println!("Decode row u_global − Δ·m − e = 0 satisfied in-CCS ✓");

    // Negative check: a wrong plaintext m' = m+1 forces e' = e − Δ with
    // |e'| = Δ − e — beyond the tight capacity, so the witness cannot be
    // committed, EVEN THOUGH the bare mod-P row closes with the full-range e'.
    let e_forged = e - delta as i128;
    let z_bad = vec![
        RqNTT::from(u_global as u128),
        RqNTT::from(m0 + 1),
        RqNTT::from(1u128),
        if e_forged < 0 {
            -RqNTT::from(e_forged.unsigned_abs())
        } else {
            RqNTT::from(e_forged.unsigned_abs())
        },
    ];
    assert!(
        ccs.check_relation(&z_bad).is_ok(),
        "mod-P row closes with the full-range forged witness (vacuity)"
    );
    assert!(
        e_forged.unsigned_abs() >= capacity,
        "forged witness must exceed the tight decomposition capacity"
    );
    println!(
        "Negative check: m' = m+1 closes the bare row but needs |e'| = {} ≥ C = {} — uncommittable ✓\n",
        e_forged.unsigned_abs(),
        capacity
    );

    // Prove: TWO decode instances (the second with NEGATIVE noise) decided
    // DIRECTLY on one shared transcript — the production path. No fold: the
    // NIFS fold decomposes the PUBLIC INPUTS (u_global ≈ Δ) with the same
    // tight gadget, which cannot fit them by design; and the byte-challenge
    // fold slack would empty the Δ-window anyway (see dkg_r7_crt.rs).
    let wit = Witness::from_w_ccs::<DP>(vec![e_ring]);
    let cm = CCCS {
        cm: wit.commit::<DP>(&scheme).unwrap(),
        x_ccs: vec![RqNTT::from(u_global as u128), RqNTT::from(m0)],
    };

    let m2: u128 = 3;
    let e2: i128 = -9;
    let u2 = (delta * m2) as i128 + e2;
    let e2_ring = -RqNTT::from(e2.unsigned_abs());
    let z2 = vec![
        RqNTT::from(u2 as u128),
        RqNTT::from(m2),
        RqNTT::from(1u128),
        e2_ring,
    ];
    ccs.check_relation(&z2)
        .expect("second decode relation failed");
    let wit2 = Witness::from_w_ccs::<DP>(vec![e2_ring]);
    let cm2 = CCCS {
        cm: wit2.commit::<DP>(&scheme).unwrap(),
        x_ccs: vec![RqNTT::from(u2 as u128), RqNTT::from(m2)],
    };

    let mut pt = PoseidonTranscript::<RqNTT, CS>::default();
    let (lcccs_a, proof_a) =
        LFLinearizationProver::<_, T>::prove(&cm, &wit, &mut pt, &ccs).expect("prove failed");
    let (lcccs_b, proof_b) =
        LFLinearizationProver::<_, T>::prove(&cm2, &wit2, &mut pt, &ccs).expect("prove failed");
    let mut vt = PoseidonTranscript::<RqNTT, CS>::default();
    use latticefold::nifs::linearization::{LFLinearizationVerifier, LinearizationVerifier};
    let verified_a = LFLinearizationVerifier::<_, T>::verify(&cm, &proof_a, &mut vt, &ccs)
        .expect("verifier failed");
    let verified_b = LFLinearizationVerifier::<_, T>::verify(&cm2, &proof_b, &mut vt, &ccs)
        .expect("verifier failed");
    assert_eq!(lcccs_a, verified_a, "first decode linearization mismatch");
    assert_eq!(lcccs_b, verified_b, "second decode linearization mismatch");
    println!("Two decode instances proven & verified on one transcript (decide-directly) ✓");

    println!("\nResult: this toy R7 decode has a public canonical m and an in-CCS centered");
    println!("rounding row with a NON-VACUOUS tight witness decomposition: the bare mod-P");
    println!("row closes for a forged plaintext, but the forged witness exceeds the tight");
    println!("capacity and cannot be committed. Production margin: vdkg_params::r7_margin_holds.");
}
