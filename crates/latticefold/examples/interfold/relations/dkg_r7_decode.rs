//! **R7 step 4 — the DECODE, in-CCS**: the final piece of R7 (§5-R7.4), which
//! the CRT slices stopped short of: recovering the plaintext from the
//! reconstructed u_global as a PROVEN relation with its bounded rounding
//! witness — "an intrinsic feature of arithmetizing integer division, not an
//! artifact of the backend."
//!
//! BFV decode: message = round(t·u_global / Q) (mod t). As an integer identity
//! with a rounding witness v:
//!
//!     t · u_global + floor(Q/2) = m · Q + v,
//!                                  0 ≤ v < Q,   0 ≤ m < t
//!
//! `v` is the shifted centered residual. The public input `u_global` is
//! required to be the canonical representative in `[0, Q)` at the CRT
//! boundary.
//! Arithmetized on the P track as ONE affine row:
//!
//!     t·u_global + floor(Q/2) − Q·m − v = 0
//!
//! with `m` (the plaintext) public in the final statement and `v` (the rounding
//! witness) secret, `u_global` public from the CRT step. `v` is full-range in
//! [0, Q) — carried via its radix-B digit decomposition like every share, with
//! the native norm proof binding the digits. §9.3 margin: every term (t·u_global is the largest!)
//! times the extraction slack must stay under P — checked numerically.
//!
//! A negative check shows a WRONG plaintext m' ≠ m admits no in-range rounding
//! witness: the relation only closes with v' = v ± Q, which the range bound on
//! v excludes.
//!
//! Goldilocks stands in for the reconstruction prime P.
//!
//! Run with: cargo run --release --example dkg_r7_decode

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

/// Same toy RNS chain as dkg_r7_circuit: Q = Π q_l.
const QLS: [u128; 3] = [101, 103, 107];
/// Plaintext modulus t (power-of-two style toy — dkg_params covers the real t).
const T_PT: u128 = 16;
/// Extraction slack for the §9.3 margin.
const SLACK: u128 = 4;
/// Goldilocks modulus (the stand-in P).
const P_MOD: u128 = 0xFFFF_FFFF_0000_0001;

/// Witness = v. The plaintext m is a public output in the CCS statement.
const WIT_LEN: usize = 1;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

// z = [u_global, m, one, v], l = 2.
const IDX_UG: usize = 0;
const IDX_M: usize = 1;
const IDX_ONE: usize = 2;
const IDX_V: usize = 3;
const N_COLS: usize = 4;

/// Decode row: t·u_global + floor(Q/2) − Q·m − v = 0.
#[allow(non_snake_case)]
fn decode_r1cs(big_q: u128) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let a0 = vec![
        (RqNTT::from(T_PT), IDX_UG),
        (RqNTT::from(big_q / 2), IDX_ONE),
        (-RqNTT::from(big_q), IDX_M),
        (-one, IDX_V),
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
    println!("LatticeFold VDKG — R7 step 4: DECODE in-CCS (P track)");
    println!("t·u_global + floor(Q/2) = m·Q + v  |  t = {T_PT}, Q = {big_q}, Goldilocks stand-in for P\n");

    let mut rng = ark_std::test_rng();

    // A BFV-shaped u_global: u = Δ·m0 + e with Δ = floor(Q/t), small noise e.
    let delta = big_q / T_PT;
    let m0: u128 = 11; // the plaintext, < t
    let e: u128 = 5; // decryption noise, << Δ/2
    let u_global = delta * m0 + e;
    assert!(u_global < big_q, "CRT output must be canonical in [0, Q)");

    // Decode identity witnesses for nearest rounding. The shifted residual
    // keeps the witness non-negative while representing a centered error.
    let shifted = T_PT * u_global + big_q / 2;
    let m = shifted / big_q;
    let v = shifted % big_q;
    assert_eq!(m, m0, "decode must recover the encoded plaintext");
    assert!(m < T_PT && v < big_q, "witness ranges");
    assert!(m < T_PT, "plaintext output must be canonical in [0, t)");
    println!("Encoded m0 = {m0} (Δ = {delta}, noise e = {e}) → u_global = {u_global}");
    println!("Decode witnesses: m = {m} (recovered ✓), shifted centered residual v = {v} < Q");

    // §9.3 margin: the largest term is t·u_global; slack·max < P.
    let max_term = (T_PT * u_global).max(m * big_q).max(v);
    assert!(SLACK * max_term < P_MOD, "no-wraparound margin violated");
    println!("§9.3 margin: {SLACK}·max(t·u, m·Q, v) < P checked numerically ✓\n");

    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(decode_r1cs(big_q), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let z = vec![
        RqNTT::from(u_global),
        RqNTT::from(m),
        RqNTT::from(1u128),
        RqNTT::from(v),
    ];
    ccs.check_relation(&z)
        .expect("decode relation not satisfied");
    println!("Decode row t·u_global + floor(Q/2) − Q·m − v = 0 satisfied in-CCS ✓");

    // Negative check: a wrong plaintext m' = m+1 forces v' = v − Q, out of the
    // rounding witness's range — with the honest in-range v it cannot close.
    let z_bad = vec![
        RqNTT::from(u_global),
        RqNTT::from(m + 1),
        RqNTT::from(1u128),
        RqNTT::from(v),
    ];
    assert!(
        ccs.check_relation(&z_bad).is_err(),
        "wrong plaintext with in-range v must fail"
    );
    println!("Negative check: m' ≠ m with in-range rounding witness REJECTED ✓\n");

    // Prove: bootstrap + fold a second decode (another output) and verify.
    let wit = Witness::from_w_ccs::<DP>(vec![RqNTT::from(v)]);
    let cm = CCCS {
        cm: wit.commit::<DP>(&scheme).unwrap(),
        x_ccs: vec![RqNTT::from(u_global), RqNTT::from(m)],
    };

    let m2: u128 = 3;
    let u2 = delta * m2 + 2;
    let shifted2 = T_PT * u2 + big_q / 2;
    let (mm2, vv2) = (shifted2 / big_q, shifted2 % big_q);
    assert!(mm2 < T_PT, "second plaintext output must be canonical");
    let z2 = vec![
        RqNTT::from(u2),
        RqNTT::from(mm2),
        RqNTT::from(1u128),
        RqNTT::from(vv2),
    ];
    ccs.check_relation(&z2)
        .expect("second decode relation failed");
    let wit2 = Witness::from_w_ccs::<DP>(vec![RqNTT::from(vv2)]);
    let cm2 = CCCS {
        cm: wit2.commit::<DP>(&scheme).unwrap(),
        x_ccs: vec![RqNTT::from(u2), RqNTT::from(mm2)],
    };

    let mut bt = PoseidonTranscript::<RqNTT, CS>::default();
    let (acc, _) =
        LFLinearizationProver::<_, T>::prove(&cm, &wit, &mut bt, &ccs).expect("bootstrap failed");
    let mut pt = PoseidonTranscript::<RqNTT, CS>::default();
    let mut vt = PoseidonTranscript::<RqNTT, CS>::default();
    let (folded, _, proof) =
        NIFSProver::<RqNTT, DP, T>::prove(&acc, &wit, &cm2, &wit2, &mut pt, &ccs, &scheme)
            .expect("folding prover failed");
    let verified = NIFSVerifier::<RqNTT, DP, T>::verify(&acc, &cm2, &proof, &mut vt, &ccs)
        .expect("folding verifier failed");
    assert_eq!(folded, verified, "accumulator mismatch");
    println!("Two decode instances folded & verified on the P track ✓");

    println!("\nResult: this toy R7 decode has public canonical m and an in-CCS nearest-rounding");
    println!("row. Production still needs exact range semantics for v, centered BFV");
    println!("representations, the real P track, and the missing external decider.");
}
