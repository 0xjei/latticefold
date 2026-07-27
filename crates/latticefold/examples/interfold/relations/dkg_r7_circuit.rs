//! **R7 in-circuit, multi-channel**: the real L-channel CRT reconstruction AS A
//! PROVEN CCS RELATION on the P track — closing the gap where `dkg_r7.rs` was
//! proven-but-single-channel and `dkg_r7_crt.rs` was multi-channel-but-unproven
//! (pure BigUint, no circuit).
//!
//! For L = 3 concrete coprime channels q_1, q_2, q_3 (Q = Π q_l), the CCS over
//! the P-track ring enforces, per channel, the plan's §5-R7 step 3:
//!
//!     u_global − u^(l) − q_l · r^(l) = 0        (one row per channel, L rows)
//!
//! with the residues u^(l) PUBLIC (interpolation outputs) and the quotient
//! witnesses r^(l) SECRET, each bounded by Q/q_l via a TIGHT witness
//! decomposition whose capacity exceeds Q/q_l only modestly — the native norm
//! proof covers them, and unlike the earlier Goldilocks parameters
//! (B^L = 2^75 > P = 2^64, where EVERY residue had a short decomposition and
//! any forged u_global admitted valid quotient witnesses) the decomposition
//! here is NOT vacuous: B'^L' = 2^20 ≪ P.
//!
//! The no-wraparound condition (§9.3) is CHECKED, not assumed: every value in
//! the identity (u_global and each r^(l)·q_l), times the extraction slack, must
//! stay below the P-track modulus — verified numerically for the concrete
//! parameters before proving. The slack S is DERIVED (see below), not asserted.
//!
//! Two independent reconstructions (different u) are folded into one
//! accumulator and verified, exercising the full NIFS pipeline including the
//! range proof on the quotient witnesses. NOTE: the NIFS fold decomposes the
//! PUBLIC INPUTS x_w with the same (B, L) gadget as the witness, so u_global
//! itself must fit the tight capacity — the toy u values are kept small for
//! this reason. At production scale (u_global ≈ Q ≈ 2^174) the shared gadget
//! would have to cover Q, destroying tightness: this is a second, structural
//! reason (besides the fold-slack/Δ-window analysis) that production R7
//! decides directly and never folds.
//!
//! Goldilocks stands in for the reconstruction prime P.
//!
//! Run with: cargo run --release --example dkg_r7_circuit

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

/// Tight quotient-witness decomposition: balanced capacity
/// C = (B/2)(B^L−1)/(B−1) ≈ 2^19 covers the honest quotients
/// (r^(l) < Q/q_l ≤ 2^13.4), while B^L = 2^20 stays far below the Goldilocks
/// modulus — the decomposition is non-vacuous (contrast: B^L = 2^75 > P in
/// the earlier parameters, where the range enforcement was illusory).
#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    const B: u128 = 16;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    const K: usize = 4;
}

/// Concrete coprime RNS channels.
const QLS: [u128; 3] = [101, 103, 107];
const L_CH: usize = QLS.len();
/// Goldilocks modulus (the stand-in P).
const P_MOD: u128 = 0xFFFF_FFFF_0000_0001;

/// Extraction slack, DERIVED (§9.3; see dkg_r7_crt.rs for the full
/// derivation). Two regimes, both checked below:
///  - S = 2: the decide-directly path (linearize + Ajtai commitment): the
///    extracted digits reach the MSIS binding boundary B'−1 vs the honest
///    balanced B'/2, doubling the recomposed witness bound.
///  - S_FOLD: this example additionally FOLDS two instances (a machinery
///    exercise): the folded witness is a short-challenge combination of
///    2K honest limb witnesses with ‖ρ‖∞ ≤ c_max = 32 (Goldilocks challenge
///    set), S_FOLD = 2·(1 + (2K−1)·c_max) = 450. The toy parameters absorb
///    it; at the production byte challenge set (c_max = 255) the same
///    structure gives ~2^13.6 — breaching the 2^10 envelope and emptying the
///    decode row's Δ-window, which is why production R7 decides directly.
const SLACK: u128 = 2;
const SLACK_FOLD: u128 = 2 * (1 + (2 * DP::K as u128 - 1) * 32);

/// Witness = the L quotient witnesses r^(l).
const WIT_LEN: usize = L_CH;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;

// z = [u_global, u^(1), u^(2), u^(3), one, r^(1), r^(2), r^(3)], l = 1 + L_CH.
const IDX_UG: usize = 0;
const IDX_RES: usize = 1; // residues at 1..=L_CH
const IDX_ONE: usize = 1 + L_CH;
const IDX_R: usize = 2 + L_CH;
const N_COLS: usize = 2 + 2 * L_CH;

/// Balanced capacity of the tight decomposition: (B/2)(B^L − 1)/(B − 1).
const fn balanced_capacity() -> u128 {
    (DP::B / 2) * (DP::B.pow(DP::L as u32) - 1) / (DP::B - 1)
}

/// One row per channel: u_global − u^(l) − q_l·r^(l) = 0.
#[allow(non_snake_case)]
fn r7_r1cs() -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let rows: Vec<Vec<(RqNTT, usize)>> = (0..L_CH)
        .map(|l| {
            vec![
                (one, IDX_UG),
                (-one, IDX_RES + l),
                (-RqNTT::from(QLS[l]), IDX_R + l),
            ]
        })
        .collect();
    R1CS::<RqNTT> {
        l: 1 + L_CH,
        A: SparseMatrix {
            nrows: L_CH,
            ncols: N_COLS,
            coeffs: rows,
        },
        B: SparseMatrix {
            nrows: L_CH,
            ncols: N_COLS,
            coeffs: vec![vec![(one, IDX_ONE)]; L_CH],
        },
        C: SparseMatrix {
            nrows: L_CH,
            ncols: N_COLS,
            coeffs: vec![vec![]; L_CH],
        },
    }
}

/// Build a reconstruction instance for global value `u`: public residues, secret
/// quotient witnesses, and the §9.3 margin check.
fn reconstruction_instance(
    u: u128,
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
) -> (CCCS<RqNTT>, Witness<RqNTT>) {
    let big_q: u128 = QLS.iter().product();
    assert!(u < big_q, "u must lie in [0, Q)");

    let residues: Vec<u128> = QLS.iter().map(|q| u % q).collect();
    let quotients: Vec<u128> = QLS
        .iter()
        .zip(&residues)
        .map(|(q, r)| (u - r) / q)
        .collect();

    // Quotient bounds: r^(l) < Q/q_l, and within the tight decomposition's
    // balanced capacity so the committed digits are well-formed.
    let capacity = balanced_capacity();
    let mut max_cross = 0u128;
    for (l, (&q, &r)) in QLS.iter().zip(&quotients).enumerate() {
        assert!(r < big_q / q, "quotient witness {l} out of its Q/q_l bound");
        assert!(
            r < capacity,
            "quotient witness {l} exceeds the tight decomposition capacity"
        );
        max_cross = max_cross.max(r * q);
    }
    // §9.3 no-wraparound margin, CHECKED for the concrete parameters:
    // the R_P identity u_global − u^(l) − r^(l)·q_l = 0 lifts to the integer
    // identity iff |·| < P, with the extracted quotient bound S·C:
    //   u + q_l + S·C·q_l < P   per row (and S·C·q_l < P/2 per term).
    let enforced = SLACK * capacity;
    assert!(
        u + QLS.iter().max().unwrap() + enforced * QLS.iter().max().unwrap() < P_MOD,
        "no-wraparound margin violated for the P-track stand-in"
    );
    assert!(
        enforced * QLS.iter().max().unwrap() < P_MOD / 2,
        "per-term margin violated for the P-track stand-in"
    );
    // The fold-path slack is absorbable at toy scale (see SLACK_FOLD above).
    assert!(
        SLACK_FOLD * capacity * QLS.iter().max().unwrap() < P_MOD / 2,
        "fold-slack margin violated for the P-track stand-in"
    );

    let mut z = vec![RqNTT::from(u)];
    z.extend(residues.iter().map(|&r| RqNTT::from(r)));
    z.push(RqNTT::from(1u128));
    z.extend(quotients.iter().map(|&r| RqNTT::from(r)));
    ccs.check_relation(&z)
        .expect("multi-channel CRT relation not satisfied");

    let wit = Witness::from_w_ccs::<DP>(quotients.iter().map(|&r| RqNTT::from(r)).collect());
    let mut x = vec![RqNTT::from(u)];
    x.extend(residues.iter().map(|&r| RqNTT::from(r)));
    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: x,
    };
    (cm, wit)
}

fn main() {
    let big_q: u128 = QLS.iter().product();
    println!("LatticeFold VDKG — R7 IN-CIRCUIT multi-channel CRT (P track)");
    println!("Channels q_l = {QLS:?}, Q = {big_q} | Goldilocks stand-in for P\n");

    let mut rng = ark_std::test_rng();
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r7_r1cs(), N, DP::L);
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // Two independent reconstructions (e.g. two decryption outputs). The
    // values are kept BELOW the tight decomposition capacity: the NIFS fold
    // decomposes the public inputs (u_global) with the same gadget, see the
    // header note — production R7 decides directly instead.
    let u_a = 400_000;
    let u_b = 300_001;
    let (cm_a, wit_a) = reconstruction_instance(u_a, &ccs, &scheme);
    let (cm_b, wit_b) = reconstruction_instance(u_b, &ccs, &scheme);
    println!("Instances: u_a = {u_a}, u_b = {u_b}");
    println!("  per-channel rows u_global = u^(l) + r^(l)·q_l all satisfied in-CCS ✓");
    println!(
        "  quotient witnesses r^(l) < Q/q_l ≤ tight capacity {} (norm-proven) ✓",
        balanced_capacity()
    );
    println!("  decomposition non-vacuous: B'^L' = {} << P = 2^64 ✓", DP::B.pow(DP::L as u32));
    println!(
        "  §9.3 margin: extracted bound S·C = {}·{}, per-term < P/2 checked ✓\n",
        SLACK,
        balanced_capacity()
    );

    // Negative check: a wrong residue set (channel-2 residue off by one) must
    // NOT satisfy the relation — no single u_global fits inconsistent residues.
    {
        let mut z = vec![RqNTT::from(u_a)];
        let residues: Vec<u128> = QLS.iter().map(|q| u_a % q).collect();
        z.push(RqNTT::from(residues[0]));
        z.push(RqNTT::from(residues[1] + 1)); // corrupted channel
        z.push(RqNTT::from(residues[2]));
        z.push(RqNTT::from(1u128));
        z.extend(
            QLS.iter()
                .zip(&residues)
                .map(|(q, r)| RqNTT::from((u_a - r) / q)),
        );
        assert!(
            ccs.check_relation(&z).is_err(),
            "corrupted residue must fail the CRT relation"
        );
        println!("Negative check: corrupted channel-2 residue REJECTED by the CCS ✓");
    }
    // Negative check (forgery): u' = u_a + 1 with the HONEST residues. The
    // only way to close the rows is a full-range quotient
    // s' = (u'−u^(l))·q_l^{−1} mod P ≈ P-sized — which exceeds the tight
    // decomposition capacity C: the witness cannot be committed at all.
    {
        let forged = u_a + 1;
        let capacity = balanced_capacity();
        let forged_quotient_1 = (forged - u_a % QLS[0]) * modpow(QLS[0], P_MOD - 2, P_MOD) % P_MOD;
        assert!(
            forged_quotient_1 >= capacity,
            "forged quotient must exceed the tight decomposition capacity"
        );
        println!(
            "Negative check: forged u_global admits only full-range quotients ({} ≥ C = {}), uncommittable ✓\n",
            forged_quotient_1, capacity
        );
    }

    // Fold the two reconstructions and verify (full NIFS incl. range proof on r).
    let mut w_acc = wit_a;
    let mut bt = PoseidonTranscript::<RqNTT, CS>::default();
    let (acc, _) = LFLinearizationProver::<_, T>::prove(&cm_a, &w_acc, &mut bt, &ccs)
        .expect("bootstrap failed");
    let mut pt = PoseidonTranscript::<RqNTT, CS>::default();
    let mut vt = PoseidonTranscript::<RqNTT, CS>::default();
    let (folded, new_w, proof) =
        NIFSProver::<RqNTT, DP, T>::prove(&acc, &w_acc, &cm_b, &wit_b, &mut pt, &ccs, &scheme)
            .expect("folding prover failed");
    let verified = NIFSVerifier::<RqNTT, DP, T>::verify(&acc, &cm_b, &proof, &mut vt, &ccs)
        .expect("folding verifier failed");
    assert_eq!(folded, verified, "accumulator mismatch");
    w_acc = new_w;
    let _ = w_acc;
    println!("Folded & verified both reconstructions on the P track ✓");

    println!("\nResult: the cross-channel step is now a PROVEN relation — L residues bound");
    println!("to one u_global via L quotient-witness rows, wrong residues and forged u_global");
    println!("rejected, the tight decomposition non-vacuous, and the margin DERIVED.");
    println!("dkg_r7_crt.rs derives the P bit-length for the production chain; this slice");
    println!("proves the same identity shape inside the CCS.");
}

/// modpow for the negative check's full-range forged quotient.
fn modpow(mut base: u128, mut exponent: u128, modulus: u128) -> u128 {
    let mut result = 1u128;
    base %= modulus;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}
