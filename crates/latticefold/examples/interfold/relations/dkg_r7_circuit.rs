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
//! witnesses r^(l) SECRET, each bounded by Q/q_l < B so the native norm proof
//! covers them. The instance is satisfiable iff a single integer u_global is
//! simultaneously consistent with all L residues — the genuine cross-channel
//! mixing that cannot stay in any single RNS track.
//!
//! The no-wraparound condition (§9.3) is CHECKED, not assumed: every value in
//! the identity (u_global and each r^(l)·q_l), times the extraction slack, must
//! stay below the P-track modulus — verified numerically for the concrete
//! parameters before proving.
//!
//! Two independent reconstructions (different u) are folded into one
//! accumulator and verified, exercising the full NIFS pipeline including the
//! range proof on the quotient witnesses.
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

#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    const K: usize = 15;
}

/// Concrete coprime RNS channels. Chosen so every quotient r^(l) < Q/q_l stays
/// under the decomposition base B (norm-provable) — the real q_l chain from
/// dkg_params.rs scales the same way on a correspondingly larger P.
const QLS: [u128; 3] = [101, 103, 107];
const L_CH: usize = QLS.len();
/// LatticeFold extraction slack absorbed by the margin (§9.3).
const SLACK: u128 = 4;
/// Goldilocks modulus (the stand-in P).
const P_MOD: u128 = 0xFFFF_FFFF_0000_0001;

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

    // Quotient bounds: r^(l) < Q/q_l, and < B so the norm proof covers them.
    let mut max_cross = 0u128;
    for (l, (&q, &r)) in QLS.iter().zip(&quotients).enumerate() {
        assert!(r < big_q / q, "quotient witness {l} out of its Q/q_l bound");
        assert!(r < DP::B, "quotient witness {l} exceeds decomposition base");
        max_cross = max_cross.max(r * q);
    }
    // §9.3 no-wraparound margin, CHECKED for the concrete parameters:
    // slack · max(u, max r·q_l) < P  ⇒ the R_P identity equals the integer identity.
    assert!(
        SLACK * u.max(max_cross) < P_MOD,
        "no-wraparound margin violated for the P-track stand-in"
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

    // Two independent reconstructions (e.g. two decryption outputs).
    let u_a = (big_q * 7) / 10;
    let u_b = (big_q * 3) / 10 + 1;
    let (cm_a, wit_a) = reconstruction_instance(u_a, &ccs, &scheme);
    let (cm_b, wit_b) = reconstruction_instance(u_b, &ccs, &scheme);
    println!("Instances: u_a = {u_a}, u_b = {u_b}");
    println!("  per-channel rows u_global = u^(l) + r^(l)·q_l all satisfied in-CCS ✓");
    println!("  quotient witnesses r^(l) < Q/q_l < B (norm-provable) ✓");
    println!("  §9.3 margin: {SLACK}·max(u, r·q_l) < P checked numerically ✓\n");

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
        println!("Negative check: corrupted channel-2 residue REJECTED by the CCS ✓\n");
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
    println!("to one u_global via L quotient-witness rows, wrong residues rejected, margin");
    println!("checked. dkg_r7_crt.rs derives the P bit-length for the production chain;");
    println!("this slice proves the same identity shape inside the CCS.");
}
