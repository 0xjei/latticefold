//! Native reconstruction-prime P ring: prove the CRT recombination of three
//! RNS channel residues inside the demo P field ring.
//!
//! The reconstructed value is written in Garner mixed-radix form
//! `v = r0 + q0 * t1 + q0 * q1 * t2` with `r0 < q0`, `t1 < q1`, `t2 < q2`.
//! Every term is below q0*q1*q2 < P, so the relation holds over the integers
//! and is one linear R1CS row in the P ring. The residues and Garner digits
//! are the committed witness; the reconstructed value is the public input.
//! (The full four-channel Garner form used by the protocol is the R7 track
//! in `vdkg_flow`; this slice demonstrates the pattern on a three-prime
//! prefix of the demo chain, whose product still fits `u128`.)
//!
//! Run with:
//!   cargo run --release --example dkg_p_reconstruction

use cyclotomic_rings::rings::{N4096PChallengeSet, N4096PRingNTT};
use latticefold::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::linearization::{
        LFLinearizationProver, LFLinearizationVerifier, LinearizationProver, LinearizationVerifier,
    },
    transcript::poseidon::PoseidonTranscript,
    vdkg_params::DEMO_THRESHOLD_MODULI,
};
use stark_rings_linalg::SparseMatrix;

type PRing = N4096PRingNTT;
type PTranscript = PoseidonTranscript<PRing, N4096PChallengeSet>;

/// Product of the three-prime Garner prefix of the demo RNS chain (fits
/// `u128`; the full four-channel product does not).
const DEMO_PREFIX_PRODUCT: u128 = {
    let [q0, q1, q2, _] = DEMO_THRESHOLD_MODULI;
    q0 as u128 * q1 as u128 * q2 as u128
};

#[derive(Clone)]
struct PReconstructionParams;

impl DecompositionParams for PReconstructionParams {
    const B: u128 = 1 << 15;
    const L: usize = 7;
    const B_SMALL: usize = 2;
    // P is a 133-bit field; retain enough binary limbs for signed field
    // representatives and the public-input decomposition.
    const K: usize = 134;
}

// Witness layout: z = [v, one, r0, t1, t2].
const IDX_VALUE: usize = 0;
const IDX_ONE: usize = 1;
const IDX_R0: usize = 2;
const IDX_T1: usize = 3;
const IDX_T2: usize = 4;

fn reconstruction_r1cs() -> R1CS<PRing> {
    let [q0, q1, _, _] = DEMO_THRESHOLD_MODULI;
    let one = PRing::from(1u128);
    let mut a_rows = vec![vec![]; 16];
    a_rows[0] = vec![
        (one, IDX_VALUE),
        (-one, IDX_R0),
        (-PRing::from(q0 as u128), IDX_T1),
        (-PRing::from(q0 as u128 * q1 as u128), IDX_T2),
    ];
    let mut b_rows = vec![vec![]; 16];
    b_rows[0] = vec![(one, IDX_ONE)];
    R1CS::<PRing> {
        l: 1,
        A: SparseMatrix {
            nrows: 16,
            ncols: 5,
            coeffs: a_rows,
        },
        B: SparseMatrix {
            nrows: 16,
            ncols: 5,
            coeffs: b_rows,
        },
        C: SparseMatrix {
            nrows: 16,
            ncols: 5,
            coeffs: vec![vec![]; 16],
        },
    }
}

/// Garner digits of a value below the three-prime prefix product.
fn garner_digits(value: u128) -> (u64, u64, u64) {
    let [q0, q1, q2, _] = DEMO_THRESHOLD_MODULI;
    let r0 = (value % q0 as u128) as u64;
    let t1 = ((value / q0 as u128) % q1 as u128) as u64;
    let t2 = (value / (q0 as u128 * q1 as u128)) as u64;
    assert!(t2 < q2, "value is not in the prefix reconstruction range");
    (r0, t1, t2)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A representative aggregated value produced by threshold reconstruction
    // on the three-prime prefix of the demo channels.
    let value: u128 = DEMO_PREFIX_PRODUCT - 0xDEAD_BEEF_CAFE;
    let (r0, t1, t2) = garner_digits(value);
    assert_eq!(
        r0 as u128
            + DEMO_THRESHOLD_MODULI[0] as u128 * t1 as u128
            + DEMO_THRESHOLD_MODULI[0] as u128 * DEMO_THRESHOLD_MODULI[1] as u128 * t2 as u128,
        value
    );

    // The decomposed witness has 3 * L = 21 limbs; pad the CCS to 32.
    let ccs = CCS::from_r1cs(reconstruction_r1cs(), 32);
    let z = vec![
        PRing::from(value),
        PRing::from(1u128),
        PRing::from(r0 as u128),
        PRing::from(t1 as u128),
        PRing::from(t2 as u128),
    ];
    ccs.check_relation(&z)?;

    let mut rng = ark_std::rand::rngs::OsRng;
    let scheme: AjtaiCommitmentScheme<PRing> =
        AjtaiCommitmentScheme::rand(4, 3 * PReconstructionParams::L, &mut rng);
    let witness = Witness::from_w_ccs::<PReconstructionParams>(vec![
        PRing::from(r0 as u128),
        PRing::from(t1 as u128),
        PRing::from(t2 as u128),
    ]);
    let cm = CCCS {
        cm: witness.commit::<PReconstructionParams>(&scheme)?,
        x_ccs: vec![PRing::from(value)],
    };

    let mut prover_transcript = PTranscript::default();
    let (prover_lcccs, proof) = LFLinearizationProver::<PRing, PTranscript>::prove(
        &cm,
        &witness,
        &mut prover_transcript,
        &ccs,
    )?;
    let mut verifier_transcript = PTranscript::default();
    let verifier_lcccs = LFLinearizationVerifier::<PRing, PTranscript>::verify(
        &cm,
        &proof,
        &mut verifier_transcript,
        &ccs,
    )?;
    assert_eq!(
        prover_lcccs, verifier_lcccs,
        "P reconstruction linearization mismatch"
    );
    assert_eq!(
        verifier_lcccs.x_w,
        vec![PRing::from(value)],
        "P reconstruction was not bound to the public reconstructed value"
    );

    // The commitment must reopen to the same Garner digits and reject others.
    let reopened = Witness::from_w_ccs::<PReconstructionParams>(witness.w_ccs.clone());
    assert_eq!(
        cm.cm,
        reopened.commit::<PReconstructionParams>(&scheme)?,
        "P reconstruction commitment did not reopen"
    );
    let tampered = Witness::from_w_ccs::<PReconstructionParams>(vec![
        PRing::from(r0 as u128 + 1),
        PRing::from(t1 as u128),
        PRing::from(t2 as u128),
    ]);
    assert_ne!(
        cm.cm,
        tampered.commit::<PReconstructionParams>(&scheme)?,
        "P reconstruction commitment accepted a tampered residue"
    );

    // A wrong reconstruction target must fail the relation.
    let mut bad_z = z.clone();
    bad_z[IDX_VALUE] = PRing::from(value + 1);
    assert!(
        ccs.check_relation(&bad_z).is_err(),
        "P reconstruction accepted a wrong recombined value"
    );

    println!("v = r0 + q0*t1 + q0*q1*t2 over the demo P ring: validated");
    println!("value = {value:#x}");
    Ok(())
}
