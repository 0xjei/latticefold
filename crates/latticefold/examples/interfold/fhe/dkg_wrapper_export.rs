//! Export the real C5 wrapper vectors from the protocol: run the R1 phase
//! with the fhe.rs-sampled committee and emit the Ajtai CRS matrices as Noir
//! constants plus the aggregated witness/commitment/digest/challenges as a
//! Prover.toml for the wrapper circuit. (WIP: currently wired to the demo
//! d=4096 parameter set; the `c5_8192` circuit directory it writes to is
//! stale.)
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_wrapper_export --features fhe-bridge,parallel

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cyclotomic_rings::rings::{
        N4096Q0ChallengeSet, N4096Q0RingNTT, N4096Q1ChallengeSet, N4096Q1RingNTT,
        N4096Q2ChallengeSet, N4096Q2RingNTT,
    };
    use ark_ff::PrimeField;
    use latticefold::{
        commitment::AjtaiCommitmentScheme,
        fhe_bridge::CommitteeConfig,
        samples::sample_dealer,
        transcript::poseidon::PoseidonTranscript,
        vdkg_flow::demo_flow,
        vdkg_params::{DemoParams, VdkgParams},
        wrapper_export::{export_c5, write_wrapper_files},
    };

    const OUT_DIR: &str = "decider-circuits/c5_8192";
    const ESM_LIMBS: usize = 6;
    const KAPPA: usize = 4;

    let config = CommitteeConfig {
        committee_n: 3,
        honest_h: 3,
        threshold_t: 2,
        recipient_id: 2,
        session_id: 0,
    };
    config.validate()?;

    let dealers = (0..config.honest_h)
        .map(|_| sample_dealer::<DemoParams>(config.honest_h, 1))
        .collect::<Result<Vec<_>, _>>()?;
    println!("sampled {} dealers via fhe.rs TRBFV", dealers.len());

    // The R1 proofs keep degree-N ring elements on the stack; run the
    // export on a dedicated big-stack thread with a large rayon pool.
    latticefold::fhe_bridge::ensure_large_rayon_stack();
    let export = std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            export_c5::<DemoParams, _>(&dealers, &config, |samples, config, channel| {
                match channel {
                    0 => demo_flow::q0::export_c5_track(samples, config),
                    1 => demo_flow::q1::export_c5_track(samples, config),
                    _ => demo_flow::q2::export_c5_track(samples, config),
                }
            })
            .map_err(|e| e.to_string())
        })
        .expect("failed to spawn export thread")
        .join()
        .unwrap_or_else(|_| Err("export thread panicked".to_string()))?;
    println!("exported {} tracks", export.tracks.len());

    // Re-derive the Ajtai CRS matrices (same from_domain tags as the export)
    // and dump them as NTT-value constants for the wrapper circuit.
    fn dump<R>(scheme: &AjtaiCommitmentScheme<R>) -> Vec<Vec<Vec<u64>>>
    where
        R: cyclotomic_rings::rings::SuitableRing,
        R::BaseRing: ark_ff::PrimeField,
    {
        scheme
            .matrix()
            .vals
            .iter()
            .map(|row| {
                row.iter()
                    .map(|element| {
                        element
                            .into_coeffs()
                            .into_iter()
                            .map(|c| c.into_bigint().as_ref()[0])
                            .collect::<Vec<u64>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }
    let scheme_q0 =
        AjtaiCommitmentScheme::<N4096Q0RingNTT>::from_domain::<
            PoseidonTranscript<N4096Q0RingNTT, N4096Q0ChallengeSet>,
        >("vdkg/r1/q0/N4096", KAPPA, (2 + ESM_LIMBS) * 5, DemoParams::DEGREE);
    let scheme_q1 =
        AjtaiCommitmentScheme::<N4096Q1RingNTT>::from_domain::<
            PoseidonTranscript<N4096Q1RingNTT, N4096Q1ChallengeSet>,
        >("vdkg/r1/q1/N4096", KAPPA, (2 + ESM_LIMBS) * 5, DemoParams::DEGREE);
    let scheme_q2 =
        AjtaiCommitmentScheme::<N4096Q2RingNTT>::from_domain::<
            PoseidonTranscript<N4096Q2RingNTT, N4096Q2ChallengeSet>,
        >("vdkg/r1/q2/N4096", KAPPA, (2 + ESM_LIMBS) * 5, DemoParams::DEGREE);
    let ajtai_values = vec![
        dump(&scheme_q0),
        dump(&scheme_q1),
        dump(&scheme_q2),
    ];

    write_wrapper_files::<DemoParams>(&export, &ajtai_values, OUT_DIR)?;
    println!("wrote {OUT_DIR}/src/{{roots,ajtai_0,ajtai_1,ajtai_2}}.nr and {OUT_DIR}/Prover.toml");

    // Consistency check: the re-derived scheme's matrix must match the
    // export's a_gamma (eval of matrix entry at gamma).
    {
        let modulus = export.tracks[0].modulus;
        let gamma = export.tracks[0].gamma;
        let coeffs = demo_flow::q0::ntt_to_coeffs(scheme_q0.matrix().vals[0][0]);
        let eval = {
            let mut acc = 0u128;
            for &c in coeffs.iter().rev() {
                acc = (acc * gamma as u128 + c as u128) % modulus as u128;
            }
            acc as u64
        };
        println!(
            "check: eval(scheme[0][0], gamma) = {eval}, exported a_gamma[0] = {:?}",
            export.tracks[0].a_gamma[0]
        );
    }
    Ok(())
}

#[cfg(not(feature = "fhe-bridge"))]
fn main() {
    eprintln!("run with --features fhe-bridge");
}
