//! Export the real C5 wrapper vectors from the protocol: run the R1 phase
//! with the fhe.rs-sampled committee and emit the Ajtai CRS matrices as Noir
//! constants plus the aggregated witness/commitment/digest/challenges as a
//! Prover.toml for the wrapper circuit, for all FOUR channels of the chosen
//! parameter set.
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_wrapper_export --features fhe-bridge,parallel \
//!     -- --params prod   # or demo

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use latticefold::fhe_bridge::CommitteeConfig;

    let mut params = "prod".to_string();
    let args: Vec<String> = std::env::args().collect();
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--params" {
            params = args
                .get(index + 1)
                .ok_or("missing value for --params")?
                .clone();
            index += 2;
        } else {
            return Err(format!("unknown argument '{}'", args[index]).into());
        }
    }

    let config = CommitteeConfig {
        committee_n: 3,
        honest_h: 3,
        threshold_t: 2,
        recipient_id: 2,
        session_id: 0,
    };
    config.validate()?;
    latticefold::fhe_bridge::ensure_large_rayon_stack();

    macro_rules! run_export {
        ($params:ty, $out:literal, $(($channel:literal, $flowq:path, $ring:ty, $cs:ty)),+ $(,)?) => {{
            use latticefold::{
                commitment::AjtaiCommitmentScheme,
                samples::sample_dealer,
                transcript::poseidon::PoseidonTranscript,
                vdkg_params::VdkgParams,
                wrapper_export::{export_c5, write_wrapper_files},
            };

            const ESM_LIMBS: usize = 6;
            const KAPPA: usize = 4;

            let dealers = (0..config.honest_h)
                .map(|_| sample_dealer::<$params>(config.honest_h, 1))
                .collect::<Result<Vec<_>, _>>()?;
            println!("sampled {} dealers via fhe.rs TRBFV", dealers.len());

            // The R1 proofs keep degree-N ring elements on the stack; run the
            // export on a dedicated big-stack thread.
            let export = std::thread::Builder::new()
                .stack_size(1 << 30)
                .spawn(move || {
                    export_c5::<$params, _>(&dealers, &config, |samples, config, channel| {
                        match channel {
                            $(
                                $channel => $flowq(samples, config),
                            )+
                            _ => unreachable!("four channels"),
                        }
                    })
                    .map_err(|e| e.to_string())
                })
                .expect("failed to spawn export thread")
                .join()
                .unwrap_or_else(|_| Err("export thread panicked".to_string()))?;
            println!("exported {} tracks", export.tracks.len());

            // Re-derive the Ajtai CRS matrices (same from_domain tags as the
            // export) and dump them as NTT-value constants for the wrapper.
            fn dump<R>(scheme: &AjtaiCommitmentScheme<R>) -> Vec<Vec<Vec<u64>>>
            where
                R: cyclotomic_rings::rings::SuitableRing,
                R::BaseRing: ark_ff::PrimeField,
            {
                use ark_ff::PrimeField;
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
            let tag = |channel: usize| {
                format!("vdkg/r1/q{channel}/N{}", <$params as VdkgParams>::DEGREE)
            };
            let ajtai_values = vec![
                $(
                    dump(&AjtaiCommitmentScheme::<$ring>::from_domain::<
                        PoseidonTranscript<$ring, $cs>,
                    >(
                        &tag($channel),
                        KAPPA,
                        (2 + ESM_LIMBS) * 5,
                        <$params as VdkgParams>::DEGREE,
                    )),
                )+
            ];

            write_wrapper_files::<$params>(&export, &ajtai_values, $out)?;
            println!("wrote {}/src/{{roots,ajtai_*.nr}} and {}/Prover.toml", $out, $out);
            Ok(())
        }};
    }

    match params.as_str() {
        "demo" => run_export!(
            latticefold::vdkg_params::DemoParams,
            "decider-circuits/c5_demo",
            (0, latticefold::vdkg_flow::demo_flow::q0::export_c5_track, cyclotomic_rings::rings::N4096Q0RingNTT, cyclotomic_rings::rings::N4096Q0ChallengeSet),
            (1, latticefold::vdkg_flow::demo_flow::q1::export_c5_track, cyclotomic_rings::rings::N4096Q1RingNTT, cyclotomic_rings::rings::N4096Q1ChallengeSet),
            (2, latticefold::vdkg_flow::demo_flow::q2::export_c5_track, cyclotomic_rings::rings::N4096Q2RingNTT, cyclotomic_rings::rings::N4096Q2ChallengeSet),
            (3, latticefold::vdkg_flow::demo_flow::q3::export_c5_track, cyclotomic_rings::rings::N4096Q3RingNTT, cyclotomic_rings::rings::N4096Q3ChallengeSet),
        ),
        "prod" => run_export!(
            latticefold::vdkg_params::ProdParams,
            "decider-circuits/c5_prod",
            (0, latticefold::vdkg_flow::prod_flow::q0::export_c5_track, cyclotomic_rings::rings::N16384Q0RingNTT, cyclotomic_rings::rings::N16384Q0ChallengeSet),
            (1, latticefold::vdkg_flow::prod_flow::q1::export_c5_track, cyclotomic_rings::rings::N16384Q1RingNTT, cyclotomic_rings::rings::N16384Q1ChallengeSet),
            (2, latticefold::vdkg_flow::prod_flow::q2::export_c5_track, cyclotomic_rings::rings::N16384Q2RingNTT, cyclotomic_rings::rings::N16384Q2ChallengeSet),
            (3, latticefold::vdkg_flow::prod_flow::q3::export_c5_track, cyclotomic_rings::rings::N16384Q3RingNTT, cyclotomic_rings::rings::N16384Q3ChallengeSet),
        ),
        other => Err(format!("unknown --params '{other}' (expected demo|prod)").into()),
    }
}

#[cfg(not(feature = "fhe-bridge"))]
fn main() {
    eprintln!("run with --features fhe-bridge");
}
