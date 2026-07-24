//! Full native VDKG flow: P1 DKG (R1 + R2 + R3 transport + folded R4) ->
//! P2 threshold public-key aggregation (R5) -> P3 user encryption (Ruser) ->
//! P4 threshold decryption (folded R6 + interpolation + P-track R7 CRT/decode),
//! over the native q0/q1/q2 RNS channels and the reconstruction prime P.
//! The user message is encrypted under the aggregated threshold key and
//! recovered by the committee, matching the coordination-trilemma flow with
//! native folding in place of recursive proof aggregation (the C5/C7 ZK
//! aggregation proofs remain out of scope).
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_fhe_full_flow --features fhe-bridge
//!   cargo +1.91.1 run --release --example dkg_fhe_full_flow --features fhe-bridge \
//!     -- --params n8192 --n 3 --h 3 --t 2 --recipient 2
//!
//! `--params n4096` (default) selects the N=4096 engineering candidate;
//! `--params n8192` selects the N=8192 parameter set matching the Noir
//! `secure-8192` security (`t = 2^20`, 3x58-bit channels, 176-bit P).
//! The transported recipient must be one of the T reconstructing parties
//! (`--recipient <= --t`). Pass `-- --help` for the full option list.

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use latticefold::{
        fhe_bridge::CommitteeConfig,
        vdkg_params::{VdkgParams, N4096Params, N8192Params},
    };

    let args: Vec<String> = std::env::args().collect();
    let mut params = "n4096".to_string();
    let mut filtered: Vec<String> = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--params" {
            params = args
                .get(index + 1)
                .ok_or("missing value for --params")?
                .clone();
            index += 2;
        } else {
            filtered.push(args[index].clone());
            index += 1;
        }
    }
    let config = {
        // from_env_args reads real argv; reconstruct it without --params.
        // There is no setter, so parse inline instead.
        let mut config = CommitteeConfig::default();
        let mut index = 1; // skip binary name
        while index < filtered.len() {
            let flag = filtered[index].as_str();
            let value = filtered
                .get(index + 1)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            match flag {
                "--n" => config.committee_n = value.parse()?,
                "--h" => config.honest_h = value.parse()?,
                "--t" => config.threshold_t = value.parse()?,
                "--recipient" => config.recipient_id = value.parse()?,
                "--session" => config.session_id = value.parse()?,
                "--help" => {
                    println!(
                        "dkg_fhe_full_flow [--params n4096|n8192] [--n N] [--h H] [--t T] \
                         [--recipient ID] [--session ID]"
                    );
                    return Ok(());
                }
                other => return Err(format!("unknown argument '{other}'").into()),
            }
            index += 2;
        }
        config.validate()?;
        config
    };
    if config.recipient_id > config.threshold_t {
        return Err(format!(
            "--recipient ({}) must be one of the T ({}) reconstructing parties",
            config.recipient_id, config.threshold_t
        )
        .into());
    }

    let start = std::time::Instant::now();
    let (recovered, message, degree) = match params.as_str() {
        "n4096" => {
            let message = (0..N4096Params::DEGREE)
                .map(|c| (7 + 31 * c as u64) % N4096Params::THRESHOLD_PLAINTEXT)
                .collect::<Vec<_>>();
            let recovered = latticefold::vdkg_flow::run_full_flow(&config, &message)?;
            (recovered, message, "N=4096")
        }
        "n8192" => {
            let message = (0..N8192Params::DEGREE)
                .map(|c| (7 + 31 * c as u64) % N8192Params::THRESHOLD_PLAINTEXT)
                .collect::<Vec<_>>();
            let recovered = latticefold::vdkg_flow::run_full_flow_n8192(&config, &message)?;
            (recovered, message, "N=8192")
        }
        other => return Err(format!("unknown --params '{other}' (want n4096|n8192)").into()),
    };
    assert_eq!(recovered, message, "decrypted plaintext mismatch");

    println!(
        "{degree} N={}/H={}/T={} committee (recipient {}, session {}): full P1->P4 flow \
         validated in {:.1}s — DKG (R1..R4), aggregation (R5), user encryption (Ruser), \
         threshold decryption (R6 + R7/P) recovered the {}-coefficient message",
        config.committee_n,
        config.honest_h,
        config.threshold_t,
        config.recipient_id,
        config.session_id,
        start.elapsed().as_secs_f64(),
        message.len(),
    );
    Ok(())
}

#[cfg(not(feature = "fhe-bridge"))]
fn main() {
    eprintln!("run with --features fhe-bridge");
}
