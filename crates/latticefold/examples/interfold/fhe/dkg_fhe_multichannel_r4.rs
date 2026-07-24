//! Full-committee multi-channel integration: H dealers, threshold T, one Z_Q
//! sharing per dealer projected to the q0/q1/q2 RNS channels, BFV transport,
//! per-channel folded R4 accumulators, and CRT recombination. The committee
//! sizes N/H/T are configurable.
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_fhe_multichannel_r4 --features fhe-bridge
//!   cargo +1.91.1 run --release --example dkg_fhe_multichannel_r4 --features fhe-bridge \
//!     -- --n 100 --h 51 --t 27 --recipient 3
//!
//! Pass `-- --help` for the full option list.

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use latticefold::fhe_bridge::CommitteeConfig;

    let config = CommitteeConfig::from_env_args()?;
    latticefold::fhe_bridge::round_trip_multichannel_committee_r4(&config)?;
    println!(
        "N={}/H={}/T={} committee (recipient {}, session {}), \
         q0/q1/q2 R2 -> BFV -> folded R4 + CRT recombination: validated",
        config.committee_n,
        config.honest_h,
        config.threshold_t,
        config.recipient_id,
        config.session_id,
    );
    Ok(())
}

#[cfg(not(feature = "fhe-bridge"))]
fn main() {
    eprintln!("run with --features fhe-bridge");
}
