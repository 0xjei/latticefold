//! Full-committee R2 -> BFV -> metadata-bound and folded R4 integration on the
//! q0 channel, with a configurable N/H/T committee.
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_fhe_committee_r4 --features fhe-bridge
//!   cargo +1.91.1 run --release --example dkg_fhe_committee_r4 --features fhe-bridge \
//!     -- --n 100 --h 51 --t 27 --recipient 3
//!
//! Pass `-- --help` for the full option list.

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use latticefold::fhe_bridge::CommitteeConfig;

    let config = CommitteeConfig::from_env_args()?;
    latticefold::fhe_bridge::round_trip_shamir_committee_r4(&config)?;
    println!(
        "N={}/H={}/T={} committee (recipient {}, session {}): \
         R2 -> BFV -> folded metadata-bound R4: validated",
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
