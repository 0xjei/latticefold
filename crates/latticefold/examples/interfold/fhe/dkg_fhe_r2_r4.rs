//! Real degree-1 Shamir R2 share -> BFV transport -> metadata-bound q0 R4.
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_fhe_r2_r4 --features fhe-bridge

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    latticefold::fhe_bridge::round_trip_shamir_share_and_prove_r4(0x1234_5678, 1, 2, 0)?;
    println!("R2 Shamir -> fhe.rs BFV -> metadata-bound q0 R4: validated");
    Ok(())
}

#[cfg(not(feature = "fhe-bridge"))]
fn main() {
    eprintln!("run with --features fhe-bridge");
}
