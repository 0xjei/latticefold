//! Real BFV encrypted-share transport followed by one native q0 R4 opening.
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_fhe_r4 --features fhe-bridge

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    latticefold::fhe_bridge::round_trip_share_and_prove_r4(0x1234_5678)?;
    println!("fhe.rs BFV transport -> native q0 R4 opening: validated");
    Ok(())
}

#[cfg(not(feature = "fhe-bridge"))]
fn main() {
    eprintln!("run with --features fhe-bridge");
}
