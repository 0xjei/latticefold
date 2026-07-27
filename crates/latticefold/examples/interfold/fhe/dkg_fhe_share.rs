//! First real `fhe.rs` integration milestone: one BFV encrypted-share round trip.
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_fhe_share --features fhe-bridge

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use latticefold::{fhe_bridge::round_trip_share, vdkg_params::DEMO_DEGREE};

    let share = 0x1234_5678u64;
    let decoded = round_trip_share(share)?;
    assert_eq!(decoded.first().copied(), Some(share));
    assert_eq!(decoded.len(), DEMO_DEGREE);
    assert!(decoded.iter().skip(1).all(|coefficient| *coefficient == 0));

    println!("fhe.rs BFV share round trip: validated");
    println!(
        "degree = {DEMO_DEGREE}, share = {share}, decoded[0] = {}",
        decoded[0]
    );
    Ok(())
}

#[cfg(not(feature = "fhe-bridge"))]
fn main() {
    eprintln!("run with --features fhe-bridge");
}
