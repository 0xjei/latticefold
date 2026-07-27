//! Validate and print the demo (d=4096) native VDKG parameter candidate.
//!
//! Run with:
//!   cargo run --release --example dkg_n4096_params

use latticefold::vdkg_params::{
    validate_demo, DemoParams, VdkgParams, DEMO_DEGREE, DEMO_RECONSTRUCTION_MODULUS,
    DEMO_SHARE_ENCRYPTION_MODULI, DEMO_SHARE_PLAINTEXT_MODULUS, DEMO_THRESHOLD_MODULI,
    DEMO_THRESHOLD_PLAINTEXT_MODULUS,
};

fn main() {
    assert!(validate_demo(), "demo parameter validation failed");
    println!("N = {DEMO_DEGREE}");
    println!("threshold plaintext modulus = {DEMO_THRESHOLD_PLAINTEXT_MODULUS}");
    println!("threshold moduli = {DEMO_THRESHOLD_MODULI:#x?}");
    println!("Q = {}", DemoParams::threshold_product());
    println!("P = {DEMO_RECONSTRUCTION_MODULUS}");
    println!("share plaintext modulus = {DEMO_SHARE_PLAINTEXT_MODULUS}");
    println!("share-encryption moduli = {DEMO_SHARE_ENCRYPTION_MODULI:#x?}");
    println!("d=4096 demo native parameter candidate: validated");
}
