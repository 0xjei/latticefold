//! Validate and print the N=4096 native VDKG parameter candidate.
//!
//! Run with:
//!   cargo run --release --example dkg_n4096_params

use latticefold::vdkg_params::{
    validate_n4096, N4096_DEGREE, N4096_RECONSTRUCTION_MODULUS, N4096_SHARE_ENCRYPTION_MODULI,
    N4096_SHARE_PLAINTEXT_MODULUS, N4096_THRESHOLD_MODULI, N4096_THRESHOLD_MODULUS_PRODUCT,
    N4096_THRESHOLD_PLAINTEXT_MODULUS,
};

fn main() {
    assert!(validate_n4096(), "N=4096 parameter validation failed");
    println!("N = {N4096_DEGREE}");
    println!("threshold plaintext modulus = {N4096_THRESHOLD_PLAINTEXT_MODULUS}");
    println!("threshold moduli = {N4096_THRESHOLD_MODULI:#x?}");
    println!("Q = {N4096_THRESHOLD_MODULUS_PRODUCT}");
    println!("P = {N4096_RECONSTRUCTION_MODULUS:#x}");
    println!("share plaintext modulus = {N4096_SHARE_PLAINTEXT_MODULUS}");
    println!("share-encryption moduli = {N4096_SHARE_ENCRYPTION_MODULI:#x?}");
    println!("N=4096 native parameter candidate: validated");
}
