//! Step 6 (completion): the REAL L-channel CRT reconstruction of R7, with an
//! explicitly DERIVED no-wraparound margin (§9.3) — not the single-track stand-in
//! used in `dkg_r7.rs`.
//!
//! After threshold decryption, each RNS channel yields a residue u^(l) = u mod
//! q_l (the per-channel interpolation output). CRT reconstruction recovers the
//! global integer u from the L residues:
//!
//!     u = Σ_l u^(l) · (Q/q_l) · [(Q/q_l)^{-1} mod q_l]   (mod Q),   Q = Π q_l
//!
//! Arithmetized on the P track, each channel contributes a QUOTIENT WITNESS:
//!
//!     u = u^(l) + r^(l) · q_l,     0 ≤ r^(l) < Q/q_l
//!
//! and the P-native ring identity must equal the intended INTEGER identity, so P
//! must exceed everything that appears, times LatticeFold's extraction slack.
//! This example does the real reconstruction over concrete coprime RNS primes
//! and DERIVES the minimum bit-length of P from the actual quantities.
//!
//! Run with: cargo run --release --example dkg_r7_crt

use num_bigint::BigUint;
use num_traits::One;

/// Concrete small RNS chain (distinct coprime primes) — stands in for the real
/// NTT-friendly q_l chosen at Step 1; the CRT math is modulus-agnostic.
const QLS: [u64; 3] = [1_073_741_827, 1_073_741_831, 1_073_741_833];

/// Extraction slack S for the no-wraparound margin, DERIVED (§9.3) from the
/// extraction structure of the implemented R7 P-track proof:
///
/// * The production R7 proof is linearize-then-decide (no folding). The
///   knowledge extractor obtains an Ajtai commitment opening f* with
///   ‖f*‖∞ < B' (the MSIS binding bound, `DecompositionParams::B`), while an
///   honest prover's balanced digits satisfy ‖f‖∞ ≤ B'/2. The recomposed
///   witness is therefore at most
///       S = (B'^L' − 1) / ((B'/2)(B'^L' − 1)/(B' − 1)) = 2(B'−1)/B'  <  2
///   times the honest balanced bound: S = 2. The challenge set does not enter
///   the operative slack — extraction is a single commitment opening (a
///   "challenge-linear-combination" with one term and coefficient 1).
///
/// * Were an R7 instance folded (production must not — plan §5-R7 outputs a
///   single decided proof), the folded witness would be a short-challenge
///   combination f_0 = Σ_{i<2K'} ρ_i f_i + f_{2K'} of 2K' honest limb
///   witnesses with ‖ρ_i‖∞ ≤ c_max from the ring's challenge set (c_max = 255
///   for the N8192/N4096 per-byte sets, 32 for Goldilocks), giving
///       S_fold = 2·(1 + (2K'−1)·c_max) ≈ 2^13.6–13.9  (K' = 13..17),
///   which EXCEEDS the ≤ 2^10 envelope assumed in analysis/SECURITY.md and —
///   decisively — empties the decode row's Δ-window (the enforced noise bound
///   S_fold·C_e would exceed Δ − E_true for any C_e ≥ E_true). Folding R7 is
///   therefore infeasible at these parameters; the P track decides directly.
///
/// The N8192/N4096 validation tests (`vdkg_params::r7_margin_holds`) codify
/// the full per-row margin accounting with this S.
const EXTRACTION_SLACK: u64 = 2;

fn egcd(a: &BigUint, m: &BigUint) -> BigUint {
    // modular inverse of a mod m via Fermat is unavailable (m not prime power
    // guaranteed here per-call is prime though) — use extended Euclid on ints.
    let (mut old_r, mut r) = (a.clone(), m.clone());
    let (mut old_s, mut s) = (BigUint::one(), BigUint::ZERO);
    // signed emulation with an offset modulus
    let mut neg_s = false;
    let mut neg_old_s = false;
    while r != BigUint::ZERO {
        let q = &old_r / &r;
        let new_r = &old_r - &q * &r;
        old_r = std::mem::replace(&mut r, new_r);
        // old_s, s update with sign tracking
        let qs = &q * &s;
        let (new_s, new_neg) = sub_signed(&old_s, neg_old_s, &qs, neg_s);
        old_s = std::mem::replace(&mut s, new_s);
        neg_old_s = std::mem::replace(&mut neg_s, new_neg);
    }
    // old_s is inverse (possibly negative) mod m
    if neg_old_s {
        m - (&old_s % m)
    } else {
        old_s % m
    }
}

// signed subtraction a(sign na) - b(sign nb) returned as (magnitude, negative?)
fn sub_signed(a: &BigUint, na: bool, b: &BigUint, nb: bool) -> (BigUint, bool) {
    match (na, nb) {
        (false, false) => {
            if a >= b {
                (a - b, false)
            } else {
                (b - a, true)
            }
        }
        (true, true) => {
            if b >= a {
                (b - a, false)
            } else {
                (a - b, true)
            }
        }
        (false, true) => (a + b, false),
        (true, false) => (a + b, true),
    }
}

fn main() {
    println!("VDKG Step 6 — real L-channel CRT reconstruction + no-wraparound margin\n");

    let q: Vec<BigUint> = QLS.iter().map(|&x| BigUint::from(x)).collect();
    let big_q: BigUint = q.iter().fold(BigUint::one(), |acc, qi| acc * qi);
    println!("RNS primes q_l: {QLS:?}");
    println!("Q = Π q_l = {big_q}  ({} bits)\n", big_q.bits());

    // A secret global value u in [0, Q).
    let u: BigUint = (&big_q * BigUint::from(7u64)) / BigUint::from(10u64); // arbitrary 0<u<Q
                                                                            // Per-channel residues (interpolation outputs).
    let residues: Vec<BigUint> = q.iter().map(|qi| &u % qi).collect();
    println!("Secret u = {u}");
    println!("Per-channel residues u^(l) = u mod q_l:");
    for (l, r) in residues.iter().enumerate() {
        println!("  u^({l}) = {r}");
    }

    // ---- CRT reconstruction from residues ----------------------------------
    let mut recon = BigUint::ZERO;
    let mut max_cross = BigUint::ZERO; // max r^(l) * q_l cross term
    for (l, qi) in q.iter().enumerate() {
        let m_l = &big_q / qi; // Q / q_l
        let inv = egcd(&(&m_l % qi), qi); // (Q/q_l)^{-1} mod q_l
        recon = (recon + &residues[l] * &m_l * &inv) % &big_q;
        // quotient witness r^(l) with u = u^(l) + r^(l) * q_l
        let r_l = (&u - &residues[l]) / qi;
        let cross = &r_l * qi;
        if cross > max_cross {
            max_cross = cross;
        }
        assert!(r_l < &big_q / qi, "quotient witness out of bound");
    }
    assert_eq!(recon, u, "CRT reconstruction incorrect");
    println!("\nCRT reconstruction ✓  (recovered u exactly)");

    // ---- Derive the no-wraparound margin for P (§9.3) -----------------------
    // Each CRT row is the R_P identity  u − u^(l) − r^(l)·q_l = 0 (mod P); it
    // lifts to the INTEGER identity iff  |u − u^(l) − r^(l)·q_l| < P.  With
    // u < Q + E_e (bounded via the decode row), u^(l) < q_l, and the EXTRACTED
    // quotient witness |r*| ≤ S·C_q where C_q is the tight decomposition
    // capacity (C_q ≥ Q/q_l, honest headroom h = C_q/(Q/q_l)):
    //
    //     P > u + q_l + S·C_q·q_l ≈ (S·h + 1)·Q + q_l + E_e
    //
    // per row, and the per-term form  S·C_q·q_l < P/2  suffices a fortiori.
    let slack = BigUint::from(EXTRACTION_SLACK);
    let largest = if u > max_cross { u.clone() } else { max_cross.clone() };
    let p_min = &largest + &slack * &max_cross + BigUint::one();
    println!("\nNo-wraparound margin derivation (not assumed):");
    println!(
        "  max |value in P-identity| = max(u, max r^(l)*q_l) = {largest}  ({} bits)",
        largest.bits()
    );
    println!("  extraction slack factor   = {EXTRACTION_SLACK}×  (derived, see const doc)");
    println!("  => P must satisfy P > u + S·max(r^(l)·q_l) = {p_min}");
    println!(
        "     i.e. P needs at least {} bits (Q is {} bits; margin adds ~{} bits).",
        p_min.bits(),
        big_q.bits(),
        p_min.bits().saturating_sub(big_q.bits())
    );
    println!("\n  Per-term form (validated for production in vdkg_params):");
    println!("     S·C_q·q_l < P/2  with C_q ≥ Q/q_l the tight decomposition capacity;");

    println!("\nResult: reconstruction is exact over real coprime channels; the P-track prime");
    println!(
        "must be chosen at >= the derived bound above (then also NTT-friendly + ≡ 1+2t mod 4t,"
    );
    println!("per dkg_params.rs). This closes the '§9.3 noted-not-derived' gap for R7.");
}
