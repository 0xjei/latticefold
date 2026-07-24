//! Validated parameter candidates for the native LatticeFold VDKG path.
//!
//! These constants are an engineering candidate, not a certified security
//! level. The validation here covers the arithmetic prerequisites: probable
//! primality, NTT-friendliness, the LatticeFold congruence, distinct moduli,
//! and the reconstruction-prime margin.

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Ring degree for the smaller production-oriented candidate.
pub const N4096_DEGREE: usize = 4096;

/// Threshold plaintext modulus, chosen as a power of two and at least N.
pub const N4096_THRESHOLD_PLAINTEXT_MODULUS: u64 = 1 << 13;

/// Native threshold-BFV RNS chain.
pub const N4096_THRESHOLD_MODULI: [u64; 3] = [0x20004c001, 0x2000f4001, 0x200164001];

/// Product of [`N4096_THRESHOLD_MODULI`].
pub const N4096_THRESHOLD_MODULUS_PRODUCT: u128 = 634029627889566009658444496897;

/// Reconstruction modulus candidate, greater than four times Q.
pub const N4096_RECONSTRUCTION_MODULUS: u128 = 0x80000000000000000000064001;

/// Plaintext modulus for individual BFV share transport.
pub const N4096_SHARE_PLAINTEXT_MODULUS: u64 = 1 << 34;

/// NTT-friendly chain used by the individual BFV transport instance.
pub const N4096_SHARE_ENCRYPTION_MODULI: [u64; 2] = [0x2000000001be0001, 0x2000000001960001];

// ---------------------------------------------------------------------------
// N=8192 candidate, matching the security of the Noir/UltraHonk `secure-8192`
// preset used by the coordination-trilemma circuits:
//
//   Noir preset        : N=8192, t=1_000_000, 3 x 58-bit primes (log2 Q ~ 172),
//                        share-encryption t = max(q_l), 2 x 60-bit primes,
//                        statistical lambda = 50, B = 20, B_chi = 1,
//                        Eq4 security cap log2(q) <= log2(B) + (d-75)/37.5
//                        (= 220.8 at d=8192).
//
//   This candidate     : N=8192, t=2^20 = 1_048_576 (>= their plaintext space,
//                        and the smallest power of two covering it), 3 x 58-bit
//                        primes (log2 Q = 174), same share-encryption shape.
//
// The Noir preset's t = 1_000_000 = 2^6 * 15625 is STRUCTURALLY incompatible
// with the LatticeFold congruence (q = 1+2t mod 4t contradicts q = 1 mod 2N
// with gcd 256: 1 vs 129, found by `dkg_params`), so t is rounded up to 2^20.
// Every prime below satisfies q = 2097153 mod 2^22, which subsumes both
// q = 1 mod 2N (NTT-friendly, X^8192+1 splits completely) and the LatticeFold
// congruence q = 1+2t mod 4t. Same correctness accounting (Eq1 margin ~8.2
// bits vs their ~6.3) and the same Eq4 security cap (174 <= 220.8).
//
// This is a parameter-search target, not a security certification: run a
// current lattice estimator before claiming 128-bit post-quantum security.
// ---------------------------------------------------------------------------

/// Ring degree for the production-matching candidate.
pub const N8192_DEGREE: usize = 8192;

/// Threshold plaintext modulus: the smallest power of two covering the Noir
/// preset's 1_000_000.
pub const N8192_THRESHOLD_PLAINTEXT_MODULUS: u64 = 1 << 20;

/// Native threshold-BFV RNS chain (58-bit primes, `q = 2097153 mod 2^22`).
pub const N8192_THRESHOLD_MODULI: [u64; 3] = [
    0x03fffffffea00001,
    0x03fffffffc600001,
    0x03fffffff8200001,
];

/// Reconstruction modulus candidate (176-bit, greater than four times Q).
///
/// Chosen of safe form (`P - 1 = 2^21 * m` with `m` prime) so a certified
/// primitive root exists for the Montgomery field configuration.
pub const N8192_RECONSTRUCTION_MODULUS: &str =
    "95780971232337531050942682516136025943519008502317057";

/// Plaintext modulus for individual BFV share transport: the largest
/// threshold prime, mirroring the Noir preset's `t_share = max(q_l)` rule.
pub const N8192_SHARE_PLAINTEXT_MODULUS: u64 = N8192_THRESHOLD_MODULI[0];

/// NTT-friendly 60-bit chain used by the individual BFV transport instance
/// (off-chain data plane only, so no LatticeFold congruence is required).
pub const N8192_SHARE_ENCRYPTION_MODULI: [u64; 2] = [0x800000000004001, 0x800000000044001];

// ---------------------------------------------------------------------------
// R3 share-transport chain (digit-form share encryption).
//
// The R3 relation proves BFV encryption of a share under the recipient's
// individual key. Shares are transported as their base-B decomposition DIGITS
// (the same digits the R2 commitments bind), so the transport plaintext
// modulus only needs to exceed the digit bound: t_share = 2^16 > B = 2^15.
// Both primes are < 2^62 (fhe.rs modulus limit), satisfy q = 1+2^17
// (mod 2^18) — subsuming NTT-friendliness for N = 4096 and N = 8192 and
// the LatticeFold congruence with t = 2^16 — and give Q_share ~ 2^124
// (Delta ~ 2^108 of noise headroom).
// ---------------------------------------------------------------------------

/// Plaintext modulus of the digit-form R3 transport instance.
pub const R3_PLAINTEXT_MODULUS: u64 = 1 << 16;

/// Ciphertext moduli of the digit-form R3 transport instance.
pub const R3_MODULI: [u64; 2] = [0x3fffffffffbe0001, 0x3ffffffffeda0001];

/// Validate the R3 chain: NTT-friendly for both degrees and
/// LatticeFold-congruent with t = 2^16.
#[must_use]
pub fn validate_r3_chain() -> bool {
    let t = R3_PLAINTEXT_MODULUS;
    R3_MODULI.iter().copied().all(|modulus| {
        probable_prime_u64(modulus)
            && modulus % (2 * N8192_DEGREE as u64) == 1
            && modulus % (2 * N4096_DEGREE as u64) == 1
            && modulus % (4 * t) == 1 + 2 * t
            && modulus > 2 * t
    }) && R3_MODULI[0] != R3_MODULI[1]
}

/// Validate the N=8192 candidate and its individual share-transport chain
/// against the Noir preset's security accounting.
#[must_use]
pub fn validate_n8192() -> bool {
    let two_n = 2 * N8192_DEGREE as u64;
    let four_t = 4 * N8192_THRESHOLD_PLAINTEXT_MODULUS;
    let lf_residue = 1 + 2 * N8192_THRESHOLD_PLAINTEXT_MODULUS;

    let mut product = BigUint::from(1u64);
    for (index, modulus) in N8192_THRESHOLD_MODULI.iter().copied().enumerate() {
        if !probable_prime_u64(modulus)
            || modulus % two_n != 1
            || modulus % four_t != lf_residue
            || N8192_THRESHOLD_MODULI[..index].contains(&modulus)
        {
            return false;
        }
        product *= modulus;
    }

    let p = BigUint::parse_bytes(N8192_RECONSTRUCTION_MODULUS.as_bytes(), 10)
        .expect("P constant must be decimal");
    if &p <= &(4u64 * &product)
        || &p % two_n != BigUint::one()
        || &p % four_t != BigUint::from(lf_residue)
        || !probable_prime_big(&p)
    {
        return false;
    }

    // Eq4 security cap of the Noir parameter search: log2(q) <= log2(B) +
    // (d-75)/37.5 with B = 20, d = 8192  =>  ~220.8 bits.
    let log2_q = product.bits() as f64;
    if log2_q > 20f64.log2() + (N8192_DEGREE as f64 - 75.0) / 37.5 {
        return false;
    }

    // Eq1 correctness margin with the Noir preset's accounting (n = 10,
    // z = t, lambda = 50, B = 20, B_chi = 1): 2*(B_C + n*B_sm) < Delta.
    let n = BigUint::from(10u64);
    let d = BigUint::from(N8192_DEGREE);
    let b = BigUint::from(20u64);
    let two_pow_lambda = BigUint::from(1u64) << 50u32;
    let benc_min = 2u64 * &d * &n * &b * &two_pow_lambda;
    let b_fresh = &benc_min + 2u64 * &d * &b * &n;
    let b_c = BigUint::from(N8192_THRESHOLD_PLAINTEXT_MODULUS) * &b_fresh;
    let b_sm_min = &b_c * &two_pow_lambda;
    let lhs = (&b_c + n * b_sm_min) << 1;
    let delta = &product / N8192_THRESHOLD_PLAINTEXT_MODULUS;
    if lhs >= delta {
        return false;
    }

    N8192_SHARE_PLAINTEXT_MODULUS > 0
        && N8192_SHARE_ENCRYPTION_MODULI
            .iter()
            .copied()
            .all(|modulus| {
                probable_prime_u64(modulus)
                    && modulus % two_n == 1
                    && modulus > N8192_SHARE_PLAINTEXT_MODULUS
            })
}


fn mul_mod(a: u128, b: u128, modulus: u128) -> u128 {
    (a * b) % modulus
}

fn pow_mod(mut base: u128, mut exponent: u128, modulus: u128) -> u128 {
    let mut result = 1u128;
    base %= modulus;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1;
    }
    result
}

/// Fixed-witness Miller-Rabin check for the sub-64-bit RNS moduli.
fn probable_prime_u64(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for small in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n == small {
            return true;
        }
        if n.is_multiple_of(small) {
            return false;
        }
    }

    let mut d = n - 1;
    let mut s = 0u32;
    while d.is_multiple_of(2) {
        d /= 2;
        s += 1;
    }

    'witness: for witness in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = pow_mod(witness as u128, d as u128, n as u128);
        if x == 1 || x == (n - 1) as u128 {
            continue;
        }
        for _ in 0..s.saturating_sub(1) {
            x = mul_mod(x, x, n as u128);
            if x == (n - 1) as u128 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn probable_prime_big(n: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    if n < &two {
        return false;
    }
    for small in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let divisor = BigUint::from(small);
        if n == &divisor {
            return true;
        }
        if n % &divisor == BigUint::zero() {
            return false;
        }
    }

    let one = BigUint::one();
    let mut d = n - &one;
    let mut s = 0u32;
    while &d % &two == BigUint::zero() {
        d >>= 1;
        s += 1;
    }

    'witness: for witness in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = BigUint::from(witness).modpow(&d, n);
        if x == one || x == n - &one {
            continue;
        }
        for _ in 0..s.saturating_sub(1) {
            x = (&x * &x) % n;
            if x == n - &one {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// Validate the N=4096 candidate and its individual share-transport chain.
#[must_use]
pub fn validate_n4096() -> bool {
    let two_n = 2 * N4096_DEGREE as u64;
    let four_t = 4 * N4096_THRESHOLD_PLAINTEXT_MODULUS;
    let lf_residue = 1 + 2 * N4096_THRESHOLD_PLAINTEXT_MODULUS;

    let mut product = 1u128;
    for (index, modulus) in N4096_THRESHOLD_MODULI.iter().copied().enumerate() {
        if !probable_prime_u64(modulus)
            || modulus % two_n != 1
            || modulus % four_t != lf_residue
            || N4096_THRESHOLD_MODULI[..index].contains(&modulus)
        {
            return false;
        }
        product *= modulus as u128;
    }
    if product != N4096_THRESHOLD_MODULUS_PRODUCT {
        return false;
    }

    if N4096_RECONSTRUCTION_MODULUS <= 4 * product
        || N4096_RECONSTRUCTION_MODULUS % two_n as u128 != 1
        || N4096_RECONSTRUCTION_MODULUS % four_t as u128 != lf_residue as u128
        || !probable_prime_big(&BigUint::from(N4096_RECONSTRUCTION_MODULUS))
    {
        return false;
    }

    N4096_SHARE_PLAINTEXT_MODULUS > N4096_THRESHOLD_MODULI.iter().copied().max().unwrap_or(0)
        && N4096_SHARE_ENCRYPTION_MODULI
            .iter()
            .copied()
            .all(|modulus| probable_prime_u64(modulus) && modulus % two_n == 1)
}

/// A validated parameter set for the native VDKG path: one threshold-BFV RNS
/// chain (three channels), the plaintext modulus, and the individual BFV
/// share-transport chain.
pub trait VdkgParams: 'static {
    /// Ring degree N.
    const DEGREE: usize;
    /// Threshold plaintext modulus t.
    const THRESHOLD_PLAINTEXT: u64;
    /// The three threshold-BFV RNS channel moduli.
    const THRESHOLD_MODULI: [u64; 3];
    /// Plaintext modulus of the individual BFV share-transport instance.
    const SHARE_PLAINTEXT: u64;
    /// Ciphertext moduli of the individual BFV share-transport instance.
    const SHARE_MODULI: [u64; 2];

    /// Product Q of the three channel moduli.
    fn threshold_product() -> BigUint {
        Self::THRESHOLD_MODULI
            .iter()
            .map(|&modulus| BigUint::from(modulus))
            .product()
    }

    /// BFV scaling factor Delta = floor(Q / t) (exact: every q_l = 1 mod t,
    /// so Q = 1 mod t).
    fn delta() -> BigUint {
        (Self::threshold_product() - 1u64) / Self::THRESHOLD_PLAINTEXT
    }
}

/// The N=4096 engineering candidate.
pub struct N4096Params;

impl VdkgParams for N4096Params {
    const DEGREE: usize = N4096_DEGREE;
    const THRESHOLD_PLAINTEXT: u64 = N4096_THRESHOLD_PLAINTEXT_MODULUS;
    const THRESHOLD_MODULI: [u64; 3] = N4096_THRESHOLD_MODULI;
    const SHARE_PLAINTEXT: u64 = N4096_SHARE_PLAINTEXT_MODULUS;
    const SHARE_MODULI: [u64; 2] = N4096_SHARE_ENCRYPTION_MODULI;
}

/// The N=8192 candidate matching the Noir `secure-8192` security.
pub struct N8192Params;

impl VdkgParams for N8192Params {
    const DEGREE: usize = N8192_DEGREE;
    const THRESHOLD_PLAINTEXT: u64 = N8192_THRESHOLD_PLAINTEXT_MODULUS;
    const THRESHOLD_MODULI: [u64; 3] = N8192_THRESHOLD_MODULI;
    const SHARE_PLAINTEXT: u64 = N8192_SHARE_PLAINTEXT_MODULUS;
    const SHARE_MODULI: [u64; 2] = N8192_SHARE_ENCRYPTION_MODULI;
}

#[cfg(test)]
mod tests {    use super::*;

    #[test]
    fn n4096_candidate_is_valid() {
        assert!(validate_n4096());
    }

    #[test]
    fn n4096_product_and_margin_are_explicit() {
        let product = N4096_THRESHOLD_MODULI
            .iter()
            .fold(1u128, |acc, &modulus| acc * modulus as u128);
        assert_eq!(product, N4096_THRESHOLD_MODULUS_PRODUCT);
        assert!(N4096_RECONSTRUCTION_MODULUS > 4 * product);
    }

    #[test]
    fn n8192_candidate_matches_noir_secure_preset_security() {
        assert!(validate_n8192());
        let log2_q = N8192_THRESHOLD_MODULI
            .iter()
            .fold(BigUint::from(1u64), |acc, &m| acc * m)
            .bits();
        // Same shape as the Noir secure-8192 preset: 3 x 58-bit, log2 Q ~ 174.
        assert_eq!(log2_q, 174);
    }

    #[test]
    fn r3_chain_is_valid_for_both_degrees() {
        assert!(validate_r3_chain());
    }
}
