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

#[cfg(test)]
mod tests {
    use super::*;

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
}
