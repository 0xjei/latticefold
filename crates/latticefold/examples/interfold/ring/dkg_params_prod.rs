//! Production parameter search: the single secure parameter set covering
//! the committee (N=100/H=51/T=27) and the lbfv multiplication example
//! (`trbfv_mul_bfv_share_binding` in fhe.rs: d=16384, 4x61-bit, Q ~ 2^244).
//!
//! Searches for:
//! - 4 x 61-bit channel primes with `q ≡ 2097153 (mod 2^22)` (subsumes the
//!   NTT condition `q ≡ 1 (mod 2N)` for N=16384 and the LatticeFold
//!   congruence `q ≡ 1+2t (mod 4t)` for t = 2^20);
//! - the reconstruction prime P (247-bit, same congruence, safe form
//!   `P - 1 = 2^21 * m` with m prime, `P > 4Q`);
//! - prints the NTT roots (primitive 2N-th roots) per prime and for P.
//!
//! Run: cargo run --release --example dkg_params_prod

use num_bigint::BigUint;
use num_traits::{One, Zero};

const RES: u64 = 1 + 2 * (1 << 20); // 2097153
const MOD: u64 = 4 * (1 << 20); // 2^22
const DEGREE: u64 = 16384;
const T: u64 = 1 << 20;

fn small_primes(limit: u32) -> Vec<u32> {
    let mut sieve = vec![true; limit as usize];
    sieve[0] = false;
    sieve[1] = false;
    for i in 2..limit {
        if sieve[i as usize] {
            let mut j = i as u64 * i as u64;
            while j < limit as u64 {
                sieve[j as usize] = false;
                j += i as u64;
            }
        }
    }
    (2..limit).filter(|&i| sieve[i as usize]).collect()
}

fn is_prime_big(n: &BigUint, smalls: &[u32]) -> bool {
    let two = BigUint::from(2u32);
    if n < &two {
        return false;
    }
    for &s in smalls {
        let divisor = BigUint::from(s);
        if n == &divisor {
            return true;
        }
        if n % &divisor == BigUint::zero() {
            return false;
        }
    }
    let one = BigUint::one();
    let mut d = n - &one;
    let mut r = 0u32;
    while &d % &two == BigUint::zero() {
        d >>= 1;
        r += 1;
    }
    'witness: for witness in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = BigUint::from(witness).modpow(&d, n);
        if x == one || x == n - &one {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = (&x * &x) % n;
            if x == n - &one {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn mod_pow_u64(base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let mut b = (base % modulus) as u128;
    let m = modulus as u128;
    while exp != 0 {
        if exp & 1 == 1 {
            result = result * b % m;
        }
        b = b * b % m;
        exp >>= 1;
    }
    result as u64
}

/// Smallest primitive root g mod p (p prime); psi = g^((p-1)/2N).
fn primitive_root_u64(p: u64, smalls: &[u32]) -> u64 {
    let mut rest = p - 1;
    let mut factors = Vec::new();
    for &s in smalls {
        while rest % s as u64 == 0 {
            factors.push(s as u64);
            rest /= s as u64;
        }
    }
    if rest > 1 {
        factors.push(rest);
    }
    factors.dedup();
    let mut g = 2u64;
    loop {
        if factors.iter().all(|&f| mod_pow_u64(g, (p - 1) / f, p) != 1) {
            return g;
        }
        g += 1;
    }
}

fn ntt_root_u64(p: u64, smalls: &[u32]) -> u64 {
    mod_pow_u64(primitive_root_u64(p, smalls), (p - 1) / (2 * DEGREE), p)
}

fn primitive_root_big(p: &BigUint, smalls: &[u32]) -> BigUint {
    let one = BigUint::one();
    let mut rest = p - &one;
    let mut factors: Vec<BigUint> = Vec::new();
    for &s in smalls {
        let divisor = BigUint::from(s);
        while &rest % &divisor == BigUint::zero() {
            if !factors.contains(&divisor) {
                factors.push(divisor.clone());
            }
            rest /= &divisor;
        }
    }
    if rest > one {
        factors.push(rest);
    }
    let mut g = BigUint::from(2u32);
    loop {
        if factors
            .iter()
            .all(|f| g.modpow(&((p - &one) / f), p) != one)
        {
            return g;
        }
        g += &one;
    }
}

fn ntt_root_big(p: &BigUint, smalls: &[u32]) -> BigUint {
    let one = BigUint::one();
    let two_n = BigUint::from(2 * DEGREE);
    primitive_root_big(p, smalls).modpow(&((p - &one) / &two_n), p)
}

fn main() {
    let smalls = small_primes(2000);

    // ---- 4 x 61-bit channel primes (step DOWN from just below 2^61, like
    // the lbfv example's 0x1fffffffff...... primes) ----
    let mut channels = Vec::new();
    let mut q = RES + ((1u64 << 61) / MOD) * MOD;
    if q >= 1u64 << 61 {
        q -= MOD;
    }
    while channels.len() < 4 {
        if is_prime_big(&BigUint::from(q), &smalls) {
            channels.push(q);
        }
        q -= MOD;
    }
    println!("channel primes (61-bit, q = {RES} mod {MOD}):");
    let mut product = BigUint::one();
    for &prime in &channels {
        println!(
            "  {prime:#018x}  generator = {}, psi = {}",
            primitive_root_u64(prime, &smalls),
            ntt_root_u64(prime, &smalls)
        );
        product *= prime;
    }
    let q_bits = product.bits();
    println!(
        "log2 Q = {:.4}, Q mod t = {}",
        q_bits as f64,
        &product % BigUint::from(T)
    );
    debug_assert_eq!(q_bits, 244);

    // ---- P: ~250-bit (Fp256, 4 limbs), same congruence, safe form, P > 4Q.
    // The R7 per-term margin with the tight CRT-quotient decomposition
    // (B' = 2^11, L' = 17): extracted |r| <= 2*C_q, need 2*C_q*q_l < P/2.
    let four_q = &product << 2;
    let modulus_big = BigUint::from(MOD);
    // Tight decomposition parameters and capacity C = (B/2)(B^L-1)/(B-1):
    // log2(C) = 10 + log2(2^187 - 1) - log2(2^11 - 1) ~ 186.
    let (b_prime, l_prime) = (1u64 << 11, 17u32);
    let capacity_log2 = 186.0f64;
    let q_l_max = *channels.iter().max().unwrap() as f64;
    let need_log2 = 1.0 + capacity_log2 + q_l_max.log2() + 1.0; // 2*C_q*q_l < P/2
    println!(
        "R7 margin input: C_q ~ 2^{capacity_log2:.1}, 2*C_q*q_l ~ 2^{:.1} => P must exceed ~2^{:.1}",
        need_log2 - 1.0,
        need_log2
    );
    let mut p = BigUint::one() << (need_log2.ceil() as usize + 1);
    p = &p / &modulus_big * &modulus_big + RES;
    let mut tries = 0u64;
    let found_p = loop {
        tries += 1;
        if is_prime_big(&p, &smalls) {
            let m: BigUint = (&p - BigUint::one()) >> 21;
            if is_prime_big(&m, &smalls) {
                break p;
            }
        }
        p += &modulus_big;
    };
    let m: BigUint = (&found_p - BigUint::one()) >> 21;
    println!(
        "P = {found_p}\n  bits = {}, tries = {tries}, P mod 2^22 = {}, m bits = {}",
        found_p.bits(),
        &found_p % &modulus_big,
        m.bits()
    );
    println!(
        "  P > 4Q: {}, P/2^{need_log2:.0} satisfied: {}",
        &found_p > &four_q,
        found_p.bits() as f64 > need_log2
    );
    println!(
        "  generator_P = {}, psi_P = {}",
        primitive_root_big(&found_p, &smalls),
        ntt_root_big(&found_p, &smalls)
    );

    // ---- Share-encryption (R3 digit transport) primes are unchanged
    // (62-bit, q = 131073 mod 2^18, two-adicity 17 >= 15 for N=16384);
    // only their NTT roots change. ----
    for prime in [0x800000000004001u64, 0x800000000044001u64] {
        println!(
            "R3 prime {prime:#x}: 2N-adicity check = {}, psi = {:#x}",
            prime % (2 * DEGREE),
            ntt_root_u64(prime, &smalls)
        );
    }
}
