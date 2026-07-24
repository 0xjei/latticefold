//! **Step 2 completion (in-repo half): the full constant set for a custom
//! `stark-rings` ring model, derived and machine-verified at production degree.**
//!
//! `dkg_params.rs` proved the production chains need §8.1 (odd t) and that a
//! power-of-two t ≥ N is directly compatible. `dkg_ring_ntt.rs` proved the NTT
//! kernel on a toy prime. This slice does the remaining derivable work: for
//! t = 2^14 and N = 8192 it
//!
//!   1. SEARCHES a concrete 3-prime ~51-bit RNS chain with the JOINT congruence
//!      q ≡ 1 (mod 2N)  ∧  q ≡ 1+2t (mod 4t)   ⇔   q ≡ 32769 (mod 65536),
//!      each prime verified by deterministic Miller–Rabin;
//!   2. derives, per prime, every constant an `ark-ff` MontConfig + NTT model
//!      needs: a verified PRIMITIVE ROOT (generator), the TWO-ADICITY v₂(q−1),
//!      and the primitive 2N-th root ψ with ψ^N ≡ −1 (negacyclic);
//!   3. RUNS a radix-2 negacyclic NTT at the REAL degree N = 8192 over each
//!      prime: round-trip identity and pointwise-product == schoolbook
//!      multiplication mod X^N+1 (the full 67M-op check, not a sample);
//!   4. finds the reconstruction prime P > slack·Q under the same congruences
//!      (BigUint, since Q is 153 bits), closing the §9.3 margin for this chain;
//!   5. prints the ready-to-paste model constant block.
//!
//! What remains after this is exactly the mechanical fork: place these
//! constants into a `stark-rings` model file (the crate's orphan rule forces
//! the impl to live there) and wire `SuitableRing` + challenge set + Poseidon
//! params in `cyclotomic-rings` — no further number theory is left to derive.
//!
//! Run with: cargo run --release --example dkg_ring_model

use num_bigint::BigUint;
use num_traits::One;

/// BFV ring degree and the directly-compatible plaintext modulus t = 2^14 ≥ N? —
/// t = 2^14 = 16384 = 2N/… note N = 8192, t = 2^14 ≥ N ✓ (power-of-two case).
const N: usize = 8192;
const T_PT: u128 = 1 << 14;
/// Joint congruence: q ≡ 1 (mod 2N) ∧ q ≡ 1+2t (mod 4t) ⇔ q ≡ 1+2t (mod 4t)
/// when 4t = 65536 is a multiple of 2N = 16384 and 1+2t ≡ 1 (mod 2N).
const MODULUS_STEP: u128 = 4 * T_PT; // 65536
const RESIDUE: u128 = 1 + 2 * T_PT; // 32769
/// Target prime size and chain length.
const TARGET_BITS: u32 = 51;
const CHAIN_LEN: usize = 3;
/// Extraction slack for the P margin (§9.3).
const SLACK: u32 = 4;

// ---- u128 modular arithmetic ----------------------------------------------

fn mul_mod(a: u128, b: u128, m: u128) -> u128 {
    // a, b < 2^64 in all our uses; product fits u128.
    (a * b) % m
}

fn pow_mod(mut b: u128, mut e: u128, m: u128) -> u128 {
    let mut acc = 1u128;
    b %= m;
    while e > 0 {
        if e & 1 == 1 {
            acc = mul_mod(acc, b, m);
        }
        b = mul_mod(b, b, m);
        e >>= 1;
    }
    acc
}

/// Deterministic Miller–Rabin for u128 < 2^64-ish (standard witness set).
fn is_prime_u128(n: u128) -> bool {
    if n < 2 {
        return false;
    }
    for p in [2u128, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n == p {
            return true;
        }
        if n % p == 0 {
            return false;
        }
    }
    let mut d = n - 1;
    let mut s = 0u32;
    while d & 1 == 0 {
        d >>= 1;
        s += 1;
    }
    'w: for a in [2u128, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = pow_mod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 0..s - 1 {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                continue 'w;
            }
        }
        return false;
    }
    true
}

/// Distinct prime factors of `n` by trial division (odd parts here are ≲ 2^37,
/// so sqrt ≲ 2^19 — fast).
fn prime_factors(mut n: u128) -> Vec<u128> {
    let mut fs = Vec::new();
    let mut d = 2u128;
    while d * d <= n {
        if n % d == 0 {
            fs.push(d);
            while n % d == 0 {
                n /= d;
            }
        }
        d += 1;
    }
    if n > 1 {
        fs.push(n);
    }
    fs
}

/// Smallest primitive root mod prime q (verified against every factor of q−1).
fn primitive_root(q: u128) -> u128 {
    let fs = prime_factors(q - 1);
    'g: for g in 2u128.. {
        for f in &fs {
            if pow_mod(g, (q - 1) / f, q) == 1 {
                continue 'g;
            }
        }
        return g;
    }
    unreachable!()
}

// ---- Negacyclic NTT (radix-2, iterative) ----------------------------------

fn bit_reverse_permute(a: &mut [u128]) {
    let n = a.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            a.swap(i, j);
        }
    }
}

/// In-place forward NTT with root `omega` (primitive n-th root), modulus q.
fn ntt(a: &mut [u128], omega: u128, q: u128) {
    let n = a.len();
    bit_reverse_permute(a);
    let mut len = 2;
    while len <= n {
        let w_len = pow_mod(omega, (n / len) as u128, q);
        for start in (0..n).step_by(len) {
            let mut w = 1u128;
            for k in 0..len / 2 {
                let u = a[start + k];
                let v = mul_mod(a[start + k + len / 2], w, q);
                a[start + k] = (u + v) % q;
                a[start + k + len / 2] = (u + q - v) % q;
                w = mul_mod(w, w_len, q);
            }
        }
        len <<= 1;
    }
}

/// Negacyclic transform: weight by ψ^i, NTT with ω = ψ².
fn negacyclic_fwd(a: &[u128], psi: u128, q: u128) -> Vec<u128> {
    let mut out: Vec<u128> = a
        .iter()
        .enumerate()
        .map(|(i, &x)| mul_mod(x, pow_mod(psi, i as u128, q), q))
        .collect();
    ntt(&mut out, mul_mod(psi, psi, q), q);
    out
}

fn negacyclic_inv(a: &[u128], psi: u128, q: u128) -> Vec<u128> {
    let n = a.len() as u128;
    let psi_inv = pow_mod(psi, 2 * n - 1, q); // ψ^(2N−1) = ψ⁻¹ (ψ^2N = 1)
    let omega_inv = mul_mod(psi_inv, psi_inv, q);
    let n_inv = pow_mod(n, q - 2, q);
    let mut out = a.to_vec();
    ntt(&mut out, omega_inv, q);
    out.iter_mut().enumerate().for_each(|(i, x)| {
        *x = mul_mod(mul_mod(*x, n_inv, q), pow_mod(psi_inv, i as u128, q), q);
    });
    out
}

/// Schoolbook negacyclic product (the full O(N²) ground truth).
fn schoolbook_negacyclic(a: &[u128], b: &[u128], q: u128) -> Vec<u128> {
    let n = a.len();
    let mut c = vec![0u128; n];
    for i in 0..n {
        if a[i] == 0 {
            continue;
        }
        for j in 0..n {
            let prod = mul_mod(a[i], b[j], q);
            let k = i + j;
            if k < n {
                c[k] = (c[k] + prod) % q;
            } else {
                c[k - n] = (c[k - n] + q - prod) % q;
            }
        }
    }
    c
}

fn main() {
    println!("VDKG Step 2 (in-repo half) — custom-ring model constants, derived & verified");
    println!("N = {N}, t = 2^14 → joint congruence q ≡ {RESIDUE} (mod {MODULUS_STEP})\n");

    // ---- 1. Search the RNS chain -------------------------------------------
    let mut chain: Vec<u128> = Vec::new();
    let mut q = ((1u128 << (TARGET_BITS - 1)) / MODULUS_STEP) * MODULUS_STEP + RESIDUE;
    while chain.len() < CHAIN_LEN {
        if is_prime_u128(q) {
            chain.push(q);
        }
        q += MODULUS_STEP;
    }
    println!("RNS chain (all ≡ {RESIDUE} mod {MODULUS_STEP}, all prime):");
    for (l, &qi) in chain.iter().enumerate() {
        assert_eq!(qi % (2 * N as u128), 1, "NTT-friendliness violated");
        assert_eq!(
            qi % MODULUS_STEP,
            RESIDUE,
            "LatticeFold congruence violated"
        );
        println!(
            "  q_{l} = {qi:#x} ({} bits)  ntt-friendly ✓  lf-congruent ✓",
            128 - qi.leading_zeros()
        );
    }

    // ---- 2+3. Per-prime model constants + full-degree NTT verification ------
    let mut rng_state = 0x243F6A8885A308D3u128; // deterministic LCG for test vectors
    let mut next = |m: u128| {
        rng_state = rng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (rng_state >> 16) % m
    };

    println!("\nPer-prime model constants (generator/two-adicity/ψ), verified:");
    for (l, &qi) in chain.iter().enumerate() {
        let g = primitive_root(qi);
        let two_adicity = (qi - 1).trailing_zeros();
        assert!(two_adicity as usize >= (2 * N).trailing_zeros() as usize);
        let psi = pow_mod(g, (qi - 1) / (2 * N as u128), qi);
        assert_eq!(
            pow_mod(psi, N as u128, qi),
            qi - 1,
            "ψ^N must be −1 (negacyclic)"
        );
        assert_eq!(pow_mod(psi, 2 * N as u128, qi), 1, "ψ^2N must be 1");

        // Full-degree verification: round-trip + pointwise == schoolbook.
        let a: Vec<u128> = (0..N).map(|_| next(qi)).collect();
        let b: Vec<u128> = (0..N).map(|_| next(qi)).collect();
        let a_hat = negacyclic_fwd(&a, psi, qi);
        assert_eq!(negacyclic_inv(&a_hat, psi, qi), a, "round-trip failed");
        let b_hat = negacyclic_fwd(&b, psi, qi);
        let prod_hat: Vec<u128> = a_hat
            .iter()
            .zip(&b_hat)
            .map(|(&x, &y)| mul_mod(x, y, qi))
            .collect();
        let via_ntt = negacyclic_inv(&prod_hat, psi, qi);
        assert_eq!(
            via_ntt,
            schoolbook_negacyclic(&a, &b, qi),
            "NTT product != schoolbook"
        );

        println!("  q_{l}: generator = {g}, two_adicity = {two_adicity}, ψ = {psi}");
        println!("       NTT@N={N}: round-trip ✓  pointwise == schoolbook (full O(N²) check) ✓");
    }

    // ---- 4. Reconstruction prime P under the derived margin -----------------
    let big_q: BigUint = chain.iter().map(|&x| BigUint::from(x)).product();
    let p_min: BigUint = &big_q * BigUint::from(SLACK) + BigUint::one();
    let step = BigUint::from(MODULUS_STEP);
    let residue = BigUint::from(RESIDUE);
    let mut p: BigUint = (&p_min / &step + BigUint::one()) * &step + &residue;
    while !is_prime_big(&p) {
        p += &step;
    }
    assert_eq!(&p % (2 * N as u64), BigUint::one());
    assert_eq!(&p % &step, residue);
    assert!(p > p_min, "P must clear the §9.3 margin");
    println!("\nReconstruction prime P (> {SLACK}·Q, same congruences, prime ✓):");
    println!("  Q = Π q_l  ({} bits)", big_q.bits());
    println!("  P = {p}  ({} bits)", p.bits());

    // ---- 5. The ready-to-paste block ---------------------------------------
    println!("\n──── stark-rings model constant block (per q_l) ────");
    for (l, &qi) in chain.iter().enumerate() {
        let g = primitive_root(qi);
        println!(
            "  // q_{l}: #[modulus = \"{qi}\"] #[generator = \"{g}\"]  two_adicity = {}",
            (qi - 1).trailing_zeros()
        );
    }
    println!("\nResult: every number-theoretic constant a custom `Ring` model needs is now");
    println!("derived and verified at production degree. The remaining Step 2 work is the");
    println!("mechanical fork: a model file in `stark-rings` holding these constants (orphan");
    println!("rule forces it there) + SuitableRing/challenge-set/Poseidon wiring — no");
    println!("further derivation left, only placement.");
}

/// Miller–Rabin for BigUint (same fixed witness set as dkg_params).
fn is_prime_big(n: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    if *n < two {
        return false;
    }
    for p in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let bp = BigUint::from(p);
        if *n == bp {
            return true;
        }
        if n % &bp == BigUint::ZERO {
            return false;
        }
    }
    let one = BigUint::one();
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while &d % &two == BigUint::ZERO {
        d >>= 1;
        s += 1;
    }
    'w: for a in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = BigUint::from(a).modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..s - 1 {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'w;
            }
        }
        return false;
    }
    true
}
