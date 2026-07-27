//! Step 1 of the VDKG implementation plan, run against a CONCRETE production
//! parameter set (`secure_8192`, degree-8192 threshold-BFV + DKG-BFV).
//!
//! A prime usable as an RNS channel in this design must satisfy TWO conditions:
//!
//!   (1) NTT-friendly for the negacyclic ring R = Z[X]/(X^N + 1):  q ≡ 1 (mod 2N)
//!       — fhe.rs needs this for its NTT.
//!   (2) LatticeFold's ring congruence:                            q ≡ 1+2t (mod 4t)
//!       — so the challenge-set / splitting machinery applies.
//!
//! This tool VERIFIES the real production moduli (threshold + DKG chains) against
//! both conditions and reports, per set, whether the native-q_l approach works or
//! the §8.1 extension-field fallback is required.
//!
//! Run with: cargo run --release --example dkg_params

use num_bigint::BigUint;
use num_traits::One;

/// Ring degree N of the secure_8192 preset.
const N: u64 = 8192;

/// secure_8192 threshold-BFV chain.
const THRESHOLD_T: u64 = 1_000_000;
const THRESHOLD_MODULI: &[u64] = &[0x02000000015a0001, 0x0200000001460001, 0x0200000001210001];

/// secure_8192 DKG-BFV chain.
const DKG_T: u64 = 144_115_188_098_531_329;
const DKG_MODULI: &[u64] = &[0x0800000000004001, 0x0800000000044001];

/// Deterministic Miller–Rabin (fixed witnesses; deterministic well past 64-bit).
fn is_prime(n: &BigUint) -> bool {
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
    'witness: for a in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let a = BigUint::from(a);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..s - 1 {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let (mut a, mut b) = (a.clone(), b.clone());
    while b != BigUint::ZERO {
        let t = b.clone();
        b = &a % &b;
        a = t;
    }
    a
}

/// Verify one RNS chain (name, t, moduli) against both conditions.
fn verify_set(name: &str, t: u64, moduli: &[u64]) {
    let two_n = BigUint::from(2 * N);
    let four_t = BigUint::from(4u64) * BigUint::from(t);
    let target2 = BigUint::from(1u64) + BigUint::from(2u64) * BigUint::from(t);

    println!("══════════════════════════════════════════════════════════");
    println!("{name}  (N = {N}, t = {t}, {} primes)", moduli.len());
    println!("  cond (1) NTT-friendly : q ≡ 1 (mod 2N = {})", 2 * N);
    println!("  cond (2) LatticeFold  : q ≡ {target2} (mod 4t = {four_t})");

    // Structural joint-feasibility (independent of the specific primes).
    let g = gcd(&two_n, &four_t);
    let r1 = BigUint::one() % &g;
    let r2 = &target2 % &g;
    let jointly_feasible = r1 == r2;
    println!(
        "  joint feasibility     : gcd(2N,4t) = {g}; need 1 ≡ {target2} (mod gcd) → {} vs {}  [{}]",
        r1,
        r2,
        if jointly_feasible { "OK" } else { "IMPOSSIBLE" }
    );
    if !jointly_feasible && t & 1 == 1 {
        println!("    root cause: odd t ⇒ 1+2t ≡ 3 (mod 4), contradicting q ≡ 1 (mod 4) from 2N.");
    }

    println!("  per-modulus check:");
    let mut all_ntt = true;
    let mut all_lf = true;
    let mut q_prod = BigUint::one();
    for (i, &m) in moduli.iter().enumerate() {
        let q = BigUint::from(m);
        let prime = is_prime(&q);
        let ntt = &q % &two_n == BigUint::one();
        let lf = &q % &four_t == target2;
        all_ntt &= ntt;
        all_lf &= lf;
        q_prod *= &q;
        println!(
            "    q_{i} = {:#018x} ({} bits)  prime:{}  ntt-friendly:{}  lf-congruent:{}",
            m,
            q.bits(),
            yn(prime),
            yn(ntt),
            yn(lf),
        );
    }
    println!("  Q = Π q_l  ({} bits)", q_prod.bits());

    println!("  VERDICT:");
    println!("    (1) NTT-friendly for all primes : {}", yn(all_ntt));
    println!("    (2) LatticeFold-congruent (all) : {}", yn(all_lf));
    if all_ntt && all_lf {
        println!("    => native q_l tracks usable directly.");
    } else if all_ntt && !all_lf {
        println!("    => NTT-friendly but NOT LatticeFold-congruent: the §8.1 small-modulus");
        println!(
            "       extension-field technique is REQUIRED to run native tracks on these primes."
        );
    } else {
        println!(
            "    => not NTT-friendly as given — unexpected for a BFV chain; recheck the preset."
        );
    }
    println!();
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "NO "
    }
}

fn main() {
    println!("VDKG Step 1 — secure_8192 parameter compatibility with LatticeFold\n");
    println!("Two BFV instances in the preset (threshold + DKG), each its own t and RNS chain,");
    println!("both over the degree-{N} ring X^{N}+1.\n");

    verify_set("THRESHOLD-BFV", THRESHOLD_T, THRESHOLD_MODULI);
    verify_set("DKG-BFV", DKG_T, DKG_MODULI);

    println!("Takeaway: production BFV moduli are chosen for NTT-friendliness (cond 1), not for");
    println!("LatticeFold's q ≡ 1+2t (mod 4t) (cond 2). Where cond 2 fails, the design's §8.1");
    println!("extension-field technique is the required path to native-q_l tracks — this is a");
    println!(
        "concrete instantiation decision Step 1 records before the custom-Ring work (Step 2)."
    );
    println!("\nNOTE: the R7 reconstruction prime P > Q must additionally clear the derived");
    println!("no-wraparound margin (see dkg_r7_crt) on top of these same two conditions.");
}
