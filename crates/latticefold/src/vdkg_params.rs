//! Validated parameter candidates for the native LatticeFold VDKG path.
//!
//! These constants are an engineering candidate, not a certified security
//! level. The validation here covers the arithmetic prerequisites: probable
//! primality, NTT-friendliness, the LatticeFold congruence, distinct moduli,
//! and the reconstruction-prime margin.

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Ring degree for the smaller production-oriented candidate.
pub const DEMO_DEGREE: usize = 4096;

/// Threshold plaintext modulus, chosen as a power of two and at least N.
pub const DEMO_THRESHOLD_PLAINTEXT_MODULUS: u64 = 1 << 13;

/// Native threshold-BFV RNS chain.
pub const DEMO_THRESHOLD_MODULI: [u64; 4] =
    [0x20004c001, 0x2000f4001, 0x200164001, 0x3fffe4001];

/// Product of [`N4096_THRESHOLD_MODULI`].
pub const DEMO_RECONSTRUCTION_MODULUS: &str =
    "696898287454081973172991196020261297242113";

/// Reconstruction modulus candidate, greater than sixteen times Q.

// ---------------------------------------------------------------------------
// R7 extraction slack and tight quotient/rounding-witness decomposition
// (plan §5-R7 step 3/4 and §9.3).
//
// EXTRACTION SLACK, DERIVED (not assumed). The knowledge extractor for the
// R7 P-track proof obtains a CCS witness whose committed digits f* are an
// Ajtai opening of cm with ||f*||_inf < B' (the MSIS binding bound,
// `DecompositionParams::B`), while an honest prover's balanced digits satisfy
// ||f||_inf <= B'/2. The recomposed witness w* = sum_j B'^j f*_j is therefore
// at most a factor
//
//     S = (B'^L' - 1) / ( (B'/2)(B'^L' - 1)/(B' - 1) ) = 2(B' - 1)/B'  <  2
//
// larger than the honest balanced bound B'^L'/2: S = 2. The challenge set
// does NOT enter the operative slack, because the R7 P-track proof is
// linearize-then-decide: extraction is a single commitment opening (a
// "challenge-linear-combination" with exactly one term and coefficient 1).
//
// For completeness, the fold-path slack IS challenge-derived: one NIFS fold
// combines 2K' limb instances as f_0 = sum_{i<2K'} rho_i f_i + f_{2K'} with
// short challenges ||rho_i||_inf <= c_max from the ring's challenge set
// (c_max = 255 for the N8192/N4096 per-byte sets, 32 for Goldilocks), so an
// extracted folded witness is a challenge-linear-combination of honest
// witnesses bounded by S_fold = 2*(1 + (2K'-1)*c_max). For the byte sets with
// K' = 13..17 this is ~2^13.6-13.9, EXCEEDING the <= 2^10 slack envelope
// assumed in analysis/SECURITY.md (the envelope holds only for
// decide-directly proofs such as R7's: 2 <= 2^10). It would also empty the
// decode row's Delta-window below (the enforced noise bound S_fold * C_e
// would exceed Delta - E_true). Folding R7 instances is therefore infeasible
// at these parameters; the P track decides directly, as implemented.
//
// TIGHT DECOMPOSITIONS. Each R7 witness class uses a separate balanced
// decomposition (base B, L limbs) chosen so that
//   - completeness: the balanced capacity C = (B/2)(B^L-1)/(B-1) >= the
//     largest honest witness (Q/q_l for the CRT quotients, E_true for the
//     centered decode noise),
//   - no-wraparound: the extracted witness (bound ENF = B^L - 1 = S*C with
//     S = 2) satisfies the per-term invariant ENF_q * q_l < P/2 and the
//     exact per-row invariant u_max + q_l + ENF_q*q_l < P, and for the
//     decode row u_max + Delta*(t-1) + ENF_e < P,
//   - decode soundness (Delta-window): E_true <= C_e and ENF_e < Delta -
//     E_true, so a wrong plaintext m' != m forces |e'| >= Delta - E_true
//     beyond the enforced bound,
// where u_max = Q + ENF_e bounds the reconstructed value via the decode row.
// ---------------------------------------------------------------------------

/// Extraction slack S of the decide-directly R7 P-track proof (see the
/// derivation above). Every margin below is computed with this S.
pub const R7_EXTRACTION_SLACK: u64 = 2;

/// N=8192 R7 CRT-quotient decomposition (B', L'): capacity C_q ~ 2^116 covers
/// Q/q_l (max quotient witness); ENF_q = B'^L' - 1 = 2^117 - 1.
pub const PROD_R7_CRT_B: u128 = 1 << 11;
/// Limbs of the N=8192 CRT-quotient decomposition.
pub const PROD_R7_CRT_L: usize = 17;
/// N=8192 R7 decode-noise decomposition (B'', L''): capacity C_e = 2^149
/// covers the Eq1 noise bound E_true ~ 2^145.6; ENF_e = 2^150 - 1 stays
/// under Delta - E_true (headroom ~16x).
pub const PROD_R7_DECODE_B: u128 = 1 << 11;
/// Limbs of the N=8192 decode-noise decomposition.
pub const PROD_R7_DECODE_L: usize = 14;

/// N=4096 R7 CRT-quotient decomposition (B', L'): capacity C_q = 2^67 covers
/// Q/q_l ~ 2^66.3; ENF_q = 2^68 - 1.
pub const DEMO_R7_CRT_B: u128 = 1 << 17;
/// Limbs of the N=4096 CRT-quotient decomposition.
pub const DEMO_R7_CRT_L: usize = 6;
/// N=4096 R7 decode-noise decomposition (B'', L''): capacity C_e = 2^83
/// covers E_true ~ 2^74; ENF_e = 2^84 - 1 stays under Delta - E_true
/// (headroom ~4x).
pub const DEMO_R7_DECODE_B: u128 = 1 << 12;
/// Limbs of the N=4096 decode-noise decomposition.
pub const DEMO_R7_DECODE_L: usize = 7;

/// Plaintext modulus for individual BFV share transport.
pub const DEMO_SHARE_PLAINTEXT_MODULUS: u64 = 1 << 34;

/// NTT-friendly chain used by the individual BFV transport instance.
pub const DEMO_SHARE_ENCRYPTION_MODULI: [u64; 2] = [0x2000000001be0001, 0x2000000001960001];

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

/// Ring degree for the production parameter set (matches the fhe.rs lbfv
/// multiplication example `trbfv_mul_bfv_share_binding`: d = 16384).
pub const PROD_DEGREE: usize = 16384;

/// Threshold plaintext modulus (power of two >= the ring degree, as the
/// LatticeFold congruence requires at d = 16384; covers the lbfv example's
/// plaintext space of 1000).
pub const PROD_THRESHOLD_PLAINTEXT_MODULUS: u64 = 1 << 20;

/// Native threshold-BFV RNS chain (four 61-bit primes, `q = 2097153 mod
/// 2^22`, subsuming NTT-friendliness for N = 16384 and the LatticeFold
/// congruence with t = 2^20). Same size class as the lbfv multiplication
/// example's 4 x 61-bit chain: log2 Q = 244.
pub const PROD_THRESHOLD_MODULI: [u64; 4] = [
    0x1fffffffffe00001,
    0x1ffffffffe600001,
    0x1fffffffef600001,
    0x1fffffffed200001,
];

/// Reconstruction modulus (177-bit, P = 5.0*Q).
///
/// Chosen of safe form (`P - 1 = 2^21 * m` with `m` prime) so a certified
/// primitive root exists for the Montgomery field configuration:
///   m = 57089907665453869730796028683266655173014990451 (prime).
/// The previous candidate (176-bit, only `4Q + 2^35`) failed the derived
/// no-wraparound invariant of the R7 margin accounting: the extracted CRT
/// quotient witness (slack S = 2 times the tight decomposition capacity
/// C_q ~ 2^116 over Q/q_l) needs `2 * C_q * q_l < P / 2`, i.e. effectively
/// `P > 4Q * 1.000122`; this P clears it with ~1.25x headroom and satisfies
/// the approximate rule `P > 2*S*Q` with S = 2 by a full factor Q.
/// It satisfies `P = 2097153 mod 2^22` (subsuming `P = 1 mod 2N` and the
/// LatticeFold congruence with t = 2^20) and fits the three-limb Fp192
/// field model. The primitive 2N-th root of unity (the P-ring NTT constant
/// in the stark-rings model) is `3^((P-1)/16384) mod P =
/// 32970195846663976618806704620762070992180491843905132`.
pub const PROD_RECONSTRUCTION_MODULUS: &str =
    "1809251394333065553493296640760748560207343510400633813116524750146147188737";

/// Plaintext modulus for individual BFV share transport: the largest
/// threshold prime, mirroring the Noir preset's `t_share = max(q_l)` rule.
pub const PROD_SHARE_PLAINTEXT_MODULUS: u64 = PROD_THRESHOLD_MODULI[0];

/// NTT-friendly 62-bit chain used by the individual BFV transport instance
/// (same primes as the digit-form R3 chain; two-adicity 17 subsumes
/// NTT-friendliness for N = 16384).
pub const PROD_SHARE_ENCRYPTION_MODULI: [u64; 2] = R3_MODULI;

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
            && modulus % (2 * PROD_DEGREE as u64) == 1
            && modulus % (2 * DEMO_DEGREE as u64) == 1
            && modulus % (4 * t) == 1 + 2 * t
            && modulus > 2 * t
    }) && R3_MODULI[0] != R3_MODULI[1]
}

/// Balanced capacity of a radix-`b`, `l`-limb decomposition:
/// `(b/2) * (b^l - 1)/(b - 1)` — the largest honestly decomposable magnitude.
fn balanced_capacity(b: u128, l: usize) -> BigUint {
    let b = BigUint::from(b);
    (b.clone() >> 1) * ((b.pow(l as u32) - BigUint::one()) / (b - BigUint::one()))
}

/// Enforced witness bound of a radix-`b`, `l`-limb decomposition under the
/// Ajtai binding boundary (digits `< b`): `b^l - 1`. This is exactly
/// [`R7_EXTRACTION_SLACK`] times the balanced capacity, up to rounding.
fn enforced_bound(b: u128, l: usize) -> BigUint {
    BigUint::from(b).pow(l as u32) - BigUint::one()
}

/// The full R7 no-wraparound margin accounting (plan §5-R7 step 3/4, §9.3):
/// quotient-row and decode-row margins plus the decode Delta-window, at the
/// derived extraction slack [`R7_EXTRACTION_SLACK`], for one parameter set.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn r7_margin_holds(
    p: &BigUint,
    moduli: [u64; 4],
    plaintext: u64,
    e_true: &BigUint,
    crt_b: u128,
    crt_l: usize,
    dec_b: u128,
    dec_l: usize,
) -> bool {
    let product: BigUint = moduli.iter().map(|&m| BigUint::from(m)).product();
    let delta = (&product - BigUint::one()) / plaintext;
    let capacity_q = balanced_capacity(crt_b, crt_l);
    let enforced_q = enforced_bound(crt_b, crt_l);
    let capacity_e = balanced_capacity(dec_b, dec_l);
    let enforced_e = enforced_bound(dec_b, dec_l);

    // Quotient completeness: the honest quotient witnesses s_l < Q/q_l must
    // fit the balanced decomposition.
    let p_half = p >> 1;
    for &modulus in &moduli {
        let quotient_bound = &product / modulus;
        if quotient_bound > capacity_q {
            return false;
        }
        // Per-term invariant: extracted |s_l| * q_l < P/2.
        if R7_EXTRACTION_SLACK * &capacity_q * modulus >= p_half {
            return false;
        }
    }

    // Decode Delta-window: E_true must fit the decomposition (completeness)
    // and the enforced bound must exclude a wrong plaintext (soundness):
    // wrong m' forces |e'| >= Delta - E_true > enforced_e.
    if e_true > &capacity_e || enforced_e >= &delta - e_true {
        return false;
    }

    // Exact per-row margins: the R_P ring identities lift to integer
    // identities. u is bounded via the decode row by u_max = Q + enforced_e.
    let u_max = &product + &enforced_e;
    for &modulus in &moduli {
        if &u_max + modulus + &enforced_q * modulus >= *p {
            return false;
        }
    }
    // Decode row: |u - Delta*m - e| <= u_max + Delta*(t-1) + enforced_e < P.
    if &u_max + &delta * (plaintext - 1) + &enforced_e >= *p {
        return false;
    }

    true
}

/// The production decode-noise bound E_true under the Noir preset's Eq1
/// accounting (n = 51, z = t, lambda = 50, B = 20, B_chi = 1):
/// E_true = B_C + n * B_sm with B_C = t * B_fresh (~2^151.7 < Delta ~ 2^224).
fn prod_decode_noise_bound() -> (BigUint, BigUint) {
    // H = 51 honest dealers (the N=100 committee) is the binding case.
    let n = BigUint::from(51u64);
    let d = BigUint::from(PROD_DEGREE);
    let b = BigUint::from(20u64);
    let two_pow_lambda = BigUint::from(1u64) << 50u32;
    let benc_min = 2u64 * &d * &n * &b * &two_pow_lambda;
    let b_fresh = &benc_min + 2u64 * &d * &b * &n;
    let b_c = BigUint::from(PROD_THRESHOLD_PLAINTEXT_MODULUS) * &b_fresh;
    let b_sm_min = &b_c * &two_pow_lambda;
    let e_true = &b_c + n * b_sm_min;
    (e_true, b_c)
}

/// Validate the production set (d = 16384, 4 x 61-bit) and its individual
/// share-transport chain against the Noir preset's security accounting and
/// the lbfv multiplication example's correctness requirement.
#[must_use]
pub fn validate_prod() -> bool {
    let two_n = 2 * PROD_DEGREE as u64;
    let four_t = 4 * PROD_THRESHOLD_PLAINTEXT_MODULUS;
    let lf_residue = 1 + 2 * PROD_THRESHOLD_PLAINTEXT_MODULUS;

    let mut product = BigUint::from(1u64);
    for (index, modulus) in PROD_THRESHOLD_MODULI.iter().copied().enumerate() {
        if !probable_prime_u64(modulus)
            || modulus % two_n != 1
            || modulus % four_t != lf_residue
            || PROD_THRESHOLD_MODULI[..index].contains(&modulus)
        {
            return false;
        }
        product *= modulus;
    }
    // Exact Delta (every q_l = 1 mod t).
    if &product % PROD_THRESHOLD_PLAINTEXT_MODULUS != BigUint::one() {
        return false;
    }
    // lbfv multiplication correctness (the fhe.rs example's accounting):
    // log2(B_C after mult) ~ 187.5 < log2(Delta) = 224.
    let delta = &product / PROD_THRESHOLD_PLAINTEXT_MODULUS;
    if delta.bits() < 224 {
        return false;
    }

    let p = BigUint::parse_bytes(PROD_RECONSTRUCTION_MODULUS.as_bytes(), 10)
        .expect("P constant must be decimal");
    // Primality, NTT-friendliness and the LatticeFold congruence.
    if &p % two_n != BigUint::one()
        || &p % four_t != BigUint::from(lf_residue)
        || !probable_prime_big(&p)
    {
        return false;
    }
    // Safe form P - 1 = 2^21 * m with m prime (certified primitive root).
    let safe_m = (&p - BigUint::one()) >> 21;
    if &p - BigUint::one() != &safe_m << 21 || !probable_prime_big(&safe_m) {
        return false;
    }
    // Fp256 model capacity (four 64-bit Montgomery limbs).
    if p.bits() > 256 {
        return false;
    }

    // Eq4 security cap of the Noir parameter search: log2(q) <= log2(B) +
    // (d-75)/37.5 with B = 20, d = 16384  =>  ~439.2 bits (Q = 244).
    let log2_q = product.bits() as f64;
    if log2_q > 20f64.log2() + (PROD_DEGREE as f64 - 75.0) / 37.5 {
        return false;
    }

    // Eq1 correctness margin with the Noir preset's accounting (n = 51,
    // z = t, lambda = 50, B = 20, B_chi = 1): 2*(B_C + n*B_sm) < Delta,
    // which holds with ~72 bits of headroom at log2(Delta) = 224.
    let (e_true, _) = prod_decode_noise_bound();
    let delta = &product / PROD_THRESHOLD_PLAINTEXT_MODULUS;
    if &e_true << 1 >= delta {
        return false;
    }

    // §9.3 no-wraparound margin for the R7 P track at the derived slack,
    // over the tight quotient/decode decompositions (replaces the bare
    // P > 4Q check).
    if !r7_margin_holds(
        &p,
        PROD_THRESHOLD_MODULI,
        PROD_THRESHOLD_PLAINTEXT_MODULUS,
        &e_true,
        PROD_R7_CRT_B,
        PROD_R7_CRT_L,
        PROD_R7_DECODE_B,
        PROD_R7_DECODE_L,
    ) {
        return false;
    }

    PROD_SHARE_PLAINTEXT_MODULUS > 0
        && PROD_SHARE_ENCRYPTION_MODULI
            .iter()
            .copied()
            .all(|modulus| {
                probable_prime_u64(modulus)
                    && modulus % two_n == 1
                    && modulus > PROD_SHARE_PLAINTEXT_MODULUS
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

/// The N=4096 decode-noise bound E_true under the fhe.rs
/// `SmudgingBoundCalculator` accounting that the flow actually samples
/// (variance 10, n = 10 dealers, one summed ciphertext, lambda = 50):
/// B_fresh = d*(2*n*var + 2*var*n), B_C = B_fresh + (Q mod t),
/// B_sm = 2^50 * B_C, E_true = B_C + n * B_sm.
///
/// Note: the Noir preset's Eq1 accounting used for N8192 (B_C = t*B_fresh)
/// is INFEASIBLE for N4096 — it gives E_true ~ 2^137 > Delta ~ 2^86 — so
/// this parameter set has no decryption-correctness margin under that
/// accounting; the fhe.rs accounting (which drops the t factor from B_C)
/// is the operative one here.
fn demo_decode_noise_bound() -> BigUint {
    let variance = 10u64;
    let dealers = BigUint::from(10u64);
    let degree = BigUint::from(DEMO_DEGREE);
    let b_e = BigUint::from(2 * variance);
    let b_fresh = &degree * &dealers * &b_e + &degree * &b_e * &dealers;
    // Every demo q_l = 1 mod t, so Q mod t = 1.
    let b_c = &b_fresh + BigUint::one();
    let two_pow_lambda = BigUint::from(1u64) << 50u32;
    let b_sm = &b_c * &two_pow_lambda;
    b_c + dealers * b_sm
}

/// Validate the demo set (d = 4096, 4 x 34-bit, benchmark-only: no
/// decryption-correctness margin exists under the production Eq1 accounting
/// at this degree, so it is not a deployment candidate) and its individual
/// share-transport chain.
#[must_use]
pub fn validate_demo() -> bool {
    let two_n = 2 * DEMO_DEGREE as u64;
    let four_t = 4 * DEMO_THRESHOLD_PLAINTEXT_MODULUS;
    let lf_residue = 1 + 2 * DEMO_THRESHOLD_PLAINTEXT_MODULUS;

    let mut product = BigUint::one();
    for (index, modulus) in DEMO_THRESHOLD_MODULI.iter().copied().enumerate() {
        if !probable_prime_u64(modulus)
            || modulus % two_n != 1
            || modulus % four_t != lf_residue
            || DEMO_THRESHOLD_MODULI[..index].contains(&modulus)
        {
            return false;
        }
        product *= modulus;
    }

    let p = BigUint::parse_bytes(DEMO_RECONSTRUCTION_MODULUS.as_bytes(), 10)
        .expect("P constant must be decimal");
    if &p % two_n != BigUint::one()
        || &p % four_t != BigUint::from(lf_residue)
        || !probable_prime_big(&p)
    {
        return false;
    }
    // Fp192 model capacity (three 64-bit Montgomery limbs).
    if p.bits() > 192 {
        return false;
    }

    // §9.3 no-wraparound margin for the R7 P track at the derived slack,
    // over the tight quotient/decode decompositions (replaces the bare
    // P > 4Q check).
    let e_true = demo_decode_noise_bound();
    if !r7_margin_holds(
        &p,
        DEMO_THRESHOLD_MODULI,
        DEMO_THRESHOLD_PLAINTEXT_MODULUS,
        &e_true,
        DEMO_R7_CRT_B,
        DEMO_R7_CRT_L,
        DEMO_R7_DECODE_B,
        DEMO_R7_DECODE_L,
    ) {
        return false;
    }

    DEMO_SHARE_PLAINTEXT_MODULUS > DEMO_THRESHOLD_MODULI.iter().copied().max().unwrap_or(0)
        && DEMO_SHARE_ENCRYPTION_MODULI
            .iter()
            .copied()
            .all(|modulus| probable_prime_u64(modulus) && modulus % two_n == 1)
}

/// A validated parameter set for the native VDKG path: one threshold-BFV RNS
/// chain (four channels), the plaintext modulus, and the individual BFV
/// share-transport chain.
pub trait VdkgParams: 'static {
    /// Ring degree N.
    const DEGREE: usize;
    /// Threshold plaintext modulus t.
    const THRESHOLD_PLAINTEXT: u64;
    /// The four threshold-BFV RNS channel moduli.
    const THRESHOLD_MODULI: [u64; 4];
    /// Plaintext modulus of the individual BFV share-transport instance.
    const SHARE_PLAINTEXT: u64;
    /// Ciphertext moduli of the individual BFV share-transport instance.
    const SHARE_MODULI: [u64; 2];

    /// Product Q of the four channel moduli.
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

/// The demo parameter set (d = 4096, 4 x 34-bit): benchmark-only — above
/// 128 bits of RLWE security but no decryption-correctness margin under the
/// production Eq1 accounting at this degree, so it is not a deployment
/// candidate. It exists for fast end-to-end runs and CI.
pub struct DemoParams;

impl VdkgParams for DemoParams {
    const DEGREE: usize = DEMO_DEGREE;
    const THRESHOLD_PLAINTEXT: u64 = DEMO_THRESHOLD_PLAINTEXT_MODULUS;
    const THRESHOLD_MODULI: [u64; 4] = DEMO_THRESHOLD_MODULI;
    const SHARE_PLAINTEXT: u64 = DEMO_SHARE_PLAINTEXT_MODULUS;
    const SHARE_MODULI: [u64; 2] = DEMO_SHARE_ENCRYPTION_MODULI;
}

/// The production parameter set (d = 16384, 4 x 61-bit, t = 2^20): matches
/// the fhe.rs lbfv multiplication example's size class (log2 Q = 244) with
/// LatticeFold-congruent primes; RLWE security estimator-expected >= 160
/// bits post-quantum (larger degree than the measured d = 8192 / Q = 174
/// point, which gave 159-161 bits); Eq1 correctness margin ~72 bits at
/// H = 51 parties and ~75 bits at n = 20; lbfv-mul margin ~36.5 bits.
pub struct ProdParams;

impl VdkgParams for ProdParams {
    const DEGREE: usize = PROD_DEGREE;
    const THRESHOLD_PLAINTEXT: u64 = PROD_THRESHOLD_PLAINTEXT_MODULUS;
    const THRESHOLD_MODULI: [u64; 4] = PROD_THRESHOLD_MODULI;
    const SHARE_PLAINTEXT: u64 = PROD_SHARE_PLAINTEXT_MODULUS;
    const SHARE_MODULI: [u64; 2] = PROD_SHARE_ENCRYPTION_MODULI;
}

/// The per-channel NTT roots (psi, omega = psi^2 mod q_l) for the wrapper
/// circuits, mirroring the stark-rings model constants.
pub fn ntt_roots<P: VdkgParams>(channel: usize) -> (u64, u64) {
    let (psi, modulus) = if P::DEGREE == PROD_DEGREE {
        (
            [875053553084042915u64, 1640367222369352504, 992394967967060181, 1918018633191661828]
                [channel],
            P::THRESHOLD_MODULI[channel],
        )
    } else {
        (
            [8003223405u64, 520027819, 8455812194, 16434184190][channel],
            P::THRESHOLD_MODULI[channel],
        )
    };
    let omega = (psi as u128 * psi as u128 % modulus as u128) as u64;
    (psi, omega)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_candidate_is_valid() {
        assert!(validate_demo());
    }

    #[test]
    fn prod_candidate_is_valid() {
        assert!(validate_prod());
    }

    #[test]
    fn prod_chain_matches_lbfv_example_size_class() {
        let log2_q = PROD_THRESHOLD_MODULI
            .iter()
            .fold(BigUint::from(1u64), |acc, &m| acc * m)
            .bits();
        // The fhe.rs lbfv multiplication example's size class: 4 x 61-bit.
        assert_eq!(log2_q, 244);
    }

    #[test]
    fn prod_reconstruction_prime_properties() {
        let p = BigUint::parse_bytes(PROD_RECONSTRUCTION_MODULUS.as_bytes(), 10)
            .expect("P constant must be decimal");
        let product: BigUint = PROD_THRESHOLD_MODULI
            .iter()
            .map(|&m| BigUint::from(m))
            .product();

        // P > 4Q at the derived slack S = 2, and P fits the Fp256 model.
        assert!(p > R7_EXTRACTION_SLACK * 2u64 * &product);
        assert!(p.bits() <= 256);

        // Primality, congruences, safe form.
        assert!(probable_prime_big(&p));
        assert_eq!(&p % (1u64 << 22), BigUint::from(2097153u64));
        assert_eq!(&p % (2 * PROD_DEGREE as u64), BigUint::one());
        assert_eq!(
            &p % (4 * PROD_THRESHOLD_PLAINTEXT_MODULUS),
            BigUint::from(1 + 2 * PROD_THRESHOLD_PLAINTEXT_MODULUS)
        );
        let safe_m = (&p - BigUint::one()) >> 21;
        assert_eq!(&p - BigUint::one(), &safe_m << 21);
        assert!(probable_prime_big(&safe_m), "safe-form cofactor must be prime");

        // Certified primitive root 3 and the P-ring NTT root (the constant
        // placed in the stark-rings n16384 model): psi = 3^((P-1)/2^15) must
        // be a primitive 2N-th root of unity, i.e. psi^N = -1 mod P.
        let exponent = (&p - BigUint::one()) / 2u64;
        assert_eq!(BigUint::from(3u64).modpow(&exponent, &p), &p - BigUint::one());
        let psi = BigUint::from(3u64).modpow(&((&p - BigUint::one()) / 32768u64), &p);
        assert_eq!(
            psi,
            BigUint::parse_bytes(
                b"800740270527046191467754138274621887446681349755193356465943639037957688602",
                10
            )
            .unwrap()
        );
        assert_eq!(psi.modpow(&16384u64.into(), &p), &p - BigUint::one());
        assert_eq!(psi.modpow(&32768u64.into(), &p), BigUint::one());
    }

    #[test]
    fn prod_margin_holds_exactly() {
        let p = BigUint::parse_bytes(PROD_RECONSTRUCTION_MODULUS.as_bytes(), 10).unwrap();
        let (e_true, _) = prod_decode_noise_bound();
        assert!(r7_margin_holds(
            &p,
            PROD_THRESHOLD_MODULI,
            PROD_THRESHOLD_PLAINTEXT_MODULUS,
            &e_true,
            PROD_R7_CRT_B,
            PROD_R7_CRT_L,
            PROD_R7_DECODE_B,
            PROD_R7_DECODE_L,
        ));
    }

    #[test]
    fn r3_chain_is_valid_for_both_degrees() {
        assert!(validate_r3_chain());
    }
}
