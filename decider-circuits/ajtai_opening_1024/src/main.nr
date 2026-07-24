//! Ajtai decider-opening circuit over the q0 ring (58-bit prime, N=1024).
//!
//! Verifies the per-track decider statement's two expensive parts:
//!   1. commitment opening: cm = A * w in NTT domain (pointwise ring
//!      products against the in-circuit NTT of the witness),
//!   2. norm bound: every witness coefficient is a small balanced digit
//!      (|w| <= B), checked in coefficient form.
//!
//! Non-native arithmetic note: q0 is 58 bits, so any single product fits a
//! BN254 field element AND a u128; reduction is `x mod q0` in the integer
//! domain. Butterfly adds/subs are lazy (values stay < 16*q0 by
//! construction) and only products are reduced.

mod roots;

use roots::{FWD_STEPS, Q0, PSI};

global B_DIGIT: u64 = 32768; // 2^15
global Q0_U: u64 = 288230376128643073;

/// Product of a,b < 2^64 reduced mod q0.
fn mul_q(a: Field, b: Field) -> Field {
    let p = (a * b) as u128 % (Q0_U as u128);
    p as Field
}

/// Lazy add; caller tracks the bound (all values < K*q0 for small K).
fn add_l(a: Field, b: Field) -> Field {
    a + b
}

/// Lazy sub: a - b + q0 (never underflows since b < q0 and a >= 0).
fn sub_l(a: Field, b: Field) -> Field {
    a + Q0 - b
}

/// Reduce a lazily-grown value (< 2^120) mod q0.
fn reduce_q(a: Field) -> Field {
    let r = (a as u128 % (Q0_U as u128)) as Field;
    r
}

/// Enforce v is a balanced digit with |v| <= B (v canonical or q0+v).
fn assert_digit(v: Field) {
    let vi = v as u64;
    let ok = if vi <= B_DIGIT {
        true
    } else if vi < Q0_U {
        (Q0_U - vi) <= B_DIGIT
    } else {
        false
    };
    assert(ok);
}

/// In-circuit forward negacyclic NTT (output values < 16*q0, unreduced).
fn ntt_forward(mut a: [Field; 1024]) -> [Field; 1024] {
    // psi-twist (inputs are canonical < q0 after the digit check)
    let mut p: Field = 1;
    for i in 0..1024 {
        a[i] = mul_q(a[i], p);
        p = mul_q(p, PSI);
    }
    // bit-reverse permutation
    let mut j: u32 = 0;
    for i in 1..1024 {
        let mut bit: u32 = 1024 >> 1;
        for _ in 0..roots::LEVELS {
            if (j & bit) != 0 {
                j = j ^ bit;
                bit = bit >> 1;
            }
        }
        j = j | bit;
        if i < j {
            let t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
    // butterflies: left/right grow by at most q0 per level; 13 levels.
    let mut length: u32 = 2;
    for level in 0..roots::LEVELS {
        let step = FWD_STEPS[level];
        for block in 0..1024 / length {
            let start = block * length;
            let mut f: Field = 1;
            for off in 0..length / 2 {
                let left = a[start + off];
                let right = mul_q(a[start + off + length / 2], f);
                a[start + off] = add_l(left, right);
                a[start + off + length / 2] = sub_l(left, right);
                f = mul_q(f, step);
            }
        }
        length = length * 2;
    }
    a
}

fn main(
    w: [[Field; 1024]; 3],
    a_in: [[Field; 1024]; 12], // KAPPA(4) x M(3), NTT form
    cm: pub [[Field; 1024]; 4],
) {
    // Norm bound on the witness digits (coefficient form).
    for j in 0..3 {
        for k in 0..1024 {
            assert_digit(w[j][k]);
        }
    }

    // Commitment opening: cm_i == sum_j A_ij * NTT(w_j) (mod q0).
    let mut acc: [[Field; 1024]; 4] = [[0; 1024]; 4];
    for j in 0..3 {
        let w_ntt = ntt_forward(w[j]);
        for i in 0..4 {
            for k in 0..1024 {
                acc[i][k] = add_l(acc[i][k], mul_q(a_in[i * 3 + j][k], w_ntt[k]));
            }
        }
    }
    for i in 0..4 {
        for k in 0..1024 {
            let diff = acc[i][k] + Q0 * 15 - cm[i][k];
            assert(reduce_q(diff) == 0);
        }
    }
}
