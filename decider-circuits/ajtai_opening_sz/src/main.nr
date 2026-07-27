//! Ajtai decider-opening circuit over the q0 ring (58-bit prime, N=16384) —
//! Schwartz–Zippel design, following the same trick as the production
//! `circuits/` (evaluate at a random point instead of arithmetizing an NTT).
//!
//! Verifies the per-track decider statement:
//!   1. NTT correctness: w_ntt = NTT(w) — the NTT is computed UNCONSTRAINED
//!      and verified at one random point r via the geometric-series identity
//!        sum_k r^k w_ntt[k] = sum_i w[i] psi^i (r^n - 1)/(r omega^i - 1)
//!      (one Montgomery-batch inversion over the n denominators).
//!   2. Commitment opening: cm = A * w_ntt pointwise, compressed to a Horner
//!      evaluation at r of the error vector (a valid Schwartz–Zippel check).
//!   3. Norm bound: every witness coefficient is a small balanced digit.
//!
//! `r` is a public input standing in for the Fiat–Shamir challenge; the
//! production version derives it by hashing the public statement in-circuit
//! (bounded hashing, plan §10).

mod roots;

use modulo::ModU128;
use roots::{OMEGA, PSI, Q0};

global B_DIGIT: u64 = 32768; // 2^15
global Q0_U: u64 = 2305843009211596801;

unconstrained fn compute_ntt(a: [Field; 16384]) -> [Field; 16384] {
    // Reference negacyclic NTT (twist + bit-reverse + DIT butterflies).
    let q = Q0_U as u128;
    let psi = PSI as u128;
    let omega = OMEGA as u128;
    let mut v: [u128; 16384] = [0; 16384];
    let mut p: u128 = 1;
    for i in 0..16384 {
        v[i] = ((a[i] as u128) * p) % q;
        p = p * psi % q;
    }
    let mut j: u32 = 0;
    for i in 1..16384 {
        let mut bit: u32 = 16384 >> 1;
        for _ in 0..14 {
            if (j & bit) != 0 {
                j = j ^ bit;
                bit = bit >> 1;
            }
        }
        j = j | bit;
        if i < j {
            let t = v[i];
            v[i] = v[j];
            v[j] = t;
        }
    }
    let mut length: u32 = 2;
    while length <= 16384 {
        let mut step: u128 = 1;
        for _ in 0..16384 / length {
            step = step * omega % q;
        }
        for block in 0..16384 / length {
            let start = block * length;
            let mut f: u128 = 1;
            for off in 0..length / 2 {
                let left = v[start + off];
                let right = v[start + off + length / 2] * f % q;
                v[start + off] = (left + right) % q;
                v[start + off + length / 2] = (left + q - right) % q;
                f = f * step % q;
            }
        }
        length = length * 2;
    }
    let mut out: [Field; 16384] = [0; 16384];
    for i in 0..16384 {
        out[i] = v[i] as Field;
    }
    out
}

/// Enforce v is a balanced digit with |v| <= B (v canonical or q0+v).
fn assert_digit(v: Field) {
    // Canonical-form check first: `v as u64` truncates mod 2^64, so without
    // this v = k*2^64 + small would pass as a "digit". Q0 < 2^61.
    v.assert_max_bit_size::<61>();
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

/// Montgomery-batch inversion of 16384 denominators (one inversion total).
fn batch_invert(m: ModU128, denoms: [Field; 16384]) -> [Field; 16384] {
    let mut prefix: [Field; 16384] = [0; 16384];
    let mut acc: Field = 1;
    for i in 0..16384 {
        acc = m.mul_mod(acc, denoms[i]);
        prefix[i] = acc;
    }
    let mut running = m.inv_mod(acc);
    let mut out: [Field; 16384] = [0; 16384];
    for ri in 0..16383 {
        let i = 16383 - ri;
        out[i] = m.mul_mod(running, prefix[i - 1]);
        running = m.mul_mod(running, denoms[i]);
    }
    out[0] = running;
    out
}

/// Verify at one random point r that `w_ntt` is the NTT of `w`:
///   sum_k r^k w_ntt[k] == sum_i w[i] psi^i (r^n - 1) / (r omega^i - 1).
fn verify_ntt(m: ModU128, w: [Field; 16384], w_ntt: [Field; 16384], r: Field) {
    // r^n - 1 via 13 squarings (n = 16384 = 2^13).
    let mut r_pow = r;
    for _ in 0..14 {
        r_pow = m.mul_mod(r_pow, r_pow);
    }
    let r_n_minus_1 = m.sub(r_pow, 1);

    // LHS: Horner evaluation of w_ntt at r.
    let mut lhs: Field = 0;
    for k in 0..16384 {
        lhs = m.mul_mod(lhs, r);
        lhs = m.add(lhs, w_ntt[k]);
    }

    // Denominators d_i = r - omega^i (the Horner LHS is
    // sum_k r^{n-1-k} w_ntt[k] = sum_i w[i] psi^i (r^n - 1)/(r - omega^i)),
    // batch-inverted.
    let mut denoms: [Field; 16384] = [0; 16384];
    let mut omega_pow: Field = 1;
    for i in 0..16384 {
        denoms[i] = m.sub(r, omega_pow);
        omega_pow = m.mul_mod(omega_pow, OMEGA);
    }
    let inv_denoms = batch_invert(m, denoms);

    // RHS: sum_i w[i] * psi^i * (r^n - 1) * inv(d_i).
    let mut rhs: Field = 0;
    let mut psi_pow: Field = 1;
    for i in 0..16384 {
        let term = m.mul_mod(w[i], psi_pow);
        let term = m.mul_mod(term, r_n_minus_1);
        let term = m.mul_mod(term, inv_denoms[i]);
        rhs = m.add(rhs, term);
        psi_pow = m.mul_mod(psi_pow, PSI);
    }

    assert(lhs == rhs);
}

fn main(
    w: [[Field; 16384]; 3],
    a_in: pub [[Field; 16384]; 12], // KAPPA(4) x M(3), NTT form (the public CRS)
    cm: pub [[Field; 16384]; 4],
    r: pub Field,
) {
    for j in 0..3 {
        for k in 0..16384 {
            assert_digit(w[j][k]);
        }
    }

    let m = ModU128::new(Q0);
    let mut w_ntts: [[Field; 16384]; 3] = [[0; 16384]; 3];
    for j in 0..3 {
        // Safety: the NTT output is verified against w in verify_ntt below.
        let w_ntt = unsafe { compute_ntt(w[j]) };
        verify_ntt(m, w[j], w_ntt, r);
        w_ntts[j] = w_ntt;
    }

    // Commitment opening: for each i, the error vector
    //   err[k] = cm_i[k] - sum_j A_ij[k] * w_ntt_j[k]
    // must vanish; check its Horner evaluation at r (Schwartz–Zippel).
    for i in 0..4 {
        let mut lhs: Field = 0; // Horner of cm_i at r
        let mut rhs: Field = 0; // sum_j Horner of A_ij * w_ntt_j at r
        for k in 0..16384 {
            lhs = m.mul_mod(lhs, r);
            lhs = m.add(lhs, cm[i][k]);
            let mut prod: Field = 0;
            for j in 0..3 {
                prod = m.add(prod, m.mul_mod(a_in[i * 3 + j][k], w_ntts[j][k]));
            }
            rhs = m.mul_mod(rhs, r);
            rhs = m.add(rhs, prod);
        }
        assert(lhs == rhs);
    }
}
