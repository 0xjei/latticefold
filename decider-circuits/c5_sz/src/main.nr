//! C5 — threshold public-key aggregation wrapper (3 RNS tracks),
//! Schwartz–Zippel design: per track, the folded R1 witness (sk, e, e_sm)
//! is committed via Ajtai and the aggregate key follows:
//!   1. decider opening: cm = A * w in NTT domain (NTT computed
//!      unconstrained, verified at one random point via the geometric-series
//!      identity + one batched inversion per element),
//!   2. norm bound on the witness digits,
//!   3. R1 aggregation: pk0_agg = -a * sk + e, checked as a Horner
//!      evaluation of the error vector at r (Schwartz–Zippel).

mod roots;

use modulo::ModU128;

global B_DIGIT: u64 = 32768;

fn assert_digit(v: Field, q: u64) {
    let vi = v as u64;
    let ok = if vi <= B_DIGIT {
        true
    } else if vi < q {
        (q - vi) <= B_DIGIT
    } else {
        false
    };
    assert(ok);
}

fn batch_invert(m: ModU128, denoms: [Field; 1024]) -> [Field; 1024] {
    let mut prefix: [Field; 1024] = [0; 1024];
    let mut acc: Field = 1;
    for i in 0..1024 {
        acc = m.mul_mod(acc, denoms[i]);
        prefix[i] = acc;
    }
    let mut running = m.inv_mod(acc);
    let mut out: [Field; 1024] = [0; 1024];
    for ri in 0..1023 {
        let i = 1023 - ri;
        out[i] = m.mul_mod(running, prefix[i - 1]);
        running = m.mul_mod(running, denoms[i]);
    }
    out[0] = running;
    out
}

fn verify_ntt(m: ModU128, w: [Field; 1024], w_ntt: [Field; 1024], r: Field, omega: Field, psi: Field) {
    let mut r_pow = r;
    for _ in 0..10 {
        r_pow = m.mul_mod(r_pow, r_pow);
    }
    let r_n_minus_1 = m.sub(r_pow, 1);

    let mut lhs: Field = 0;
    for k in 0..1024 {
        lhs = m.mul_mod(lhs, r);
        lhs = m.add(lhs, w_ntt[k]);
    }

    let mut denoms: [Field; 1024] = [0; 1024];
    let mut omega_pow: Field = 1;
    for i in 0..1024 {
        denoms[i] = m.sub(r, omega_pow);
        omega_pow = m.mul_mod(omega_pow, omega);
    }
    let inv_denoms = batch_invert(m, denoms);

    let mut rhs: Field = 0;
    let mut psi_pow: Field = 1;
    for i in 0..1024 {
        let term = m.mul_mod(w[i], psi_pow);
        let term = m.mul_mod(term, r_n_minus_1);
        let term = m.mul_mod(term, inv_denoms[i]);
        rhs = m.add(rhs, term);
        psi_pow = m.mul_mod(psi_pow, psi);
    }
    assert(lhs == rhs);
}

/// One track: opening + norms + R1 aggregation row.
fn track(
    w: [[Field; 1024]; 3],
    w_ntts: [[Field; 1024]; 3],
    a_in: [[Field; 1024]; 12],
    cm: [[Field; 1024]; 4],
    a_crs_ntt: [Field; 1024],
    pk0_agg: [Field; 1024],
    q: u64,
    psi: Field,
    omega: Field,
    r: Field,
) {
    let m = ModU128::new(q as Field);
    for j in 0..3 {
        for k in 0..1024 {
            assert_digit(w[j][k], q);
        }
        verify_ntt(m, w[j], w_ntts[j], r, omega, psi);
    }
    // opening: err_i[k] = cm_i[k] - sum_j A_ij[k] w_ntt_j[k] vanishes at r
    for i in 0..4 {
        let mut lhs: Field = 0;
        let mut rhs: Field = 0;
        for k in 0..1024 {
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
    // R1 aggregation: err[k] = pk0_agg[k] + a_ntt[k]*sk_ntt[k] - e_ntt[k]
    let mut lhs: Field = 0;
    let mut rhs: Field = 0;
    for k in 0..1024 {
        lhs = m.mul_mod(lhs, r);
        lhs = m.add(lhs, pk0_agg[k]);
        let prod = m.mul_mod(a_crs_ntt[k], w_ntts[0][k]);
        let term = m.sub(w_ntts[1][k], prod);
        rhs = m.mul_mod(rhs, r);
        rhs = m.add(rhs, term);
    }
    assert(lhs == rhs);
}

unconstrained fn compute_ntt(a: [Field; 1024], psi: Field, omega: Field, q: u64) -> [Field; 1024] {
    let qq = q as u128;
    let psi_u = psi as u128;
    let omega_u = omega as u128;
    let mut v: [u128; 1024] = [0; 1024];
    let mut p: u128 = 1;
    for i in 0..1024 {
        v[i] = ((a[i] as u128) * p) % qq;
        p = p * psi_u % qq;
    }
    let mut j: u32 = 0;
    for i in 1..1024 {
        let mut bit: u32 = 1024 >> 1;
        for _ in 0..10 {
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
    while length <= 1024 {
        let mut step: u128 = 1;
        for _ in 0..1024 / length {
            step = step * omega_u % qq;
        }
        for block in 0..1024 / length {
            let start = block * length;
            let mut f: u128 = 1;
            for off in 0..length / 2 {
                let left = v[start + off];
                let right = v[start + off + length / 2] * f % qq;
                v[start + off] = (left + right) % qq;
                v[start + off + length / 2] = (left + qq - right) % qq;
                f = f * step % qq;
            }
        }
        length = length * 2;
    }
    let mut out: [Field; 1024] = [0; 1024];
    for i in 0..1024 {
        out[i] = v[i] as Field;
    }
    out
}

fn main(
    w_0: [[Field; 1024]; 3],
    a_in_0: [[Field; 1024]; 12],
    cm_0: [[Field; 1024]; 4],
    a_crs_ntt_0: [Field; 1024],
    pk0_agg_0: pub [Field; 1024],
    w_1: [[Field; 1024]; 3],
    a_in_1: [[Field; 1024]; 12],
    cm_1: [[Field; 1024]; 4],
    a_crs_ntt_1: [Field; 1024],
    pk0_agg_1: pub [Field; 1024],
    w_2: [[Field; 1024]; 3],
    a_in_2: [[Field; 1024]; 12],
    cm_2: [[Field; 1024]; 4],
    a_crs_ntt_2: [Field; 1024],
    pk0_agg_2: pub [Field; 1024],
    r: pub Field,
) {
    // Safety: every NTT output is verified against its coefficients in
    // verify_ntt before use.
    let w_ntts_0 = [
        unsafe { compute_ntt(w_0[0], roots::PSI_0, roots::OMEGA_0, roots::Q_0) },
        unsafe { compute_ntt(w_0[1], roots::PSI_0, roots::OMEGA_0, roots::Q_0) },
        unsafe { compute_ntt(w_0[2], roots::PSI_0, roots::OMEGA_0, roots::Q_0) },
    ];
    let w_ntts_1 = [
        unsafe { compute_ntt(w_1[0], roots::PSI_1, roots::OMEGA_1, roots::Q_1) },
        unsafe { compute_ntt(w_1[1], roots::PSI_1, roots::OMEGA_1, roots::Q_1) },
        unsafe { compute_ntt(w_1[2], roots::PSI_1, roots::OMEGA_1, roots::Q_1) },
    ];
    let w_ntts_2 = [
        unsafe { compute_ntt(w_2[0], roots::PSI_2, roots::OMEGA_2, roots::Q_2) },
        unsafe { compute_ntt(w_2[1], roots::PSI_2, roots::OMEGA_2, roots::Q_2) },
        unsafe { compute_ntt(w_2[2], roots::PSI_2, roots::OMEGA_2, roots::Q_2) },
    ];
    track(w_0, w_ntts_0, a_in_0, cm_0, a_crs_ntt_0, pk0_agg_0, roots::Q_0, roots::PSI_0, roots::OMEGA_0, r);
    track(w_1, w_ntts_1, a_in_1, cm_1, a_crs_ntt_1, pk0_agg_1, roots::Q_1, roots::PSI_1, roots::OMEGA_1, r);
    track(w_2, w_ntts_2, a_in_2, cm_2, a_crs_ntt_2, pk0_agg_2, roots::Q_2, roots::PSI_2, roots::OMEGA_2, r);
}
