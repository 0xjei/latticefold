//! C5 — threshold public-key aggregation wrapper (3 RNS tracks).
//!
//! Per track t (modulus q_t, 58-bit):
//!   1. decider opening: cm_t = A_t * w_t in NTT domain (Ajtai commitment of
//!      the track's folded R1 witness (sk, e, e_sm)),
//!   2. norm bound: every witness coefficient is a small balanced digit,
//!   3. R1 aggregation relation: pk0_agg_t = -a_t * sk + e (pointwise in NTT
//!      domain; a_t is the public CRS element, pk0_agg_t the public output).
//!
//! Non-native arithmetic: 58-bit moduli inside BN254 — products fit a u128;
//! butterfly adds are lazy, only products reduce.

mod roots;

global B_DIGIT: u64 = 32768;

fn mul_q(a: Field, b: Field, q: u64) -> Field {
    ((a * b) as u128 % (q as u128)) as Field
}

fn add_l(a: Field, b: Field) -> Field {
    a + b
}

fn sub_l(a: Field, b: Field, q: Field) -> Field {
    a + q - b
}

fn reduce_q(a: Field, q: u64) -> Field {
    ((a as u128 % (q as u128)) as Field)
}

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

fn ntt_forward(mut a: [Field; 1024], psi: Field, steps: [Field; 10], q: u64) -> [Field; 1024] {
    let mut p: Field = 1;
    for i in 0..1024 {
        a[i] = mul_q(a[i], p, q);
        p = mul_q(p, psi, q);
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
            let t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
    let mut length: u32 = 2;
    for level in 0..10 {
        let step = steps[level];
        for block in 0..1024 / length {
            let start = block * length;
            let mut f: Field = 1;
            for off in 0..length / 2 {
                let left = a[start + off];
                let right = mul_q(a[start + off + length / 2], f, q);
                a[start + off] = add_l(left, right);
                a[start + off + length / 2] = sub_l(left, right, q as Field);
                f = mul_q(f, step, q);
            }
        }
        length = length * 2;
    }
    a
}

/// One track: opening + norms + R1 aggregation row.
fn track(
    w: [[Field; 1024]; 3],
    a_in: [[Field; 1024]; 12],
    cm: [[Field; 1024]; 4],
    a_crs_ntt: [Field; 1024],
    pk0_agg: [Field; 1024],
    q: u64,
    psi: Field,
    steps: [Field; 10],
) {
    for j in 0..3 {
        for k in 0..1024 {
            assert_digit(w[j][k], q);
        }
    }
    let qf = q as Field;
    let mut acc: [[Field; 1024]; 4] = [[0; 1024]; 4];
    let mut sk_ntt: [Field; 1024] = [0; 1024];
    let mut e_ntt: [Field; 1024] = [0; 1024];
    for j in 0..3 {
        let w_ntt = ntt_forward(w[j], psi, steps, q);
        if j == 0 {
            sk_ntt = w_ntt;
        }
        if j == 1 {
            e_ntt = w_ntt;
        }
        for i in 0..4 {
            for k in 0..1024 {
                acc[i][k] = add_l(acc[i][k], mul_q(a_in[i * 3 + j][k], w_ntt[k], q));
            }
        }
    }
    for i in 0..4 {
        for k in 0..1024 {
            let diff = acc[i][k] + qf * 15 - cm[i][k];
            assert(reduce_q(diff, q) == 0);
        }
    }
    for k in 0..1024 {
        // R1 aggregation row: pk0_agg = -a * sk + e (mod q).
        let rhs = sub_l(e_ntt[k], mul_q(a_crs_ntt[k], sk_ntt[k], q), qf);
        assert(reduce_q(rhs + qf * 15 - pk0_agg[k], q) == 0);
    }
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
) {
    track(w_0, a_in_0, cm_0, a_crs_ntt_0, pk0_agg_0, roots::Q_0, roots::PSI_0, roots::STEPS_0);
    track(w_1, a_in_1, cm_1, a_crs_ntt_1, pk0_agg_1, roots::Q_1, roots::PSI_1, roots::STEPS_1);
    track(w_2, a_in_2, cm_2, a_crs_ntt_2, pk0_agg_2, roots::Q_2, roots::PSI_2, roots::STEPS_2);
}
