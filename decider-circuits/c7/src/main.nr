//! C7 — final decryption wrapper: Lagrange interpolation consistency, CRT
//! reconstruction with quotient witnesses, and the BFV decode, for the FOUR
//! channels of the production parameter set (61-bit primes, Q ~ 2^244,
//! t = 2^20).
//!
//! All checks are integer identities (the honest values stay below 2^245,
//! which fits a single BN254 field element, so no wraparound modulo P can
//! occur — the §9.3 margin made literal). No NTT or limb arithmetic is
//! needed for this core; the accompanying R6/P decider openings reuse the
//! per-track Ajtai opening circuit (`ajtai_opening_sz`).
//!
//! Public inputs: per-channel interpolated residues u_l, the reconstructed
//! value u, the decryption shares d_i, and the decoded plaintext m.
//! Witness: the Garner digits, the quotient witnesses, and the rounding
//! error e.

mod roots;

use roots::{
    DELTA, DELTA_HALF, LAMBDAS_0, LAMBDAS_1, LAMBDAS_2, LAMBDAS_3, Q_0, Q_1, Q_2, Q_3, T_PLAIN,
};

global N: u32 = 16384;

fn mul_q(a: Field, b: Field, q: u64) -> Field {
    ((a * b) as u128 % (q as u128)) as Field
}

/// Per-channel interpolation check: u_l == sum_i lambda_i * d_i (mod q_l),
/// binding the interpolated residues to the public decryption shares.
fn check_interpolation(
    d_1: [Field; N],
    d_2: [Field; N],
    u_l: [Field; N],
    lambdas: [Field; 2],
    q: u64,
) {
    for k in 0..N {
        let acc = mul_q(lambdas[0], d_1[k], q) + (q as Field) * 4 + mul_q(lambdas[1], d_2[k], q);
        let diff = acc - u_l[k];
        assert(((diff as u128) % (q as u128)) == 0);
    }
}

fn main(
    // Decryption shares are public: the protocol broadcasts them (plan R7:
    // "every d_i has already been publicly revealed"). The verifier fixes
    // them to the true broadcast values (canonical, < q_l).
    d_0_1: pub [Field; N],
    d_0_2: pub [Field; N],
    d_1_1: pub [Field; N],
    d_1_2: pub [Field; N],
    d_2_1: pub [Field; N],
    d_2_2: pub [Field; N],
    d_3_1: pub [Field; N],
    d_3_2: pub [Field; N],
    u_0: pub [Field; N],
    u_1: pub [Field; N],
    u_2: pub [Field; N],
    u_3: pub [Field; N],
    u: pub [Field; N],
    m: pub [Field; N],
    r0: [Field; N],
    t1: [Field; N],
    t2: [Field; N],
    t3: [Field; N],
    s0: [Field; N],
    s1: [Field; N],
    s2: [Field; N],
    s3: [Field; N],
    e: [Field; N],
) {
    check_interpolation(d_0_1, d_0_2, u_0, LAMBDAS_0, Q_0);
    check_interpolation(d_1_1, d_1_2, u_1, LAMBDAS_1, Q_1);
    check_interpolation(d_2_1, d_2_2, u_2, LAMBDAS_2, Q_2);
    check_interpolation(d_3_1, d_3_2, u_3, LAMBDAS_3, Q_3);

    // Q = q0*q1*q2*q3 ~ 2^244 and the quotient bounds Q/q_l ~ 2^183, all as
    // field elements (the products exceed u128, so NO `as u128` truncation
    // is used anywhere below).
    let q_field = (Q_0 as Field) * (Q_1 as Field) * (Q_2 as Field) * (Q_3 as Field);
    let q1q2 = (Q_1 as u128 * Q_2 as u128) as Field;
    let q0q1 = (Q_0 as u128 * Q_1 as u128) as Field;
    let q0q1q2 = q0q1 * (Q_2 as Field);
    let bound_s0 = q1q2 * (Q_3 as Field); // Q/q0 = q1*q2*q3
    let bound_s1 = (Q_0 as Field) * (Q_2 as Field) * (Q_3 as Field); // Q/q1 = q0*q2*q3
    let bound_s2 = q0q1 * (Q_3 as Field); // Q/q2 = q0*q1*q3
    let bound_s3 = q0q1q2; // Q/q3 = q0*q1*q2

    for k in 0..N {
        // Digit bounds, canonical and truncation-free: x < q_l iff
        // q_l - 1 - x does not wrap mod p (q_l < 2^61, wraps give ~2^254).
        ((Q_0 as Field) - 1 - r0[k]).assert_max_bit_size::<61>();
        ((Q_1 as Field) - 1 - t1[k]).assert_max_bit_size::<61>();
        ((Q_2 as Field) - 1 - t2[k]).assert_max_bit_size::<61>();
        ((Q_3 as Field) - 1 - t3[k]).assert_max_bit_size::<61>();
        // Quotient witnesses s_l < Q/q_l: the bounds are ~2^183, enforced
        // canonically as field elements (s_l are additionally pinned mod p
        // by the public (u, u_l) in the quotient rows below).
        (bound_s0 - 1 - s0[k]).assert_max_bit_size::<184>();
        (bound_s1 - 1 - s1[k]).assert_max_bit_size::<184>();
        (bound_s2 - 1 - s2[k]).assert_max_bit_size::<184>();
        (bound_s3 - 1 - s3[k]).assert_max_bit_size::<184>();

        // Garner recombination: u = r0 + q0*t1 + q0*q1*t2 + q0*q1*q2*t3
        // (integers). With the digit bounds above this is < 2Q < p, hence an
        // integer equality with unique digits for u < Q.
        let garner = r0[k]
            + t1[k] * (Q_0 as Field)
            + t2[k] * q0q1
            + t3[k] * q0q1q2;
        assert(garner == u[k]);

        // Quotient witnesses binding u to the public channel residues:
        // u = u_l + s_l * q_l (integers).
        assert(u[k] == u_0[k] + s0[k] * (Q_0 as Field));
        assert(u[k] == u_1[k] + s1[k] * (Q_1 as Field));
        assert(u[k] == u_2[k] + s2[k] * (Q_2 as Field));
        assert(u[k] == u_3[k] + s3[k] * (Q_3 as Field));

        // Decode: u = Delta * m + e (mod Q), with m < t and e a CENTERED
        // rounding error: |e| <= Delta/2, i.e. e in [0, Delta/2] union
        // [Q - Delta/2, Q). The field identity holds mod p, so the relation
        // takes two branches: Delta*m + e == u (positive noise) or
        // Delta*m + e == u + Q (negative noise, e = Q - |e|). All terms are
        // < 2^245 << p, so each branch is an integer identity; the centered
        // bound below leaves only the measure-zero boundary |e| = Delta/2
        // ambiguous (unique decode).
        assert((DELTA * m[k] + e[k] - u[k]) * (DELTA * m[k] + e[k] - u[k] - q_field) == 0);
        ((T_PLAIN as Field) - 1 - m[k]).assert_max_bit_size::<20>();
        // e < Q canonically, then |e| = min(e, Q - e) <= Delta/2.
        (q_field - 1 - e[k]).assert_max_bit_size::<245>();
        let e_abs = if (e[k] + e[k]).lt(q_field) { e[k] } else { q_field - e[k] };
        (DELTA_HALF - e_abs).assert_max_bit_size::<224>();
    }
}
