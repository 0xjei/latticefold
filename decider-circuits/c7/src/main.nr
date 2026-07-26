//! C7 — final decryption wrapper: Lagrange interpolation consistency, CRT
//! reconstruction with quotient witnesses, and the BFV decode.
//!
//! All checks are integer identities (the honest values stay below 2^174,
//! which fits a single BN254 field element, so no wraparound modulo P can
//! occur — the §9.3 margin made literal). No NTT or limb arithmetic is
//! needed for this core; the accompanying R6/P decider openings reuse the
//! C5-style opening circuit (`ajtai_opening`).
//!
//! Public inputs: per-channel interpolated residues u_l, the reconstructed
//! value u, and the decoded plaintext m. Witness: the Garner digits, the
//! quotient witnesses, and the rounding error e.

mod roots;

use roots::{DELTA, DELTA_HALF, LAMBDAS_0, LAMBDAS_1, LAMBDAS_2, Q_0, Q_1, Q_2, T_PLAIN};

fn mul_q(a: Field, b: Field, q: u64) -> Field {
    ((a * b) as u128 % (q as u128)) as Field
}

/// Per-channel interpolation check: u_l == sum_i lambda_i * d_i (mod q_l),
/// binding the interpolated residues to the public decryption shares.
fn check_interpolation(
    d_1: [Field; 1024],
    d_2: [Field; 1024],
    u_l: [Field; 1024],
    lambdas: [Field; 2],
    q: u64,
) {
    for k in 0..1024 {
        let acc = mul_q(lambdas[0], d_1[k], q) + (q as Field) * 4 + mul_q(lambdas[1], d_2[k], q);
        let diff = acc - u_l[k];
        assert(((diff as u128) % (q as u128)) == 0);
    }
}

fn main(
    // Decryption shares are public: the protocol broadcasts them (plan R7:
    // "every d_i has already been publicly revealed"). The verifier fixes
    // them to the true broadcast values (canonical, < q_l).
    d_0_1: pub [Field; 1024],
    d_0_2: pub [Field; 1024],
    d_1_1: pub [Field; 1024],
    d_1_2: pub [Field; 1024],
    d_2_1: pub [Field; 1024],
    d_2_2: pub [Field; 1024],
    u_0: pub [Field; 1024],
    u_1: pub [Field; 1024],
    u_2: pub [Field; 1024],
    u: pub [Field; 1024],
    m: pub [Field; 1024],
    r0: [Field; 1024],
    t1: [Field; 1024],
    t2: [Field; 1024],
    s0: [Field; 1024],
    s1: [Field; 1024],
    s2: [Field; 1024],
    e: [Field; 1024],
) {
    check_interpolation(d_0_1, d_0_2, u_0, LAMBDAS_0, Q_0);
    check_interpolation(d_1_1, d_1_2, u_1, LAMBDAS_1, Q_1);
    check_interpolation(d_2_1, d_2_2, u_2, LAMBDAS_2, Q_2);

    // Q = q0*q1*q2 ~ 2^174 and Q/2 (via 2*e < Q, avoiding field division).
    let q_field = (Q_0 as Field) * (Q_1 as Field) * (Q_2 as Field);

    for k in 0..1024 {
        // Digit bounds, canonical and truncation-free: x < q_l iff
        // q_l - 1 - x does not wrap mod p (q_l < 2^58, wraps give ~2^254).
        // The old `x as u64`/`as u128` casts truncated mod 2^64/2^128.
        ((Q_0 as Field) - 1 - r0[k]).assert_max_bit_size::<58>();
        ((Q_1 as Field) - 1 - t1[k]).assert_max_bit_size::<58>();
        ((Q_2 as Field) - 1 - t2[k]).assert_max_bit_size::<58>();
        // Quotient witnesses s_l are uniquely pinned mod p by the public
        // (u, u_l) in the quotient rows below, so range checks on their
        // canonical representatives suffice.
        assert((s0[k] as u128) < (Q_1 as u128) * (Q_2 as u128));
        assert((s1[k] as u128) < (Q_0 as u128) * (Q_2 as u128));
        assert((s2[k] as u128) < (Q_0 as u128) * (Q_1 as u128));

        // Garner recombination: u = r0 + q0*t1 + q0*q1*t2 (integers).
        // With the digit bounds above this is < 2Q < p, hence an integer
        // equality with unique digits for u < Q.
        let garner = r0[k]
            + t1[k] * (Q_0 as Field)
            + t2[k] * ((Q_0 as u128 * Q_1 as u128) as Field);
        assert(garner == u[k]);

        // Quotient witnesses binding u to the public channel residues:
        // u = u_l + s_l * q_l (integers).
        assert(u[k] == u_0[k] + s0[k] * (Q_0 as Field));
        assert(u[k] == u_1[k] + s1[k] * (Q_1 as Field));
        assert(u[k] == u_2[k] + s2[k] * (Q_2 as Field));

        // Decode: u = Delta * m + e (integers, all terms < 2^175 << p), with
        // m < t and e a CENTERED rounding error: |e| <= Delta/2, i.e.
        // e in [0, Delta/2] union [Q - Delta/2, Q). All bounds are enforced
        // on canonical representatives (no `as` truncation): the old
        // `(e as u128) <= (DELTA_HALF as u128)` truncated DELTA_HALF mod
        // 2^128 and let a forged (m', e') decode the same public u to a
        // different plaintext.
        assert(u[k] == DELTA * m[k] + e[k]);
        ((T_PLAIN as Field) - 1 - m[k]).assert_max_bit_size::<20>();
        // e < Q canonically, then |e| = min(e, Q - e) <= Delta/2.
        (q_field - 1 - e[k]).assert_max_bit_size::<174>();
        let e_abs = if (e[k] + e[k]).lt(q_field) { e[k] } else { q_field - e[k] };
        (DELTA_HALF - e_abs).assert_max_bit_size::<153>();
    }
}
