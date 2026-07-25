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
    d_0_1: [Field; 1024],
    d_0_2: [Field; 1024],
    d_1_1: [Field; 1024],
    d_1_2: [Field; 1024],
    d_2_1: [Field; 1024],
    d_2_2: [Field; 1024],
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

    for k in 0..1024 {
        // Digit bounds: r0 < q0, t1 < q1, t2 < q2; quotients s_l < Q/q_l.
        assert((r0[k] as u64) < Q_0);
        assert((t1[k] as u64) < Q_1);
        assert((t2[k] as u64) < Q_2);
        assert((s0[k] as u128) < (Q_1 as u128) * (Q_2 as u128));
        assert((s1[k] as u128) < (Q_0 as u128) * (Q_2 as u128));
        assert((s2[k] as u128) < (Q_0 as u128) * (Q_1 as u128));

        // Garner recombination: u = r0 + q0*t1 + q0*q1*t2 (integers).
        let garner = r0[k]
            + t1[k] * (Q_0 as Field)
            + t2[k] * ((Q_0 as u128 * Q_1 as u128) as Field);
        assert(garner == u[k]);

        // Quotient witnesses binding u to the public channel residues:
        // u = u_l + s_l * q_l (integers).
        assert(u[k] == u_0[k] + s0[k] * (Q_0 as Field));
        assert(u[k] == u_1[k] + s1[k] * (Q_1 as Field));
        assert(u[k] == u_2[k] + s2[k] * (Q_2 as Field));

        // Decode: u = Delta * m + e with 0 <= e <= Delta/2, m < t.
        assert(u[k] == DELTA * m[k] + e[k]);
        assert((e[k] as u128) <= (DELTA_HALF as u128));
        assert((m[k] as u64) < T_PLAIN);
    }
}
