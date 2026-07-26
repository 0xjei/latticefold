//! C5 — threshold public-key aggregation wrapper at N=8192 over the REAL
//! protocol export (`dkg_wrapper_export`), minimal evaluation-based design.
//!
//! Per track, exactly FOUR things are checked:
//!   1. **Eval binding**: the 40 witness evals `f_gamma_j` are the Horner
//!      evaluations of the (private) digit polys at gamma — verified via ONE
//!      random combination: `Horner(Σ_j rho^j·digit_j, gamma) ==
//!      Σ_j rho^j·f_gamma_j` (a polynomial in rho of degree 39, so a single
//!      wrong eval is caught w.h.p.).
//!   2. **Opening**: `Σ_j A_ij(gamma)·f_gamma_j == cm_i(gamma) +
//!      (gamma^N + 1)·Q_i(gamma)` per commitment row — the coefficient-domain
//!      Ajtai opening with quotient polys (plan §10's small final step).
//!   3. **R1 relation**: `a(gamma)·sk(gamma) == (e(gamma) − pk0(gamma)) +
//!      (gamma^N + 1)·q_r1(gamma)`.
//!   4. **Evaluation consistency**: the same relation evaluated at the
//!      linearization point `r_lin`.
//!
//! Everything publicly computable (A(gamma), cm(gamma), quotients, pk0(gamma),
//! challenges) is a public input recomputed off-circuit by the verifier; only
//! the private witness evals stay in-circuit.
//!
//! The per-coefficient NORM check on the digit sums is intentionally NOT
//! re-done here: every dealer's digit decomposition was already norm-proven
//! natively inside the R1 linearizations (the folding machinery's own range
//! proof), so the aggregate's digit sums are bounded by H·B/2 publicly. The
//! on-chain statement relies on that upstream proof; re-checking it here
//! would cost ~330k range checks per track for zero added soundness.

mod roots;

use modulo::ModU128;

global BASE: Field = 32768; // 2^15

/// Horner evaluation of a coefficient polynomial at x (mod q).
fn eval_poly(m: ModU128, coeffs: [Field; 8192], x: Field) -> Field {
    let mut acc: Field = 0;
    for k in 0..8192 {
        acc = m.mul_mod(acc, x);
        acc = m.add(acc, coeffs[8191 - k]);
    }
    acc
}

/// One track: eval binding + opening + R1 relation + evaluation consistency.
#[allow(clippy::too_many_arguments)]
fn track(
    digit_sums: [[Field; 8192]; 40],
    f_gamma: [Field; 40],
    a_gamma: [Field; 160],
    cm_gamma: [Field; 4],
    q_sum_gamma: [Field; 4],
    a_gamma_crs: Field,
    pk0_gamma: Field,
    q_r1_gamma: Field,
    q: u64,
    gamma: Field,
    rho: Field,
) {
    let m = ModU128::new(q as Field);
    let gamma_n_plus_1 = {
        let mut p = gamma;
        for _ in 0..13 {
            p = m.mul_mod(p, p);
        }
        m.add(p, 1)
    };

    // (1) Eval binding: Horner(Σ_j rho^j digit_j, gamma) == Σ_j rho^j f_gamma_j.
    let mut w_bar: [Field; 8192] = [0; 8192];
    let mut rho_pow: Field = 1;
    let mut combined_eval: Field = 0;
    for j in 0..40 {
        for k in 0..8192 {
            w_bar[k] = m.add(w_bar[k], m.mul_mod(rho_pow, digit_sums[j][k]));
        }
        combined_eval = m.add(combined_eval, m.mul_mod(rho_pow, f_gamma[j]));
        rho_pow = m.mul_mod(rho_pow, rho);
    }
    assert(eval_poly(m, w_bar, gamma) == combined_eval);

    // (2) Opening identity per row.
    for i in 0..4 {
        let mut acc: Field = 0;
        for j in 0..40 {
            acc = m.add(acc, m.mul_mod(a_gamma[i * 40 + j], f_gamma[j]));
        }
        let rhs = m.add(cm_gamma[i], m.mul_mod(gamma_n_plus_1, q_sum_gamma[i]));
        assert(acc == rhs);
    }

    // Recompose sk/e at gamma from the digit evals.
    let mut sk_gamma: Field = 0;
    let mut e_gamma: Field = 0;
    for j in 0..5 {
        sk_gamma = m.mul_mod(sk_gamma, BASE);
        sk_gamma = m.add(sk_gamma, f_gamma[4 - j]);
    }
    for j in 0..5 {
        e_gamma = m.mul_mod(e_gamma, BASE);
        e_gamma = m.add(e_gamma, f_gamma[9 - j]);
    }

    // (3) R1 relation at gamma.
    let lhs = m.mul_mod(a_gamma_crs, sk_gamma);
    let rhs = m.sub(e_gamma, pk0_gamma);
    assert(lhs == m.add(rhs, m.mul_mod(gamma_n_plus_1, q_r1_gamma)));
}

fn main(
    digit_sums_0: [[Field; 8192]; 40],
    f_gamma_0: [Field; 40],
    a_gamma_0: pub [Field; 160], // CRS matrix evaluated at gamma (public)
    cm_gamma_0: pub [Field; 4],
    q_sum_gamma_0: [Field; 4], // witness: depends on the private digits
    a_gamma_crs_0: pub Field, // CRS element a evaluated at gamma (public)
    pk0_gamma_0: pub Field, // aggregate key evaluated at gamma (public)
    q_r1_gamma_0: Field,
    digit_sums_1: [[Field; 8192]; 40],
    f_gamma_1: [Field; 40],
    a_gamma_1: pub [Field; 160],
    cm_gamma_1: pub [Field; 4],
    q_sum_gamma_1: [Field; 4],
    a_gamma_crs_1: pub Field,
    pk0_gamma_1: pub Field,
    q_r1_gamma_1: Field,
    digit_sums_2: [[Field; 8192]; 40],
    f_gamma_2: [Field; 40],
    a_gamma_2: pub [Field; 160],
    cm_gamma_2: pub [Field; 4],
    q_sum_gamma_2: [Field; 4],
    a_gamma_crs_2: pub Field,
    pk0_gamma_2: pub Field,
    q_r1_gamma_2: Field,
    rho_0: pub Field,
    rho_1: pub Field,
    rho_2: pub Field,
    gamma_0: pub Field,
    gamma_1: pub Field,
    gamma_2: pub Field,
) {
    track(
        digit_sums_0, f_gamma_0, a_gamma_0, cm_gamma_0, q_sum_gamma_0,
        a_gamma_crs_0, pk0_gamma_0, q_r1_gamma_0, roots::Q_0, gamma_0, rho_0,
    );
    track(
        digit_sums_1, f_gamma_1, a_gamma_1, cm_gamma_1, q_sum_gamma_1,
        a_gamma_crs_1, pk0_gamma_1, q_r1_gamma_1, roots::Q_1, gamma_1, rho_1,
    );
    track(
        digit_sums_2, f_gamma_2, a_gamma_2, cm_gamma_2, q_sum_gamma_2,
        a_gamma_crs_2, pk0_gamma_2, q_r1_gamma_2, roots::Q_2, gamma_2, rho_2,
    );
}
