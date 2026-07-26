//! Minimal modular arithmetic context, extracted from
//! `circuits/lib/src/math/modulo/` (LGPL-3.0-only, Gnosis Guild / Interfold):
//! unconstrained computation + in-circuit verification.

pub unconstrained fn __compute_mod_reduction(value: Field, q: Field) -> (Field, Field) {
    let value_u128 = value as u128;
    let q_u128 = q as u128;
    ((value_u128 / q_u128) as Field, (value_u128 % q_u128) as Field)
}

pub unconstrained fn __sub_with_underflow(lhs: Field, rhs: Field, m: Field) -> (Field, bool) {
    let lhs_i = lhs as u128;
    let rhs_i = rhs as u128;
    if lhs_i >= rhs_i {
        ((lhs_i - rhs_i) as Field, false)
    } else {
        ((m as u128 + lhs_i - rhs_i) as Field, true)
    }
}

pub struct ModU128 {
    pub m: Field,
}

impl ModU128 {
    pub fn new(m: Field) -> Self {
        ModU128 { m }
    }

    /// n mod m in [0, m), fully constrained. Assumes m < 2^59 and n < m^2
    /// (i.e. all operands are canonical, previously reduced values), so the
    /// in-circuit product/sum `n` equals the integer one (no wrap mod p).
    pub fn reduce_mod(self, n: Field) -> Field {
        let (q, r) = unsafe { __compute_mod_reduction(n, self.m) };
        // Enforce r < m canonically (m < 2^59): if r >= m, m-1-r wraps to a
        // huge value and the bit-size check fails.
        (self.m - 1 - r).assert_max_bit_size::<59>();
        // Bound the quotient. Honest calls have n < m^2, hence q = n/m < m
        // < 2^59 < 2^70. With q < 2^70 and m < 2^59, q*m + r < 2^130 << p
        // (BN254, ~2^254), so the equality below holds over the INTEGERS and
        // (q, r) = (n div m, n mod m) is unique. Without this bound q is a
        // free field element and ANY claimed remainder r* in [0, m) passes
        // via q* = (n - r*) * m^-1 (mod p).
        q.assert_max_bit_size::<70>();
        assert(n == q * self.m + r);
        r
    }

    pub fn add(self, lhs: Field, rhs: Field) -> Field {
        self.reduce_mod(lhs + rhs)
    }

    pub fn sub(self, lhs: Field, rhs: Field) -> Field {
        let (result, underflow) = unsafe { __sub_with_underflow(lhs, rhs, self.m) };
        if underflow {
            assert(lhs + self.m == rhs + result, "sub underflow check");
        } else {
            assert(lhs == rhs + result, "sub check");
        }
        result
    }

    pub fn mul_mod(self, lhs: Field, rhs: Field) -> Field {
        self.reduce_mod(lhs * rhs)
    }

    /// val^(-1) mod m via an unconstrained hint + verification (prime m).
    pub fn inv_mod(self, val: Field) -> Field {
        let result = unsafe {
            // Safety: Fermat inversion hint; verified by the mul_mod check below.
            let v = val as u128;
            let m = self.m as u128;
            let mut x: u128 = 1;
            let mut b = v;
            for i in 0..128 {
                if (m - 2) >> i & 1 == 1 {
                    x = x * b % m;
                }
                b = b * b % m;
            }
            x as Field
        };
        assert(self.mul_mod(val, result) == 1, "inv check");
        result
    }
}

#[test]
fn test_reduce_mod_honest() {
    let m = ModU128::new(288230376128643073); // 58-bit prime
    assert(m.reduce_mod(12345) == 12345);
    assert(m.reduce_mod(288230376128643073 + 42) == 42);
    let m_small = ModU128::new(100);
    assert(m_small.reduce_mod(1234567) == 67);
    // mul path: n = a*b with a, b < m
    assert(m_small.mul_mod(97, 99) == 3); // 97*99 = 9603 = 3 (mod 100)
}

#[test]
fn test_inv_mod_honest() {
    let m = ModU128::new(288230376128643073);
    let inv = m.inv_mod(123456789);
    assert(m.mul_mod(123456789, inv) == 1);
}

// Attacker model (the original exploit): for n = 12345, m = 100, claim the
// wrong remainder r' = 46 (true: 45) and set q' = (n - r') * m^-1 mod p.
// The remainder check passes (r' < m) and the field equality holds by
// construction; only the quotient bound rejects it, because q' ~ p/m ~ 2^247
// exceeds 2^70.
#[test(should_fail)]
fn test_reduce_mod_wrong_remainder_rejected() {
    let m = ModU128::new(100);
    let (n, r) = (12345, 46);
    let q = (n - r) / m.m; // field division: q*m == n - r (mod p), q ~ 2^247
    (m.m - 1 - r).assert_max_bit_size::<59>();
    q.assert_max_bit_size::<70>();
    assert(n == q * m.m + r);
}
