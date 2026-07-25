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

    /// n mod m in [0, m), fully constrained. Assumes m < 2^59.
    pub fn reduce_mod(self, n: Field) -> Field {
        let (q, r) = unsafe { __compute_mod_reduction(n, self.m) };
        // Enforce r < m canonically (m < 2^59): if r >= m, m-1-r wraps to a
        // huge value and the bit-size check fails.
        (self.m - 1 - r).assert_max_bit_size::<59>();
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
