//! Real BFV witness sampling via the pinned `fhe.rs` TRBFV module.
//!
//! Replaces the demonstration's non-negative toy samplers with the
//! production distributions:
//!
//! - **Secret keys**: `SecretKey::random` (ternary, signed).
//! - **Errors**: `Poly::small` (CBD with the parameter set's variance).
//! - **Smudging noise**: `TRBFV::generate_smudging_error_with_participant_count`
//!   — sampled with the correct Urban–Rambaud bound from
//!   `SmudgingBoundCalculator` (wide: ~2^122 at lambda=50 with one summed
//!   ciphertext; it does NOT fit a single channel, which is why the
//!   commitment side uses base-B limbs, per plan §9.2).

use std::{error::Error, sync::Arc};

use fhe::bfv::{self, SecretKey};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_rand::rng;
use num_bigint::BigInt;

use crate::vdkg_params::VdkgParams;

/// Statistical security parameter for the smudging noise (matches the Noir
/// preset's benchmark configuration).
pub const SMUDGING_LAMBDA: usize = 50;

/// Build the threshold-BFV parameter set used for sampling (same primes and
/// variance as the target instance).
pub fn threshold_bfv_params<P: VdkgParams>() -> Result<Arc<bfv::BfvParameters>, Box<dyn Error>> {
    Ok(bfv::BfvParametersBuilder::new()
        .set_degree(P::DEGREE)
        .set_plaintext_modulus(P::THRESHOLD_PLAINTEXT)
        .set_moduli(&P::THRESHOLD_MODULI)
        .set_variance(10)
        .build_arc()?)
}

/// One dealer's sampled R1 secrets, in fhe.rs's production distributions.
pub struct DealerSamples {
    /// Ternary secret-key polynomial (signed coefficients in {-1, 0, 1}).
    pub sk: Vec<i64>,
    /// CBD error polynomial (signed, small).
    pub e: Vec<i64>,
    /// Smudging-noise polynomial (signed, WIDE — see [`smudging_max_bits`]).
    pub e_sm: Vec<BigInt>,
}

/// Sample one dealer's R1 secrets with the real distributions. `accepted` is
/// the number of honest contributions the smudging noise must hide (H), and
/// `num_ciphertexts` is the number of fresh ciphertext additions the noise
/// must cover (the application's z). The TRBFV threshold is the maximal
/// corruption tolerance `(accepted - 1) / 2` its API requires.
pub fn sample_dealer<P: VdkgParams>(
    accepted: usize,
    num_ciphertexts: usize,
) -> Result<DealerSamples, Box<dyn Error>> {
    let params = threshold_bfv_params::<P>()?;

    let mut key_rng = rng();
    let secret_key = SecretKey::random(&params, &mut key_rng);
    let sk = secret_key.coeffs.as_ref().to_vec();

    let ctx = params.context_at_level(0)?.clone();
    let mut err_rng = rng();
    let e_poly = Poly::<PowerBasis>::small(&ctx, params.variance(), &mut err_rng)?;
    let e = e_poly
        .coefficients()
        .row(0)
        .iter()
        .map(|&c| c as i64)
        .collect::<Vec<_>>();

    let trbfv = fhe::trbfv::TRBFV::new(accepted, (accepted - 1) / 2, params)?;
    let mut sm_rng = rng();
    let e_sm = trbfv.generate_smudging_error_with_participant_count(
        num_ciphertexts,
        0,
        accepted,
        fhe::trbfv::Lambda::secure(SMUDGING_LAMBDA)?,
        &mut sm_rng,
    )?;

    Ok(DealerSamples { sk, e, e_sm })
}

/// The bit length of the largest smudging coefficient in a batch (drives the
/// limb count used for the R1 commitment and the R7 decode witness).
pub fn smudging_max_bits(samples: &[DealerSamples]) -> usize {
    samples
        .iter()
        .flat_map(|dealer| dealer.e_sm.iter())
        .map(|c| {
            use num_traits::Signed;
            c.abs().bits() as usize
        })
        .max()
        .unwrap_or(0)
}

/// Decompose one wide signed integer into balanced base-`2^15` limbs
/// (least significant first), exactly the plan §9.2 limb splitting.
pub fn balanced_limbs(value: &BigInt, limb_count: usize) -> Vec<i64> {
    const BASE: i64 = 1 << 15;
    let mut rem = value.clone();
    let mut out = Vec::with_capacity(limb_count);
    for _ in 0..limb_count {
        let mut digit: i64 = (&rem % BigInt::from(BASE))
            .try_into()
            .expect("limb must fit i64");
        if digit > BASE / 2 {
            digit -= BASE;
            rem = (rem - digit) / BASE;
        } else if digit < -(BASE / 2) {
            digit += BASE;
            rem = (rem - digit) / BASE;
        } else {
            rem = (rem - digit) / BASE;
        }
        out.push(digit);
    }
    debug_assert_eq!(rem, BigInt::from(0), "limb decomposition must be exact");
    out
}

/// Recompose balanced base-`2^15` limbs back to the integer.
pub fn recompose_limbs(limbs: &[i64]) -> BigInt {
    const BASE: i64 = 1 << 15;
    let mut value = BigInt::from(0);
    for &digit in limbs.iter().rev() {
        value = value * BASE + digit;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vdkg_params::ProdParams;

    #[test]
    fn limbs_round_trip() {
        for v in [
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(-1),
            BigInt::from(1u128 << 100),
            BigInt::from(-(1i128 << 100)),
            BigInt::from(32768i64 * 32768 + 12345),
        ] {
            let limbs = balanced_limbs(&v, 12);
            assert_eq!(recompose_limbs(&limbs), v);
        }
    }

    #[test]
    fn dealer_samples_have_expected_shapes() {
        let samples = sample_dealer::<ProdParams>(5, 1).unwrap();
        assert_eq!(samples.sk.len(), ProdParams::DEGREE);
        assert_eq!(samples.e.len(), ProdParams::DEGREE);
        assert_eq!(samples.e_sm.len(), ProdParams::DEGREE);
        assert!(samples.sk.iter().all(|&c| (-1..=1).contains(&c)));
        // The smudging noise must be wide (statistical hiding), i.e. far
        // beyond a single 61-bit channel.
        let bits = smudging_max_bits(&[samples]);
        assert!(bits > 61, "smudging too small: {bits} bits");
    }
}
