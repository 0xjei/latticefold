// Interfold VDKG ring: q = 1125899909038081, a 51-bit prime that is BOTH
// NTT-friendly for the BFV ring (q ≡ 1 mod 2N, N = 8192) and LatticeFold-
// congruent (q ≡ 1 + 2t mod 4t, t = 2^14) — the q_0 of the RNS chain found and
// verified by the latticefold crate's `dkg_ring_model` example (plan §12.2).
use stark_rings::cyclotomic_ring::models::interfold::{Fq, RqNTT, RqPoly};

use super::SuitableRing;
use crate::{
    ark_base::*,
    challenge_set::{error, LatticefoldChallengeSet},
};

/// Interfold VDKG q_l ring in the NTT form.
///
/// The base field of the NTT form is the 51-bit VDKG RNS prime field.
///
/// The NTT form has 16 components (X^16 + 1 splits completely: q ≡ 1 mod 32).
pub type InterfoldRingNTT = RqNTT;

/// Interfold VDKG q_l ring in the coefficient form.
///
/// The cyclotomic polynomial is $X^{16} + 1$ of degree 16.
pub type InterfoldRingPoly = RqPoly;

impl SuitableRing for InterfoldRingNTT {
    type CoefficientRepresentation = InterfoldRingPoly;

    type PoseidonParams = InterfoldPoseidonConfig;
}

pub struct InterfoldPoseidonConfig;

#[derive(Clone)]
pub struct InterfoldChallengeSet;

/// Small challenges are the ring elements with coefficients in range [0; 2^8[.
impl LatticefoldChallengeSet<InterfoldRingNTT> for InterfoldChallengeSet {
    const BYTES_NEEDED: usize = 16;

    fn short_challenge_from_random_bytes(
        bs: &[u8],
    ) -> Result<
        <InterfoldRingNTT as SuitableRing>::CoefficientRepresentation,
        error::ChallengeSetError,
    > {
        if bs.len() != Self::BYTES_NEEDED {
            return Err(error::ChallengeSetError::TooFewBytes(
                bs.len(),
                Self::BYTES_NEEDED,
            ));
        }

        Ok(InterfoldRingPoly::from(
            bs.iter().map(|&x| Fq::from(x)).collect::<Vec<Fq>>(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_challenge_from_random_bytes() {
        let bytes: [u8; 16] = [
            0x7b, 0x4b, 0xe5, 0x8e, 0xe5, 0x11, 0xd2, 0xd0, 0x9c, 0x22, 0xba, 0x2e, 0xeb, 0xa8,
            0xba, 0x35,
        ];
        let challenge = InterfoldChallengeSet::short_challenge_from_random_bytes(&bytes).unwrap();

        let expected =
            InterfoldRingPoly::from(bytes.iter().map(|&x| Fq::from(x)).collect::<Vec<Fq>>());

        assert_eq!(expected, challenge)
    }
}
