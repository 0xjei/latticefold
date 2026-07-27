//! Native N=8192 LatticeFold rings for the three threshold-BFV RNS channels
//! and the reconstruction prime of the "Noir secure-8192 security" parameter
//! set (`t = 2^20`, three 58-bit primes, 176-bit P).

use stark_rings::cyclotomic_ring::models::n8192::{
    Fq0, Fq1, Fq2, FqP, FqS0, FqS1, PRingNTT, PRingPoly, Q0RingNTT, Q0RingPoly, Q1RingNTT,
    Q1RingPoly, Q2RingNTT, Q2RingPoly, S0RingNTT, S0RingPoly, S1RingNTT, S1RingPoly,
};

use super::SuitableRing;
use crate::{
    ark_base::*,
    challenge_set::{error, LatticefoldChallengeSet},
};

pub type N8192Q0RingNTT = Q0RingNTT;
pub type N8192Q0RingPoly = Q0RingPoly;
pub type N8192Q0Field = Fq0;
pub type N8192Q1RingNTT = Q1RingNTT;
pub type N8192Q1RingPoly = Q1RingPoly;
pub type N8192Q1Field = Fq1;
pub type N8192Q2RingNTT = Q2RingNTT;
pub type N8192Q2RingPoly = Q2RingPoly;
pub type N8192Q2Field = Fq2;
pub type N8192PRingNTT = PRingNTT;
pub type N8192PRingPoly = PRingPoly;
pub type N8192PField = FqP;
pub type N8192S0RingNTT = S0RingNTT;
pub type N8192S0RingPoly = S0RingPoly;
pub type N8192S0Field = FqS0;
pub type N8192S1RingNTT = S1RingNTT;
pub type N8192S1RingPoly = S1RingPoly;
pub type N8192S1Field = FqS1;

impl SuitableRing for N8192Q0RingNTT {
    type CoefficientRepresentation = N8192Q0RingPoly;
    type PoseidonParams = N8192Q0PoseidonConfig;
}

impl SuitableRing for N8192Q1RingNTT {
    type CoefficientRepresentation = N8192Q1RingPoly;
    type PoseidonParams = N8192Q1PoseidonConfig;
}

impl SuitableRing for N8192Q2RingNTT {
    type CoefficientRepresentation = N8192Q2RingPoly;
    type PoseidonParams = N8192Q2PoseidonConfig;
}

impl SuitableRing for N8192PRingNTT {
    type CoefficientRepresentation = N8192PRingPoly;
    type PoseidonParams = N8192PPoseidonConfig;
}

impl SuitableRing for N8192S0RingNTT {
    type CoefficientRepresentation = N8192S0RingPoly;
    type PoseidonParams = N8192S0PoseidonConfig;
}

impl SuitableRing for N8192S1RingNTT {
    type CoefficientRepresentation = N8192S1RingPoly;
    type PoseidonParams = N8192S1PoseidonConfig;
}

pub struct N8192Q0PoseidonConfig;
pub struct N8192Q1PoseidonConfig;
pub struct N8192Q2PoseidonConfig;
pub struct N8192PPoseidonConfig;
pub struct N8192S0PoseidonConfig;
pub struct N8192S1PoseidonConfig;

#[derive(Clone)]
pub struct N8192Q0ChallengeSet;

#[derive(Clone)]
pub struct N8192Q1ChallengeSet;

#[derive(Clone)]
pub struct N8192Q2ChallengeSet;

#[derive(Clone)]
pub struct N8192PChallengeSet;

#[derive(Clone)]
pub struct N8192S0ChallengeSet;

#[derive(Clone)]
pub struct N8192S1ChallengeSet;

macro_rules! impl_challenge_set {
    ($set:ty, $ring:ty, $poly:ty, $field:ty) => {
        impl LatticefoldChallengeSet<$ring> for $set {
            const BYTES_NEEDED: usize = 8192;

            fn short_challenge_from_random_bytes(
                bs: &[u8],
            ) -> Result<$poly, error::ChallengeSetError> {
                if bs.len() != Self::BYTES_NEEDED {
                    return Err(error::ChallengeSetError::TooFewBytes(
                        bs.len(),
                        Self::BYTES_NEEDED,
                    ));
                }
                Ok(<$poly>::from(
                    bs.iter().map(|&byte| <$field>::from(byte)).collect::<Vec<_>>(),
                ))
            }
        }
    };
}

impl_challenge_set!(N8192Q0ChallengeSet, N8192Q0RingNTT, N8192Q0RingPoly, N8192Q0Field);
impl_challenge_set!(N8192Q1ChallengeSet, N8192Q1RingNTT, N8192Q1RingPoly, N8192Q1Field);
impl_challenge_set!(N8192Q2ChallengeSet, N8192Q2RingNTT, N8192Q2RingPoly, N8192Q2Field);
impl_challenge_set!(N8192PChallengeSet, N8192PRingNTT, N8192PRingPoly, N8192PField);
impl_challenge_set!(N8192S0ChallengeSet, N8192S0RingNTT, N8192S0RingPoly, N8192S0Field);
impl_challenge_set!(N8192S1ChallengeSet, N8192S1RingNTT, N8192S1RingPoly, N8192S1Field);

#[cfg(test)]
mod tests {
    use stark_rings::PolyRing;

    use super::*;
    use crate::challenge_set::LatticefoldChallengeSet;

    #[test]
    fn challenge_sets_use_the_full_ring_degree() {
        let bytes = vec![7u8; 8192];
        assert_eq!(
            N8192Q0ChallengeSet::short_challenge_from_random_bytes(&bytes)
                .unwrap()
                .coeffs()
                .len(),
            8192
        );
        assert_eq!(N8192Q0ChallengeSet::BYTES_NEEDED, 8192);
        assert_eq!(N8192Q1ChallengeSet::BYTES_NEEDED, 8192);
        assert_eq!(N8192Q2ChallengeSet::BYTES_NEEDED, 8192);
        assert_eq!(N8192PChallengeSet::BYTES_NEEDED, 8192);
    }
}
