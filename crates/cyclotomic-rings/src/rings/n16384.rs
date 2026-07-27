//! Native N=16384 LatticeFold rings for the production parameter set
//! (`t = 2^20`, four 61-bit LF-congruent primes, 251-bit Fp256 P).

use stark_rings::cyclotomic_ring::models::n16384::{
    Fq0, Fq1, Fq2, Fq3, FqP, FqS0, FqS1, PRingNTT, PRingPoly, Q0RingNTT, Q0RingPoly, Q1RingNTT,
    Q1RingPoly, Q2RingNTT, Q2RingPoly, Q3RingNTT, Q3RingPoly, S0RingNTT, S0RingPoly, S1RingNTT,
    S1RingPoly,
};

use super::SuitableRing;
use crate::{
    ark_base::*,
    challenge_set::{error, LatticefoldChallengeSet},
};

pub type N16384Q0RingNTT = Q0RingNTT;
pub type N16384Q0RingPoly = Q0RingPoly;
pub type N16384Q0Field = Fq0;
pub type N16384Q1RingNTT = Q1RingNTT;
pub type N16384Q1RingPoly = Q1RingPoly;
pub type N16384Q1Field = Fq1;
pub type N16384Q2RingNTT = Q2RingNTT;
pub type N16384Q2RingPoly = Q2RingPoly;
pub type N16384Q2Field = Fq2;
pub type N16384Q3RingNTT = Q3RingNTT;
pub type N16384Q3RingPoly = Q3RingPoly;
pub type N16384Q3Field = Fq3;
pub type N16384PRingNTT = PRingNTT;
pub type N16384PRingPoly = PRingPoly;
pub type N16384PField = FqP;
pub type N16384S0RingNTT = S0RingNTT;
pub type N16384S0RingPoly = S0RingPoly;
pub type N16384S0Field = FqS0;
pub type N16384S1RingNTT = S1RingNTT;
pub type N16384S1RingPoly = S1RingPoly;
pub type N16384S1Field = FqS1;

macro_rules! impl_suitable_ring {
    ($ntt:ty, $poly:ty, $config:ty) => {
        impl SuitableRing for $ntt {
            type CoefficientRepresentation = $poly;
            type PoseidonParams = $config;
        }
    };
}

pub struct N16384Q0PoseidonConfig;
pub struct N16384Q1PoseidonConfig;
pub struct N16384Q2PoseidonConfig;
pub struct N16384Q3PoseidonConfig;
pub struct N16384PPoseidonConfig;
pub struct N16384S0PoseidonConfig;
pub struct N16384S1PoseidonConfig;

impl_suitable_ring!(N16384Q0RingNTT, N16384Q0RingPoly, N16384Q0PoseidonConfig);
impl_suitable_ring!(N16384Q1RingNTT, N16384Q1RingPoly, N16384Q1PoseidonConfig);
impl_suitable_ring!(N16384Q2RingNTT, N16384Q2RingPoly, N16384Q2PoseidonConfig);
impl_suitable_ring!(N16384Q3RingNTT, N16384Q3RingPoly, N16384Q3PoseidonConfig);
impl_suitable_ring!(N16384PRingNTT, N16384PRingPoly, N16384PPoseidonConfig);
impl_suitable_ring!(N16384S0RingNTT, N16384S0RingPoly, N16384S0PoseidonConfig);
impl_suitable_ring!(N16384S1RingNTT, N16384S1RingPoly, N16384S1PoseidonConfig);

#[derive(Clone)]
pub struct N16384Q0ChallengeSet;
#[derive(Clone)]
pub struct N16384Q1ChallengeSet;
#[derive(Clone)]
pub struct N16384Q2ChallengeSet;
#[derive(Clone)]
pub struct N16384Q3ChallengeSet;
#[derive(Clone)]
pub struct N16384PChallengeSet;
#[derive(Clone)]
pub struct N16384S0ChallengeSet;
#[derive(Clone)]
pub struct N16384S1ChallengeSet;

macro_rules! impl_challenge_set {
    ($set:ty, $ring:ty, $poly:ty, $field:ty) => {
        impl LatticefoldChallengeSet<$ring> for $set {
            const BYTES_NEEDED: usize = 16384;

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

impl_challenge_set!(N16384Q0ChallengeSet, N16384Q0RingNTT, N16384Q0RingPoly, N16384Q0Field);
impl_challenge_set!(N16384Q1ChallengeSet, N16384Q1RingNTT, N16384Q1RingPoly, N16384Q1Field);
impl_challenge_set!(N16384Q2ChallengeSet, N16384Q2RingNTT, N16384Q2RingPoly, N16384Q2Field);
impl_challenge_set!(N16384Q3ChallengeSet, N16384Q3RingNTT, N16384Q3RingPoly, N16384Q3Field);
impl_challenge_set!(N16384PChallengeSet, N16384PRingNTT, N16384PRingPoly, N16384PField);
impl_challenge_set!(N16384S0ChallengeSet, N16384S0RingNTT, N16384S0RingPoly, N16384S0Field);
impl_challenge_set!(N16384S1ChallengeSet, N16384S1RingNTT, N16384S1RingPoly, N16384S1Field);

#[cfg(test)]
mod tests {
    use stark_rings::PolyRing;

    use super::*;
    use crate::challenge_set::LatticefoldChallengeSet;

    #[test]
    fn challenge_sets_use_the_full_ring_degree() {
        let bytes = vec![7u8; 16384];
        assert_eq!(
            N16384Q0ChallengeSet::short_challenge_from_random_bytes(&bytes)
                .unwrap()
                .coeffs()
                .len(),
            16384
        );
        assert_eq!(N16384Q0ChallengeSet::BYTES_NEEDED, 16384);
        assert_eq!(N16384Q3ChallengeSet::BYTES_NEEDED, 16384);
        assert_eq!(N16384PChallengeSet::BYTES_NEEDED, 16384);
    }
}
