//! Native N=4096 LatticeFold rings for the three threshold-BFV RNS channels.

use stark_rings::cyclotomic_ring::models::n4096::{
    Fq0, Fq1, Fq2, FqP, PRingNTT, PRingPoly, Q0RingNTT, Q0RingPoly, Q1RingNTT, Q1RingPoly,
    Q2RingNTT, Q2RingPoly,
};

use super::SuitableRing;
use crate::{
    ark_base::*,
    challenge_set::{error, LatticefoldChallengeSet},
};

pub type N4096Q0RingNTT = Q0RingNTT;
pub type N4096Q0RingPoly = Q0RingPoly;
pub type N4096Q0Field = Fq0;
pub type N4096Q1RingNTT = Q1RingNTT;
pub type N4096Q1RingPoly = Q1RingPoly;
pub type N4096Q1Field = Fq1;
pub type N4096Q2RingNTT = Q2RingNTT;
pub type N4096Q2RingPoly = Q2RingPoly;
pub type N4096Q2Field = Fq2;
pub type N4096PRingNTT = PRingNTT;
pub type N4096PRingPoly = PRingPoly;
pub type N4096PField = FqP;

impl SuitableRing for N4096Q0RingNTT {
    type CoefficientRepresentation = N4096Q0RingPoly;
    type PoseidonParams = N4096Q0PoseidonConfig;
}

impl SuitableRing for N4096Q1RingNTT {
    type CoefficientRepresentation = N4096Q1RingPoly;
    type PoseidonParams = N4096Q1PoseidonConfig;
}

impl SuitableRing for N4096Q2RingNTT {
    type CoefficientRepresentation = N4096Q2RingPoly;
    type PoseidonParams = N4096Q2PoseidonConfig;
}

impl SuitableRing for N4096PRingNTT {
    type CoefficientRepresentation = N4096PRingPoly;
    type PoseidonParams = N4096PPoseidonConfig;
}

pub struct N4096Q0PoseidonConfig;
pub struct N4096Q1PoseidonConfig;
pub struct N4096Q2PoseidonConfig;
pub struct N4096PPoseidonConfig;

#[derive(Clone)]
pub struct N4096Q0ChallengeSet;

#[derive(Clone)]
pub struct N4096Q1ChallengeSet;

#[derive(Clone)]
pub struct N4096Q2ChallengeSet;

impl LatticefoldChallengeSet<N4096Q0RingNTT> for N4096Q0ChallengeSet {
    const BYTES_NEEDED: usize = 4096;

    fn short_challenge_from_random_bytes(
        bs: &[u8],
    ) -> Result<N4096Q0RingPoly, error::ChallengeSetError> {
        if bs.len() != Self::BYTES_NEEDED {
            return Err(error::ChallengeSetError::TooFewBytes(
                bs.len(),
                Self::BYTES_NEEDED,
            ));
        }
        Ok(N4096Q0RingPoly::from(
            bs.iter().map(|&byte| Fq0::from(byte)).collect::<Vec<Fq0>>(),
        ))
    }
}

impl LatticefoldChallengeSet<N4096Q1RingNTT> for N4096Q1ChallengeSet {
    const BYTES_NEEDED: usize = 4096;

    fn short_challenge_from_random_bytes(
        bs: &[u8],
    ) -> Result<N4096Q1RingPoly, error::ChallengeSetError> {
        if bs.len() != Self::BYTES_NEEDED {
            return Err(error::ChallengeSetError::TooFewBytes(
                bs.len(),
                Self::BYTES_NEEDED,
            ));
        }
        Ok(N4096Q1RingPoly::from(
            bs.iter().map(|&byte| Fq1::from(byte)).collect::<Vec<Fq1>>(),
        ))
    }
}

#[derive(Clone)]
pub struct N4096PChallengeSet;

impl LatticefoldChallengeSet<N4096PRingNTT> for N4096PChallengeSet {
    const BYTES_NEEDED: usize = 4096;

    fn short_challenge_from_random_bytes(
        bs: &[u8],
    ) -> Result<N4096PRingPoly, error::ChallengeSetError> {
        if bs.len() != Self::BYTES_NEEDED {
            return Err(error::ChallengeSetError::TooFewBytes(
                bs.len(),
                Self::BYTES_NEEDED,
            ));
        }
        Ok(N4096PRingPoly::from(
            bs.iter().map(|&byte| FqP::from(byte)).collect::<Vec<FqP>>(),
        ))
    }
}

impl LatticefoldChallengeSet<N4096Q2RingNTT> for N4096Q2ChallengeSet {
    const BYTES_NEEDED: usize = 4096;

    fn short_challenge_from_random_bytes(
        bs: &[u8],
    ) -> Result<N4096Q2RingPoly, error::ChallengeSetError> {
        if bs.len() != Self::BYTES_NEEDED {
            return Err(error::ChallengeSetError::TooFewBytes(
                bs.len(),
                Self::BYTES_NEEDED,
            ));
        }
        Ok(N4096Q2RingPoly::from(
            bs.iter().map(|&byte| Fq2::from(byte)).collect::<Vec<Fq2>>(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use stark_rings::PolyRing;

    use super::*;
    use crate::challenge_set::LatticefoldChallengeSet;

    #[test]
    fn challenge_sets_use_the_full_ring_degree() {
        let bytes = vec![7u8; 4096];
        assert_eq!(
            N4096Q0ChallengeSet::short_challenge_from_random_bytes(&bytes)
                .unwrap()
                .coeffs()
                .len(),
            4096
        );
        assert_eq!(N4096Q0ChallengeSet::BYTES_NEEDED, 4096);
        assert_eq!(N4096Q1ChallengeSet::BYTES_NEEDED, 4096);
        assert_eq!(N4096Q2ChallengeSet::BYTES_NEEDED, 4096);
    }
}
