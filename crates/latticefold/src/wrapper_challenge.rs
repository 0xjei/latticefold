//! Off-circuit Fiat–Shamir challenge derivation for the C5/C7 wrapper
//! circuits, per plan §7.1/§11: the challenges are bound to the published
//! commitments, not derived in-circuit.
//!
//! The protocol is commit-then-challenge:
//!
//! 1. The prover publishes the compact commitment digests (§6.2 outer
//!    commitments, 1–4 field elements each) for every quantity entering the
//!    wrapper: the folded-track accumulators, the aggregate key, the
//!    committee/parameter domain.
//! 2. The wrapper's challenge is
//!    `r = Poseidon(tag, digest_1, ..., digest_k)`, derived OFF-CIRCUIT.
//!    It is unpredictable to the prover at commitment time (the commitments
//!    are MSIS-binding), so the Schwartz–Zippel checks inside the wrapper are
//!    sound — with **zero in-circuit hashing**.
//! 3. The on-chain verifier recomputes `r` from the published digests (one
//!    hash over a handful of field elements — cheap) and checks it equals
//!    the wrapper's public input.
//!
//! The same module derives the linearization challenge point used for the
//! decider's evaluation-consistency check (the folding transcript's own
//! native challenge, replayed off-circuit per plan §7.1).

use cyclotomic_rings::{challenge_set::LatticefoldChallengeSet, rings::SuitableRing};
use stark_rings::Ring;

use crate::transcript::{poseidon::PoseidonTranscript, Transcript};

/// Derive base-field challenges from a domain tag and a list of digests
/// (commitment ring elements absorbed coefficient-wise).
pub fn derive_field_challenges<R: SuitableRing, CS: LatticefoldChallengeSet<R>>(
    tag: &str,
    digests: &[R],
    count: usize,
) -> Vec<R::BaseRing> {
    let mut transcript = PoseidonTranscript::<R, CS>::default();
    for &byte in tag.as_bytes() {
        transcript.absorb_field_element(&R::BaseRing::from(byte));
    }
    for digest in digests {
        transcript.absorb(digest);
    }
    transcript.get_challenges(count)
}

/// Derive one full ring-element challenge (per-coefficient squeeze) from a
/// domain tag and digests.
pub fn derive_ring_challenge<R: SuitableRing, CS: LatticefoldChallengeSet<R>>(
    tag: &str,
    digests: &[R],
) -> R
where
    R: From<Vec<R::BaseRing>>,
{
    let mut transcript = PoseidonTranscript::<R, CS>::default();
    for &byte in tag.as_bytes() {
        transcript.absorb_field_element(&R::BaseRing::from(byte));
    }
    for digest in digests {
        transcript.absorb(digest);
    }
    R::from(transcript.get_challenges(R::dimension()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyclotomic_rings::rings::{N8192Q0ChallengeSet, N8192Q0RingNTT};

    #[test]
    fn challenge_derivation_is_deterministic_and_domain_separated() {
        let digest = N8192Q0RingNTT::from(42u128);
        let a = derive_field_challenges::<N8192Q0RingNTT, N8192Q0ChallengeSet>(
            "vdkg/c5/q0",
            &[digest],
            4,
        );
        let b = derive_field_challenges::<N8192Q0RingNTT, N8192Q0ChallengeSet>(
            "vdkg/c5/q0",
            &[digest],
            4,
        );
        let c = derive_field_challenges::<N8192Q0RingNTT, N8192Q0ChallengeSet>(
            "vdkg/c5/q1",
            &[digest],
            4,
        );
        assert_eq!(a, b, "same tag + digests must re-derive the same challenge");
        assert_ne!(a, c, "different tags must give different challenges");
    }
}
