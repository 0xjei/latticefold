//! The NIFS module defines the behaviour of the [LatticeFold](https://eprint.iacr.org/2024/257.pdf) protocol
//!
//! NIFS = Non Interactive Folding Scheme

use alloc::string::String;

use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{marker::PhantomData, vec::Vec};
use cyclotomic_rings::rings::SuitableRing;
use stark_rings::OverField;

use self::{decomposition::*, error::LatticefoldError, folding::*, linearization::*};
use crate::{
    arith::{error::CSError, Witness, CCCS, CCS, LCCCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    transcript::{Transcript, TranscriptWithShortChallenges},
};

pub mod decomposition;
pub mod error;
pub mod folding;
pub mod linearization;
pub mod tree;

#[cfg(test)]
mod tests;

/// `NTT` is a cyclotomic ring in the NTT form.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct LFProof<NTT: OverField> {
    pub linearization_proof: LinearizationProof<NTT>,
    pub decomposition_proof_l: DecompositionProof<NTT>,
    pub decomposition_proof_r: DecompositionProof<NTT>,
    pub folding_proof: FoldingProof<NTT>,
}

/// `NTT` is a suitable cyclotomic ring.
/// `P` is the decomposition parameters.
/// `T` is the FS-transform transcript.
pub struct NIFSProver<NTT, P, T> {
    _r: PhantomData<NTT>,
    _p: PhantomData<P>,
    _t: PhantomData<T>,
}

impl<NTT: SuitableRing, P: DecompositionParams, T: TranscriptWithShortChallenges<NTT>>
    NIFSProver<NTT, P, T>
{
    pub fn prove(
        acc: &LCCCS<NTT>,
        w_acc: &Witness<NTT>,
        cm_i: &CCCS<NTT>,
        w_i: &Witness<NTT>,
        transcript: &mut impl TranscriptWithShortChallenges<NTT>,
        ccs: &CCS<NTT>,
        scheme: &AjtaiCommitmentScheme<NTT>,
    ) -> Result<(LCCCS<NTT>, Witness<NTT>, LFProof<NTT>), LatticefoldError<NTT>> {
        sanity_check::<NTT, P>(ccs)?;

        absorb_public_input::<NTT>(acc, cm_i, transcript);

        let (linearized_cm_i, linearization_proof) =
            LFLinearizationProver::<_, T>::prove(cm_i, w_i, transcript, ccs)?;
        let (mz_mles_l, decomposed_lcccs_l, decomposed_wit_l, decomposition_proof_l) =
            LFDecompositionProver::<_, T>::prove::<P>(acc, w_acc, transcript, ccs, scheme)?;
        let (mz_mles_r, decomposed_lcccs_r, decomposed_wit_r, decomposition_proof_r) =
            LFDecompositionProver::<_, T>::prove::<P>(
                &linearized_cm_i,
                w_i,
                transcript,
                ccs,
                scheme,
            )?;

        let (mz_mles, lcccs, wit_s) = {
            let mut lcccs = decomposed_lcccs_l;
            let mut lcccs_r = decomposed_lcccs_r;
            lcccs.append(&mut lcccs_r);

            let mut wit_s = decomposed_wit_l;
            let mut wit_s_r = decomposed_wit_r;
            wit_s.append(&mut wit_s_r);

            let mut mz_mles = mz_mles_l;
            let mut mz_mles_r = mz_mles_r;
            mz_mles.append(&mut mz_mles_r);
            (mz_mles, lcccs, wit_s)
        };

        let (folded_lcccs, wit, folding_proof) =
            LFFoldingProver::<_, T>::prove::<P>(&lcccs, wit_s, transcript, ccs, &mz_mles)?;

        Ok((
            folded_lcccs,
            wit,
            LFProof {
                linearization_proof,
                decomposition_proof_l,
                decomposition_proof_r,
                folding_proof,
            },
        ))
    }

    /// Fold two accumulators into one (no linearization: both are already
    /// relaxed LCCCS instances). This is the decompose-and-fold half of
    /// [`NIFSProver::prove`] applied symmetrically to both inputs, and is the
    /// building block for binary fold trees. Soundness is inherited from the
    /// child accumulators' own verification history; a verifier checking the
    /// tree verifies every node's [`LFAccProof`] (in any order).
    pub fn prove_acc(
        acc_l: &LCCCS<NTT>,
        w_l: &Witness<NTT>,
        acc_r: &LCCCS<NTT>,
        w_r: &Witness<NTT>,
        transcript: &mut impl TranscriptWithShortChallenges<NTT>,
        ccs: &CCS<NTT>,
        scheme: &AjtaiCommitmentScheme<NTT>,
    ) -> Result<(LCCCS<NTT>, Witness<NTT>, LFAccProof<NTT>), LatticefoldError<NTT>> {
        sanity_check::<NTT, P>(ccs)?;

        absorb_acc::<NTT>(acc_l, b"acc", transcript);
        absorb_acc::<NTT>(acc_r, b"acc_r", transcript);

        let (mz_mles_l, decomposed_lcccs_l, decomposed_wit_l, decomposition_proof_l) =
            LFDecompositionProver::<_, T>::prove::<P>(acc_l, w_l, transcript, ccs, scheme)?;
        let (mz_mles_r, decomposed_lcccs_r, decomposed_wit_r, decomposition_proof_r) =
            LFDecompositionProver::<_, T>::prove::<P>(acc_r, w_r, transcript, ccs, scheme)?;

        let (mz_mles, lcccs, wit_s) = {
            let mut lcccs = decomposed_lcccs_l;
            let mut lcccs_r = decomposed_lcccs_r;
            lcccs.append(&mut lcccs_r);

            let mut wit_s = decomposed_wit_l;
            let mut wit_s_r = decomposed_wit_r;
            wit_s.append(&mut wit_s_r);

            let mut mz_mles = mz_mles_l;
            let mut mz_mles_r = mz_mles_r;
            mz_mles.append(&mut mz_mles_r);
            (mz_mles, lcccs, wit_s)
        };

        let (folded_lcccs, wit, folding_proof) =
            LFFoldingProver::<_, T>::prove::<P>(&lcccs, wit_s, transcript, ccs, &mz_mles)?;

        Ok((
            folded_lcccs,
            wit,
            LFAccProof {
                decomposition_proof_l,
                decomposition_proof_r,
                folding_proof,
            },
        ))
    }
}

/// Proof of an accumulator+accumulator fold (no linearization: both inputs
/// are already relaxed LCCCS instances). Enables binary fold trees: the same
/// total fold count as a sequential chain, but log2(n) depth with
/// independent (parallelizable) nodes.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct LFAccProof<NTT: OverField> {
    pub decomposition_proof_l: DecompositionProof<NTT>,
    pub decomposition_proof_r: DecompositionProof<NTT>,
    pub folding_proof: FoldingProof<NTT>,
}

/// `NTT` is a suitable cyclotomic ring.
/// `P` is the decomposition parameters.
/// `T` is the FS-transform transcript.
pub struct NIFSVerifier<NTT, P, T> {
    _r: PhantomData<NTT>,
    _p: PhantomData<P>,
    _t: PhantomData<T>,
}

impl<NTT: SuitableRing, P: DecompositionParams, T: TranscriptWithShortChallenges<NTT>>
    NIFSVerifier<NTT, P, T>
{
    pub fn verify(
        acc: &LCCCS<NTT>,
        cm_i: &CCCS<NTT>,
        proof: &LFProof<NTT>,
        transcript: &mut impl TranscriptWithShortChallenges<NTT>,
        ccs: &CCS<NTT>,
    ) -> Result<LCCCS<NTT>, LatticefoldError<NTT>> {
        sanity_check::<NTT, P>(ccs)?;

        if cm_i.x_ccs.len() != ccs.l || acc.cm.len() != cm_i.cm.len() {
            return Err(CSError::LengthsNotEqual(
                String::from("accumulator/instance commitment or public-input length"),
                String::from("CCS shape"),
                acc.cm.len().max(cm_i.cm.len()),
                ccs.l,
            )
            .into());
        }

        absorb_public_input::<NTT>(acc, cm_i, transcript);

        let linearized_cm_i = LFLinearizationVerifier::<_, T>::verify(
            cm_i,
            &proof.linearization_proof,
            transcript,
            ccs,
        )?;
        let decomposed_acc = LFDecompositionVerifier::<_, T>::verify::<P>(
            acc,
            &proof.decomposition_proof_l,
            transcript,
            ccs,
        )?;
        let decomposed_cm_i = LFDecompositionVerifier::<_, T>::verify::<P>(
            &linearized_cm_i,
            &proof.decomposition_proof_r,
            transcript,
            ccs,
        )?;

        let lcccs_s = {
            let mut decomposed_acc = decomposed_acc;
            let mut decomposed_cm_i = decomposed_cm_i;

            decomposed_acc.append(&mut decomposed_cm_i);

            decomposed_acc
        };

        Ok(LFFoldingVerifier::<NTT, T>::verify::<P>(
            &lcccs_s,
            &proof.folding_proof,
            transcript,
            ccs,
        )?)
    }

    /// Verify an accumulator+accumulator fold, mirroring
    /// [`NIFSProver::prove_acc`].
    pub fn verify_acc(
        acc_l: &LCCCS<NTT>,
        acc_r: &LCCCS<NTT>,
        proof: &LFAccProof<NTT>,
        transcript: &mut impl TranscriptWithShortChallenges<NTT>,
        ccs: &CCS<NTT>,
    ) -> Result<LCCCS<NTT>, LatticefoldError<NTT>> {
        sanity_check::<NTT, P>(ccs)?;

        if acc_l.cm.len() != acc_r.cm.len() {
            return Err(CSError::LengthsNotEqual(
                String::from("accumulator commitment lengths"),
                String::from("each other"),
                acc_l.cm.len().max(acc_r.cm.len()),
                acc_l.cm.len().min(acc_r.cm.len()),
            )
            .into());
        }

        absorb_acc::<NTT>(acc_l, b"acc", transcript);
        absorb_acc::<NTT>(acc_r, b"acc_r", transcript);

        let decomposed_l = LFDecompositionVerifier::<_, T>::verify::<P>(
            acc_l,
            &proof.decomposition_proof_l,
            transcript,
            ccs,
        )?;
        let decomposed_r = LFDecompositionVerifier::<_, T>::verify::<P>(
            acc_r,
            &proof.decomposition_proof_r,
            transcript,
            ccs,
        )?;

        let lcccs_s = {
            let mut decomposed_l = decomposed_l;
            let mut decomposed_r = decomposed_r;

            decomposed_l.append(&mut decomposed_r);

            decomposed_l
        };

        Ok(LFFoldingVerifier::<NTT, T>::verify::<P>(
            &lcccs_s,
            &proof.folding_proof,
            transcript,
            ccs,
        )?)
    }
}

fn sanity_check<NTT: SuitableRing, DP: DecompositionParams>(
    ccs: &CCS<NTT>,
) -> Result<(), LatticefoldError<NTT>> {
    if ccs.m != usize::max((ccs.n - ccs.l - 1) * DP::L, ccs.m).next_power_of_two() {
        return Err(CSError::InvalidSizeBounds(ccs.m, ccs.n, DP::L).into());
    }

    Ok(())
}

/// Absorb one LCCCS accumulator under a domain tag (used by the
/// accumulator+accumulator fold path; prover and verifier absorb the same
/// values in the same order).
fn absorb_acc<NTT: SuitableRing>(
    acc: &LCCCS<NTT>,
    tag: &'static [u8],
    transcript: &mut impl Transcript<NTT>,
) {
    transcript.absorb_field_element(&<NTT::BaseRing as Field>::from_base_prime_field(
        <NTT::BaseRing as Field>::BasePrimeField::from_be_bytes_mod_order(tag),
    ));

    transcript.absorb_slice(&acc.r);
    transcript.absorb_slice(&acc.v);
    transcript.absorb_slice(acc.cm.as_ref());
    transcript.absorb_slice(&acc.u);
    transcript.absorb_slice(&acc.x_w);
    transcript.absorb(&acc.h);
}

fn absorb_public_input<NTT: SuitableRing>(
    acc: &LCCCS<NTT>,
    cm_i: &CCCS<NTT>,
    transcript: &mut impl Transcript<NTT>,
) {
    transcript.absorb_field_element(&<NTT::BaseRing as Field>::from_base_prime_field(
        <NTT::BaseRing as Field>::BasePrimeField::from_be_bytes_mod_order(b"acc"),
    ));

    transcript.absorb_slice(&acc.r);
    transcript.absorb_slice(&acc.v);
    transcript.absorb_slice(acc.cm.as_ref());
    transcript.absorb_slice(&acc.u);
    transcript.absorb_slice(&acc.x_w);
    transcript.absorb(&acc.h);

    transcript.absorb_field_element(&<NTT::BaseRing as Field>::from_base_prime_field(
        <NTT::BaseRing as Field>::BasePrimeField::from_be_bytes_mod_order(b"cm_i"),
    ));

    transcript.absorb_slice(cm_i.cm.as_ref());
    transcript.absorb_slice(&cm_i.x_ccs);
}
