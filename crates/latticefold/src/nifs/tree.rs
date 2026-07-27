//! Binary fold trees: fold `n` instances into one accumulator with
//! `ceil(log2 n)` sequential depth instead of `n - 1`, each tree node
//! independent (parallelizable). The total fold count is unchanged (`n - 1`
//! acc+acc folds plus `n` leaf linearizations) — the win is wall-clock, not
//! CPU. Soundness is per-node: a verifier checks every leaf linearization
//! and every [`LFAccProof`], in any order; the final accumulator binds the
//! whole tree.
//!
//! Transcript discipline (Fiat–Shamir): each leaf and node runs on a FRESH
//! transcript that absorbs (a) the caller-supplied label (session/committee/
//! channel metadata via `absorb_label`), and (b) its own coordinates —
//! `(0, i)` for leaf `i`, `(level, index)` for fold nodes — before the
//! sub-protocols absorb their instances. Prover and verifier derive
//! identical transcripts from the tree shape, so verification is exact.

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use alloc::{string::String, vec::Vec};
use cyclotomic_rings::rings::SuitableRing;

use super::{
    error::{LatticefoldError, LinearizationError},
    linearization::{
        LFLinearizationProver, LFLinearizationVerifier, LinearizationProver,
        LinearizationVerifier,
    },
    NIFSProver, NIFSVerifier,
};
use crate::{
    arith::{Witness, CCCS, CCS, LCCCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    transcript::{Transcript, TranscriptWithShortChallenges},
};

type Instance<NTT> = (CCCS<NTT>, Witness<NTT>);
type Accumulator<NTT> = (LCCCS<NTT>, Witness<NTT>);

fn tree_error<NTT: SuitableRing>(message: &str) -> LatticefoldError<NTT> {
    LinearizationError::ParametersError(String::from(message)).into()
}

fn absorb_node<NTT: SuitableRing, T: Transcript<NTT>>(transcript: &mut T, level: u64, index: u64) {
    transcript.absorb(&NTT::from(level as u128));
    transcript.absorb(&NTT::from(index as u128));
}

fn par_map<NTT: SuitableRing, A: Send, B: Send>(
    items: Vec<A>,
    f: impl Fn(A) -> Result<B, LatticefoldError<NTT>> + Sync + Send,
) -> Result<Vec<B>, LatticefoldError<NTT>> {
    #[cfg(feature = "parallel")]
    let results: Vec<Result<B, LatticefoldError<NTT>>> =
        items.into_par_iter().map(f).collect();
    #[cfg(not(feature = "parallel"))]
    let results: Vec<Result<B, LatticefoldError<NTT>>> = items.into_iter().map(f).collect();
    results.into_iter().collect()
}

/// Linearize one instance into a size-1 accumulator (tree leaf), verified
/// unless `skip_verify` (the `DKG_VERIFY_FOLDS=0` default in the demo flows).
#[allow(clippy::too_many_arguments)]
fn leaf<NTT, P, T>(
    index: u64,
    cm: &CCCS<NTT>,
    witness: &Witness<NTT>,
    ccs: &CCS<NTT>,
    absorb_label: &(dyn Fn(&mut T) + Sync),
    skip_verify: bool,
) -> Result<Accumulator<NTT>, LatticefoldError<NTT>>
where
    NTT: SuitableRing,
    P: DecompositionParams,
    T: TranscriptWithShortChallenges<NTT> + Default,
{
    let mut prover_transcript = T::default();
    absorb_label(&mut prover_transcript);
    absorb_node(&mut prover_transcript, 0, index);
    let (accumulator, proof) =
        LFLinearizationProver::<_, T>::prove(cm, witness, &mut prover_transcript, ccs)?;

    if !skip_verify {
        let mut verifier_transcript = T::default();
        absorb_label(&mut verifier_transcript);
        absorb_node(&mut verifier_transcript, 0, index);
        let verified =
            LFLinearizationVerifier::<_, T>::verify(cm, &proof, &mut verifier_transcript, ccs)?;
        if verified != accumulator {
            return Err(tree_error("tree leaf linearization mismatch"));
        }
    }

    Ok((accumulator, witness.clone()))
}

/// Fold a pair of accumulators (tree node), verified unless `skip_verify`.
#[allow(clippy::too_many_arguments)]
fn node<NTT, P, T>(
    level: u64,
    index: u64,
    left: &Accumulator<NTT>,
    right: &Accumulator<NTT>,
    ccs: &CCS<NTT>,
    scheme: &AjtaiCommitmentScheme<NTT>,
    absorb_label: &(dyn Fn(&mut T) + Sync),
    skip_verify: bool,
) -> Result<Accumulator<NTT>, LatticefoldError<NTT>>
where
    NTT: SuitableRing,
    P: DecompositionParams,
    T: TranscriptWithShortChallenges<NTT> + Default,
{
    let mut prover_transcript = T::default();
    absorb_label(&mut prover_transcript);
    absorb_node(&mut prover_transcript, level, index);
    let (accumulator, witness, proof) = NIFSProver::<NTT, P, T>::prove_acc(
        &left.0,
        &left.1,
        &right.0,
        &right.1,
        &mut prover_transcript,
        ccs,
        scheme,
    )?;

    if !skip_verify {
        let mut verifier_transcript = T::default();
        absorb_label(&mut verifier_transcript);
        absorb_node(&mut verifier_transcript, level, index);
        let verified = NIFSVerifier::<NTT, P, T>::verify_acc(
            &left.0,
            &right.0,
            &proof,
            &mut verifier_transcript,
            ccs,
        )?;
        if verified != accumulator {
            return Err(tree_error("tree node fold mismatch"));
        }
    }

    Ok((accumulator, witness))
}

/// Fold `instances` into a single accumulator as a binary tree. Odd counts
/// promote the last accumulator unchanged. `absorb_label` must absorb the
/// caller's full metadata context (session, committee, channel, and any
/// per-instance tags in order); node coordinates are absorbed on top.
pub fn fold_tree<NTT, P, T>(
    instances: &[Instance<NTT>],
    ccs: &CCS<NTT>,
    scheme: &AjtaiCommitmentScheme<NTT>,
    absorb_label: &(dyn Fn(&mut T) + Sync),
    skip_verify: bool,
) -> Result<Accumulator<NTT>, LatticefoldError<NTT>>
where
    NTT: SuitableRing,
    P: DecompositionParams,
    T: TranscriptWithShortChallenges<NTT> + Default,
{
    if instances.is_empty() {
        return Err(tree_error("cannot fold an empty instance list"));
    }

    let progress = std::env::var_os("DKG_PROGRESS").is_some();
    let total = instances.len();
    let start = std::time::Instant::now();
    if progress {
        eprintln!("[fold-tree] {total} instances: leaf linearizations started");
    }

    // Leaves: one linearization per instance (independent, parallel).
    let mut accumulators = par_map(
        instances
            .iter()
            .enumerate()
            .map(|(index, (cm, witness))| (index as u64, cm, witness))
            .collect::<Vec<_>>(),
        |(index, cm, witness)| {
            leaf::<NTT, P, T>(index, cm, witness, ccs, absorb_label, skip_verify)
        },
    )?;
    if progress {
        eprintln!(
            "[fold-tree] {total} leaves done in {:.1}s; fold levels started",
            start.elapsed().as_secs_f64()
        );
    }

    // Levels: pairwise acc+acc folds (independent within a level, parallel).
    let mut level = 1u64;
    while accumulators.len() > 1 {
        let promoted = if accumulators.len() % 2 == 1 {
            accumulators.pop()
        } else {
            None
        };
        let level_size = accumulators.len() / 2;
        let level_start = std::time::Instant::now();
        let mut pairs: Vec<(u64, Accumulator<NTT>, Accumulator<NTT>)> = Vec::new();
        let mut iter = accumulators.into_iter();
        let mut index = 0u64;
        while let (Some(left), Some(right)) = (iter.next(), iter.next()) {
            pairs.push((index, left, right));
            index += 1;
        }
        accumulators = par_map(pairs, |(index, left, right)| {
            node::<NTT, P, T>(
                level,
                index,
                &left,
                &right,
                ccs,
                scheme,
                absorb_label,
                skip_verify,
            )
        })?;
        if let Some(tail) = promoted {
            accumulators.push(tail);
        }
        if progress {
            eprintln!(
                "[fold-tree] level {level} ({level_size} folds) done in {:.1}s (total {:.1}s)",
                level_start.elapsed().as_secs_f64(),
                start.elapsed().as_secs_f64()
            );
        }
        level += 1;
    }
    if progress {
        eprintln!(
            "[fold-tree] complete: {total} instances -> 1 accumulator in {:.1}s",
            start.elapsed().as_secs_f64()
        );
    }

    accumulators
        .into_iter()
        .next()
        .ok_or_else(|| tree_error("fold tree produced no accumulator"))
}
