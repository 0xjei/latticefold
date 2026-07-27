//! **Ruser cross-channel message consistency** — the untrusted-user protection
//! the design calls out (§5 Ruser, bullet 2) and the r3_ruser slice only noted.
//!
//! A user encrypting to the threshold key submits ONE logical plaintext `m`
//! but L per-channel ciphertexts. Unlike DKG values (honestly generated once by
//! fhe.rs), the user is untrusted and could encrypt DIFFERENT messages across
//! channels to corrupt the downstream computation. The design prevents this by
//! a commit-once message commitment Com(m): each of the L per-channel Ruser
//! instances must prove its own `m` is an opening of that same commitment.
//!
//! Demonstrated here with L = 2 channel tracks (both on the Goldilocks stand-in
//! ring — real channels are separate moduli/tracks, which is exactly why they
//! CANNOT be folded together and each carries its own CCS + proof):
//!
//!   1. commit-once: Com(m) published from the user's message digits;
//!   2. per channel l: own (pk0_l, pk1_l, Δ_l), own randomness (u,e0,e1),
//!      Ruser CCS satisfied and proved; the channel's committed witness places
//!      `m` in a FIXED slot whose digits are exactly Com(m)'s preimage — since
//!      decomposition is deterministic, recomputing the message commitment from
//!      each channel's witness and comparing to Com(m) is the example's
//!      consistency check. The equality-of-openings proof needed for
//!      verifier-side soundness is not yet part of the CCS/NIFS statement;
//!   3. CHEAT: a channel-2 submission encrypting m' ≠ m satisfies its OWN ct
//!      equations but fails the Com(m) check → detected, submission rejected.
//!
//! Run with: cargo run --release --example dkg_ruser_consistency

use ark_std::UniformRand;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::{AjtaiCommitmentScheme, Commitment},
    decomposition_parameters::DecompositionParams,
    nifs::linearization::{
        LFLinearizationProver, LFLinearizationVerifier, LinearizationProver, LinearizationVerifier,
    },
    transcript::poseidon::PoseidonTranscript,
};
use stark_rings_linalg::SparseMatrix;

type RqNTT = GoldilocksRingNTT;
type CS = GoldilocksChallengeSet;
type T = PoseidonTranscript<RqNTT, CS>;

#[derive(Clone)]
struct DP {}
impl DecompositionParams for DP {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    const K: usize = 15;
}

/// Witness = (u, e0, e1, m); m occupies the LAST slot in every channel.
const WIT_LEN: usize = 4;
const N: usize = WIT_LEN * DP::L;
const KAPPA: usize = 4;
const CHANNELS: usize = 2; // L = 2 stand-in RNS channels

// z = [ct0, ct1, one, u, e0, e1, m]
const IDX_CT0: usize = 0;
const IDX_CT1: usize = 1;
const IDX_ONE: usize = 2;
const IDX_U: usize = 3;
const IDX_E0: usize = 4;
const IDX_E1: usize = 5;
const IDX_M: usize = 6;
const N_COLS: usize = 7;

#[allow(non_snake_case)]
fn enc_r1cs(pk0: &RqNTT, pk1: &RqNTT, delta: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let neg_one = -one;
    let a0 = vec![
        (one, IDX_CT0),
        (-*pk0, IDX_U),
        (neg_one, IDX_E0),
        (-*delta, IDX_M),
    ];
    let a1 = vec![(one, IDX_CT1), (-*pk1, IDX_U), (neg_one, IDX_E1)];
    R1CS::<RqNTT> {
        l: 2,
        A: SparseMatrix {
            nrows: 2,
            ncols: N_COLS,
            coeffs: vec![a0, a1],
        },
        B: SparseMatrix {
            nrows: 2,
            ncols: N_COLS,
            coeffs: vec![vec![(one, IDX_ONE)], vec![(one, IDX_ONE)]],
        },
        C: SparseMatrix {
            nrows: 2,
            ncols: N_COLS,
            coeffs: vec![vec![], vec![]],
        },
    }
}

fn short(rng: &mut impl ark_std::rand::Rng) -> RqNTT {
    RqNTT::from(rng.gen_range(0..3u128))
}

/// The message commitment: the digits of `m` in the witness's m-slot, committed
/// under the dedicated message key. Deterministic ⇒ same m, same commitment.
fn message_commitment(m: RqNTT, scheme: &AjtaiCommitmentScheme<RqNTT>) -> Commitment<RqNTT> {
    Witness::<RqNTT>::from_w_ccs::<DP>(vec![m])
        .commit::<DP>(scheme)
        .unwrap()
}

/// One channel's Ruser submission for message `m`; returns the instance and the
/// message commitment recomputed FROM the channel's own witness slot.
struct ChannelSubmission {
    cm: CCCS<RqNTT>,
    wit: Witness<RqNTT>,
    m_com: Commitment<RqNTT>,
}

fn submit(
    m: RqNTT,
    pk0: &RqNTT,
    pk1: &RqNTT,
    delta: &RqNTT,
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
    m_scheme: &AjtaiCommitmentScheme<RqNTT>,
    rng: &mut impl ark_std::rand::Rng,
) -> ChannelSubmission {
    let (u, e0, e1) = (short(rng), short(rng), short(rng));
    let ct0 = *pk0 * u + e0 + *delta * m;
    let ct1 = *pk1 * u + e1;
    let z = vec![ct0, ct1, RqNTT::from(1u128), u, e0, e1, m];
    ccs.check_relation(&z)
        .expect("Ruser relation not satisfied");

    let wit = Witness::from_w_ccs::<DP>(vec![u, e0, e1, m]);
    // The m-slot digits are the last DP::L entries of the decomposed witness —
    // exactly the preimage of the published message commitment.
    let m_digits = wit.f[(WIT_LEN - 1) * DP::L..].to_vec();
    let m_com = m_scheme.commit_ntt(&m_digits).unwrap();

    let cm = CCCS {
        cm: wit.commit::<DP>(scheme).unwrap(),
        x_ccs: vec![ct0, ct1],
    };
    ChannelSubmission { cm, wit, m_com }
}

fn main() {
    println!("LatticeFold VDKG — Ruser CROSS-CHANNEL message consistency (untrusted user)");
    println!("L={CHANNELS} channel tracks, one commit-once Com(m) | Goldilocks stand-in\n");

    let mut rng = ark_std::test_rng();

    // Dedicated message-commitment key (shared by all channels' checks).
    let m_scheme: AjtaiCommitmentScheme<RqNTT> =
        AjtaiCommitmentScheme::rand(KAPPA, DP::L, &mut rng);

    // Per-channel public data: own threshold key + scaling constant, own CCS.
    let channels: Vec<(RqNTT, RqNTT, RqNTT)> = (0..CHANNELS)
        .map(|l| {
            (
                RqNTT::rand(&mut rng),
                RqNTT::rand(&mut rng),
                RqNTT::from(3 + 2 * l as u128),
            )
        })
        .collect();
    let ccss: Vec<CCS<RqNTT>> = channels
        .iter()
        .map(|(pk0, pk1, d)| CCS::from_r1cs_padded(enc_r1cs(pk0, pk1, d), N, DP::L))
        .collect();
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    // (1) The user commits to m ONCE.
    let m = short(&mut rng);
    let com_m = message_commitment(m, &m_scheme);
    println!("(1) commit-once: Com(m) published (single message commitment) ✓");

    // (2) One submission per channel; each proves its CCS and its m-slot digits
    //     must open Com(m).
    for (l, ((pk0, pk1, delta), ccs)) in channels.iter().zip(&ccss).enumerate() {
        let sub = submit(m, pk0, pk1, delta, ccs, &scheme, &m_scheme, &mut rng);
        assert_eq!(sub.m_com, com_m, "channel {l} message does not open Com(m)");

        // Channel-track proof (channels are separate tracks — folded within a
        // channel across submissions, never across channels/moduli).
        let mut pt = PoseidonTranscript::<RqNTT, CS>::default();
        let (_lin, proof) = LFLinearizationProver::<_, T>::prove(&sub.cm, &sub.wit, &mut pt, ccs)
            .expect("channel proof failed");
        let mut vt = PoseidonTranscript::<RqNTT, CS>::default();
        LFLinearizationVerifier::<_, T>::verify(&sub.cm, &proof, &mut vt, ccs)
            .expect("channel proof verification failed");
        println!(
            "(2) channel {l}: Ruser CCS proved ✓  m-slot opens Com(m) ✓  (Δ_l = {})",
            3 + 2 * l
        );
    }

    // (3) CHEAT: channel-2 submission with a DIFFERENT message m' ≠ m. Its own
    //     ct equations hold, but its m-slot cannot open Com(m).
    let m_cheat = m + RqNTT::from(1u128);
    let (pk0, pk1, delta) = &channels[CHANNELS - 1];
    let cheat = submit(
        m_cheat,
        pk0,
        pk1,
        delta,
        &ccss[CHANNELS - 1],
        &scheme,
        &m_scheme,
        &mut rng,
    );
    ccss[CHANNELS - 1]
        .check_relation(&{
            // the cheater's ciphertext is internally consistent…
            let mut z = vec![cheat.cm.x_ccs[0], cheat.cm.x_ccs[1], RqNTT::from(1u128)];
            z.extend(cheat.wit.w_ccs.iter().copied());
            z
        })
        .expect("cheat ct is internally valid — that's the point");
    assert_ne!(cheat.m_com, com_m, "cheat MUST fail the Com(m) check");
    println!(
        "\n(3) CHEAT: channel-{} submission with m' ≠ m is internally valid but",
        CHANNELS - 1
    );
    println!("    fails the Com(m) opening check → submission rejected ✓");

    println!("\nResult: the commit-once/reference-many consistency check is exercised.");
    println!("A production verifier still needs an equality-of-openings relation in");
    println!("the proof statement; these local commitment comparisons are not sufficient.");
}
