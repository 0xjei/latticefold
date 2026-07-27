//! The CROSS-RELATION CHAIN the per-relation slices left unwired: one channel's
//! DKG run where each relation consumes the PREVIOUS relation's actual outputs,
//! bound by the §6 commitment-and-consistency chain — not fresh random witnesses.
//!
//! Flow (single Goldilocks channel standing in for one q_l track):
//!
//!   R1  each dealer i:  pk0_i = -a·sk_i + e_i, folded; publishes Com(sk_i),
//!       Com(e_sm_i) — the commit-once anchors.
//!   R2  each dealer Shamir-shares ITS OWN sk_i and e_sm_i. The CCS enforces
//!       BOTH plan constraints: (2) batched Reed–Solomon H·Y = 0, and — the
//!       previously-missing constraint (1) — consistency with R1: the sharing's
//!       zeroth value s_0 is a witness column bound by the interpolation row
//!       Σ_k λ_k·Y[k] = s_0, and its commitment must equal the R1 anchor
//!       (deterministic decomposition ⇒ Com([s_0]) == Com([sk_i]) iff values match).
//!   R4  each recipient aggregates the REAL received shares: agg_k = Σ_i Y_i[k].
//!       Free link: Σ Com(digits) == Com(Σ digits), and the linear recompose of
//!       the digit-sum equals agg_k — so Com(Σ digits) publicly pins agg_k.
//!   R6  the 27 = T threshold recipients compute d_k = ct0 + ct1·agg_sk_k +
//!       agg_esm_k with the CHAINED aggregates as witness, folded. The z-value
//!       is asserted equal to the R4-pinned aggregate before proving.
//!   R7  (public, no ZK per the design): Lagrange-interpolate the d_k at 0 and
//!       check the end-to-end DKG identity
//!           Σ_k λ_k·d_k  ==  ct0 + ct1·(Σ_i sk_i) + (Σ_i e_sm_i)
//!       i.e. the threshold decryption really reconstructs against the SUM of
//!       the dealers' R1 secrets — the whole point of the protocol.
//!
//! Also includes a CHEAT test: a dealer whose R2 sharing has s_0 ≠ its R1 sk is
//! caught by the commitment-anchor mismatch (and would be discarded, per §2.3).
//!
//! Per-relation mechanics (opening folds for R4, norm proofs, etc.) are covered
//! by the individual slices; this example is about the LINKS between them.
//!
//! Run with: cargo run --release --example dkg_chain

use std::time::Instant;

use ark_ff::{Field, PrimeField};
use ark_std::UniformRand;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::{AjtaiCommitmentScheme, Commitment},
    decomposition_parameters::DecompositionParams,
    nifs::{
        linearization::{LFLinearizationProver, LinearizationProver},
        NIFSProver, NIFSVerifier,
    },
    transcript::poseidon::PoseidonTranscript,
};
use stark_rings::cyclotomic_ring::{models::goldilocks::Fq, ICRT};
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
    // R4 carries sums of up to 51 decomposed shares into R6. Those sums are
    // intentionally non-canonical and need extra binary headroom beyond the
    // single-value B decomposition before the next fold.
    const K: usize = 22;
}

/// Committee N=100, threshold T=27 (degree-26 polynomial), H=51 honest dealers.
const SHARES: usize = 100;
const T_DEG: usize = 26;
const THRESH: usize = T_DEG + 1; // 27
const PARITY: usize = SHARES - THRESH; // 73
const DEALERS: usize = 51;

const KAPPA: usize = 4;

fn scalar_ring(c: Fq) -> RqNTT {
    RqNTT::from(c.into_bigint().as_ref()[0] as u128)
}

/// Evaluation points a_1..a_n.
fn eval_points() -> Vec<Fq> {
    (1..=SHARES as u64).map(Fq::from).collect()
}

/// GRS dual multipliers u_k = 1 / Π_{j≠k}(a_k − a_j) (parity rows).
fn dual_multipliers(a: &[Fq]) -> Vec<Fq> {
    a.iter()
        .enumerate()
        .map(|(k, &ak)| {
            a.iter()
                .enumerate()
                .filter(|(j, _)| *j != k)
                .fold(Fq::ONE, |acc, (_, &aj)| acc * (ak - aj))
                .inverse()
                .unwrap()
        })
        .collect()
}

/// Lagrange-at-0 weights over a subset of the points.
fn lagrange0(points: &[Fq]) -> Vec<Fq> {
    points
        .iter()
        .enumerate()
        .map(|(i, &xi)| {
            points
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .fold(Fq::ONE, |acc, (_, &xj)| {
                    acc * xj * (xj - xi).inverse().unwrap()
                })
        })
        .collect()
}

/// A short ring element (stand-in for a ternary DKG secret / error).
fn short(rng: &mut impl ark_std::rand::Rng) -> RqNTT {
    RqNTT::from(rng.gen_range(0..3u128))
}

/// Deterministic commit-once anchor for a single ring value.
fn anchor(v: RqNTT, scheme: &AjtaiCommitmentScheme<RqNTT>) -> Commitment<RqNTT> {
    Witness::<RqNTT>::from_w_ccs::<DP>(vec![v])
        .commit::<DP>(scheme)
        .unwrap()
}

// ---------------------------------------------------------------------------
// R1: pk0 = -a*sk + e, with e_sm included in the committed short witness.
// z = [pk0, 1, sk, e, e_sm].
// ---------------------------------------------------------------------------
const R1_WIT: usize = 3;
const R1_N: usize = R1_WIT * DP::L;

#[allow(non_snake_case)]
fn r1_r1cs(a: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    R1CS::<RqNTT> {
        l: 1,
        A: SparseMatrix {
            nrows: 1,
            ncols: 5,
            coeffs: vec![vec![(-*a, 2), (one, 3), (-one, 0)]],
        },
        B: SparseMatrix {
            nrows: 1,
            ncols: 5,
            coeffs: vec![vec![(one, 1)]],
        },
        C: SparseMatrix {
            nrows: 1,
            ncols: 5,
            coeffs: vec![vec![]],
        },
    }
}

// ---------------------------------------------------------------------------
// R2: parity rows H·Y = 0  PLUS the R1-consistency row  Σ_k λ_k·Y[k] − s_0 = 0.
// z = [one, s0, Y_0..Y_{n-1}].
// ---------------------------------------------------------------------------
const R2_WIT: usize = 1 + SHARES; // s0 + shares
const R2_N: usize = R2_WIT * DP::L;
const R2_IDX_S0: usize = 1;
const R2_IDX_Y: usize = 2; // Y_k at column 2+k
const R2_COLS: usize = 2 + SHARES;

#[allow(non_snake_case)]
fn r2_r1cs(a: &[Fq], u: &[Fq], lam: &[Fq]) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    let rows = PARITY + 1;
    let mut A_rows = Vec::with_capacity(rows);

    // Parity rows: Σ_k u_k·a_k^r · Y[k] = 0.
    for r in 0..PARITY {
        let row = (0..SHARES)
            .map(|k| (scalar_ring(u[k] * a[k].pow([r as u64])), R2_IDX_Y + k))
            .collect();
        A_rows.push(row);
    }
    // Consistency-with-R1 row (plan constraint #1): Σ_{k<THRESH} λ_k·Y[k] − s0 = 0.
    let mut bind = vec![(-one, R2_IDX_S0)];
    for (k, &l) in lam.iter().enumerate() {
        bind.push((scalar_ring(l), R2_IDX_Y + k));
    }
    A_rows.push(bind);

    R1CS::<RqNTT> {
        l: 0,
        A: SparseMatrix {
            nrows: rows,
            ncols: R2_COLS,
            coeffs: A_rows,
        },
        B: SparseMatrix {
            nrows: rows,
            ncols: R2_COLS,
            coeffs: vec![vec![(one, 0)]; rows],
        },
        C: SparseMatrix {
            nrows: rows,
            ncols: R2_COLS,
            coeffs: vec![vec![]; rows],
        },
    }
}

/// Shamir-share `secret` (s_0 = secret, higher coefficients uniform).
fn deal(secret: RqNTT, a: &[Fq], rng: &mut impl ark_std::rand::Rng) -> Vec<RqNTT> {
    let mut s = vec![secret];
    for _ in 0..T_DEG {
        s.push(RqNTT::rand(rng));
    }
    a.iter()
        .map(|&ak| {
            (0..=T_DEG).fold(RqNTT::from(0u128), |acc, j| {
                acc + scalar_ring(ak.pow([j as u64])) * s[j]
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// R6: d = ct0 + ct1*sk + e_sm.  z = [ct0, ct1, d, one, sk, e_sm].
// ---------------------------------------------------------------------------
const R6_WIT: usize = 2;
const R6_N: usize = R6_WIT * DP::L;

#[allow(non_snake_case)]
fn r6_r1cs(ct1: &RqNTT) -> R1CS<RqNTT> {
    let one = RqNTT::from(1u128);
    R1CS::<RqNTT> {
        l: 3,
        A: SparseMatrix {
            nrows: 1,
            ncols: 6,
            coeffs: vec![vec![(one, 2), (-one, 0), (-*ct1, 4), (-one, 5)]],
        },
        B: SparseMatrix {
            nrows: 1,
            ncols: 6,
            coeffs: vec![vec![(one, 3)]],
        },
        C: SparseMatrix {
            nrows: 1,
            ncols: 6,
            coeffs: vec![vec![]],
        },
    }
}

/// Fold a list of (instance, witness) pairs into one verified accumulator.
fn fold_all(
    label: &str,
    insts: &[(CCCS<RqNTT>, Witness<RqNTT>)],
    ccs: &CCS<RqNTT>,
    scheme: &AjtaiCommitmentScheme<RqNTT>,
) {
    let (cm0, w0) = &insts[0];
    let mut w_acc = w0.clone();
    let mut bt = PoseidonTranscript::<RqNTT, CS>::default();
    let (mut acc, _) =
        LFLinearizationProver::<_, T>::prove(cm0, &w_acc, &mut bt, ccs).expect("bootstrap failed");
    let mut pt = PoseidonTranscript::<RqNTT, CS>::default();
    let mut vt = PoseidonTranscript::<RqNTT, CS>::default();
    let start = Instant::now();
    // Instance 0 is already represented by the bootstrap accumulator.
    for (i, (cm_i, wit_i)) in insts.iter().enumerate().skip(1) {
        let (na, nw, proof) =
            NIFSProver::<RqNTT, DP, T>::prove(&acc, &w_acc, cm_i, wit_i, &mut pt, ccs, scheme)
                .expect("folding prover failed");
        let va = NIFSVerifier::<RqNTT, DP, T>::verify(&acc, cm_i, &proof, &mut vt, ccs)
            .expect("folding verifier failed");
        assert_eq!(na, va, "{label}: accumulator mismatch at instance {i}");
        acc = na;
        w_acc = nw;
    }
    println!(
        "  {label}: {} instances folded & verified in {:?}",
        insts.len(),
        start.elapsed()
    );
}

fn main() {
    println!("LatticeFold VDKG — cross-relation CHAIN (R1→R2→R4→R6→R7, one channel)");
    println!("Committee N={SHARES}, threshold T={THRESH}, honest dealers H={DEALERS} | Goldilocks stand-in\n");

    let mut rng = ark_std::test_rng();
    let pts = eval_points();
    let um = dual_multipliers(&pts);
    let lam_thresh = lagrange0(&pts[..THRESH]);

    // One Ajtai key per witness layout. Cross-relation anchors always use the
    // single-value layout (`anchor_scheme`) so commitments to the SAME value in
    // different relations are directly comparable — the commit-once pattern.
    let anchor_scheme: AjtaiCommitmentScheme<RqNTT> =
        AjtaiCommitmentScheme::rand(KAPPA, DP::L, &mut rng);
    let r1_scheme: AjtaiCommitmentScheme<RqNTT> =
        AjtaiCommitmentScheme::rand(KAPPA, R1_N, &mut rng);
    let r6_scheme: AjtaiCommitmentScheme<RqNTT> =
        AjtaiCommitmentScheme::rand(KAPPA, R6_N, &mut rng);
    let r2_scheme: AjtaiCommitmentScheme<RqNTT> =
        AjtaiCommitmentScheme::rand(KAPPA, R2_N, &mut rng);

    let a_crs = RqNTT::rand(&mut rng);

    // ---- R1: dealer contributions + commit-once anchors ---------------------
    println!("── R1: contributions pk0_i = -a·sk_i + e_i");
    let r1_ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r1_r1cs(&a_crs), R1_N, DP::L);
    let mut sks = Vec::new();
    let mut esms = Vec::new();
    let mut sk_anchors = Vec::new();
    let mut esm_anchors = Vec::new();
    let mut r1_insts = Vec::new();
    for _ in 0..DEALERS {
        let sk = short(&mut rng);
        let e = short(&mut rng);
        let e_sm = short(&mut rng);
        let pk0 = e - a_crs * sk;
        let z = vec![pk0, RqNTT::from(1u128), sk, e, e_sm];
        r1_ccs.check_relation(&z).expect("R1 relation failed");
        // e_sm is not part of the public-key equation, but it must still be
        // included in this proof so its shortness is established before it is
        // shared and used by R6.
        let wit = Witness::from_w_ccs::<DP>(vec![sk, e, e_sm]);
        let cm = CCCS {
            cm: wit.commit::<DP>(&r1_scheme).unwrap(),
            x_ccs: vec![pk0],
        };
        r1_insts.push((cm, wit));
        // Publish the commit-once anchors R2 must open against.
        sk_anchors.push(anchor(sk, &anchor_scheme));
        esm_anchors.push(anchor(e_sm, &anchor_scheme));
        sks.push(sk);
        esms.push(e_sm);
    }
    fold_all("R1", &r1_insts, &r1_ccs, &r1_scheme);
    println!("  published anchors Com(sk_i), Com(e_sm_i) for all {DEALERS} dealers ✓\n");

    // ---- R2: share the R1 secrets; CCS binds s_0 to the shares --------------
    println!("── R2: Shamir sharing of the R1 secrets (parity + s_0-consistency rows)");
    let r2_ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r2_r1cs(&pts, &um, &lam_thresh), R2_N, DP::L);
    let mut sk_shares = Vec::new(); // [dealer][recipient]
    let mut esm_shares = Vec::new();
    let mut r2_insts = Vec::new();
    for i in 0..DEALERS {
        for (secret, store, anchors) in [
            (sks[i], &mut sk_shares, &sk_anchors),
            (esms[i], &mut esm_shares, &esm_anchors),
        ] {
            let shares = deal(secret, &pts, &mut rng);
            let mut z = vec![RqNTT::from(1u128), secret];
            z.extend(shares.iter().copied());
            r2_ccs
                .check_relation(&z)
                .expect("R2 parity + s0-consistency rows failed");
            // Cross-relation LINK to R1: the sharing's s_0 must open the R1
            // anchor. Decomposition is deterministic, so equal values ⇔ equal
            // commitments — checkable by anyone from published data.
            assert_eq!(
                anchor(secret, &anchor_scheme),
                anchors[i],
                "R2 s_0 does not open the dealer's R1 anchor"
            );
            let mut w = vec![secret];
            w.extend(shares.iter().copied());
            let wit = Witness::from_w_ccs::<DP>(w);
            let cm = CCCS {
                cm: wit.commit::<DP>(&r2_scheme).unwrap(),
                x_ccs: vec![],
            };
            r2_insts.push((cm, wit));
            store.push(shares);
        }
    }
    fold_all("R2", &r2_insts, &r2_ccs, &r2_scheme);
    println!("  every sharing's s_0 verified against its R1 anchor (free link) ✓");

    // CHEAT: a dealer sharing a DIFFERENT secret than its R1 contribution.
    let cheat_secret = sks[0] + RqNTT::from(1u128);
    assert_ne!(
        anchor(cheat_secret, &anchor_scheme),
        sk_anchors[0],
        "cheating sharing must fail the anchor check"
    );
    println!("  CHEAT dealer (s_0 ≠ R1 sk) caught by anchor mismatch → discarded ✓\n");

    // ---- R4: recipients aggregate the REAL received shares ------------------
    println!("── R4: per-recipient aggregation of the actual R2 shares");
    let agg_sk: Vec<RqNTT> = (0..SHARES)
        .map(|k| {
            sk_shares
                .iter()
                .fold(RqNTT::from(0u128), |acc, s| acc + s[k])
        })
        .collect();
    let agg_esm: Vec<RqNTT> = (0..SHARES)
        .map(|k| {
            esm_shares
                .iter()
                .fold(RqNTT::from(0u128), |acc, s| acc + s[k])
        })
        .collect();
    // Free link, recipient 0 as representative: Σ Com(digits of V) == Com(Σ digits),
    // and the linear recompose of the digit-sum is exactly agg_0 — pinning agg_0
    // publicly with NO circuit. (Σ digits is non-canonical: norm cost shifts
    // downstream, per the design's R4/R6 note.)
    let digit_wits: Vec<Witness<RqNTT>> = sk_shares
        .iter()
        .map(|s| Witness::from_w_ccs::<DP>(vec![s[0]]))
        .collect();
    let f_sum: Vec<RqNTT> = (0..DP::L)
        .map(|j| {
            digit_wits
                .iter()
                .fold(RqNTT::from(0u128), |acc, w| acc + w.f[j])
        })
        .collect();
    let sum_of_coms = digit_wits.iter().skip(1).fold(
        digit_wits[0].commit::<DP>(&anchor_scheme).unwrap(),
        |acc, w| acc + &w.commit::<DP>(&anchor_scheme).unwrap(),
    );
    assert_eq!(
        anchor_scheme.commit_ntt(&f_sum).unwrap(),
        sum_of_coms,
        "Ajtai homomorphism broken on chained shares"
    );
    let recomposed = f_sum
        .iter()
        .enumerate()
        .fold(RqNTT::from(0u128), |acc, (j, d)| {
            acc + *d * RqNTT::from(DP::B.pow(j as u32))
        });
    assert_eq!(
        recomposed, agg_sk[0],
        "digit-sum recompose must equal the aggregate"
    );
    println!("  Σ Com(V_digits) == Com(Σ digits), recompose(Σ digits) == agg  ✓ (no circuit)\n");

    // Carry the non-canonical digit sums forward into R6. Re-decomposing a
    // full-range aggregate would introduce carries and disconnect its
    // commitment from the R4 homomorphic sum. `from_f_coeff` preserves the
    // exact summed digit vector while reconstructing the same ring aggregate.
    let r4_aggregate: Vec<(Witness<RqNTT>, Commitment<RqNTT>)> = (0..SHARES)
        .map(|k| {
            let pair_wits: Vec<Witness<RqNTT>> = sk_shares
                .iter()
                .zip(&esm_shares)
                .map(|(sk, esm)| Witness::from_w_ccs::<DP>(vec![sk[k], esm[k]]))
                .collect();
            let f_sum: Vec<RqNTT> = (0..R6_N)
                .map(|j| {
                    pair_wits
                        .iter()
                        .fold(RqNTT::from(0u128), |acc, w| acc + w.f[j])
                })
                .collect();
            let commitment = r6_scheme.commit_ntt(&f_sum).unwrap();
            let witness = Witness::from_f_coeff::<DP>(ICRT::elementwise_icrt(f_sum));
            assert_eq!(witness.commit::<DP>(&r6_scheme).unwrap(), commitment);
            assert_eq!(witness.w_ccs, vec![agg_sk[k], agg_esm[k]]);
            (witness, commitment)
        })
        .collect();
    println!("  R4 non-canonical digit sums carried into R6 commitments ✓\n");

    // ---- R6: threshold recipients compute decryption shares -----------------
    println!("── R6: decryption shares from the CHAINED aggregates (T={THRESH} recipients)");
    let ct0 = RqNTT::rand(&mut rng);
    let ct1 = RqNTT::rand(&mut rng);
    let r6_ccs: CCS<RqNTT> = CCS::from_r1cs_padded(r6_r1cs(&ct1), R6_N, DP::L);
    let mut ds = Vec::new();
    let mut r6_insts = Vec::new();
    for k in 0..THRESH {
        // Witness = the recipient's aggregated shares from R4 — not fresh randomness.
        let (sk_k, esm_k) = (agg_sk[k], agg_esm[k]);
        let d = ct0 + ct1 * sk_k + esm_k;
        let z = vec![ct0, ct1, d, RqNTT::from(1u128), sk_k, esm_k];
        r6_ccs
            .check_relation(&z)
            .expect("R6 relation failed on chained aggregate");
        let wit = r4_aggregate[k].0.clone();
        assert_eq!(wit.w_ccs, vec![sk_k, esm_k]);
        assert_eq!(wit.commit::<DP>(&r6_scheme).unwrap(), r4_aggregate[k].1);
        let cm = CCCS {
            cm: wit.commit::<DP>(&r6_scheme).unwrap(),
            x_ccs: vec![ct0, ct1, d],
        };
        r6_insts.push((cm, wit));
        ds.push(d);
    }
    fold_all("R6", &r6_insts, &r6_ccs, &r6_scheme);
    println!();

    // ---- R7 (public): interpolation closes the loop -------------------------
    println!("── R7: public Lagrange interpolation of the d_k at 0");
    let sk_total: RqNTT = sks.iter().fold(RqNTT::from(0u128), |acc, s| acc + *s);
    let esm_total: RqNTT = esms.iter().fold(RqNTT::from(0u128), |acc, s| acc + *s);
    let interp_d = lam_thresh
        .iter()
        .zip(&ds)
        .fold(RqNTT::from(0u128), |acc, (&l, &d)| acc + scalar_ring(l) * d);
    // End-to-end DKG identity: interpolated shares reconstruct against the SUM
    // of every dealer's R1 secret (Σ λ_k = 1 at x=0).
    assert_eq!(
        interp_d,
        ct0 + ct1 * sk_total + esm_total,
        "end-to-end chain identity failed"
    );
    println!("  Σ λ_k·d_k == ct0 + ct1·(Σ sk_i) + Σ e_sm_i  ✓");
    println!("  (threshold decryption reconstructs against the aggregated R1 secrets)\n");

    println!("Result: R1's toy values are the ones R2 shares (in-CCS s_0 row +");
    println!(
        "example-side anchor equality), R4 aggregates the real R2 shares (free homomorphic link),"
    );
    println!("R6 proves over R4's actual aggregates, and R7's public interpolation closes");
    println!("the loop — the arithmetic part of §6 is exercised end-to-end on one channel;");
    println!("verifier-bound equality-of-openings links remain to be implemented.");
}
