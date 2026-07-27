# VDKG Implementation Report — LatticeFold-Based Verifiable DKG for RNS-BFV

**Date:** 2026-07-26 · **Branch:** `interfold` · **Status:** research prototype (not production)
**Design spec:** [`plan.md`](plan.md) · **Slice catalog:** [`crates/latticefold/examples/interfold/DKG_SLICES.md`](crates/latticefold/examples/interfold/DKG_SLICES.md)

---

## 1. Executive summary

**Question asked:** validate the plan, and determine whether the protocol sustains a 100-node
committee end-to-end.

**Answer:** yes, at measurement scale. The complete P1→P4 protocol — distributed key generation
(R1–R4), threshold public-key aggregation (R5), user encryption (Ruser), and threshold decryption
(R6 + R7/P) — runs green with proofs at every step for a **N=100 / H=51 / T=27** committee at ring
degree N=4096 in **5.2 hours wall-clock** (63 CPU-hours) on a 14-core Apple-silicon laptop, peak
memory **17 GiB**, recovering the exact 4096-coefficient plaintext. Nothing in the measured cost
structure grows superlinearly with committee size. At production degree N=8192 the same run is
estimated at ~2× (≈10–12h on the same machine, ≈5h on a 28-core box).

**Plan validation:** every relation in plan.md §5 exists, runs, and is exercised in one integrated
flow. The plan's central claims are confirmed in code: RNS-native arithmetic with zero quotient
witnesses (except, by design, in R7), free homomorphic linear links, batched Reed–Solomon as one
ring equation per row, native multi-instance folding replacing recursive aggregation — including a
new **binary fold tree** (acc+acc folding) that cut the flow's wall time by 2.2× at H=5 and is the
structural reason 100 nodes is feasible. Known, itemized gaps remain (§5 below): the
equality-of-openings links, the terminal decider, and the on-chain wrapper — all previously
identified, none blocking the feasibility question.

This report covers: what exists and is verified (§4), what is missing (§5), benchmarks (§6),
scaling analysis (§7), security posture (§8), reproduction (§9), component map (§10).

---

## 2. What the system proves

Per plan.md: each dealer proves their BFV key contribution (R1), the Reed–Solomon validity of
their Shamir sharing (R2), the correct encryption of every share digit under the recipient's
individual key (R3), and each recipient proves knowledge of the committed share openings (R4).
Aggregation of the threshold public key is free by Ajtai homomorphism (R5). A user proves their
encryption under the aggregate key (Ruser). Each reconstruction party proves their decryption
share (R6), and a public CRT-reconstruction + decode relation (R7) produces the plaintext with a
succinct proof. All arithmetic is native to each RNS prime; commitments are Ajtai (MSIS);
aggregation is by LatticeFold folding.

---

## 3. Status vs plan §12 (implementation plan)

| Plan step | Status | Notes |
| --- | --- | --- |
| 1. Parameter set + congruence checks | ✅ Done | N8192/N4096 chains machine-checked (primality, NTT, LF congruence, margins). Odd-`t` obstruction found; `t = 2^20`. R7 margin now **derived**, old N8192 P provably insufficient → replaced with verified 177-bit P. |
| 2. Custom `Ring` types | ✅ Done | `stark-rings` fork (`0xjei/stark-rings#interfold`): N8192 (3×Fp64 + Fp192 P), N4096, Interfold 51-bit model; NTT kernels verified vs schoolbook. |
| 3. R1 + R4 vertical slice | ✅ Done | In slices and in the integrated flow. |
| 4. R2 batched RS + digit decomposition | ✅ Done | GRS parity as one ring equation/row; digit-decomposed shares. |
| 5. R3 + Ruser + folding benchmark | 🟡 Mostly | **R3 now wired into the full flow** (this milestone): real fhe.rs extended encryption, per-digit proofs, folded per transport prime. Ruser per-channel done; **cross-channel `Com(m)` still missing**. Folding-vs-baseline benchmark exists (`dkg_bench_folding`). |
| 6. R5, R6, R7 | ✅ Done | R7 quotient/noise bounds are **verifier-enforced** (tight decompositions; negative tests). R5 is a thin decided-proof shape. |
| 7. Decider → on-chain wrapper | 🟡 Partial | Per-track decider statement extracted (~3.1 KB). Noir wrapper circuits exist and are now **sound measurement prototypes** (see §8). Missing: P-track wrapper, L+1 track combination/recursion, Solidity + gas. |
| 8. Wide smudging noise | ✅ Done | Base-B limbs at relation level; production limb count in the flow. |

---

## 4. What exists and is verified

### Protocol flow (`vdkg_flow.rs`, `fhe_bridge.rs`, `r3_bridge.rs`)
- **Full P1→P4 integrated flow** on native rings, generic over `N4096Params`/`N8192Params`, with
  production fhe.rs TRBFV witness distributions (ternary sk, CBD errors, λ=50 smudging).
- **R3 wired in** (this milestone): shares move as their base-B digits — the same digits the R2
  commitments bind — encrypted with fhe.rs `try_encrypt_extended` (full `(u,e1,e2)` witness),
  proven natively per transport prime (`ct0 = pk0·u + e1 + δ·digit`, `ct1 = pk1·u + e2`), folded
  per prime, decrypted for real, recomposed and checked. One recipient individual key is shared
  across all channels (R0-consistent). Each R3 instance is transcript-bound to
  (sender, recipient, share-kind, channel, prime, limb).
- **Fiat–Shamir statement binding** (this milestone): every linearization/fold absorbs the
  instance (`cm`, `x_ccs`) before challenges; per-party tags in R2/R3/R6. Regression test:
  statement substitution now fails verification.
- **CSPRNG** (this milestone): all protocol randomness from `OsRng` (was `test_rng`, a public
  fixed seed — critical if ever deployed).
- **R7 margin enforcement** (this milestone): extraction slack **derived** (S=2 decide-directly;
  fold-path slack 2^13.2–2^14 shown infeasible → P track decides directly, as plan §5-R7
  specifies); tight per-witness decompositions; forged-u / forged-m negative tests; new N8192 P
  (177-bit, safe form, verified); `plan.md`'s decode formula corrected to the centered form.

### Folding infrastructure
- **Binary fold trees** (this milestone): `NIFSProver::prove_acc` / `NIFSVerifier::verify_acc`
  (accumulator+accumulator folding) and `nifs::tree::fold_tree` — log2(n) depth, same total fold
  count, per-node transcripts (fresh FS with node coordinates), per-node verification, rayon
  parallelism. Unit tests: odd/even trees verify; tampered witness rejected.
- All three fold call sites (R3, R4, R6) use the tree; sk/e_sm tracks and channels run
  concurrently.

### Parameters & analysis
- `vdkg_params.rs`: machine-checked validators (`validate_n4096`, `validate_n8192`) run in CI via
  `cargo test`; explicit CRT-row and decode-row margin checks.
- `estimators/SECURITY.md`: lattice-estimator certification — N8192 keys ≈159–161 bits PQ, N4096
  ≈137–139 bits PQ. **Caveat:** its Ajtai module widths are ~L× too small vs the deployed
  digit-decomposed shapes, so "unconditionally binding" does not carry over; a re-estimation with
  correct `m` is owed (§5).

### Decider wrapper circuits (`decider-circuits/`)
- Soundness pass (this milestone): `reduce_mod` quotient range-constrained in both
  `decider-circuits/modulo` and the dormant production original `circuits/lib/.../U128.nr`
  (previously any claimed remainder passed — attack replicated as a `should_fail` test);
  `assert_digit` canonical before `as u64` casts; Ajtai CRS matrices / folded commitments /
  decryption shares are now `pub` inputs; C7 Garner bounds and decode enforced without truncation,
  with centered-noise support. Verified: forged decode (same public `u`, different plaintext)
  **now rejected**; honest C7 proof verifies with `bb` (UltraHonk). Remaining deltas documented in
  `decider-circuits/SPEC.md` (SZ-challenge witness binding, `r_lin` transcript derivation).

### Relation slices & examples
- `crates/latticefold/examples/interfold/`: R0–R7 slices, cross-relation chain, cheater isolation
  (live at fold level), double commitments, wide smudging, parameter checkers, NTT kernel,
  native-ring R1 — all runnable (`run_dkg_pipeline.sh`).

---

## 5. What's missing (honest gap list, prioritized)

1. **Equality-of-openings links** — the protocol's remaining soundness gaps, all example-side
   assertions today: R1↔R2 secret anchor, R2→R4 share binding (opens R2's commitment — native
   relation, needs wiring), Ruser's cross-channel `Com(m)` (per plan §5-Ruser, required to stop
   cross-channel message forking), e_sm limb↔residue binding. R2→R3 digit identity holds by
   construction (same decomposition) but is not a verifier-visible proof link.
2. **Terminal decider** — no in-repo decider, so norm bounds are never *terminally* enforced in
   the flow, and fold accumulators are dropped after self-checks (no artifact produced). Needed
   for any verifiable output: per-track decider → the wrapper circuits of §4.
3. **Fold verification off by default** — `DKG_VERIFY_FOLDS=1` enables per-node verifier
   self-checks (roughly 2× fold cost); default runs are prove-only. Fine for benchmarks; not
   evidence for a third party.
4. **On-chain wrapper completion** — P-track wrapper circuit (176-bit limb arithmetic), L+1 track
   combination (single circuit or UltraHonk recursion), §6.2 double-commitment digests as circuit
   inputs, Solidity generation + gas. Wrapper soundness deltas from SPEC.md: SZ challenge must be
   witness-bound (in-circuit Poseidon) and amplified beyond ~45 bits/check; `r_lin`/γ/ρ must be
   re-derived from the folding transcript.
5. **R2 cost at N=100** — the new measured bottleneck (§7): R2's witness is O(N) shares, so
   per-proof cost grows with committee size. Lever: batch/merge or restructure R2 proofs.
6. **Streaming folds** — instances are collected before folding; memory is linear in H
   (manageable: 17 GiB at H=51) but a streaming fold-consume design makes it ~constant.
7. **SECURITY.md m-width re-estimation** — the binding analysis used pre-decomposition module
   widths; re-run the estimator with the deployed widths (κ=4, m·d up to ~630k).
8. **Housekeeping** — `dkg_wrapper_export.rs` (WIP) has a wrong-domain-tag CRS derivation (L1);
   `circuits/lib` doesn't compile under nargo beta.22 (148 pre-existing errors, version skew);
   e_sm one-time-reuse guard absent; committee-demo hardcoded secrets are demo-only.
   (Resolved since: the dead `c5_8192`/`c5_sz`/`c5_4096` circuit dirs — including the
   cleartext witness export — were deleted in the fc5e5ab cleanup.)

---

## 6. Benchmarks

Hardware: Apple silicon laptop, 14 threads (bb reports), builds `release`, features
`fhe-bridge,parallel`, Rust 1.91.1 (fhe-bridge path) / nightly-2025-03-06 (lib).

### 6.1 Full P1→P4 flow — N=100 committee (the headline run)

**N=100 / H=51 / T=27, degree N=4096, session 100** — green end-to-end (recovered the exact
4096-coefficient message), all phases proven:

| Metric | Value |
| --- | --- |
| **Wall-clock total** | **18,735.8 s (5h 12m)** |
| CPU total (user) | 228,038 s (63.3 CPU-hours) |
| Avg core utilization | 12.2 / 14 |
| **Peak RSS** | **17.0 GiB (18.3 GB)** |
| R3 instances proven | 3,060 (51 dealers × 5 digits × 2 primes × 2 kinds × 3 channels) |
| R4 openings proven | 306 |
| R6 shares proven | 81 (27 × 3 channels) |

Phase wall-times (overlapping — channels and share-kinds run concurrently):

| Phase | Wall time | Comment |
| --- | --- | --- |
| Dealer phase (R2 proofs + R3 transport instances) | **~11,657 s** | Dominant: R2's witness is O(N) (101 shares at N=100) |
| R3 fold chains (255 instances × 2 primes) | 4,763–6,606 s per track | ~22–26 s/fold, tree-folded |
| R4 fold chains (50 folds) | 90–622 s per track | tree-folded |
| R6 + R7/P | minutes | R7 decides directly on the P track |

### 6.2 Progression at N=5/H=5/T=3 (same machine, degree N=4096)

| Configuration | Wall time |
| --- | --- |
| Flow with unproven R3 data plane (before this milestone) | 356 s |
| Flow + proven R3, sequential fold chains | 1,676 s |
| **Flow + proven R3, binary fold trees + track concurrency** | **773 s (2.2× faster)** |

### 6.3 Earlier component measurements (from `DKG_SLICES.md`, same machine class)

| Component | Measurement |
| --- | --- |
| R3 benchmark, degree N=8192 (`dkg_fhe_r3`) | 50 instances proven + folded into 1 accumulator/prime in 756 s ≈ **15 s/instance** |
| Noir C3 baseline (same relation, degree 8192) | 3.48M constraints, 10.76 s isolated prove × 432 proofs/round **plus** recursive aggregation |
| Decider wrapper `ajtai_opening_sz` (per-track, ProdParams channel, N=16384) | **6.05M opcodes / 10.2M gates** (2× the N=8192 figure — linear scaling); the C5 aggregate = 4 of these + recursion |
| Decider wrapper `c7` (4 channels, ProdParams, N=16384) | **5.06M opcodes / 12.5M gates; `bb prove`+`verify` pass** — runs once per threshold decryption |
| Decider wrapper `c7` (3 channels, N=1024, superseded) | 303k opcodes / 748k gates; 2.7 s prove |
| Full flow N=8192, H=5/T=3 (pre-R3-wiring) | ~316 s |
| Full flow N=8192, H=3/T=2 with limb-heavy R7 | ~22 min |

---

## 7. Feasibility assessment — 100-node committee

**Verdict: sustained, with clear scaling laws and identified levers.**

- **CPU work** grows linearly with H (instances: R3 = H×5×2×2×3, R4 = H×6, R6 = T×3). At H=51:
  ~63 CPU-hours total at N=4096. Nothing superlinear in the *protocol* — but note R2's per-proof
  cost is O(N) (its witness holds all N shares), which is why the dealer phase dominates at
  N=100 (~62% of wall time). This is the top optimization target: restructure/batch R2 or split
  its witness.
- **Wall time** is governed by parallelism: fold trees give log2(n) depth per chain; the measured
  machine averaged 12.2/14 cores. Levers, in order: (a) more cores — the workload is
  embarrassingly parallel across 18 fold trees + dealer instances; (b) R2 restructure; (c)
  streaming folds to relieve memory pressure at larger H.
- **Memory** is linear in H under the current collect-then-fold design: 17 GiB at H=51/N=4096
  (≈1 MB/instance held before folding). Streaming folds make it ~constant; the accumulator is
  fixed-size.
- **N=8192 estimate:** per-instance/fold costs roughly double (NTT size) → ~10–12h wall on this
  machine, ~5h on 28 cores, memory ~2×. The R3 component benchmark at 8192 (15 s/instance)
  supports this extrapolation.
- **Comparison vs the Noir baseline:** the R3 axis alone cost the Noir design 432 C3 proofs/round
  at 10.76 s each *plus* recursive aggregation; here 3,060 R3 instances fold into 12 trees with
  one decider each. Folding's win is structural: N statements → 1 accumulator per track, so the
  expensive decider/on-chain wrapper runs once per track, not per party.

---

## 8. Security posture

Discipline applied throughout (per the "untrusted prover" rule): every security-relevant check
must live verifier-side — in-circuit constraints, the NIFS/linearization verifier, or publicly
recomputable commitments. Prover-side asserts are completeness guards only.

| Review finding | Severity | Status |
| --- | --- | --- |
| Deterministic public-seed RNG for shares/user randomness | Critical | ✅ Fixed (`OsRng`) |
| `reduce_mod` unbounded quotient (decider + dormant production) | Critical | ✅ Fixed + `should_fail` test |
| SZ challenge prover-controlled / fixed | Critical | 🟡 Documented delta (SPEC.md §"Soundness pass"); fix = in-circuit Poseidon over witness commitment |
| Private CRS/commitments/shares in wrapper circuits | Critical | ✅ Fixed (now `pub` inputs) |
| C7 decode truncation → same `u`, two plaintexts (bb-verified exploit) | Critical | ✅ Fixed; forge now rejected; centered noise supported |
| FS transcripts didn't absorb `cm`/`x_ccs` (statement substitution) | High | ✅ Fixed + regression test |
| R7 quotient/noise bounds not range-enforced; slack asserted | High | ✅ Fixed (tight decompositions, derived S, new P, negative tests) |
| Cross-relation equality-of-openings missing | High | ⬜ Open (§5.1) — documented, next milestone |
| R3 unproven data plane | High | ✅ Fixed (this milestone) |
| SECURITY.md module-width mismatch | Medium | ⬜ Open (§5.7) |
| Fold verification off by default | Medium | 🟡 By design for demos (`DKG_VERIFY_FOLDS=1`) |
| Lagrange index set not bound in-circuit; panic surface | Low | ⬜ Open (§5.8) |

Positive confirmations from the review: N8192/N4096 parameters all verify exactly; batched-RS R2
is one ring equation/row; R4 aggregation is genuinely circuit-free; the core folding verifier was
*strengthened*, never weakened; cheater isolation works at fold level; smudging is correctly
applied in R6 for a single decryption.

---

## 9. Reproduction

```bash
# Rust toolchains: nightly-2025-03-06 (lib), 1.91.1 (fhe-bridge path)
rustup install nightly-2025-03-06 1.91.1

# Unit + integration tests (params, margins, fold trees, transcript binding)
cargo test -p latticefold
cargo +1.91.1 test --release --features fhe-bridge -p latticefold --lib

# The headline N=100 run (~5.2h on 14 cores; N=4096 default):
DKG_PHASE_TIMING=1 cargo +1.91.1 run --release --example dkg_fhe_full_flow \
  --features fhe-bridge,parallel -- --n 100 --h 51 --t 27 --recipient 3 --session 100

# Smaller configs / N=8192:
cargo +1.91.1 run --release --example dkg_fhe_full_flow --features fhe-bridge,parallel
cargo +1.91.1 run --release --example dkg_fhe_full_flow --features fhe-bridge,parallel \
  -- --params n8192 --n 5 --h 5 --t 3 --recipient 3

# Per-node fold verification (≈2× fold cost):
DKG_VERIFY_FOLDS=1 DKG_PHASE_TIMING=1 cargo +1.91.1 run --release \
  --example dkg_fhe_full_flow --features fhe-bridge,parallel

# R3 component benchmark (degree 8192):
cargo +1.91.1 run --release --example dkg_fhe_r3 --features fhe-bridge,parallel -- --dealers 5

# Wrapper circuits (nargo 1.0.0-beta.22 + bb 5.0.0):
cd decider-circuits/modulo && nargo test
cd ../c7 && nargo execute && bb prove -b target/c7.json -w target/c7.gz -o target -t evm \
  --write_vk && bb verify -k target/vk -p target/proof -i target/public_inputs -t evm
```

---

## 10. Component map

| Path | Contents |
| --- | --- |
| `plan.md` | Design spec (§5-R7 decode formula corrected this milestone) |
| `crates/latticefold/src/vdkg_flow.rs` | Integrated P1→P4 flow (R1, R5, Ruser, R6, P-track R7) |
| `crates/latticefold/src/fhe_bridge.rs` | Committee plumbing: R2 (GRS), proven R3 transport, R4, fold chains |
| `crates/latticefold/src/r3_bridge.rs` | R3 relation, fhe.rs extended-encryption transport, per-tag folding |
| `crates/latticefold/src/nifs/tree.rs` | **Binary fold trees** (`fold_tree`) |
| `crates/latticefold/src/nifs.rs` | NIFS core + **`prove_acc`/`verify_acc`** (acc+acc folding) |
| `crates/latticefold/src/vdkg_params.rs` | N4096/N8192 parameter sets + validators (new 177-bit P) |
| `crates/latticefold/src/samples.rs` | Production fhe.rs/TRBFV witness sampling |
| `crates/latticefold/examples/interfold/` | Relation slices R0–R7, chains, benchmarks (see `DKG_SLICES.md`) |
| `decider-circuits/` | Noir decider-wrapper measurement circuits + SPEC.md |
| `estimators/` | Lattice-estimator certification + raw outputs |
| `dkg-fhe/` | Self-contained runner for the flow examples |
