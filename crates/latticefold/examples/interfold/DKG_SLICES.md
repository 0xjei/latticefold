# Lattice-Based VDKG — LatticeFold vertical slices

Working, runnable slices of the *Lattice-Based Verifiable DKG, User Encryption
and Threshold Decryption for RNS-BFV* design, each mapping one protocol relation
onto the NethermindEth `latticefold` primitives (Ajtai commitments, CCS, native
norm proofs, NIFS folding).

The examples are executable relation-level demonstrations: each builds a toy
satisfying instance, checks `ccs.check_relation`, commits with the Ajtai
scheme, and (where applicable) folds + verifies with `NIFSProver`/
`NIFSVerifier`. They are not a production DKG or standalone zero-knowledge
proofs.

## Standing assumption (deliberate)

All slices use the **Goldilocks ring as a stand-in for a real RNS prime `q_l`**.
Swapping in an actual `q_l` (the `q_l ≡ 1 + 2t (mod 4t)`, NTT-friendly custom
`Ring`) is a **type substitution**, not a redesign — this is the long-pole item
(§12.2) and is intentionally deferred so the relation shapes could be validated
first on a ring that already works.

## The slices

| Relation | File | What it proves | Result |
| --- | --- | --- | --- |
| **R0** | `dkg_r0.rs` | Individual key commitments pinned; broadcast validation + tamper detection | no witness, no proof — per the design |
| **R1** | `dkg_r1.rs` | `pk0_i = -a·sk_i + e_i`, with `e_sm_i` included in the short witness | native modular reduction free; no quotient witnesses |
| **R2** | `dkg_r2.rs` | Shamir sharing with batched Reed–Solomon `H·Y = 0` + digit decomposition | **3 ring constraints replace 72 field checks** |
| **R3 / Ruser** | `dkg_r3_ruser.rs` | BFV encryption `ct0 = pk0·u + e0 + Δ·m`, `ct1 = pk1·u + e1`; high-arity folding | GRECO replacement; ~15 instances/s throughput |
| **R4** | `dkg_r4.rs` | Share receipt + aggregation | **free** homomorphic aggregation vs. **proof-required** opening, cleanly split |
| **R5** | `dkg_r5.rs` | Threshold PK aggregation (public) | digit-vector homomorphism is free; canonical digit carries still need a proof |
| **R6** | `dkg_r6.rs` | Decryption-share `d_i = ct0 + ct1·sk_share + e_sm_share` | public linear image of committed digits; no fresh commitment |
| **R7** | `dkg_r7.rs` | Lagrange interpolation + CRT quotient-witness shape (single track) | public interpolation free; **quotient witnesses reappear** here |
| **R7 (multi)** | `dkg_r7_circuit.rs` | Real L-channel CRT **in-CCS**: L quotient rows bind residues to one `u_global`; corrupted residue rejected; §9.3 margin checked | the cross-channel step as a proven relation |
| **R7 (decode)** | `dkg_r7_decode.rs` | The decode `t·u + floor(Q/2) = m·Q + v` in-CCS with a shifted centered residual; wrong plaintext rejected | toy nearest-rounding relation |
| **Ruser (×L)** | `dkg_ruser_consistency.rs` | Cross-channel `Com(m)` recomputation and cheat detection | example-side check; equality proof missing |
| **CHAIN** | `dkg_chain.rs` | R1→R2→R4→R6→R7 with toy outputs; `e_sm` shortness and non-canonical aggregate digits carried forward | arithmetic chain exercised; external commitment links remain missing |
| **Isolation** | `dkg_cheater_isolation.rs` | A party with an unsatisfiable instance fails ITS OWN fold step, is identified O(1) and discarded; accumulator untouched; honest 50/51 fold green | the Urban–Rambaud discard rule, live |
| **§9.2** | `dkg_wide_smudging.rs` | ~2^40-wide smudging noise as base-B limbs: one affine recompose row, limbs norm-provable, folded across the committee | the deferred wide-noise item, closed at relation level |
| **§6.2** | `dkg_double_commitment.rs` | Rank-1 outer commitment over the inner κ-vector: 3.9× smaller on-chain artifact, broadcast validation, tamper detection, inner-layer homomorphism intact | double commitments, demonstrated |
| **Step 2** | `dkg_ring_model.rs` | Concrete 51-bit LF-congruent RNS chain + P found; generator/two-adicity/ψ derived per prime; radix-2 negacyclic NTT verified at REAL N=8192 vs full schoolbook | every custom-ring constant derived & verified |

## Layout

All slices live under `crates/latticefold/examples/interfold/`, grouped by
concern (and registered as `[[example]]` targets in `crates/latticefold/Cargo.toml`,
so they are still invoked by bare name):

| Subfolder | Contents |
| --- | --- |
| `relations/` | the R0–R7 relation slices (`dkg_r0` … `dkg_r7_decode`) |
| `composition/` | multi-relation chains, cheater isolation, cross-channel consistency, aggregate/double-commitment, wide smudging |
| `ring/` | custom-ring model + NTT, parameter checks, folding benchmark |
| `fhe/` | native N=4096 `fhe.rs` BFV bridge, P-reconstruction ring, N=4096 params (see also `dkg-fhe/` at the repo root) |

Run any slice by name (the subfolder does not appear on the command line):

```bash
cargo run --release --example dkg_r1     # …r2, r3_ruser, r4, r5, r6, r7
```

Or run the **whole set as one pipeline** (ordered by protocol phase P1→P4, with a
pass/fail summary):

```bash
bash crates/latticefold/examples/interfold/run_dkg_pipeline.sh
```

## Production parameter set (`secure_8192`)

`dkg_params.rs` now verifies the real degree-8192 preset (threshold-BFV +
DKG-BFV chains) against both conditions. Result:

| Chain | t | primes | NTT-friendly | LatticeFold-congruent |
| --- | --- | --- | --- | --- |
| THRESHOLD-BFV | 1,000,000 (even) | 3 × 58-bit | ✅ all | ❌ none (gcd=256: 1 vs 129) |
| DKG-BFV | 144,115,188,098,531,329 (odd) | 2 × 60-bit | ✅ all | ❌ none (odd-t: 1 vs 3 mod 4) |

**Both production chains are NTT-friendly but NOT LatticeFold-congruent** — so
this deployment **requires the §8.1 extension-field technique** to run native
`q_l` tracks. That is a concrete, parameter-specific instantiation decision for
Step 2, surfaced before any ring is written.

## What these slices establish against real code

1. **The affine-native-`R_q` pattern works** (R1, R3, Ruser, R6): public ring
   elements (`a`, `pk`, `ct1`, `Δ`) embed as ring-valued constraint
   coefficients, giving native `R_q` multiplication with **no quotient witnesses
   / range-check machinery** for the modular reduction — design Goal #1/#2.
2. **The free/proof-required split is real** (R4, R5): Ajtai homomorphism makes
   linear cross-relation checks verifiable from published commitments with **no
   circuit**; only knowledge-of-short-opening needs a fold.
3. **Batched RS is one ring equation per row** (R2): scalars embed as *constant*
   ring elements, so `H·Y` acts coefficient-independently (no `X^N+1` mixing).
4. **The "shares aren't short" machinery is characterized** (R2/R4/R6): the
   Ajtai commitment is over the radix-B **digit decomposition**, which is
   *non-linear* — so the homomorphism lives on the committed digits
   (`Σ Com(f) = Com(Σ f)`), and aggregating digits shifts norm cost downstream,
   exactly as the design's R4/R6 notes anticipate.
5. **R7 is where quotient witnesses return** — isolated to the one cross-channel
   step, range-proven natively, gated by the no-wraparound margin (§9.3).

## What is NOT covered here (honest gaps, per §7/§10/§12)

- **Verifier-bound equality-of-openings across relations.** The chain and the
  Ruser example exercise anchor/message checks with local assertions. They do
  not put those hidden-opening equalities into a CCS/NIFS statement, so they
  are integration tests rather than production soundness links.
- **The §8.1 extension-field ring for odd-`t` production chains.** The custom
  ring is DONE for the power-of-two-`t` point (`interfold` model in the
  `stark-rings` fork; `dkg_r1_native.rs` runs on it), but the `secure_8192` production primes
  have odd `t`, where the congruence is structurally impossible — they need a
  non-fully-split model (babybear's Fp9-style CRT) over the same fork.
- **Swapping the remaining slices off Goldilocks** — mechanical now that
  `dkg_r1_native.rs` proves the substitution; each slice is a type-alias change.
- **Batched-arity fold tree** — cheater isolation is demonstrated per fold step
  (`dkg_cheater_isolation.rs`, O(1) identification, discard, honest-path
  unaffected); the `L`-ary batched tree of §7 needs an API beyond acc+1 NIFS.
- **Double commitments inside the folded relation** — the §6.2 rank-1
  outer-commitment publication shape is demonstrated (`dkg_double_commitment.rs`);
  the outer OPENING argument inside a LatticeFold+ proof awaits
  `latticefold-plus` growing CCS support.
- **The decider → Solidity wrapper (§7.1, §10)** — no tooling compiles a
  LatticeFold decider to an on-chain verifier; this is out of the repo and
  remains the final unimplemented, unbenchmarked step.

## Step 1 result — a real parameter obstruction (`dkg_params.rs`)

The congruence-compatibility checker found a **structural obstruction**, not just
a config value:

> A `q_l` must be **both** NTT-friendly (`q ≡ 1 mod 2N`) **and** LatticeFold-
> congruent (`q ≡ 1 + 2t mod 4t`). For any **odd** plaintext modulus `t` (i.e.
> essentially every prime `t` used in BFV), `1 + 2t ≡ 3 (mod 4)`, which
> contradicts `q ≡ 1 (mod 4)` forced by NTT-friendliness. **The two conditions
> are mutually exclusive for odd `t`.**

Consequences recorded for Step 2:
- With a prime/odd `t`, the native-`q_l` approach **requires** LatticeFold's
  small-modulus extension-field fallback (§8.1) — it is not optional.
- A power-of-two `t ≥ N` is directly compatible; the tool finds a concrete
  3-prime RNS chain + reconstruction prime `P > Q` for that case (all ~51-bit,
  all conditions verified).

```bash
cargo run --release --example dkg_params
```

## The cross-relation chain (`dkg_chain.rs`)

The per-relation slices validate each relation's *shape* in isolation, on fresh
random witnesses. `dkg_chain.rs` wires the toy arithmetic: R2 shares the R1
secrets (the plan's R2 constraint #1, as an in-CCS interpolation row `Σλ_k·Y[k]
= s_0`), R4 aggregates the actual R2 shares,
R6 proves over R4's actual aggregates, and R7's public interpolation verifies
the end-to-end identity `Σλ_k·d_k = ct0 + ct1·(Σ sk_i) + Σ e_sm_i`. A dealer
whose sharing deviates from its R1 value is caught by an explicit example-side
anchor assertion, not by a verifier-visible equality-of-openings proof.

Honest scoping of the anchor links: `Witness::from_w_ccs` decomposes
deterministically, so equal toy values produce equal commitments. The folded
proofs still do not bind the R1 and R2 hidden openings to one another; an
equality-of-openings protocol is still required.

## Additional completions (partials closed)

- **Step 5 baseline** (`dkg_bench_folding.rs`) — folding vs. the independent-proof
  (recursive-aggregation) baseline. HONEST result: folding is *not* a free win at
  small N (its per-fold proof is larger/slower than bare linearization); its win
  is **structural** — N instances collapse to ONE accumulator, so the expensive
  decider/on-chain wrapper runs once instead of N times. Amortization only pays
  off once the (unimplemented) Step 7 decider exists and at scale.
- **Step 6 real CRT** (`dkg_r7_crt.rs`) — the actual L-channel CRT reconstruction
  over concrete coprime primes, with the no-wraparound margin (§9.3) **derived**
  (P ≥ slack · max(u, max r·q_l)), not merely noted. Closes the R7 "noted-not-
  derived" gap left by `dkg_r7.rs`.
- **Step 2 NTT kernel** (`dkg_ring_ntt.rs`) — the negacyclic NTT each stark-rings
  model hand-writes (`crt_in_place`/`icrt_in_place`), implemented standalone for
  a real NTT-friendly prime and verified: round-trip + pointwise product ==
  schoolbook mul mod X^N+1. Proves the custom-`Ring` kernel is sound; the rest of
  Step 2 is mechanical wiring inside `stark-rings`.

- **N=4096 native FHE path** (`dkg_fhe_share.rs`, `dkg_fhe_r4.rs`,
  `dkg_fhe_r2_r4.rs`, `dkg_fhe_committee_r4.rs`, `dkg_fhe_multichannel_r4.rs`;
  opt-in `--features fhe-bridge`, Rust 1.91.1) — real `fhe.rs` BFV transport of
  full polynomial shares, **configurable N/H/T** threshold Shamir sharing over
  Z_Q with CRT-congruent projections to the native q0/q1/q2 rings, per-channel
  GRS-syndrome R2 linearization, metadata-bound R4 openings (domain tag =
  sender + 2^16·recipient + 2^32·channel) folded per channel with NIFS, and
  coefficient-wise CRT recombination of the transported shares. The committee is
  a `CommitteeConfig { committee_n, honest_h, threshold_t, recipient_id,
  session_id }` (validated `0 < T <= H <= N`, `1 <= recipient <= N`); the two
  committee examples take a CLI (`-- --n 100 --h 51 --t 27 --recipient 3
  --session <id>`). The session/N/H/T/channel are absorbed into every R2 + R4
  Poseidon transcript so a proof cannot be replayed under a different committee.
  See **`dkg-fhe/`** at the repo root for a self-contained runner + README.

  Runs green at demo scale (N=H=5/T=3), at N=8/H=5/T=3, and at the full
  committee N=100/H=51/T=27. Performance: the R4 fold chain dominates (~99%,
  serial by accumulator dependency). Levers: the `H` dealer R2 proofs are
  parallelized (`par_iter`, `--features parallel`); the multichannel q0/q1/q2
  fold chains run concurrently (`std::thread::scope`, ~3x); and the per-fold
  NIFS verifier self-check (~half of each fold) is deferred by default (prover
  only), re-enabled with `DKG_VERIFY_FOLDS=1`. So a fold is ~7.5s prove-only vs
  ~15s prove+verify. Set `DKG_PHASE_TIMING=1` for a per-phase breakdown.
- **P reconstruction ring** (`dkg_p_reconstruction.rs`, no feature needed) —
  the 104-bit reconstruction prime P is a real `SuitableRing`
  (`N4096PRingNTT`, two-limb `FqP` with balanced decomposition); the Garner
  recombination `v = r0 + q0·t1 + q0·q1·t2` of the three channel residues is
  proven natively in the P ring with commitment reopen/tamper checks.

## Mapping to the design's §12 implementation plan

- ✅ **Step 1** — param set + `q_l`/`P` congruence check (`dkg_params.rs`); found
  the odd-`t` obstruction.
- ✅ **Step 3** — R1 + R4 (commitment-opening vertical slice)
- ✅ **Step 4** — R2 (batched Reed–Solomon + digit decomposition)
- ✅ **Step 5** — R3 + Ruser (`dkg_r3_ruser.rs`) **+ folding-vs-baseline benchmark**
  (`dkg_bench_folding.rs`)
- ✅ **Step 6** — R5, R6, R7: in-CCS L-channel CRT (`dkg_r7_circuit.rs`), in-CCS
  decode with rounding witness (`dkg_r7_decode.rs`), production-chain margin
  derivation (`dkg_r7_crt.rs`) — §5-R7 steps 1–4 all covered.
- ✅ **Step 2** — **the custom ring is REAL and slices run on it.** The orphan
  rule was resolved the only way it can be: `stark-rings` is forked
  (`0xjei/stark-rings`, branch `interfold`, wired via a `[patch]` git dependency),
  carrying a new model
  `interfold` for q = 1125899909038081 — the 51-bit prime that is NTT-friendly
  (q ≡ 1 mod 2N, N = 8192) AND LatticeFold-congruent (q ≡ 1+2t mod 4t,
  t = 2^14), found by `dkg_ring_model.rs`. X^16+1 splits completely (q ≡ 1 mod
  32), so the CRT needs no field extension; the model's own tests verify the
  root table and 1000× CRT-product-vs-schoolbook. `cyclotomic-rings` gains
  `InterfoldRingNTT` + `InterfoldChallengeSet` + Grain-LFSR-generated Poseidon
  params. **`dkg_r1_native.rs` folds and verifies R1 on this ring** — same code
  as `dkg_r1.rs` up to type aliases, and faster (smaller field). The odd-`t`
  production chains still need the §8.1 extension-field variant of the same
  model (a non-fully-split CRT like babybear's Fp9 path).
- 🟡 **Step 7** — the in-repo part is done: `dkg_decider_statement.rs` extracts the
  compact, **fixed-size (~3.1 KB) per-track decider statement** a wrapper would
  verify, independent of how many instances were folded, and
  `dkg_double_commitment.rs` demonstrates the §6.2 compact publication shape.
  The wrapper itself (combine L+1 tracks → Solidity verifier) remains external
  and unbuilt: no tooling compiles a LatticeFold decider to an EVM verifier, as
  flagged from the first message.
- ✅ **Step 8** — wide smudging noise (§9.2), closed at the relation level
  (`dkg_wide_smudging.rs`): base-B limb split, one affine recompose row, limbs
  individually norm-provable, folded across the committee; the production limb
  count is a Step 1 parameter choice.

## The one remaining wall, precisely

1. ~~**Custom ring (Step 2)**~~ — **RESOLVED** by forking `stark-rings`
   (`0xjei/stark-rings#interfold`, wired via a `[patch]` git dependency — the
   only placement Rust's coherence rules permit) and adding the `interfold`
   model there; `dkg_r1_native.rs` runs on it.
2. **On-chain decider (Step 7)** — no compiler exists from a lattice/ring decider
   to a Solidity/EVM verifier. The compact statement it would consume is
   extracted and measured here; the verifier generator does not exist.

## Bottom line

The repository has executable relation-shape demonstrations for R0–R7 (R7
includes toy multi-channel CRT and nearest-rounding decode), plus an arithmetic
chain (`dkg_chain.rs`). Its cross-relation commitment links and Ruser's
cross-channel `Com(m)` check are example-side assertions, not verifier-bound
equality proofs. It also demonstrates
cheater isolation is live at the fold level, wide smudging noise is handled via
bounded limbs, the §6.2 double-commitment publication shape is demonstrated,
the parameter obstruction is found, the folding tradeoff is measured honestly,
and the full custom-ring constant set is derived and verified at production
degree. The two genuinely-external items remain — the `stark-rings` fork
holding the (now fully derived) ring model, and the on-chain decider wrapper —
because they live outside this crate, not because they were skipped.
