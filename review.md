# Review of `plan.md` — Gap Analysis

**Date:** 2026-07-27 · **Subject:** [`plan.md`](plan.md) (design proposal) · **Cross-checked against:** [`report.md`](report.md), [`decider-circuits/SPEC.md`](decider-circuits/SPEC.md), `dkg-fhe/README.md`, `crates/latticefold/src/vdkg_params.rs`, `crates/latticefold/src/vdkg_flow.rs`

This review distinguishes three kinds of "missing": **(A)** mechanisms the protocol needs but the plan never specifies, **(B)** internal contradictions, and **(C)** places where the implementation has already moved on and the plan is stale. The relation-by-relation core (affine shapes, batched Reed–Solomon, digit decomposition, P-track CRT) is sound and validated in code — the gaps are around it.

---

## A. Missing mechanisms (design-level, most important)

### 1. The load-bearing invariant behind R6/R7 is never stated

R7 multiplies decryption shares by Lagrange coefficients *mod `q_l`*, which are full-range. The reason decode still works is that **everything hit by a λᵢ is an exact Shamir share** — both `sk` shares and `e_sm` shares reconstruct exactly (Σλᵢ·g(i) = g(0) with zero noise growth), while the only true noise (the ciphertext's own error) carries coefficient Σλᵢ = 1. This invariant is the foundation of the whole decryption design, and it has a sharp consequence the plan never draws: **fresh smudging noise cannot be added at R6** — a per-party fresh `e_sm,i` gets multiplied by a full-range λᵢ and destroys the decode window. That is precisely why smudging must be DKG-shared. One paragraph in §5 (R6/R7) would prevent a future implementer from "fixing" the wrong thing.

### 2. Multi-decryption lifecycle / smudging stock is absent

A corollary of #1: since smudging shares are committed at DKG (R1) and consumed at R6, each `(sk_share, e_sm_share)` pair is **one-time use**. Two decryptions reusing the same share give `d_i − d_i' = Δct₀ + Δct₁·sk_share_i` — public share recovery. The report already says "smudging is correctly applied in R6 *for a single decryption*" and lists "e_sm one-time-reuse guard absent" (§5.8). The plan needs an epoch/request model: provision K smudging sharings at DKG, or run a per-request e_sm-only sharing round, plus request/epoch IDs bound into R6 instances to make reuse provably impossible.

### 3. Multi-prover folding: who knows the folded witness?

§4.1 says cross-party folding is "exactly what LatticeFold's high-arity multi-folding is for" — but folding is single-knower: the folder must know every witness being folded. Nobody knows Σρⱼ·wⱼ over *other parties'* secrets. Sequential folding does not fix it: in a pairwise chain, party 2 receives an accumulator witness that fully determines party 1's witness; in general it leaks known linear combinations of others' secrets (lattice-hint attack surface). The demo folds cross-party only because it runs in one process. The plan should adopt an explicit principle — **fold only within single-knower sets** (dealer folds own R2/R3; recipient folds own R4; R1/R6 decided per party or per small group) — and re-derive the §7.1/§10 wrapper cost from that, or else specify a distributed-folding protocol. The implementation already implicitly follows single-knower grouping for R3/R4; R6's fold does not.

### 4. Zero-knowledge is never specified

The plan says only R7 "requires no zero-knowledge," but never says how ZK is *achieved* anywhere else. Three concrete holes:

- Folding transcripts contain unmasked, witness-derived sumcheck messages — not ZK by default — yet §7.1 has transcripts publicly replayed.
- §10's "send the final folded witness in the clear" decider option is a direct secret leak for R1/R2/R3/R4/R6 tracks and must be explicitly ruled out for them.
- §2.2 hedges on hiding commitments ("what we use in case we needed"). Decide per relation, and note that hiding commitments break §4.3's "anyone can recompute the commitment locally" unless the randomness is broadcast with the value.

### 5. Cross-modulus binding has no mechanism anywhere it occurs

- **Ruser's `Com(m)`** (§5): a single commitment "referenced" by L per-channel instances is not native — an Ajtai commitment is modulus-bound, and the claimed precedent ("already used for `sk_i`") is per-channel, not cross-modulus. Needs either the commitment on the P track with per-channel quotient-witness links, or per-channel `Com_l(m)` plus a P-track equality proof. Report §5.1 confirms this is the open link.
- **R7's inputs**: `d_i` / `u^{(l)}` are computed on the `q_l` tracks but consumed on the P track; the on-chain artifact needs a binding chain (homomorphically-derived per-channel `Com(d_i)` + quotient-witness link into the P track, same trick as the CRT step). "Broadcast in the clear" binds humans, not proofs.
- **§6.2 double commitments**: the outer Ajtai instance must bind inner vectors whose coefficients are ~`q_l`-sized — i.e. outer modulus > inner range, an unstated parameter condition. The hedged "I think this preserves homomorphism" can be resolved: yes, additively (it is linear in the inner vector), under that norm condition.

### 6. No security / threat-model section

Missing entirely: corruption thresholds (T vs n/H); rushing adversary and rogue-key analysis (R1's proof of knowledge is the mitigation — say so explicitly); discard/attribution rules (who is blamed when R4 fails, given R0 has no well-formedness proof); transcript/domain binding (every Fiat–Shamir transcript absorbing `cm`, `x_ccs`, party tags, session ID — the report treated its absence as a HIGH-severity fix, yet the plan never mentions it); and CRS genesis (who samples `a`, the `A_l`, and the outer keys — need nothing-up-my-sleeve derivation, else binding is vacuous).

---

## B. Internal contradictions

### 7. Track taxonomy: "L + 1 tracks" doesn't survive contact with §7.1

Folding requires same-shaped CCS *and* same modulus *and* a single knower, so the real structure is tracks per (relation × channel × transport prime × share-kind × fold group) — the implementation's R3 alone produced 12 trees at 3 channels. §4.1/§7's "L independent tracks + 1" understates the wrapper's combination job and the on-chain artifact count by an order of magnitude. §7.1's "identical shape across all L+1 tracks" and §4.3's "single element per published quantity" need to be rewritten against the real taxonomy.

### 8. §7.1 vs §10: who verifies the folding transcript?

§7.1 says transcripts are "handled by the native on-chain replay above" — no such "above" exists (dangling reference) — while §10 says the wrapper re-derives FS challenges so verifiers don't redo transcripts, and "the LatticeFold layer never appears on-chain directly." `decider-circuits/SPEC.md` has already picked a resolution (transcripts verified natively off-chain; wrapper covers deciders only; remaining delta: `r_lin`/γ/ρ re-derivation from the transcript). The plan should state the chosen model.

### 9. §7 references "§4.4" — it doesn't exist

The missing subsection was presumably the fold-tree structure. That content now exists (binary fold trees, per-node transcripts, acc+acc folding) and is also exactly where goal 4's cheater-isolation mechanism should be specified — it currently isn't, anywhere in the plan.

---

## C. Stale relative to the implementation

### 10. R3's relation is obsolete

Plan: encrypt the *recomposed share* per threshold channel, assuming the PVSS plaintext space exceeds max `q_l`. Implemented: digit-form transport on a dedicated 2-prime chain with `t_share = 2^16 > B` (`R3_MODULI`), instance per (sender, recipient, kind, digit, prime). The digit design removes the `t_ind > max q_l` assumption entirely and changes all instance counts — §5-R3 and the table row should be rewritten.

### 11. §8.1 understates the congruence story

Parameter search found a non-power-of-two `t` (the Noir preset's 1,000,000) is *structurally incompatible* — not merely "must be checked." The resolution (t = 2^20, a power of two ≥ N; `q ≡ 1+2t (mod 4t)` then subsumes NTT-friendliness) is a design result worth stating in the plan, along with the concrete Demo/Prod families. Also worth one clarifying line: the `t` in LatticeFold's congruence is identified with BFV's plaintext modulus in this design — say so explicitly, since the symbols collide.

### 12. §9.2 is no longer "out of scope"

Wide smudging is solved via base-B limbs (λ=50, ~2^74-wide noise, `ESM_LIMBS`). Update §3's non-goals too.

### 13. §9.3 is no longer TBD

The margin was derived: S=2 decide-directly; `2·C_q·q_l < P/2`, effectively `P > ~4Q`; safe-form 177-bit P = 5.0·Q; fold-path slack (2^13+) shown infeasible → the P track decides directly, never folds. The plan still says "computed during parameter selection rather than assumed"; replace with the derivation pointer. Also generalize the rule: *any* track whose extraction slack breaches its norm envelope must decide directly — this policy belongs in §5/§8, not just R7.

### 14. §12 and the status header

Steps 1–6 and 8 are done per report.md §3. Re-scope §12 to what remains: equality-of-openings links, terminal decider, wrapper completion (P-track circuit, track combination, Solidity/gas), R2 restructure (its O(N) witness is now the measured bottleneck — a concrete open problem the plan's "maybe merge circuits" note doesn't capture).

---

## D. Smaller items

- **R0**: one line of rationale for skipping individual-key well-formedness (or add the R1-shaped proof — it is the same cheap relation and removes the R4 attribution ambiguity).
- **R4**: resolve the margin note. R4 is redundant for correctness (R6's opening proof subsumes it, and given R3+R0, receipt failure is self-inflicted) — keep only for early liveness detection, and say that.
- **Ruser range on m**: "depends on t vs norm bound" can now be resolved for t = 2^20 against the chosen Ajtai bound.
- **§4.3**: note that hiding commitments require broadcasting the commitment randomness alongside the value for the local recompute check.
- **Typos/loose ends**: "biding" → binding; "wastn't", "accomodate", "relativly", "decyrption", "handeled"; "`$P$track`" (missing space); "Rqi's"; R1 "`a_i` is public" → "`a`"; R2 "zeroth share" → "evaluation at zero"; R2's "low-order coefficients are the short secret" conflates packed sharing with coefficient-wise sharing — clarify.

---

## Priority

If only three get fixed first:

1. **#1 + #2 together** — the exact-reconstruction invariant and the smudging lifecycle are one design decision and currently undocumented.
2. **#3** — witness ownership determines whether the folding architecture survives deployment.
3. **#5** — the cross-modulus bindings are the remaining soundness surface (confirmed by report.md §5.1).
