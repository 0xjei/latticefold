# Open Questions — for the cryptographers

**Status:** living list of crypto-level decisions arising from the LatticeFold VDKG
implementation (`report.md` is the source of truth for status/benchmarks). Each item
has: context, options, a recommendation, and the plan.md hook. Nothing here blocks
the engineering items (full-matrix R3/R4 fan-out, R0-for-all, e2e runs) — those
proceed regardless.

---

## Q1. Digit-decomposition base `b` (plan §8, parameter 4)

**Context.** Shares are committed as base-`b` digits (`b = 2^15`, L=5 limbs for the
61-bit channels). Every digit is transported and proven separately in R3, so L
multiplies the dominant instance axis. The binding invariant is
`b × extraction_slack < (q−1)/2` (estimators/SECURITY.md).

**Option:** `b = 2^21` → L=3, i.e. **−40% R3 instances**. Invariant check:
β = 2^21 × 2^10(slack) = 2^31 ≪ (q−1)/2 ≈ 2^60. Enormous headroom.

**Recommendation:** adopt. It is the plan's own knob (§8.4), costs one constant
change + validator re-run, and is the cheapest large win available.

---

## Q2. R2 arithmetization: commit to the sharing polynomial, not the shares
(plan amendment candidate)

**Context.** R2 currently commits to the N share evaluations `Y[k]`
(plan: "Output: Com(digits of Y_l[k]) per recipient"), so its witness — and every
downstream reuse — is O(N) per dealer. At N=100 this was ~62% of single-machine
wall time. The measured bottleneck.

**Proposal (amendment).** Commit to the **T coefficients** of the degree-(T−1)
sharing polynomial instead (also full-range → also digit-decomposed, T×L limbs).
Reed–Solomon validity becomes *definitional* (the committed object is the
polynomial); each share `Y[k] = Σ_j x_k^j P_j` is a public linear map, so the R4
link becomes an Ajtai-homomorphism check plus a native opening of a *coefficient*
commitment (§6.1 pattern unchanged). Witness: O(T) instead of O(N) (27 vs 100 at
the standard config — 3.7×; matters more as N grows).

**Why it needs sign-off:** it changes R2's output shape and the R2→R4 link
semantics. The commitment-chain logic is unchanged, but it IS a protocol-level
edit to plan §5-R2/§6.1.

**Recommendation:** adopt after review; it removes the only committee-growing term
in the prover.

---

## Q3. Eliminate R4? (plan §R4's own note)

**Context.** R4 proves knowledge of a short-digit opening of the sender's R2
commitment per received share. The plan notes: *"we can even get rid of this
circuit as well thanks to the fact that commitments are homomorphic at the
expense of a relatively added cost during decryption — i will be checking this."*

**Options:** (a) keep R4 as-is (native opening, ~3% of total cost); (b) drop it —
recipients use decrypted values directly, aggregation is purely homomorphic; the
"added cost during decryption" the note mentions must be quantified.

**Recommendation:** evaluate (b) only after Q2 lands (the R2→R4 link changes
shape either way). Small win; do not prioritize.

---

## Q4. Full-share transport — currently blocked, needs a policy decision

**Context.** Plan R3 encrypts the *recomposed share* in one plaintext
(`t_share ≥ max(q_l)`), which is 1 ciphertext per share instead of L
digit-ciphertexts (−5× R3 instances at L=5, −3× at L=3). It requires transport
primes satisfying the LF congruence for `t_share = 2^61`, i.e. `q ≡ 1+2^62 (mod
2^63)` — **63-bit primes**, above fhe.rs's 2^62 modulus limit. That limit is why
digit transport exists (`t_share = 2^16`, 62-bit primes).

**Options:** (a) keep digit transport (plan-compliant, works today); (b) lift the
2^62 limit in the fhe.rs fork — a library change, *not* a parameter-set change —
plus a 63-bit LF-congruent transport chain; (c) prove R3 differently (no known
viable shape).

**Recommendation:** keep (a) for now; revisit (b) only if R3 cost dominates after
Q1 (−40%) — with L=3 the digit overhead is 3×, tolerable.

---

## Q5. Ajtai module-width re-estimation (estimators/SECURITY.md correction)

**Context.** The certification analyzed Ajtai binding at module widths m_mod ∈
{2,3,7} — the *pre-decomposition* widths. Deployed commitments are over the digit
decompositions, so the real widths are m_mod ∈ {10, 40, 505, ...} ring columns
(m·d up to ~630k). With those, κ·d < m·d on every track: nothing is "injective",
and the report's "unconditionally binding" conclusion does not carry over — the
tracks fall back to *computational* MSIS hardness, which was never estimated with
the correct m.

**Ask:** re-run the estimator with the deployed widths (κ=4, β = digit bound ×
slack). Expected outcome: still ≥128-bit by a wide margin (Gaussian-heuristic
back-of-envelope says so), but the claim must be re-derived, not assumed. Also
re-check the β < (q−1)/2 invariant on the Demo set (only ~7 bits of headroom).

**Recommendation:** do this before any external security claim. Days of estimator
time, no code.

---

## Q6. Schwartz–Zippel challenge binding in the wrapper circuits
(decider-circuits/SPEC.md, "Soundness pass")

**Context.** The wrapper's SZ evaluation point `r` is currently a fixed constant /
digest-derived only from public data, so a prover chooses wrapper witnesses
*after* knowing `r` (the point-evaluation checks are then satisfiable by linear
algebra). MSIS binding of the upstream commitments does not rescue this.

**Proposal (per plan §10's sanctioned "bounded in-circuit hashing"):** the prover
commits to the wrapper witness first (small hash/Ajtai commitment), and `r` is
derived over that commitment. Also: a single point at degree ~2^14 over a 61-bit
modulus gives ~45–47 bits of soundness per check — amplify (multiple independent
points) or document the relaxation.

**Recommendation:** required for the on-chain wrapper; for the *benchmark*
prototype it is a documented cost delta (Poseidon absorption of ~24k
elements/track). Decision: which hash (Poseidon2 vs the production circuits'
choice) and how many points.

---

## Q7. `r_lin`/γ/ρ re-derivation from the folding transcript

**Context.** The wrapper takes the folding challenges as free public inputs;
`r_lin = [1,…]` makes the evaluation-consistency check degenerate. For the
on-chain artifact, the verifier (contract) must re-derive them from the folding
transcript (plan §10 anticipated this bounded in-circuit hashing).

**Recommendation:** required for production wrapper; same family as Q6 — treat
together.

---

## Q8. e_sm (smudging noise) is one-time material — enforcement policy

**Context.** fhe.rs documents smudging noise as one-time pre-shared material.
Our DKG deals e_sm shares once (P1) for use in P4. A *second* threshold
decryption under the same DKG instance would reuse them and collapse the
statistical hiding (two `d_i` differing only in `ct1·sk_share`).

**Options:** (a) document "one decryption per DKG instance" (current state,
nothing enforces it); (b) derive fresh e_sm contributions per decryption epoch
(extra DKG traffic); (c) larger initial e_sm budget.

**Recommendation:** (a) for the benchmark scope; (b) becomes a real question for
multi-decryption deployments.

---

## Q9. Wide smudging noise (plan §9.2) — confirm the closure

**Context.** Plan deferred "smudging noise wider than one native modulus". The
implementation commits e_sm as 6 balanced base-2^15 limbs (~2^89 capacity vs
~2^74 needed at λ=50, H=51) and shares per-channel residues — relation-level
closure exists (`dkg_wide_smudging.rs`).

**Ask:** confirm the production limb count and that the R1↔R2 limb/residue
binding (currently example-side) gets folded into the equality-of-openings work
(Q of the engineering list, not a crypto question).

**Recommendation:** close as done once the binding lands.

---

## Q10. Odd-`t` extension field — only if lbfv ever needs odd t

**Context.** LF congruence is impossible for odd `t` (structural: `1+2t ≡ 3 mod
4` contradicts NTT). We use `t = 2^20` (superset of lbfv's t=1000). If any future
deployment mandates a specific odd t, the small-modulus extension-field
technique (plan §8.1) is required — real new ring machinery.

**Recommendation:** keep t = 2^20; no action unless mandated.

---

## Q11. Witness ownership in folding — the single-knower principle (from review.md #3)

**Context.** Folding is single-knower: the folder must hold every witness it folds.
Our single-process demo folds cross-party only because one process holds all
secrets. In deployment: a dealer folds its own R2/R3 (fine — its own secrets); a
recipient folds its own R4 (fine). But (a) R6's fold spans T parties' shares, and
(b) any acc+acc merge across parties hands the merger a witness that fully
determines a linear combination of *other parties'* secrets (lattice-hint attack
surface). Note this also constrains the distributed-fold-tree picture: subtrees
must respect knower sets, and coordinator merges need their own argument.

**Options:** (a) adopt the explicit principle **fold only within single-knower
sets** (R1/R6 decided per party or per small group; R2/R3 per dealer; R4 per
recipient) and re-derive wrapper cost from that taxonomy; (b) specify a
distributed-folding/MPC protocol for cross-party merges (real research work).

**Recommendation:** (a) — it's what the implementation already implicitly does
for R3/R4; write it into plan §4.1/§7 and the deployment docs. Decide who (if
anyone) merges cross-party accumulators, or structure tracks so no such merge
is needed.

---

## Q12. Zero-knowledge is unspecified (from review.md #4)

**Context.** The plan says only R7 needs no ZK, but never says how ZK is achieved
anywhere else. Folding transcripts carry unmasked, witness-derived sumcheck
messages (not ZK by default); §10's "send the final folded witness in the clear"
decider option is a direct secret leak for R1/R2/R3/R4/R6 and must be ruled out
for those tracks; and the hiding-commitment hedge in §2.2 needs a per-relation
decision (hiding commitments also break §4.3's local-recompute check unless the
randomness is broadcast with the value).

**Options:** (a) accept "proofs of knowledge, not ZK proofs" for DKG traffic
(witnesses stay with their owners; only commitments/accumulators are public) and
mark exactly which artifacts are published; (b) add masking/ZK machinery where
published artifacts leak.

**Recommendation:** (a) is likely sufficient given the publication model
(commitments + decided digests only) — but it must be *stated* per relation,
with the clear-witness decider option explicitly forbidden for secret tracks.

---

## Q13. Smudging lifecycle / multi-decryption epochs (from review.md #1+#2; supersedes Q8)

**Context.** The design works because everything hit by a full-range Lagrange
coefficient is an *exact* Shamir share — sk and e_sm shares reconstruct exactly,
while the ciphertext's own noise carries Σλᵢ = 1. Consequence: **fresh smudging
cannot be added at R6** (a per-party fresh e_smᵢ gets multiplied by a full-range
λᵢ and blows the decode window) — smudging must be DKG-shared, and each
`(sk_share, e_sm_share)` pair is **one-time use**. A second decryption reusing
them gives public share recovery (`d_i − d_i' = Δct₀ + Δct₁·sk_share`).

**Options:** (a) document "one decryption per DKG instance" (status quo, nothing
enforces it); (b) provision K smudging sharings at DKG (K decryptions per
instance); (c) a per-request e_sm-only sharing round, with request/epoch IDs
bound into R6 instances so reuse is provably impossible.

**Recommendation:** document the invariant in plan §5-R6/R7 now (it's the
foundation of the whole decryption design), and pick (b) or (c) for any
multi-decryption deployment.

---

## Q14. Threat-model section for plan.md (from review.md #6)

**Context.** The plan has no security section: corruption thresholds (T vs n/H);
rushing-adversary and rogue-key analysis (R1's proof of knowledge is the
mitigation — say so); discard/attribution rules (who is blamed when R4 fails,
given R0 proves no key well-formedness); transcript/domain binding as an explicit
requirement (its absence was a HIGH-severity finding in the code review);
CRS genesis (who samples `a`, the `A_l`, outer keys — need nothing-up-my-sleeve
derivation, else binding is vacuous; the implementation uses domain-separated
Poseidon-squeezed `from_domain`, which answers this — write it down).

**Recommendation:** add the section; most answers already exist in the
implementation and just need to be stated.

---

### Already decided / closed (for the record)

- Extraction slack: **derived** (S=2 decide-directly; folding R7 shown infeasible
  at these parameters → P track decides directly, as plan §5-R7 specifies).
- N8192 reconstruction prime replaced with a verified 177-bit value; ProdParams P
  (251-bit, safe form) derived from the same accounting.
- Centered decode `u = Δ·m + e` adopted over the plan's original
  `−Q⁻¹·(t·u) mod Q mod t` (the t·u term exceeds the P-track modulus; plan.md
  §5-R7.4 corrected in place).
- Transport of shares as R2-committed digits with per-instance metadata binding
  (sender, recipient, share-kind, channel, prime, limb).
