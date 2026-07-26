# Decider wrapper circuits (C5/C7) — specification and status

Plan §7.1/§10: the ZK aggregation boundaries wrap **only the small per-track
decider statements** of the LatticeFold tracks — never the folding
transcripts (those verify natively). The decider relation has an identical
shape across tracks (commitment opening + norm bound + evaluation
consistency), differing only in the modulus. Everything here runs over the
N=8192 parameter set of `crates/latticefold/src/vdkg_params.rs` (three
58-bit RNS primes; 176-bit P for the reconstruction track).

## The Schwartz–Zippel design (final, after the compile-time investigation)

The wrapper circuits do NOT arithmetize any NTT. Following the same trick as
the production `circuits/` (GRECO-style: everything is evaluated at a random
point with Horner):

1. **The witness NTT is computed UNCONSTRAINED** (brillig — free; conditional
   swaps don't matter there).
2. **NTT correctness is verified at one random point `r`** via the
   geometric-series identity
   `Σ_k r^{n-1-k}·w_ntt[k] = Σ_i w[i]·ψ^i·(r^n−1)/(r−ω^i)`, with the n
   denominators inverted in ONE Montgomery batch (~3n muls + 1 inversion).
3. **The opening check** `cm = A·w_ntt` is compressed to a Horner evaluation
   of the error vector at `r` (valid Schwartz–Zippel check).
4. Norm bound: per-coefficient balanced-digit range checks.

`r` is currently a public input standing in for the Fiat–Shamir challenge;
production derives it by hashing the public statement in-circuit (bounded
hashing, plan §10).

### Off-circuit Fiat–Shamir (current design, plan §7.1/§11)

**Ajtai commitments substitute for in-circuit hashing of the challenge.**
The Schwartz–Zippel challenge `r` and the linearization point `r_lin` are
derived **off-circuit** from the published commitment digests (§6.2 double
commitments — 1–4 field elements each), commit-then-challenge:

1. Prover publishes the digests of every quantity entering the wrapper
   (folded accumulators, aggregate key, committee/parameter domain).
2. `r = Poseidon(tag, digests…)` is derived off-circuit
   (`crates/latticefold/src/wrapper_challenge.rs`) — unpredictable to the
   prover at commitment time (MSIS binding), so the SZ checks are sound with
   **zero in-circuit hashing**.
3. The on-chain verifier recomputes `r` from the digests (one hash over a
   handful of field elements) and checks it equals the wrapper's public
   input.

This is exactly the plan's stance: Ajtai replaces hash commitments
(consistency links free), while Fiat–Shamir stays native/off-circuit
(LatticeFold's Poseidon transcript for the tracks; digest-derived for the
wrapper) — in-circuit hashing would only be needed if the wrapper had to
re-derive full folding transcripts, which the §7.1 split avoids.

### The decider's three checks (all now present in `c5_sz`)

1. **Commitment opening** (`cm = A·w_ntt`, Horner-at-r).
2. **Norm bound** (balanced-digit range checks).
3. **Evaluation consistency**: the R1 relation row
   `pk0_agg + a·sk − e = 0` evaluated at the linearization challenge point
   `r_lin` as `eq(0000, r_lin)² · row_val = 0` per coefficient — the
   decider's check that the folded instance satisfies its relation at the
   folding track's own challenge (replayed off-circuit).

### Why the naive in-circuit NTT died (compile-time root causes)

1. **Bit-reverse permutation.** Conditional array swaps with data-dependent
   indices (`if i < j { swap(a[i], a[j]) }`) lower to memory operations that
   are O(N²) — at N=8192 this made compilation hang (>30 min, aborted).
   First fix attempt: permute inputs off-circuit and drop the permutation.
2. **DIT-vs-DIF.** The decimation-in-time butterfly does NOT have the
   "natural input → bit-reversed output" property (verified numerically);
   its dual (decimation-in-frequency) does. A DIF variant worked, but…
3. **Cost of reductions.** Every `x as u128` cast in the modular reduction
   was a ~130-250-gate bit decomposition (11.4M opcodes). Replacing it with
   `(m−1−r).assert_max_bit_size(59)` (their own `polynomial.nr` pattern)
   brought it to 2.8M. The Schwartz–Zippel design then removes the NTT
   machinery altogether and is far simpler to compile.

## Measured (Apple M4 Pro, nargo 1.0.0-beta.22 + bb 5.0.0, evm-no-zk)

| Circuit | Design | Degree | ACIR opcodes | Compile | Prove (bb) | Proof |
| --- | --- | --- | --- | --- | --- | --- |
| `ajtai_opening` † | in-circuit NTT (u128 div) | 1024 | 757,396 | 21s | 5.8s | 9.5 KB |
| `c5` † | in-circuit NTT (3 tracks) | 1024 | 2,389,356 | 75s | 17.9s | 10.2 KB |
| `c7` | integer identities (interp+CRT+decode) | 1024 | 319,488 | 2.4s | 2.7s | 10.0 KB |
| **`ajtai_opening_sz`** | **Schwartz–Zippel** | **8192** | **2,803,935** | **93s** | **12.3s** | **9.9 KB** |
| **`c5_sz`** | **Schwartz–Zippel (3 tracks, opening only)** | **1024** | **1,127,984** | **36s** | **5.2s** | **9.5 KB** |
| **`c5_sz`** | **SZ + evaluation consistency (3 tracks)** | **1024** | **1,164,956** | **39s** | **5.3s** | **9.5 KB** |

† superseded intermediate experiments (removed from the tree; numbers kept
for the record — the in-circuit-NTT design at N=8192 never finished
compiling). The remaining circuits in the tree are `ajtai_opening_sz`,
`c5_sz`, `c7`, the `modulo` lib, and the vector generators in `scripts/`.

Cost structure per track (SZ): per witness element ≈ 3 Horner/NTT-verify
loops of N (≈ 15 modular ops/coefficient) + κ·m·N opening products + N digit
checks. `c5_sz` at N=8192 projects to ≈ 9M opcodes (3 tracks × ~3M); the
production R1 witness has 15 digit elements per track (5 limbs × 3 values)
rather than the prototype's 3, i.e. ~5× the NTT-verify cost → ~25-30M for a
3-track C5 → per-track circuits + UltraHonk recursion (plan §7.1 option 3).

## C5 — threshold public-key aggregation (`c5_sz/`)

- **Public inputs:** per track: `cm_t` (folded R1 Ajtai commitment),
  `pk0_agg_t`, plus the SZ challenge `r`. (In production these enter as §6.2
  double-commitment digests — see "On-chain footprint".)
- **Witness:** per track: folded R1 witness `(sk, e, e_sm)`, the track's
  Ajtai matrix and CRS element `a` (NTT form).
- **Proves:** (a) each track decider opening + NTT correctness + norm bound;
  (b) `pk0_agg_t = -a_t·sk + e` per track.

## C7 — final decryption (`c7/`)

Key structural fact: every R7 row is an integer identity whose products stay
below 2^174 (Garner `u = r0 + q0·t1 + q0q1·t2`, quotient witnesses
`u = u_l + s_l·q_l`, decode `u = Δ·m + e`), so the whole CRT+decode core fits
a **single BN254 field element per value** — no NTT and no limb arithmetic,
which is the §9.3 no-wraparound margin made literal in-circuit. The
interpolation check `u_l = Σ λ_i·d_i (mod q_l)` binds the residues to the
public decryption shares (58-bit muls). Measured: **319,488 opcodes at
N=1024** (T=2 parties), prove 2.7s, verified. The R7 public-computation core
is NOT the bottleneck; the accompanying R6/P decider openings (C5-shape
circuits) are. The P-track Ajtai opening itself (176-bit modulus) needs
limb schoolbook multiplication for the NTT-verify products (twiddle
products overflow BN254) and is the one remaining arithmetic implementation.

## On-chain footprint (important)

`cm` (4×8192 field elements/track) and `pk0_agg` (8192/track) as public
inputs are ~1.3 MB of calldata — unacceptable. Per plan §6.2, every
published quantity must enter as a **double-commitment digest** (1-4 field
elements), with the wrapper gaining one small outer-opening argument each.
The current circuits take the full vectors for measurement; swapping them to
digests is a required production change.

## Missing for production

1. **Real vectors from the Rust side** (the folded accumulators of
   `vdkg_flow.rs` and their §6.2 digests, with `r`/`r_lin` derived by
   `wrapper_challenge.rs`) — current vectors are Python-generated with
   identical shapes and a fixed challenge.
2. **Digit-limb witnesses** (m=15 per track) replacing the m=3 prototype.
3. **Per-track circuits + UltraHonk recursion** for the ≥25M-opcode
   production C5, and the P-track limb arithmetic for the C7 decider opening.
4. **Solidity verifier + gas measurement** on the final circuits (`bb
   write_solidity_verifier` works; measured gas needs a Foundry run — the
   article's artifacts were 3.2-3.8M gas for reference).

## Soundness pass (2026-07-26) — fixed, and remaining known gaps

Fixed in the circuits: the `reduce_mod` quotient is now range-constrained
(honest `n < m^2`, so `q < 2^70`; then `q*m + r < 2^130 << p` makes the
divmod equality an integer identity — previously `q` was a free field
element and any claimed remainder passed); the same fix was applied to the
dormant production original `circuits/lib/src/math/modulo/U128.nr`;
`assert_digit` now enforces canonical form before its `as u64` cast (the
cast truncated mod 2^64); the Ajtai CRS matrices, folded commitments, CRS
element `a`, per-gamma evals, and the C7 decryption shares are now `pub`
inputs (the verifier fixes them to the true values); C7's Garner digit
bounds and decode window are enforced on canonical representatives without
`as` casts, and the decode accepts centered noise `e in [0, Delta/2] union
[Q - Delta/2, Q)` matching the Rust flow.

Remaining known gaps (documented cost deltas, not yet implemented):

1. **SZ challenge binding.** `r` is currently a fixed compiled-in constant
   (or public input), and the off-circuit derivation in
   `wrapper_challenge.rs` binds only public digests, so a prover chooses the
   wrapper witnesses (w, w_ntt) *after* knowing the evaluation point.
   Production must derive `r` over a commitment to the wrapper witness
   (bounded in-circuit hashing, sanctioned by plan.md section 10) — expect
   an opcode delta for the Poseidon absorption of ~24k elements/track.
   Also: a single evaluation point at degree ~2^13 over a 58-bit modulus
   gives ~45-bit per-check soundness; production needs amplification
   (multiple independent points).
2. **`r_lin` (and gamma/rho) must be re-derived from the folding
   transcript.** As free public inputs they make the evaluation-consistency
   check degenerate (`r_lin = [1, ...]` forces `eq0 = 0`). The verifier
   side must replay the folding transcript's Fiat-Shamir to bind them.
3. **Public-input integrity is a verifier obligation**: with CRS matrices,
   commitments and shares now public, the verifier/contract must source
   them from the real CRS digests and broadcast values, not from the
   prover's supplied proof bundle.
