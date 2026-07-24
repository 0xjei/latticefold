# Decider wrapper circuits (C5/C7) — specification and status

Plan §7.1/§10: the ZK aggregation boundaries wrap **only the small per-track
decider statements** of the LatticeFold tracks — never the folding
transcripts (those verify natively). The decider relation has an identical
shape across tracks (commitment opening + norm bound + evaluation
consistency), differing only in the modulus. Everything here runs over the
N=8192 parameter set of `crates/latticefold/src/vdkg_params.rs` (three
58-bit RNS primes; 176-bit P for the reconstruction track).

## The decider relation (per track, ring R_q, degree N)

1. **Commitment opening** — `cm = A · w` over `R_q`, `A` the public κ×m
   Ajtai matrix (κ = 4), `w` the residual folded witness (m ring elements).
   Verified in NTT domain: one forward NTT per witness element, then `κ·m·N`
   pointwise products.
2. **Norm bound** — every witness coefficient is a small balanced digit
   (`|w| ≤ B`), checked in coefficient form (this is why the NTT of the
   witness happens in-circuit rather than receiving NTT-form witnesses).
3. **Evaluation consistency** — the folded LCCCS instance satisfies the
   folded (sparse) CCS relation with the transcript challenges. The R1
   relation row `pk0 = -a·sk + e` is one pointwise NTT-domain identity and is
   included in C5 below; the full transcript-challenge replay (Poseidon over
   `R_q` inside BN254) is the bounded in-circuit hashing of plan §10 and is
   **not implemented here** (see "Missing for production").

## C5 — threshold public-key aggregation (`c5/`)

- **Public inputs:** per track: `cm_t` (the track's folded R1 Ajtai
  commitment), `pk0_agg_t` (the aggregated key component). (In production
  these enter as §6.2 double-commitment digests — see "On-chain footprint".)
- **Witness:** per track: the folded R1 witness `(sk, e, e_sm)` and the
  track's Ajtai matrix + CRS element `a` (NTT form).
- **Proves:** (a) each track decider opening + norm bound; (b) the
  aggregation relation `pk0_agg_t = -a_t·sk + e` per track.

## C7 — final decryption (spec; not built this session)

Same decider core for the 3 R6 tracks, plus the P track (176-bit field):
interpolation consistency vs the supplied party IDs (public Lagrange
coefficients), CRT reconstruction rows `u = u_l + s_l·q_l` with bounded
quotient witnesses, and the decode row `u = Δ·m + e` with a bounded rounding
witness. The 176-bit field arithmetic needs 2-3 BN254 limbs per element
(≈3-4× the per-mul cost of the 58-bit tracks).

## Measured (Apple M4 Pro, nargo 1.0.0-beta.22 + bb 5.0.0, evm-no-zk)

| Circuit | Degree | ACIR opcodes | Compile | Prove (bb) | Proof |
| --- | --- | --- | --- | --- | --- |
| `ajtai_opening` (1 track, m=3) | 1024 | 757,396 | 21s | 5.8s | 9.5 KB |
| `c5` (3 tracks, m=3) | 1024 | 2,389,356 | 75s | 17.9s | 10.2 KB |

Cost structure per track: `m` NTTs ≈ `m · N·log2(N)` muls mod q (each ≈ 3-4
gates) + `κ·m·N` opening products + `3·N` digit range checks. The NTTs are
~90% of the cost.

**Scaling to N=8192** (the production degree): butterflies grow ×10.65
(8192·13 vs 1024·10) → ≈ 8M opcodes (opening) and ≈ 25M opcodes (C5 as
built). The production R1 witness has **15 digit elements per track** (3
logical values × 5 decomposition limbs) rather than the prototype's 3 short
elements, multiplying the NTT cost by ~5 → **~60-70M opcodes for a 3-track
C5 at N=8192**. Proving stays off-chain-feasible (minutes), but the
production shape should be **per-track decider circuits + UltraHonk
recursive combination** (plan §7.1, option 3), keeping each circuit ≤ ~25M.

## On-chain footprint (important)

`cm` (4×8192 field elements/track) and `pk0_agg` (8192/track) as public
inputs are ~1.3 MB of calldata — unacceptable. Per plan §6.2, every
published quantity must enter as a **double-commitment digest** (1-4 field
elements), with the wrapper gaining one small outer-opening argument each.
The current circuits take the full vectors for measurement; swapping them to
digests is a required production change.

## Missing for production

1. **Transcript-challenge binding.** The LCCCS evaluation-consistency check
   requires the folding transcript's challenges (Poseidon over `R_q`),
   replayed in-circuit (bounded hashing, plan §10) or the transcripts
   published and replayed natively on-chain (plan §7.1 open question (a)).
2. **Real vectors from the Rust side** (the folded accumulators of
   `vdkg_flow.rs`) — current vectors are Python-generated with identical
   shapes.
3. **Digit-limb witnesses** (m=15 per track) replacing the m=3 prototype.
4. **Per-track circuits + UltraHonk recursion** for the ≥60M-opcode
   production C5, and the C7 build (P-track limbs + interpolation/CRT/decode
   rows).
5. **Solidity verifier + gas measurement** on the final circuits (`bb
   write_solidity_verifier` works; measured gas needs a Foundry run — the
   article's artifacts were 3.2-3.8M gas for reference).
