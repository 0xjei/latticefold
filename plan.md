# Design Document

## Lattice-Based Verifiable DKG, User Encryption, and Threshold Decryption for RNS-BFV using LatticeFold / LatticeFold+ and Ajtai Commitments

**Status:** Design proposal
**Scope:** Distributed Key Generation (DKG), user encryption under the threshold key, and threshold decryption, over RNS-BFV. Relinearization-key generation is out of scope for now.
**Base references:** Boneh & Chen, *LatticeFold* (eprint 2024/257) and *LatticeFold+* (eprint 2025/247); the NethermindEth `latticefold` implementation : https://github.com/NethermindEth/latticefold; Urban & Rambaud, *Robust Multiparty Computation from Threshold Encryption Based on RLWE* (eprint 2024/1285); `fhe.rs` (RNS-BFV library), and our current implementation and design: https://github.com/theinterfold/interfold/tree/main

---

## 1. Executive Summary

Circuit-based PVDKG designs built over a general-purpose SNARK backend (e.g. Noir/UltraHonk over BN254) must re-derive every RNS-BFV ring operation as an *integer* identity with explicit quotient witnesses for the $(X^N+1)$ and $q_l$ reductions, because the backend's native field has nothing to do with BFV's own primes. Bounding those quotient witnesses is what drives GRECO-style range-check machinery, and, separately, deriving a Fiat-Shamir challenge for a Schwartz–Zippel check requires hashing the relevant transcript *inside* the circuit, since the challenge must be verifiably bound to the actual witness-dependent values (although not all of this hashing was extra work as we needed to perform some hashing so as to be able to split circuits.)

This document specifies an alternative backend for the same protocol — DKG, user encryption, and threshold decryption — built on:

- **Ajtai commitments** in place of hash-based commitments. Because Ajtai commitments are additively/linearly homomorphic under any public scalar or matrix, most cross-relation consistency checks reduce to public arithmetic on already-published commitments, with no circuit and no re-hashing required.
- **LatticeFold / LatticeFold+ CCS relations native to each RNS prime $q_l$**, so that BFV's modular reductions are free (ring equality already means "mod $q_l$, mod $X^N+1$"), removing the quotient-witness/range-check machinery for that specific purpose.
- **Native multi-instance folding**, replacing recursive proof aggregation, with an explicit tree structure that preserves the ability to isolate a specific cheating party without paying tree-search cost in the common, all-honest case.
- A **minimal-on-chain-footprint publication model**: only compact commitments and a handful of decided-proof artifacts are ever published on-chain; the underlying witnesses, keys, shares, and ciphertexts are exchanged over a broadcast/gossip layer and validated against the on-chain commitments (so the footprint should be the same as what we currently have.)

Every relation in the protocol is worked out explicitly below, together with its degree in the witness, its norm/decomposition requirements, and its publication footprint.

---

## 2. Background

### 2.1 RNS-BFV

Ring $R=\mathbb Z[X]/(X^N+1)$; plaintext modulus $t$; ciphertext modulus $Q=\prod_{l=1}^L q_l$, each $q_l$ prime and NTT-friendly, with each RNS channel $R_{q_l}$ stored and computed independently. A fresh BFV ciphertext of plaintext $m$ under public key $(pk_0,pk_1)=(-a\cdot sk+e,\ a)$ is $ct_0=pk_0\cdot u+e_0+\Delta_l\cdot m$, $ct_1=pk_1\cdot u+e_1$, with $\Delta_l$ an RNS-friendly per-channel scaling constant and $u,e_0,e_1$ short. Homomorphic multiplication, rescaling, and the final plaintext decode are the operations that do not respect the RNS/CRT split; only the decode step is relevant to this design (§5, R7).

### 2.2 LatticeFold / LatticeFold+ and Ajtai commitments

Ajtai commitment: $\mathrm{Com}(\vec x)=A\vec x\bmod q$, $A\in R_q^{\kappa\times m}$ public (note this description is only of the one of a biding commitment, not hiding, but there is a version where the commitment is both binding and hiding and so this version is what we use in case we needed the hiding property). It is additively and $R_q$-linearly homomorphic under any scalar or public matrix, of any norm: $a\cdot\mathrm{Com}(\vec x)=\mathrm{Com}(a\vec x)$ holds unconditionally as ring algebra. Binding holds only for inputs (and openings-under-extraction) within a norm bound $B$ tied to MSIS hardness for the chosen $(q,\kappa,m)$. Values that are not natively short — most importantly, Shamir shares, which are evaluations of a random polynomial and are therefore close to uniform modulo $q_l$ regardless of how short the underlying secret is — must first be gadget/digit-decomposed into short digits ($y=\sum_j b^j y_j$, $\|y_j\|_\infty<b$) before they can be committed; the recompose map is linear, so this decomposition composes cleanly with the commitment's homomorphism (§6).

LatticeFold folds CCS relations over $R_q$ (a single fixed prime $q$, satisfying $q\equiv 1+2t\pmod{4t}$) via an expansion/decomposition/folding pipeline with a sumcheck-based norm proof; LatticeFold+ replaces the range proof with a purely algebraic one and adds double commitments (commitments of commitments. I think this preserves homomorphism, and for sure one layer of commitment preserves homomorphism so worst case we use one layer of commitments.), yielding a faster prover, a simpler verifier circuit, and — used deliberately here — a way to publish a compact outer commitment in place of a full inner commitment vector (§6.2). A folding scheme reduces many instances to one; it is not itself a SNARK, and a final "decider" step is required, either a direct check of the last folded instance or an external SNARK/STARK wrapping.

The NethermindEth `latticefold` repository is a proof-of-concept exposing `R1CS<R>` and `CCS<R>` structs generic over a `Ring` trait; its ready-made rings (BabyBear/Goldilocks/Stark) are fixed STARK-oriented primes and will not generally coincide with `fhe.rs`'s RNS primes, so a custom `Ring` implementation per RNS prime used in this design is required.

### 2.3 Protocol structure and theoretical basis

The protocol is organized into four phases, following our current design: **P1** distributed key generation, **P2** threshold public-key aggregation, **P3** user encryption under the threshold key, **P4** threshold decryption. The DKG/decryption design mirrors Urban & Rambaud's robust threshold-BFV construction: every party's contribution is accompanied by a proof, and any party whose proof fails verification is discarded from the authorized set, restricted here to key generation and decryption (relinearization is out of scope).

---

## 3. Design Goals and Non-Goals

**Goals**

1. No non-native modulus emulation for RNS-level BFV arithmetic.
2. No GRECO-style range-check machinery (foreign-field bit-decomposition and in-circuit Fiat-Shamir hashing); norm/shortness is enforced by LatticeFold's/LatticeFold+'s native range-proof machinery.
3. Homomorphic (Ajtai) commitments in place of hash commitments, so linear cross-relation checks are free.
4. Native multi-folding in place of recursive proof aggregation, while retaining the ability to identify a specific cheating party.
5. A single explicitly-larger prime $P>Q$ for the one step (final CRT reconstruction and decode) that cannot respect the RNS split, under a derived (not assumed) no-wraparound margin.
6. Minimal on-chain footprint: only compact commitments and decided-proof artifacts on-chain; bulk data over broadcast.
7. Deployable, verifiable on-chain SNARKs as the final artifact, with an explicit account of what that requires.

**Non-goals**

- Relinearization key generation (but just postponed for now, should be doable as well)
- FHE evaluation correctness (which is not handeled as well in our current design with Noir).
- Handling smudging noise wider than a single native modulus (§9.2).

---

## 4. Architectural Principles

### 4.1 Two axes of aggregation

- **Across RNS channels ($q_1,\dots,q_L$):** different primes cannot be folded together in one LatticeFold instantiation — the commitment space, norm bound, and challenge space are all tied to one fixed modulus. **Result: $L$ independent LatticeFold tracks, one per RNS channel**, each with its own Ajtai key $A_l\in R_{q_l}^{\kappa\times m}$, plus **one additional reconstruction track** over a large prime $P>Q$ used once, at the end (§5, R7). Combining the outputs of these $L+1$ tracks into a single submitted artifact requires a separate mechanism, described in §7 and §10 — not a LatticeFold-native operation.
- **Across parties, within a fixed channel:** all parties instantiate the same-shaped relation for the same $q_l$; this is exactly what LatticeFold's high-arity multi-folding is for, and is where recursive-proof-aggregation is replaced by native folding.

### 4.2 Free vs. proof-required consistency

A check of the form "commitment $C$ equals a public linear combination of commitments $C_1,\dots,C_k$" is directly and deterministically verifiable by anyone from the published commitments alone, with no circuit involved, by Ajtai's homomorphism. What still requires an actual proof is knowledge of a *short opening* consistent with a commitment — the core commitment-opening relation LatticeFold is built around. Every relation below is annotated with which of its checks fall into each category.

### 4.3 Publication model

The blockchain stores only: (a) compact (outer/double) commitments to each track's aggregated state, and (b) the decided-proof artifacts needed to verify those commitments were correctly derived. Full witnesses, keys, ciphertexts, and shares are exchanged over a broadcast/gossip layer; any party can validate a broadcast value against the corresponding on-chain commitment by recomputing a single (outer) commitment locally — a cheap operation that requires no trust in whoever relayed the value. §6.2 describes the double-commitment mechanism used to keep the on-chain artifact to a single ring/field element per published quantity rather than a full $\kappa$-element commitment vector.

---

## 5. Relation-by-Relation Design

Note in the following we might merge some circuits if performance is good enough ( as actually some circuits in our current design with Noir could have been merged if it wastn't for provers work that couldn't accomodate for this)
Notation: $l=1,\dots,L$ ranges over RNS channels; $i,j$ range over parties in the authorized set $A$; "linear in the witness" means the equation, after treating all previously broadcast/committed public values as public instance data, is affine in the remaining secret witness.

| # | Purpose | Degree | Needs decomposition | On-chain artifact |
| --- | --- | --- | --- | --- |
| R0 | Individual key commitment | — | no | none required |
| R1 | Threshold-key & smudging-noise contribution | 1 | no (native secrets short) | folded/decided digest per channel |
| R2 | Shamir sharing (batched Reed–Solomon) | 1 | yes (shares) | folded/decided digest per channel |
| R3 | Encryption of shares under individual keys | 1 | no beyond inherited share digits | folded/decided digest per channel |
| R4 | Share receipt and aggregation | 1 | inherited | folded/decided digest per channel |
| R5 | Threshold public-key aggregation | 1 (no secrets) | inherited (public) | compact commitment + proof |
| Ruser | User encryption (replaces GRECO) | 1 | depends on $t$ vs. norm bound | per-submission or folded digest |
| R6 | Decryption-share computation | 1 | yes (share-of-sum) | folded/decided digest per channel |
| R7 | Lagrange interpolation, CRT reconstruction, decode | 1 (no secrets) | quotient witnesses only | compact commitment + proof |

### R0 — Individual Key Commitment

Each party's individual BFV key pair is used only to secure DKG traffic between parties. Witness: none — $(pk_0^{ind},pk_1^{ind})$ are public BFV data. Output: $\mathrm{Com}_l(pk_0^{ind}),\mathrm{Com}_l(pk_1^{ind})$ per channel, pinning the value later relations must reference. Well-formedness of the individual key relative to a genuine secret key is not separately proved here; a malformed individual key is caught downstream when the owning party fails R4 and is discarded.

### R1 — Threshold-Key and Smudging-Noise Contribution Generation

Witness (short, per party, per channel): $sk_i,e_i,e_{sm,i}$. Public: CRS element $a$. Constraint:

$$
pk_{0,i}=-a\cdot sk_i+e_i\pmod{q_l},\qquad pk_{1,i}=a.
$$

$a_i$ is public, so $a\cdot sk_i$ is public-times-secret — affine, not quadratic — and the equation is checked as a native $R_{q_l}$ identity with no quotient-witness correction terms of any kind. Norm constraints on $sk_i,e_i,e_{sm,i}$ use LatticeFold's/LatticeFold+'s native range-proof machinery. Outputs: $\mathrm{Com}_l(sk_i)$, $\mathrm{Com}_l(e_{sm,i})$; $pk_{0,i}$ is public and its commitment can be recomputed by anyone.

### R2 — Shamir Sharing of the Contribution

A Shamir share — an evaluation of a degree-$T$ polynomial (whose low-order coefficients are the short secret) at a fixed public point — is, by construction, close to uniform modulo $q_l$, independent of how short the underlying secret is. Every share value that will be committed must therefore be gadget/digit-decomposed into short digits before commitment; this is not specific to any one relation but a property of what a share mathematically is, and applies to every downstream relation that reuses a share (R3, R4, R6).

Constraints:

1. **Consistency with R1:** the zeroth share equals the value committed there (linear).
2. **Reed–Solomon validity**, batched over the whole polynomial rather than per coefficient. Party $i$'s share to recipient $k$, for a fixed channel $l$, is a single ring element $Y_l[k]\in R_{q_l}$ whose $c$th coefficient is the coefficient-$c$ share value. The Reed–Solomon parity-check matrix $H_l$ has entries in $\mathbb Z_{q_l}$ that do not depend on the coefficient index (only on the fixed set of evaluation points), so the single ring-level equation

$$
H_l\cdot \vec Y_l^{\,T}=\vec 0\pmod{q_l}
$$

(scalar entries of $H_l$ acting on a vector of ring elements via native scalar-times-ring-element multiplication) is coefficient-wise identical to checking the ordinary per-coefficient parity check for every coefficient simultaneously — scalar multiplication of a ring element acts independently on each coefficient, so no cross-coefficient mixing is introduced (this is unlike genuine ring *multiplication*, which does mix coefficients through the $X^N+1$ reduction). This reduces $N$ scalar constraints per check-row to a single ring-level constraint per check-row, one of the direct benefits of representing a party's shares as ring elements rather than $N$ independent field elements.
3. **Norm bound on the decomposed digits** (not on the shares themselves, which are intentionally full range).

Output: $\mathrm{Com}_l(\text{digits of }Y_l[k])$ per recipient $k$.

### R3 — Encrypting a Share Under the Recipient's Individual Key

Witness: encryption randomness $u^{ind}$, errors $e_0^{ind},e_1^{ind}$ (short, no decomposition), and the already-short share digits from R2. Public: recipient's $(pk_0^{ind},pk_1^{ind})$, pinned to R0, and $\Delta_l$ (This assumes the plaintext space of the second instance of BFV, namely the one used for PVSS (i.e. the individual keys) is larger than the largest qi). Constraint:

$$
ct_0=pk_0^{ind}\cdot u^{ind}+e_0^{ind}+\Delta_l\cdot(\text{recomposed share}),\qquad ct_1=pk_1^{ind}\cdot u^{ind}+e_1^{ind},
$$

entirely affine (public $pk_0^{ind},pk_1^{ind},\Delta_l$ times secret witnesses, plus a linear recompose of already-short digits). Norm checks on $u,e_0,e_1$ only; share-digit shortness is inherited from R2 via commitment binding. Run $|A|\times(|A|-1)$ times per channel per share type — the axis where high-arity folding gives the largest gain over recursive-proof aggregation.

### R4 — Share Receipt and Aggregation

Because R2 already committed to the true share value before it was ever encrypted, the recipient does not need to re-derive or re-verify the BFV decryption formula. It only needs to prove knowledge of a short-digit opening $V$ matching the sender's R2 commitment — the received value is obtained in practice by running the real decryption via `fhe.rs` off-circuit and supplying the result as a witness; binding of the R2 commitment guarantees this is the correct share regardless of how it was obtained. This is exactly LatticeFold's own foundational commitment-opening relation, unmodified.

Aggregation $agg_{i,l}=\sum_{a\in A}V_{a\to i}\pmod{q_l}$ is a sum of committed values; the new commitment $\mathrm{Com}_l(agg_{i,l})=\sum_a\mathrm{Com}_l(V_{a\to i})$ is computed publicly, with no additional circuitry — the only proof required is knowledge of each opening.

Note that we can even get rid of this circuit as well thanks to the fact that commitments are homomorphic at the expensive of a relativly added cost during decyrption i will be checking this.

### R5 — Threshold Public-Key Aggregation

$pk_{0,agg}=\sum_i pk_{0,i}$, $pk_{1,agg}=a\pmod{q_l}$: a computation over exclusively public values, requiring no hiding. It is nonetheless wrapped in a small decided proof — not for soundness of the sum itself (anyone could recompute it), but so that a client wishing to encrypt to the threshold key can retrieve, in one step, the aggregated public key together with a compact validity proof, without redoing the $L\times|A|$-term summation or fetching and verifying every individual party's key share. The on-chain artifact is a compact (double) commitment to $pk_{agg}$ plus its decided proof; the full $pk_{agg}$ polynomial itself is served over the broadcast layer and checked locally by recomputing its commitment.

### Ruser — User Encryption (replacement for GRECO)

Structurally identical to R3, now under the threshold public key: witness $u,e_0,e_1$ (short) and the user's plaintext $m$; public $(pk_{0,agg},pk_{1,agg})$ pinned to R5, and $\Delta_l$. Constraint:

$$
ct_0=pk_{0,agg}\cdot u+e_0+\Delta_l\cdot m,\qquad ct_1=pk_{1,agg}\cdot u+e_1,
$$

again fully affine in the witness. Two points specific to this relation:

- **Range on $m$:** $m$ must lie in the valid plaintext range; whether this requires digit decomposition or falls within a native "short" bound depends on how $t$ compares to the chosen Ajtai norm bound — a parameter-dependent choice, resolved the same way share decomposition is (§6). Either way, the check itself uses LatticeFold's/LatticeFold+'s native range-proof machinery, not a foreign-field bit-decomposition.
- **Cross-channel consistency of $m$:** unlike DKG values (which are honestly generated once by `fhe.rs` and simply represented per channel), a user is untrusted and could attempt to encrypt inconsistent messages across channels to corrupt the downstream FHE computation. This is prevented by committing to $m$ (or its digits) once, in a dedicated message commitment, and having each of the $L$ per-channel Ruser instances prove its own use of $m$ is an opening of that same commitment — reusing the same commit-once/reference-many-times pattern already used for $sk_i$.

### R6 — Decryption-Share Computation

Witness: the digit-decomposed $sk_i^{share}$ and $e_{sm,i}^{share}$ from R4. **Both are full range, not short.** A party's secret-key share used here is the sum of the shares it received from every other party (R4's aggregation output); summing several values that are each individually close to uniform modulo $q_l$ does not make the sum short — it remains, in the relevant sense, a share (its whole purpose is to be one point on a degree-$T$ polynomial that reconstructs the aggregated secret under Lagrange interpolation), and must be represented via its already-established digit decomposition, exactly as in R2–R4. The same applies to the aggregated smudging-noise share.

Public input: the ciphertext to decrypt $(ct_0,ct_1)$ (itself full range — a ciphertext component is not short either) and the claimed decryption share $d_i$. Constraint:

$$
d_i=ct_0+ct_1\cdot(\text{recomposed }sk_i^{share})+(\text{recomposed }e_{sm,i}^{share})\pmod{q_l}.
$$

$ct_1$ is a public, full-range ring element multiplying a linear combination of short secret digits — still affine overall. $d_i$ requires no norm bound and no fresh commitment: it is simply the public output of a linear map applied to an already-committed short-digit witness, broadcast in the clear once computed (the smudging noise ensures this reveals nothing about the underlying share). Norm checks on the digits are inherited from R2/R4, not repeated.

### R7 — Lagrange Interpolation, CRT Reconstruction, and Decoding

By this point every $d_i$ has already been publicly revealed — this is the one relation in the protocol that requires no zero-knowledge at all, only succinctness of an otherwise moderately expensive, entirely public computation. It runs once, on a dedicated LatticeFold track with modulus $P$ prime, $P>Q=\prod_l q_l$.

1. **Lagrange coefficients** $L_i(0)\bmod q_l$, computed from public party indices — fully public, may be checked in-circuit purely to bind the specific index set used.
2. **Per-channel interpolation** $u^{(l)}=\sum_i d_i^{(l)}\cdot L_i(0)\bmod q_l$: public arithmetic.
3. **CRT reconstruction**, the one step that genuinely mixes information across all $L$ channels and therefore cannot stay within any single RNS track: for each $l$, $u^{(l)}+r^{(l)}\cdot q_l=u_{global}$, with quotient witnesses $r^{(l)}$ bounded by roughly $Q/q_l$, checked with native range-proof machinery.
4. **Decoding:** $message=-Q^{-1}\cdot(t\cdot u_{global})\bmod Q\bmod t$, with centered-representation sign handling, again requiring a bounded quotient/rounding witness — an intrinsic feature of arithmetizing integer division, not an artifact of the backend.

**No-wraparound requirement.** $P$ must exceed $Q$, every $r^{(l)}\cdot q_l$ cross term, and $u_{global}$, by a margin large enough that the $R_P$-native ring identity does not silently diverge from the intended integer identity — accounting explicitly for LatticeFold's own extraction slack (an extracted witness can be a small constant factor larger than an honest prover's), not merely asserted (§9.3).

The final artifact published is the plaintext output together with its decided proof, so that no observer needs to redo the interpolation/reconstruction/decode themselves.

---

## 6. Commitment and Consistency Chain

### 6.1 Linear vs. opening links

- **Linear links** (R4's aggregation, R5's summation, R6's reuse of already-committed share digits): verified for free by recombining published commitments with known public coefficients.
- **Opening links** (R2's consistency with R1, R4's opening of R2's per-recipient commitment, Ruser's cross-channel message consistency): require an actual folded CCS proof, but reduce directly to LatticeFold's native commitment-opening relation.

### 6.2 Double commitments for compact publication

Whenever a commitment must appear on-chain, an outer Ajtai commitment (with a small, e.g. rank-1, output) is taken over the inner commitment vector, following LatticeFold+'s own double-commitment ("commitment of a commitment") construction. This lets the on-chain artifact be a single ring or field element rather than a full $\kappa$-element commitment vector; the accompanying proof includes an opening argument linking the published outer digest back to the inner commitment and, ultimately, to the real witness, at the cost of one additional (but small, fixed-size) opening step. This mechanism is used for every commitment that must be published on-chain per the publication model in §4.3; commitments used only internally between relations (never published) can remain single-layer.

---

## 7. Folding Strategy

- $L$ independent per-channel tracks, each organized as a small-arity fold tree per §4.4, plus one reconstruction track over $P$.
- Tracks cannot be merged into one another by LatticeFold itself, since each is defined over a different modulus; combining the $L+1$ tracks' final decided statements into a single artifact for on-chain submission is done by a separate proving backend at the final wrapping stage, described in §7.1 and deployed per §10, not by folding.

### 7.1 Combining the $L+1$ tracks at the end

Since folding cannot cross moduli, the $L+1$ tracks (one per RNS channel plus the reconstruction track over $P$) must be combined by a mechanism outside LatticeFold itself. The approach proposed here splits the combination work by cost, following directly from where expense actually lies in the folding scheme's own verification:

- **The decider's work is the genuinely expensive part.** Checking that a track's final accumulated instance has a satisfying witness (a full commitment opening, a norm bound, and an evaluation-consistency check) is linear in the local residual witness size and does not shrink as a result of folding; this is exactly the piece LatticeFold's own paper flags as needing to be "outsourced" to an external SNARK.

Given this split, the proposed combination mechanism is:

1. For each of the $L+1$ tracks, only the decider relation is wrapped in a conventional SNARK circuit (Noir/Barretenberg, or a STARK) — never the whole folding transcript, which is handled by the native on-chain replay above.
2. The decider relation has an **identical shape** across all $L+1$ tracks — the same check (commitment opening, norm bound, evaluation consistency) — differing only in which modulus it is instantiated over ($q_l$ for the RNS tracks, $P$ for the reconstruction track). The same circuit template is therefore written once and reused $L+1$ times, each instantiation emulating a different native modulus inside the wrapper's own field.
3. The $L+1$ resulting statements are combined into a single artifact for on-chain submission, either by including all $L+1$ decider checks inside one circuit (producing a single proof directly, if the combined witness is small enough to be practical) or by producing $L+1$ separate proofs and combining them via recursive proof verification (e.g. Barretenberg's native support for verifying one UltraHonk proof inside another).

This mechanism is proposed but not yet implemented or benchmarked. Its two open questions are (a) the actual gas cost of replaying a track's folding-transcript checks natively on-chain, and (b) the non-native-arithmetic overhead of emulating each $q_l$'s modular reduction inside the wrapper circuit's own field for the decider check specifically — the same category of cost as the GRECO-style range checks avoided elsewhere in this design, here reintroduced but confined to one small opening check per track rather than to the whole protocol.

---

## 8. Parameter Selection

1. **RNS primes $q_l$** must remain NTT-friendly (required by `fhe.rs`) and separately satisfy LatticeFold's $q_l\equiv 1+2t\pmod{4t}$ congruence; this is a joint constraint that must be checked per candidate BFV parameter set, with LatticeFold's small-modulus extension-field technique available as a fallback if a chosen $q_l$ does not naturally satisfy it.
2. **Reconstruction prime $P$**, prime, $P>Q$ with the explicit margin of §5 (R7) and §9.3, subject to the same congruence requirement.
3. **Ajtai commitment parameters** $(\kappa,m,B)$, chosen via standard lattice-estimator methodology, separately for natively-short witnesses and for digit-decomposed full-range values (shares, and their downstream reuses).
4. **Digit-decomposition base $b$**, balancing witness blow-up against per-digit range-proof cost.
5. **Smudging-noise bound:** the statistical security parameter is chosen so the smudging-noise contribution, and its shares after decomposition, remain representable within its native channel throughout the protocol up to final CRT reconstruction (§9.2).

---

## 9. Known Issues and Mitigations

### 9.1 Large-norm committed values

The values requiring decomposition before commitment are Shamir shares (of secret-key contributions, smudging-noise contributions, and their sums) — not the native BFV secrets and errors, which are short by construction. The mitigation is base-$b$ digit decomposition at first commitment (R2), carried unchanged through every downstream relation that reuses a share (R3, R4, R6) via commitment binding.

### 9.2 Smudging noise wider than one native prime

Out of scope for this version, under the assumption that the statistical security parameter keeps the smudging-noise contribution (and its shares) within its native channel throughout. If this needs relaxing, available mitigations are LatticeFold's extension-field technique, splitting the noise into multiple independently-committed bounded limbs (the same decomposition machinery already used for shares, applied to the noise itself), or a dedicated wider prime channel for smudging noise alone.

### 9.3 No-wraparound margin in R7

The choice of $P$ must be justified with an explicit norm-accounting derivation covering the largest $r^{(l)}\cdot q_l$ cross term and LatticeFold's own extraction slack, computed during parameter selection rather than assumed.

---

## 10. On-Chain Deployment

- Neither LatticeFold nor LatticeFold+ is succinct enough by itself for cheap on-chain verification: deciding a track means either sending the final folded witness in the clear (linear in the local relation's size) or wrapping it in an external SNARK/STARK.
- No production tooling compiles a LatticeFold/LatticeFold+ decider into a Solidity verifier. Noir/Barretenberg offers mature, one-command Solidity verifier generation over BN254 using native EVM pairing precompiles; no equivalent exists for ring/lattice arithmetic.
- **Proposed path:** decide each of the $L+1$ tracks down to a small, fixed-size statement, then combine and wrap only that already-small collection of statements — not the underlying RNS-native computation:
    - **Noir/Barretenberg (UltraHonk/BN254):** mature Solidity verifier tooling, at the cost of reintroducing non-native arithmetic (now only for checking $L+1$ small lattice-relation openings) and dropping end-to-end post-quantum security at this last mile, since BN254 rests on the discrete-log assumption even though every relation upstream is MSIS-based. If this wrapper is also made to re-derive the folding tracks' own Fiat-Shamir challenges (needed for the wrapper to be sound without requiring every verifier to redo the folding transcript itself), it reintroduces a bounded amount of in-circuit hashing — the same category of cost GRECO incurs throughout its entire circuit set, but here confined to one small, final step.
    - **A STARK-based wrapper:** preserves post-quantum security end-to-end, at the cost of larger proofs and less mature on-chain verifier tooling; whether an existing STARK-to-EVM verifier can absorb this final check at acceptable gas cost is an open question.
- Gas/calldata costs are expected to be dominated by the wrapper proof itself (Ethereum charges per calldata byte); the LatticeFold layer never appears on-chain directly, only its decided digests and the wrapper proof.
- The wrapper is checking a public statement for everything downstream of RNS reconstruction (R7) and a handful of small, already-succinct opening claims for everything upstream — it is not re-proving the bulk BFV computation.

---

## 11. Comparison with a Circuit-Based (Noir/Poseidon2) Baseline

| Aspect | Circuit-based baseline | This proposal |
| --- | --- | --- |
| Native modulus | Foreign field (e.g. BN254), unrelated to BFV | Native to each $q_l$ (or $P$ for reconstruction) |
| Modular-reduction handling | Explicit quotient witnesses + range checks | Free (ring `=` already means mod $q_l$, mod $X^N+1$) |
| Norm/range proofs | Foreign-field bit-decomposition range gadgets | LatticeFold/LatticeFold+ native sumcheck/algebraic range proof |
| Fiat-Shamir for Schwartz–Zippel challenges | Hashed in-circuit throughout | Native (off-circuit) for the bulk protocol; reappears, bounded, only in the final wrapper if used |
| Reed–Solomon check | Per coefficient | Batched as one ring-level equation per check row |
| Cross-relation commitments | Hash-based; recompute and compare in-circuit | Ajtai; linear links free, opening links via native relation |
| Multi-proof aggregation | Recursive proof verification embedded in a circuit | Native multi-instance folding before aggregating proofs over all Rqi’s |
| Public-key aggregation | A circuit recomputing a hash chain | A thin decided proof purely for compact client retrieval; the sum itself needs no hiding |
| On-chain published data | Whatever the design chooses to commit | Minimal by construction: double/outer commitments plus decided proofs only |
| Post-quantum | No, throughout | Yes, up to the final on-chain wrapper trade-off |
| On-chain verifier maturity | Mature, if using Noir/Barretenberg | Unsolved at the LatticeFold layer; addressed by wrapping only the final small statement |

---

## 12. Suggested Implementation Plan

1. Fix a concrete `fhe.rs` BFV parameter set and check congruence compatibility of every $q_l$ and of $P$ with LatticeFold's requirements.
2. Implement the required custom `Ring` types for each $q_l$ and for $P$.
3. Implement R1 and R4 first (both map directly onto LatticeFold's existing commitment-opening relation) as a vertical slice.
4. Implement R2 with batched Reed–Solomon and digit decomposition; validate interoperation with R1/R4's commitments.
5. Implement R3 and Ruser, and benchmark high-arity folding across the pairwise/many-submitter instance sets against a recursive-proof-aggregation baseline.
6. Implement R5, R6, and R7 (the latter on its dedicated $P$track), with an explicit derivation and test of the no-wraparound margin.
7. Prototype the on-chain wrapper against a testnet deployment for both the Noir/Barretenberg and STARK options, measuring gas/calldata cost.
8. Revisit the deferred wide-smudging-noise item (§9.2) if required by the target security parameters.
