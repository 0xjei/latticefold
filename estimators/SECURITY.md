# Concrete lattice-security estimation — threshold-BFV + Ajtai commitments

Date: 2026-07-24. All raw output: `analysis/estimator_output.txt`. Reproduce with
`analysis/venv/bin/python -u analysis/estimate_security.py` (~20 min).

## 1. Methodology

**Tool.** [malb/lattice-estimator](https://github.com/malb/lattice-estimator), commit
`3e48ef421ec256afddb3e7d2249a77eab6e9ba12` (main). The package is not on PyPI and
upstream requires SageMath; we ran it on **passagemath 10.8.7** (pip wheels of the
SageMath library) inside `analysis/venv` (Python 3.13.3, macOS arm64). The estimator's
reference checks reproduce upstream values exactly: Kyber512 → dual_hybrid 2^139.7,
Dilithium2 MSIS → 2^152.2 (MATZOV) / 2^154.2 (BDGL16).

**Cost models.** Headline numbers use **MATZOV** (quantum sieving, `0.264·β + o(β)`-class
list-decoding sieves — the post-quantum model, and the default of this estimator
version); **BDGL16** (classical sieving `0.292·β`) is reported as a classical reference.
Every LWE number below is the **minimum over the full default attack suite**: primal
uSVP, primal BDD, BDD-hybrid, BDD-MITM-hybrid, dual, dual-hybrid, coded-BKW, Arora-GB.

**Estimator patches (numerics only, semantics unchanged, documented in the script header):**
1. `reduction.py`: `2**(0.2075·sieve_dim)` evaluated in arbitrary precision instead of
   float64 (3 identical sites). Fixes a float64 overflow that aborts any estimate with
   sieve dimension > ~4937 — our dimensions are 16k–57k. Regression-checked against the
   unpatched Dilithium2 value.
2. `gb.py`: Arora-GB's exact rational power-series precision truncated from `2n` to 256.
   The default is computationally infeasible at n=4096/8192 (it hangs the unmodified
   estimator). Conservative: whenever the degree of regularity is < 256 the result is
   exact; otherwise the attack is reported as +∞, which means rop ≥ binom(n+256,256)²
   (≥ 2^1588 at n=4096, ≥ 2^1677 at n=8192) — never the bottleneck either way.

**RLWE → LWE mapping.** An RLWE public key/encryption over `R_Q = Z_Q[X]/(X^n+1)` is
analysed as plain LWE with dimension n and modulus Q — standard practice (no known
attack exploits the ring structure here; the estimator itself uses this for FHE
schemes). Sample complexity `m = +∞` (adversary may use arbitrarily many ciphertexts,
not just the public key) — the conservative choice. Error: `DiscreteGaussian(σ=3.2)`
(CBD bound B=20). Secrets: (a) ternary `SparseTernary(p=n/2, m=n/2, n=n)` matching
fhe.rs-style ternary keys (NB: on this estimator commit the argument order is
`(p, m, n)`); (b) `Uniform(0,1)` matching the current demo's binary distribution.

**MSIS/Ajtai → SIS mapping.** Binding of `Com(x) = A·x mod q`, `A ∈ R_q^{κ×m_mod}`,
`R_q = Z_q[X]/(X^d+1)`, openings with `‖·‖∞ < β`, is MSIS_{q,κ,m_mod,d}. As a
Z_q-linear map, A has **κ·d output rows** and **m_mod·d input columns**, so we estimate
plain SIS with `SIS.Parameters(n = κ·d, q = q, length_bound = β, m = m_mod·d, norm = +∞)`.
This is exactly the estimator's own convention for Dilithium's MSIS schemes
(Dilithium2: d=256, κ=4 → n=1024, m=2304). Justification: negacyclic multiplication
turns each ring element into d Z_q-columns; known MSIS attacks do not exploit the
module/ring structure for these shapes, so plain-SIS is the standard conservative
estimate. The attacked q-ary kernel lattice has dimension m_mod·d and volume q^{κ·d}.
Two structural facts make several cases decidable analytically, and the estimator
agrees where it can run:
- **κ·d > m_mod·d (more equations than unknowns):** A is injective w.h.p., the kernel
  lattice is `q·Z^m`, shortest kernel vector `q·e_i` with `‖·‖∞ = q`. For any β < q
  **no solution exists at all** → unconditionally binding. Estimator: rop = +∞.
- **β ≥ (q−1)/2:** the integer vector `q·e_i` is *always* a kernel vector with
  `‖·‖∞ = q ≤ β`, regardless of dimensions → trivial break. The estimator refuses the
  instance outright: *"SIS trivially easy. Please set norm bound < q."*

**Scope note.** The smudging-noise security is *statistical* (λ = 50 bits of statistical
distance), not lattice-based; it is out of the estimator's scope and is not covered by
any number below.

## 2. Part A — BFV/RLWE threshold-key security

Moduli: N8192 uses Q = 288230376128643073 · 288230376090894337 · 288230376019591169
(log₂Q = 174.00); N4096 uses Q = 8590245889 · 8590934017 · 8591392769 (log₂Q = 99.00).

| Set | n | log₂Q | Secret | MATZOV (post-quantum) | BDGL16 (classical) | ≥128 bits PQ? |
|---|---|---|---|---|---|---|
| **N8192** | 8192 | 174.00 | ternary (fhe.rs-style) | **160.5** (bdd) | 164.2 (dual_hybrid) | **YES** (+32.5) |
| **N8192** | 8192 | 174.00 | binary {0,1} (demo) | **159.2** (dual_hybrid) | 162.5 (dual_hybrid) | **YES** (+31.2) |
| **N4096** | 4096 | 99.00 | ternary | **139.2** (bdd) | 141.9 (dual_hybrid) | **YES** (+11.2) |
| **N4096** | 4096 | 99.00 | binary {0,1} | **137.0** (dual_hybrid) | 139.0 (dual_hybrid) | **YES** (+9.0) |

Per-attack details in `estimator_output.txt`. Coded-BKW and Arora-GB are infeasible at
these dimensions (rop = +∞ / 2^617 ≫ others); the bottleneck attacks are primal BDD and
dual-hybrid, requiring BKZ block sizes β ≈ 374–445. Binary secrets cost only ~1–2 bits
vs ternary — both distributions clear 128 bits post-quantum on both sets.

### Eq4 rule-of-thumb cross-check — `log2(q) ≤ log2(B) + (d−75)/37.5`, B = 20, d = n

| Set | log₂Q | formula bound | verdict | formula margin | estimator (MATZOV) | estimator margin over 128 |
|---|---|---|---|---|---|---|
| N8192 | 174.00 | 220.78 | **satisfied** | +46.78 bits of modulus | 159.2–160.5 | +31–32 bits |
| N4096 | 99.00 | 111.55 | **satisfied** | +12.55 bits of modulus | 137.0–139.2 | +9–11 bits |

**Conclusion:** the formula's accept/reject verdict **matches the estimator's 128-bit
accept/reject at both parameter sets** (both accept; estimator confirms with margin).
The margins even correlate: +12.6 modulus bits ↔ ~+9–11 security bits (N4096) and
+46.8 ↔ ~+31–32 (N8192), i.e. the formula's implied 128-bit boundary sits within
roughly 10–15 modulus bits of the estimator's — the formula is mildly optimistic in
proportion but directionally sound at these points. Inverse check: Eq4 requires
d ≥ 3625 for log₂Q = 99.00 (deployed 4096) and d ≥ 6438 for log₂Q = 174.00 (deployed
8192). Caveat: the formula ignores the secret distribution; the estimator shows that
costs only ~1–2 bits here.

## 3. Part B — MSIS/Ajtai commitment security (ring degree d = 8192)

> **Correction (supersedes an earlier version of this table).** The β values first used
> for R4/R6 (2^75) and R7 (2^120) were input-parameter errors on the requirements side:
> 2^75 = B^L (B = 2^15, L = 5) is the *recomposition capacity* of the digit
> decomposition — the size of the values publicly reconstructed from the digits — not a
> bound on the committed witness. **The Ajtai commitments bind the decomposition DIGITS
> themselves** (`‖·‖∞ < B = 2^15`), inflated only by the LatticeFold extraction slack.
> The corrected scenarios below use β = B·2^5 = 2^20 and β = B·2^10 = 2^25. (The
> earlier alarm "R4/R6 BROKEN at β = 2^75" followed from that wrong input: at β ≥ q the
> trivial kernel vector `q·e_i` always exists. With the honest digit bounds, β ≪ q and
> the finding disappears.) Raw output for both the superseded and the corrected runs is
> in `estimator_output.txt` (Part B and Part B2).

| Track | q | m_mod | β | κ | SIS (n, m) | structure | estimator rop (MATZOV / BDGL16) | verdict |
|---|---|---|---|---|---|---|---|---|
| R1 | ~2^58 | 3 | 2^15 | 4 | (32768, 24576) | injective | +∞ / +∞ | **unconditionally binding** |
| R1 | ~2^58 | 3 | 2^20 | 4 | (32768, 24576) | injective | **+∞ / +∞** | **unconditionally binding** |
| R4/R6 | ~2^58 | 2 | 2^20 | 4 | (32768, 16384) | injective | **+∞ / +∞** | **unconditionally binding** |
| R4/R6 | ~2^58 | 2 | 2^25 | 4 | (32768, 16384) | injective | **+∞ / +∞** | **unconditionally binding** |
| R7 P-track | ~2^176 | 7 | 2^20 | 4 | (32768, 57344) | compressing | **+∞ / +∞** | **no admissible solutions exist w.h.p.** |
| R7 P-track | ~2^176 | 7 | 2^25 | 4 | (32768, 57344) | compressing | **+∞ / +∞** | **no admissible solutions exist w.h.p.** |

Reading:
- **R1 and R4/R6 (κ=4, m=3 and m=2):** κ·d = 32768 > m·d, so A is injective w.h.p.; the
  only kernel vectors are `q·Z^m`-multiples with norm ≥ q ≈ 2^58 ≫ β. No MSIS solution
  exists at all — binding is **unconditional** (norm margin log₂(q/β): 38 bits at
  β = 2^20, 33 bits at β = 2^25). Even setting injectivity aside, the counting bound
  would require ≈ 23 (β = 2^20) resp. ≈ 18.5 (β = 2^25) ring-element columns for any
  solution to exist — vs the 3 (R1) and 2 (R4/R6) actually deployed.
- **R7 P-track (κ=4, m=7):** genuinely compressing (kernel dimension ≥ 24576), but at
  the honest digit bounds the *counting bound* kills it: the expected number of
  admissible kernel vectors is `(2β+1)^m / q^n ≈ 2^-4,562,944` (β = 2^20) and
  `2^-4,276,224` (β = 2^25) — i.e. **no admissible solution exists with overwhelming
  probability**. Equivalently: the Gaussian-heuristic shortest kernel vector is
  ≈ 2^106.4, a full 86.4 / 81.4 bits above β = 2^20 / 2^25; solutions would only
  appear at m ≈ 67 (resp. 54) ring-element columns vs the 7 deployed. The estimator
  agrees: rop = +∞ (both cost models).
- **Why binding requires β < (q−1)/2 (design invariant):** the integer vector `q·e_i`
  is *always* a kernel vector of A mod q with `‖·‖∞ = q`, independent of κ and m. Any
  enforced bound β ≥ q therefore makes extraction non-unique (x and x + q·e_i both
  admissible) and MSIS vacuous; the estimator rejects such instances as "trivially
  easy". The current design satisfies the invariant with wide margin: β = 2^20 / 2^25
  vs (q−1)/2 ≈ 2^57 on the q-tracks (**37 / 32 bits of headroom**) and ≈ 2^175 on the
  P-track (**155 / 150 bits**). The invariant to preserve under future parameter
  changes: digit bound × extraction slack must stay below (q−1)/2.

### Does κ = 4 suffice?

**Yes — comfortably, at every track.** With the corrected digit bounds, κ = 4 already
makes R1 and R4/R6 *algebraically* binding (injective A: no kernel vectors at all) and
R7 *information-theoretically* binding (expected number of admissible kernel vectors
≈ 2^-4.5·10⁶). Doubling to κ = 8 would only make R7 algebraically binding too
(κ·d = 65536 > m·d = 57344) — pure headroom that buys nothing in practice, and it makes
commitments longer than the witness (rate > 1), an engineering cost with no security
need. Assumptions: (i) the standard MSIS→SIS mapping above (ring structure unexploited
by known attacks); (ii) A sampled honestly at random; (iii) β is the extraction bound
the proof system enforces on openings (digit bound 2^15 × folding slack ≤ 2^10 in the
scenarios analysed). The real design constraint is not κ but the invariant β < (q−1)/2
from the `q·e_i` argument above — currently met with 32–37 bits of headroom on the
q-tracks and ~150 bits on the P-track.

## 4. Bottom line (plain language)

- **Parameter set N8192 provides ~159–161 bits of post-quantum security for the BFV
  threshold keys** (min over the full attack suite, quantum cost model, unlimited
  samples; ~162–164 bits classical) — comfortably above the 128-bit target, for both
  the fhe.rs-style ternary and the demo binary secret distributions.
- **N4096 provides ~137–139 bits post-quantum** (~139–142 classical) — also above 128,
  but with only ~9–11 bits of headroom; fine as an engineering candidate, no margin for
  future attack improvements.
- **The Eq4 rule of thumb agrees with the raw estimator's 128-bit accept/reject at both
  sets** (both accepted by the formula, both confirmed ≥ 128 bits by the estimator); its
  margin is mildly optimistic (~1.5× in bits) but directionally reliable here.
- **The Ajtai commitments are binding unconditionally (not just ≥128 bits) at every
  track, already at κ = 4:** R1 and R4/R6 use injective matrices (more Z_q-equations
  than unknowns — no nonzero kernel vectors exist at all, norm margin 33–43 bits below
  q), and on the R7 P-track the expected number of admissible kernel vectors is
  ≈ 2^-4.5·10⁶ (the shortest one is ≈ 2^106 while the enforced bound is ≤ 2^25). There
  is **no broken track**: an earlier draft of this report flagged R4/R6 as broken at
  β = 2^75, which was an input error — 2^75 = B^L is the digit decomposition's
  recomposition capacity, not the committed-witness bound. The one invariant to watch
  in future parameter changes is β < (q−1)/2 (else the trivial kernel vector `q·e_i`
  exists); the design currently respects it with 32–37 bits of headroom on the q-tracks.
  **κ = 4 suffices; κ = 8 would add only redundant headroom.**
- The smudging noise's λ = 50 security is statistical (indistinguishability), not
  lattice-based — intentionally outside this analysis.

## 5. Files

- `analysis/estimate_security.py` — the estimation script, Parts A + B (documents both patches).
- `analysis/estimate_security_b2.py` — follow-up script, Part B2 (corrected digit norm bounds).
- `analysis/estimator_output.txt` — full raw stdout: Part A, Part B (superseded β inputs,
  kept for the record), and the appended Part B2 (corrected bounds).
- `analysis/venv/` — Python 3.13 venv: lattice-estimator @ 3e48ef4 + passagemath 10.8.7.
