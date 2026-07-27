# Benchmarks — LatticeFold VDKG

**Machine:** Apple silicon laptop, 14 threads, `release` build, features
`fhe-bridge,parallel`, Rust 1.91.1 (fhe-bridge) / nightly-2025-03-06 (lib).
**Legend:** ✅ measured · 📐 estimated/extrapolated · ⬜ not yet run.

---

## 1. Headline runs

### ✅ N=100 committee, full P1→P4 flow (2026-07-26)

**N=100 / H=51 / T=27, degree 4096 (3 channels at the time), session 100** —
green end-to-end, exact 4096-coefficient plaintext recovered, every phase proven.

| Metric | Value |
| --- | --- |
| **Wall-clock** | **18,735.8 s (5h 12m)** |
| CPU (user) | 228,038 s (63.3 CPU-h) |
| Avg core utilization | 12.2 / 14 |
| **Peak RSS** | **17.0 GiB** |
| R3 instances proven | 3,060 (51 × 5 digits × 2 primes × 2 kinds × 3 ch) |
| R4 openings | 306 |
| R6 shares | 81 |

Phase wall-times (overlapping, concurrent tracks):

| Phase | Wall | Note |
| --- | --- | --- |
| Dealer phase (R2 + R3 instances) | ~11,657 s | R2's O(N) witness dominates (62%) |
| R3 fold chains (255 inst × 2 primes) | 4,763–6,606 s/track | ~22–26 s/fold |
| R4 fold chains (50 folds) | 90–622 s/track | |
| R6 + R7/P | minutes | R7 decides directly |

> Scope note: this run transported **one** recipient's shares (demo scoping);
> the full dealer→recipient matrix is ~99× the R3 axis (see §4).

### ✅ N=5/H=5/T=3 progression (degree 4096)

| Configuration | Wall |
| --- | --- |
| Unproven R3 data plane (pre-milestone) | 356 s |
| Proven R3, sequential fold chains | 1,676 s |
| **Proven R3, binary fold trees + track concurrency** | **773 s (2.2× faster)** |

---

## 2. Per-instance / per-circuit constants

| Component | ✅ Measured |
| --- | --- |
| Fold cost per instance (R3, d=4096, in-flow) | ~26 s |
| R3 benchmark `dkg_fhe_r3` (d=8192) | 50 instances → 1 accumulator/prime in 756 s ≈ **15 s/instance** |
| Noir C3 baseline (same relation) | 3.48M constraints, 10.76 s isolated prove × 432 proofs/round **+ recursive aggregation** |
| Per-track decider `ajtai_opening_sz` (ProdParams channel, N=16384) | **6.05M opcodes / 10.2M gates**, witness solved (exactly 2× the N=8192 figure — linear scaling) |
| Decryption wrapper `c7` (4 channels, ProdParams, N=16384) | **5.06M opcodes / 12.5M gates, `bb prove`+`verify` pass** — once per decryption |
| `c7` predecessor (3 channels, N=1024) | 303k opcodes / 748k gates, 2.7 s prove |
| Full flow N=8192, H=5/T=3 (pre-R3-wiring) | ~316 s |
| Full flow N=8192, H=3/T=2, limb-heavy R7 | ~22 min |

---

## 3. Security parameters (validated)

| Set | Role | RLWE security (estimator) | Notes |
| --- | --- | --- | --- |
| d=8192, 3×58-bit, Q=174 | legacy bench | **159–161 bits PQ** (MATZOV, full suite) | ✅ estimator-certified (estimators/SECURITY.md) |
| d=4096, Q=99 | demo | 137–139 bits PQ | thin margin; also fails production Eq1 → **benchmark-only** |
| **ProdParams**: d=16384, 4×61-bit, Q=244, t=2^20, P=251-bit | **production** | 📐 expected ≥160 bits (same methodology; larger d, modestly larger Q) | Eq1 margin ~72 bits (H=51) / ~75 bits (n=20); lbfv-mul margin ~36.5 bits; Eq4 cap 439 |

---

## 4. Scaling & estimates (extrapolations, clearly marked)

Per-instance cost scales ~linearly with ring degree: 📐 ~90 s at d=16384.

### N=100 / H=51 / T=27, ProdParams, **full recipient matrix**

| Setting | R3 instances | Wall time |
| --- | --- | --- |
| 📐 Single laptop (14 cores) | 396,000 | ~29 days |
| 📐 **Distributed (100 laptops)** — each dealer proves own R3 (secret witness, non-outsourceable): 198 CPU-h/dealer ÷ 14 cores | 396,000 | **~16–18 h** |
| 📐 + digit base L=3 (Q1) + drop R4 (Q3) | 237,600 | **~11–13 h** |

### N=20 / H=14 / T=9, ProdParams, full matrix (the lbfv/Noir-blocker config)

| Setting | Wall time |
| --- | --- |
| 📐 Single laptop | ~2.3 days |
| 📐 **Distributed (20 laptops)**: 1,520 instances/dealer = 38 CPU-h ÷ 14 | **~3 h** |
| Noir baseline, same config | **does not compile** |

### N=5 / H=5 / T=3, ProdParams

📐 ~450 folds ≈ 11 CPU-h ÷ ~12 cores ≈ **~1 h wall** (45–90 min), ~2 GB RAM. ⬜ not yet run.

---

## 5. Cost structure (where the time goes)

| Phase | Scaling | Share at N=100 | Notes |
| --- | --- | --- | --- |
| R3 (share-encryption proofs) | **N×(N−1) quadratic** × L digits × 2 primes | ~85% | protocol-inherent axis; L is the tunable multiplier (openquestions.md Q1/Q4) |
| R2 (sharing proofs) | linear in parties, **O(N) per proof** | ~10% | the committee-growing term; R2 amendment removes it (Q2) |
| R4 (openings) | linear | ~3% | droppable per plan note (Q3) |
| R1/R5/R6/R7 | linear / constant | ~2% | C7 ≈ 1 min per decryption |

---

## 6. Benchmark runs to schedule

| # | Run | Config | Purpose | Status |
| --- | --- | --- | --- | --- |
| 1 | ProdParams e2e | `--params prod --n 5 --h 5 --t 3` | first 4-channel production-param execution | ⬜ est. ~1 h |
| 2 | Full-matrix fan-out e2e | N=20/H=14/T=9, prod | the decision-grade number at the Noir-blocker config | ⬜ needs R3/R4 fan-out work |
| 3 | N=100 full matrix | distributed or single-machine | scaling claim | ⬜ after #2 |
| 4 | `DKG_VERIFY_FOLDS=1` pass | any of the above | prove+verify cost (≈2× folds) | ⬜ |

Command (example for #1):
```bash
DKG_PHASE_TIMING=1 cargo +1.91.1 run --release --example dkg_fhe_full_flow \
  --features fhe-bridge,parallel -- --params prod --n 5 --h 5 --t 3 --recipient 3
```
