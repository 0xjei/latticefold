#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Concrete lattice-security estimation for the threshold-BFV + Ajtai-commitment design.

Tool: malb/lattice-estimator @ 3e48ef421ec256afddb3e7d2249a77eab6e9ba12 (main),
running on passagemath 10.8.7 wheels (pip-installable SageMath) inside analysis/venv.

Two documented, semantics-preserving patches to the installed estimator (numerics only):
  1. estimator/reduction.py: `N = floor(2 ** (0.2075 * ...))` computed in
     arbitrary precision (RR) instead of float64, at the three cost-model sites
     (MATZOV/GJ21, BDGL16, ADPS16 families). Identical value; avoids a float64
     OverflowError for sieve dimensions > ~4937, which our large dimensions hit.
     Regression check: Dilithium2_MSIS_WkUnf still estimates to 2^152.2 (upstream value).
  2. arora-gb Gröbner-basis cost (estimator/gb.py, gb_cost) is evaluated with the
     power-series precision truncated to 256 instead of the default 2n (=8192/16384).
     The default is computationally infeasible at n=4096/8192 (exact rational power
     series to order 2n inside a loop over t up to n). Truncation is CONSERVATIVE:
     whenever dreg < 256 the result is exact; otherwise the attack reports +Infinity,
     which we interpret with the lower bound rop >= binomial(n+256, 256)^2
     (~2^1677 at n=8192, ~2^1588 at n=4096) -- either way far above 128 bits and
     never the bottleneck attack.

Cost models: MATZOV [MATZOV22] (default of this estimator version; quantum sieving,
this is the post-quantum headline) and BDGL16 [BDGL16] (classical sieving, reference).
arora-gb and coded-BKW costs do not depend on the reduction cost model, so they are
only run in the MATZOV pass and reused for the classical table.

LWE/RLWE mapping: an RLWE sample over R_Q = Z_Q[X]/(X^n+1) is analysed as plain LWE
with dimension n and modulus Q (standard practice: no known attack exploits the ring
structure of a single RLWE sample; the estimator itself uses this for e.g. FHE schemes).
Sample complexity m = +Infinity (conservative: adversary may use arbitrarily many
ciphertexts, not just the public key).

MSIS/Ajtai mapping: binding of Com(x) = A*x mod q with A in R_q^{kappa x m_mod},
R_q = Z_q[X]/(X^d+1), openings of infinity-norm < beta, is MSIS_{q,kappa,m_mod,d}.
As a Z_q-linear map, A has kappa*d output rows and m_mod*d input columns, i.e. this
is plain SIS over Z_q with n = kappa*d equations and m = m_mod*d unknowns, bound beta
in the infinity norm. This is exactly the estimator's own convention for Dilithium's
MSIS schemes (e.g. Dilithium2: d=256, kappa=4 -> n=1024, m=(k+l+1)*256=2304).
Justification: negacyclic multiplication turns each ring element into d Z_q-columns;
known MSIS attacks do not exploit the module/ring structure for these shapes, so the
plain-SIS estimate is the standard conservative choice. The attacked q-ary kernel
lattice then has dimension m_mod*d and volume q^{kappa*d}.
"""

import math
import sys
import time

from sage.all import oo, RR
from sage.all import log as sage_log

import estimator
import estimator.gb as _gbmod
from estimator import LWE, SIS, ND, RC, schemes

# ---------------------------------------------------------------------------
# Patch 2: truncate arora-gb power-series precision (conservative, see header)
# ---------------------------------------------------------------------------
_GB_PREC = 256
_orig_gb_cost = _gbmod.gb_cost


def _gb_cost_truncated(n, D, omega=2, prec=_GB_PREC):
    return _orig_gb_cost(n, D, omega=omega, prec=prec)


_gbmod.gb_cost = _gb_cost_truncated

ESTIMATOR_COMMIT = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12 (malb/lattice-estimator main)"


def log2rop(rop):
    """log2 of a Cost rop entry; None if +Infinity / NaN. Uses sage arithmetic:
    float() silently overflows to inf for RR values above ~2^1024."""
    try:
        if rop == oo:
            return None
        b = float(sage_log(RR(rop), 2))
        if math.isnan(b) or math.isinf(b):
            return None
        return b
    except Exception:
        return None


def banner(s):
    print()
    print("=" * 78)
    print(s)
    print("=" * 78, flush=True)


def subbanner(s):
    print()
    print("--- %s ---" % s, flush=True)


def summarize_estimate(res):
    """Return (best_attack, best_bits, {attack: bits})."""
    bits = {}
    for name, cost in res.items():
        b = log2rop(cost["rop"])
        bits[name] = b  # None => +Infinity
    finite = {k: v for k, v in bits.items() if v is not None}
    if finite:
        best = min(finite, key=finite.get)
        return best, finite[best], bits
    return None, None, bits


def print_bits_table(bits):
    for k, v in bits.items():
        print("    %-16s rop = %s" % (k, "2^%.1f" % v if v is not None else "+Infinity"),
              flush=True)


# ---------------------------------------------------------------------------
# Sanity anchors (upstream reference values)
# ---------------------------------------------------------------------------
banner("0. ENVIRONMENT AND SANITY ANCHORS")
print("estimator source commit : %s" % ESTIMATOR_COMMIT)
print("estimator module        : %s" % estimator.__file__)
print("python                  : %s" % sys.version.split()[0])
try:
    import importlib.metadata as im
    print("passagemath-modules     : %s" % im.version("passagemath-modules"))
except Exception as e:
    print("passagemath version query failed: %s" % e)
print("arora-gb gb_cost prec   : %d (truncated, conservative)" % _GB_PREC)
print("cost models             : MATZOV (quantum, headline), BDGL16 (classical ref)")

t0 = time.time()
ky = LWE.estimate(schemes.Kyber512, quiet=True)
ky_best, ky_bits, _ = summarize_estimate(ky)
print("sanity: Kyber512 best = %s 2^%.1f (expect dual_hybrid ~2^139-140) [%.1fs]"
      % (ky_best, ky_bits, time.time() - t0), flush=True)
t0 = time.time()
dil = SIS.estimate(schemes.Dilithium2_MSIS_WkUnf, quiet=True)
print("sanity: Dilithium2_MSIS_WkUnf lattice rop = 2^%.1f (expect ~2^152.2) [%.1fs]"
      % (log2rop(dil["lattice"]["rop"]), time.time() - t0), flush=True)

# ===========================================================================
# PART A: RLWE/BFV threshold-key security
# ===========================================================================
banner("PART A: RLWE/BFV threshold-key security (RLWE analysed as LWE, m=+Infinity)")

Q8192 = 288230376128643073 * 288230376090894337 * 288230376019591169
Q4096 = 8590245889 * 8590934017 * 8591392769

SETS = {
    "N8192": {"n": 8192, "Q": Q8192},
    "N4096": {"n": 4096, "Q": Q4096},
}
for name, s in SETS.items():
    print("%s: n = %d" % (name, s["n"]))
    print("  Q = %d" % s["Q"])
    print("  log2(Q) = %.4f" % math.log2(s["Q"]), flush=True)

Xe = ND.DiscreteGaussian(3.2)  # CBD with bound B=20, as in fhe.rs-style BFV


def secret_dists(n):
    return {
        # fhe.rs-style ternary secret; estimator API on this commit is
        # SparseTernary(p, m, n): p plus-ones, m minus-ones, dimension n.
        "ternary": ND.SparseTernary(p=n // 2, m=n // 2, n=n),
        # current demo distribution: uniform binary {0,1}
        "binary": ND.Uniform(0, 1, n=n),
    }


lwe_results = {}  # (set, dist, model) -> (best_attack, best_bits, bits)

for setname, s in SETS.items():
    for distname, Xs in secret_dists(s["n"]).items():
        params = LWE.Parameters(n=s["n"], q=s["Q"], Xs=Xs, Xe=Xe,
                                tag="%s/%s" % (setname, distname))
        # ---- MATZOV (quantum), FULL default attack suite ----
        subbanner("A/%s/%s -- LWE.estimate, FULL default suite, MATZOV (quantum)" % (setname, distname))
        print(params, flush=True)
        t0 = time.time()
        res = LWE.estimate(params, red_cost_model=RC.MATZOV, quiet=False)
        print("[elapsed %.1fs]" % (time.time() - t0), flush=True)
        best, bits, allbits = summarize_estimate(res)
        print("summary (MATZOV):", flush=True)
        print_bits_table(allbits)
        print("  => minimum: %s at %s"
              % ("2^%.1f" % bits if bits is not None else "+Infinity", best), flush=True)
        lwe_results[(setname, distname, "MATZOV")] = (best, bits, allbits)

        # ---- BDGL16 (classical reference); arora-gb & bkw are model-independent ----
        subbanner("A/%s/%s -- LWE.estimate, lattice attacks only, BDGL16 (classical)"
                  % (setname, distname))
        t0 = time.time()
        res_c = LWE.estimate(params, red_cost_model=RC.BDGL16, quiet=True,
                             deny_list=("arora-gb", "bkw"))
        print("[elapsed %.1fs]" % (time.time() - t0), flush=True)
        best_c, bits_c, allbits_c = summarize_estimate(res_c)
        # carry over model-independent attacks from the MATZOV run
        for k in ("arora-gb", "bkw"):
            if k in allbits:
                allbits_c[k] = allbits[k]
        print_bits_table(allbits_c)
        print("  => minimum over lattice attacks: %s at %s"
              % ("2^%.1f" % bits_c if bits_c is not None else "+Infinity", best_c),
              flush=True)
        lwe_results[(setname, distname, "BDGL16")] = (best_c, bits_c, allbits_c)

# ---------------------------------------------------------------------------
# Eq4 rule-of-thumb cross-check
# ---------------------------------------------------------------------------
banner("A': Eq4 rule-of-thumb cross-check: log2(q) <= log2(B) + (d-75)/37.5, B=20, d=n")
B = 20
for setname, s in SETS.items():
    d = s["n"]
    lhs = math.log2(s["Q"])
    rhs = math.log2(B) + (d - 75) / 37.5
    ok = lhs <= rhs
    print("%s: log2(Q) = %.2f,  log2(B)+(d-75)/37.5 = %.2f  ->  %s by %.2f bits of modulus"
          % (setname, lhs, rhs, "SATISFIED" if ok else "VIOLATED", rhs - lhs), flush=True)
    for distname in ("ternary", "binary"):
        _, bits_pq, _ = lwe_results[(setname, distname, "MATZOV")]
        est_ok = bits_pq is not None and bits_pq >= 128
        print("    %-7s estimator (MATZOV): %s -> 128-bit PQ %s"
              % (distname,
                 "2^%.1f" % bits_pq if bits_pq is not None else "+Infinity",
                 "PASS" if est_ok else "FAIL"), flush=True)
# what degree does the formula require for exactly these moduli?
for setname, s in SETS.items():
    d_req = 37.5 * (math.log2(s["Q"]) - math.log2(B)) + 75
    print("%s: Eq4 requires d >= %.0f for log2(Q)=%.2f, B=20 (deployed d=%d)"
          % (setname, d_req, math.log2(s["Q"]), s["n"]), flush=True)

# ===========================================================================
# PART B: MSIS/Ajtai commitment security
# ===========================================================================
banner("PART B: MSIS/Ajtai commitment security (mapping: SIS n=kappa*d, m=m_mod*d, norm=inf)")

q58 = 288230376128643073
P176 = 95780971232337531050942682516136025943519008502317057
D = 8192  # ring degree for all tracks

tracks = [
    # (tag, q, m_mod, beta)
    ("R1     (N8192, q~2^58,  m=3, beta=2^15 )", q58, 3, 2**15),
    ("R4/R6  (N8192, q~2^58,  m=2, beta=2^75 )", q58, 2, 2**75),
    ("R7 P-tr(N8192, q~2^176, m=7, beta=2^120)", P176, 7, 2**120),
]

sis_results = {}  # (track, kappa) -> dict with everything we learned
for tag, q, m_mod, beta in tracks:
    for kappa in (4, 8):
        n_sis = kappa * D
        m_sis = m_mod * D
        subbanner("B/%s kappa=%d -> SIS(n=%d, q~2^%.1f, beta=2^%.1f, m=%d, norm=inf)"
                  % (tag.strip(), kappa, n_sis, math.log2(q), math.log2(beta), m_sis))
        info = {"n_sis": n_sis, "m_sis": m_sis, "q": q, "beta": beta, "kappa": kappa}

        # --- analytic facts that hold regardless of the estimator ---
        if n_sis > m_sis:
            print("  structure: kappa*d = %d > m_mod*d = %d" % (n_sis, m_sis))
            print("  A in R_q^(%dx%d) is injective w.h.p. (more Z_q-equations than unknowns)."
                  % (kappa, m_mod))
            print("  Kernel lattice Lambda = q*Z^m: shortest nonzero kernel vector is q*e_i")
            print("  with ||.||_inf = q ~ 2^%.1f. Any beta < q admits NO solution at all."
                  % math.log2(q))
            info["structure"] = "injective"
        else:
            print("  structure: kappa*d = %d <= m_mod*d = %d (compressing, real kernel, dim >= %d)"
                  % (n_sis, m_sis, m_sis - n_sis))
            info["structure"] = "compressing"
        # counting bound: m needed for a solution to exist at all (estimator's own default)
        m_needed = 2 * math.ceil(n_sis * math.log(q, 2 * beta + 1))
        print("  counting bound: solutions exist only for m >= ~%d Z_q-columns (~%.1f ring elements);"
              " deployed: %d columns (%d ring elements)"
              % (m_needed, m_needed / D, m_sis, m_mod))
        info["m_needed_cols"] = m_needed

        if beta >= (q - 1) / 2:
            print("  beta = 2^%.1f >= (q-1)/2 ~ 2^%.1f: TRIVIAL break -- x = q*e_i is a kernel"
                  % (math.log2(beta), math.log2((q - 1) / 2)))
            print("  vector with ||x||_inf = q <= beta. MSIS unsound at this bound,"
                  " independent of kappa.")
            info["trivial"] = True

        params = SIS.Parameters(n=n_sis, q=q, length_bound=beta, m=m_sis, norm=oo,
                                tag="%s k=%d" % (tag.strip(), kappa))
        for model_name, model in (("MATZOV", RC.MATZOV), ("BDGL16", RC.BDGL16)):
            t0 = time.time()
            try:
                res = SIS.estimate(params, red_cost_model=model, quiet=True)
                lat = res["lattice"]
                bits = log2rop(lat["rop"])
                print("  estimator[%s]: rop = %s  (beta_BKZ=%s, d=%s, zeta=%s, prob=%s) [%.1fs]"
                      % (model_name,
                         "2^%.1f" % bits if bits is not None else "+Infinity",
                         lat.get("beta"), lat.get("d"), lat.get("zeta"), lat.get("prob"),
                         time.time() - t0), flush=True)
                info[model_name] = bits
                info[model_name + "_raw"] = lat
            except Exception as e:
                print("  estimator[%s]: raised %s: %s" % (model_name, type(e).__name__, e),
                      flush=True)
                info[model_name] = "error: %s" % e
        sis_results[(tag, kappa)] = info

# ===========================================================================
# SUMMARY
# ===========================================================================
banner("SUMMARY TABLES")

print("\nBFV/RLWE key security (bits = min over full attack suite, m=+Infinity):")
print("%-8s %-8s %-22s %-22s %-10s" % ("set", "secret", "MATZOV (PQ) best", "BDGL16 (class.)", ">=128 PQ?"))
for setname in SETS:
    for distname in ("ternary", "binary"):
        b_m, bits_m, _ = lwe_results[(setname, distname, "MATZOV")]
        b_c, bits_c, _ = lwe_results[(setname, distname, "BDGL16")]
        pq = "YES" if (bits_m is not None and bits_m >= 128) else "NO"
        print("%-8s %-8s %-22s %-22s %-10s"
              % (setname, distname,
                 ("%.1f (%s)" % (bits_m, b_m)) if bits_m is not None else "inf",
                 ("%.1f (%s)" % (bits_c, b_c)) if bits_c is not None else "inf",
                 pq))

print("\nMSIS/Ajtai commitment security:")
print("%-38s %-6s %-12s %-14s %-14s %s"
      % ("track", "kappa", "structure", "MATZOV rop", "BDGL16 rop", "verdict"))
for (tag, kappa), info in sis_results.items():
    m_b = info.get("MATZOV"); c_b = info.get("BDGL16")
    f = lambda b: ("2^%.1f" % b) if isinstance(b, float) else ("+inf" if b is None else "n/a")
    if info.get("trivial"):
        verdict = "BROKEN at beta>=q (trivial kernel vector)"
    elif info["structure"] == "injective" and not info.get("trivial"):
        verdict = "unconditionally binding (no kernel vectors)"
    else:
        verdict = "binding, huge margin" if (isinstance(m_b, float) and m_b >= 128) else "CHECK"
    print("%-38s %-6d %-12s %-14s %-14s %s" % (tag.strip(), kappa, info["structure"],
                                               f(m_b), f(c_b), verdict))

print("\nDone.")
