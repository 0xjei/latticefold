#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Follow-up (Part B2): corrected norm bounds for the MSIS/Ajtai tracks.

Correction: the previously used beta values for R4/R6 (2^75) and R7 (2^120) were
input-parameter errors. 2^75 = B^L (B=2^15, L=5) is the RECOMPOSITION CAPACITY of the
digit decomposition, i.e. the size of the values that can be publicly reconstructed
from the committed digits -- not a bound on the committed witness. The committed
vectors are the decomposition DIGITS themselves, with ||.||_inf < B = 2^15, inflated
by the LatticeFold extraction slack. We therefore estimate:

  R1    (q~2^58,  d=8192, m=3 ring el., kappa=4): beta = 2^20           (symmetry)
  R4/R6 (q~2^58,  d=8192, m=2 ring el., kappa=4): beta = 2^20, 2^25     (slack 2^5, 2^10)
  R7    (q~2^176, d=8192, m=7 ring el., kappa=4): beta = 2^20, 2^25     (slack 2^5, 2^10)

Mapping (unchanged from Part B): MSIS_{q,kappa,m,d} -> SIS.Parameters(n=kappa*d, q=q,
length_bound=beta, m=m*d, norm=+Infinity). Runs in the same venv as Part B, which
includes the documented arbitrary-precision patch to estimator/reduction.py.
"""

import math
import sys
import time

from sage.all import oo, RR
from sage.all import log as sage_log

from estimator import SIS, RC


def log2rop(rop):
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


q58 = 288230376128643073
P176 = 95780971232337531050942682516136025943519008502317057
D = 8192
KAPPA = 4

cases = [
    ("R1    beta=2^20 (q~2^58,  m=3)", q58, 3, 2**20),
    ("R4/R6 beta=2^20 (q~2^58,  m=2)", q58, 2, 2**20),
    ("R4/R6 beta=2^25 (q~2^58,  m=2)", q58, 2, 2**25),
    ("R7    beta=2^20 (q~2^176, m=7)", P176, 7, 2**20),
    ("R7    beta=2^25 (q~2^176, m=7)", P176, 7, 2**25),
]

banner("PART B2: MSIS/Ajtai with CORRECTED digit norm bounds (beta = B*slack, B=2^15)")
print("mapping: SIS(n=kappa*d, q, beta, m=m_mod*d, norm=+inf), d=%d, kappa=%d" % (D, KAPPA))
print("cost models: MATZOV (PQ), BDGL16 (classical)", flush=True)

summary = []
for tag, q, m_mod, beta in cases:
    n_sis, m_sis = KAPPA * D, m_mod * D
    subbanner("B2/%s -> SIS(n=%d, q~2^%.1f, beta=2^%.1f, m=%d)"
              % (tag.strip(), n_sis, math.log2(q), math.log2(beta), m_sis))
    rec = {"tag": tag.strip()}

    # -- structural analysis -------------------------------------------------
    half_q_margin = math.log2((q - 1) / 2) - math.log2(beta)
    print("  beta vs (q-1)/2: 2^%.1f vs 2^%.1f -> margin %.1f bits (must be > 0 for binding to be meaningful)"
          % (math.log2(beta), math.log2((q - 1) / 2), half_q_margin))
    rec["half_q_margin"] = half_q_margin

    if n_sis > m_sis:
        print("  structure: kappa*d = %d > m*d = %d -> A injective w.h.p.;" % (n_sis, m_sis))
        print("  kernel lattice = q*Z^m, shortest kernel vector q*e_i with ||.||_inf = q ~ 2^%.1f."
              % math.log2(q))
        print("  beta = 2^%.1f < q -> NO admissible solution exists: unconditionally binding."
              % math.log2(beta))
        print("  norm margin: log2(q/beta) = %.1f bits" % (math.log2(q) - math.log2(beta)))
        rec["structure"] = "injective"
        rec["norm_margin"] = math.log2(q) - math.log2(beta)
    else:
        # expected number of admissible solutions for random A (counting bound)
        log_num = m_sis * math.log2(2 * beta + 1) - n_sis * math.log2(q)
        # Gaussian-heuristic shortest vector of the q-ary lattice (dim m_sis, vol q^n_sis)
        log_gh = 0.5 * math.log2(m_sis / (2 * math.pi * math.e)) + (n_sis / m_sis) * math.log2(q)
        print("  structure: compressing (kernel dim >= %d)" % (m_sis - n_sis))
        print("  expected #admissible solutions ~ 2^(%.0f)  [= (2*beta+1)^m / q^n]"
              % log_num)
        print("  Gaussian-heuristic shortest kernel vector ~ 2^%.1f vs beta = 2^%.1f -> gap %.1f bits"
              % (log_gh, math.log2(beta), log_gh - math.log2(beta)))
        m_needed = 2 * math.ceil(n_sis * math.log(q, 2 * beta + 1))
        print("  counting bound: solutions exist only for m >= ~%d columns (~%.1f ring elements); deployed %d"
              % (m_needed, m_needed / D, m_mod))
        rec["structure"] = "compressing"
        rec["log_num_solutions"] = log_num
        rec["log_gh"] = log_gh

    # -- estimator ------------------------------------------------------------
    params = SIS.Parameters(n=n_sis, q=q, length_bound=beta, m=m_sis, norm=oo, tag=tag)
    for model_name, model in (("MATZOV", RC.MATZOV), ("BDGL16", RC.BDGL16)):
        t0 = time.time()
        try:
            res = SIS.estimate(params, red_cost_model=model, quiet=True)
            lat = res["lattice"]
            bits = log2rop(lat["rop"])
            print("  estimator[%s]: rop = %s  (beta_BKZ=%s, d=%s, zeta=%s) [%.1fs]"
                  % (model_name,
                     "2^%.1f" % bits if bits is not None else "+Infinity",
                     lat.get("beta"), lat.get("d"), lat.get("zeta"), time.time() - t0),
                  flush=True)
            rec[model_name] = bits
        except Exception as e:
            print("  estimator[%s]: raised %s: %s" % (model_name, type(e).__name__, e), flush=True)
            rec[model_name] = "error: %s" % e
    summary.append(rec)

banner("PART B2 SUMMARY")
print("%-32s %-12s %-14s %-14s %s" % ("case", "structure", "MATZOV rop", "BDGL16 rop", "verdict"))
for rec in summary:
    f = lambda b: ("2^%.1f" % b) if isinstance(b, float) else ("+inf" if b is None else "n/a")
    if rec["structure"] == "injective":
        verdict = "unconditionally binding (norm margin 2^%.0f)" % rec["norm_margin"]
    elif rec.get("log_num_solutions", 0) < -128:
        verdict = "no admissible solutions exist w.h.p. (2^%.0f expected)" % rec["log_num_solutions"]
    else:
        verdict = "binding"
    print("%-32s %-12s %-14s %-14s %s"
          % (rec["tag"], rec["structure"], f(rec.get("MATZOV")), f(rec.get("BDGL16")), verdict))
print("\nDone (Part B2).")
