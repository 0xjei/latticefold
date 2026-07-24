#!/usr/bin/env bash
#
# Simulate an end-to-end run of the scattered VDKG slices as ONE pipeline,
# ordered by the design's protocol phases (P1 DKG -> P2 aggregation ->
# P3 encryption -> P4 decryption), plus setup and cross-cutting artifacts.
#
# Each slice is a standalone `cargo` example; this runner just sequences them,
# prints phase headers, and reports pass/fail + timing with a final summary.
#
# Usage (from anywhere in the repo):
#   bash crates/latticefold/examples/interfold/run_dkg_pipeline.sh
#
set -u

# Locate the workspace root (this script lives in
# crates/latticefold/examples/interfold).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
cd "$ROOT"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[32m'; RED=$'\033[31m'; CYN=$'\033[36m'; RST=$'\033[0m'

# Ordered pipeline: "phase|example|description"
PIPELINE=(
  "SETUP|dkg_params|Step 1 — verify secure_8192 moduli vs LatticeFold congruences"
  "SETUP|dkg_ring_ntt|Step 2 — negacyclic NTT kernel for a custom RNS-prime ring"
  "SETUP|dkg_ring_model|Step 2 — full custom-ring model constants, derived+verified @ N=8192"
  "SETUP|dkg_r1_native|Step 2 DONE — R1 folded on the REAL 51-bit q_l ring (no stand-in)"
  "P1 DKG|dkg_r0|R0 — individual key commitments pinned (no witness, no proof)"
  "P1 DKG|dkg_r1|R1 — threshold-key/smudging contribution  pk0=-a*sk+e (per party)"
  "P1 DKG|dkg_cheater_isolation|Cheating party identified at its own fold step + discarded"
  "P1 DKG|dkg_wide_smudging|§9.2 — wide smudging noise via bounded limbs (norm-provable)"
  "P1 DKG|dkg_r2|R2 — Shamir sharing, batched Reed-Solomon H*Y=0 + digit decomp"
  "P1 DKG|dkg_r3_ruser|R3 — share encryption ct0=pk0*u+e0+Δ*m (high-arity folding)"
  "P1 DKG|dkg_r4|R4 — share receipt: free homomorphic aggregation + folded openings"
  "P2 AGG|dkg_r5|R5 — threshold public-key aggregation (public + thin decided proof)"
  "P3 ENC|dkg_ruser_consistency|Ruser — cross-channel Com(m) consistency + cheat detection"
  "P4 DEC|dkg_r6|R6 — decryption-share d_i = ct0 + ct1*sk_share + e_sm_share"
  "P4 DEC|dkg_r7|R7 — interpolation + CRT quotient-witness shape (single track)"
  "P4 DEC|dkg_r7_circuit|R7 — IN-CIRCUIT L-channel CRT, proven + negative check"
  "P4 DEC|dkg_r7_decode|R7 — DECODE in-CCS: t*u = m*Q + v with rounding witness"
  "P4 DEC|dkg_r7_crt|R7 — production-chain CRT + derived no-wraparound margin"
  "E2E|dkg_chain|Toy arithmetic chain R1→R2→R4→R6→R7; commitment links are example assertions"
  "WRAP|dkg_double_commitment|§6.2 — rank-1 double commitments for compact publication"
  "WRAP|dkg_bench_folding|Folding vs independent-proof baseline (honest tradeoff)"
  "WRAP|dkg_decider_statement|Compact fixed-size decider statement per track (Step 7 in-repo)"
)

echo "${BOLD}${CYN}==> Building all examples (release)…${RST}"
if ! cargo build --release --examples >/dev/null 2>&1; then
  echo "${RED}Build failed. Run 'cargo build --release --examples' to see errors.${RST}"
  exit 1
fi
echo "${GRN}Build OK.${RST}"

pass=0; fail=0; last_phase=""
declare -a results
start_all=$SECONDS

for entry in "${PIPELINE[@]}"; do
  IFS='|' read -r phase ex desc <<< "$entry"
  if [[ "$phase" != "$last_phase" ]]; then
    echo
    echo "${BOLD}${CYN}────────── ${phase} ──────────${RST}"
    last_phase="$phase"
  fi
  echo
  echo "${BOLD}▶ ${ex}${RST}  ${DIM}${desc}${RST}"
  t0=$SECONDS
  if cargo run --release --example "$ex" 2>/dev/null; then
    dt=$((SECONDS - t0))
    echo "${GRN}✓ ${ex} (${dt}s)${RST}"
    results+=("${GRN}✓${RST} ${ex}")
    pass=$((pass+1))
  else
    dt=$((SECONDS - t0))
    echo "${RED}✗ ${ex} FAILED (${dt}s)${RST}"
    results+=("${RED}✗${RST} ${ex}")
    fail=$((fail+1))
  fi
done

total=$((SECONDS - start_all))
echo
echo "${BOLD}${CYN}══════════ PIPELINE SUMMARY ══════════${RST}"
for r in "${results[@]}"; do echo "  $r"; done
echo
echo "  ${BOLD}${pass} passed, ${fail} failed${RST}  in ${total}s"
if [[ $fail -eq 0 ]]; then
  echo "  ${GRN}${BOLD}Full VDKG slice pipeline ran green.${RST}"
else
  echo "  ${RED}Some slices failed — see output above.${RST}"
fi
exit $fail
