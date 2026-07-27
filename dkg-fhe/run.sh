#!/usr/bin/env bash
#
# Driver for the native FHE-bridge DKG committee demonstrations (DemoParams
# d=4096 / ProdParams d=16384, four RNS channels).
#
# Runs the configurable threshold-DKG committee path (channel-native Shamir
# sharing -> per-channel GRS-syndrome R2 proofs -> proven R3 digit transport
# -> metadata-bound, session-bound R4 openings folded per channel with NIFS
# fold trees).
#
# Usage:
#   ./run.sh [--example committee|multichannel] \
#            [--n N] [--h H] [--t T] [--recipient ID] [--session ID] \
#            [--threads K] [--seq] [--timing] [--verify]
#
# Examples:
#   ./run.sh                                   # defaults: committee, N=H=5, T=3
#   ./run.sh --n 100 --h 51 --t 27             # full committee
#   ./run.sh --example full-flow -- --params prod --n 5 --h 5 --t 3  # prod e2e
#   ./run.sh --timing                          # print per-phase timings
#
# Requires the fhe.rs MSRV toolchain (see README.md):
#   rustup toolchain install 1.91.1
set -euo pipefail

# Resolve the workspace root (this script lives in <root>/dkg-fhe/).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TOOLCHAIN="${DKG_TOOLCHAIN:-1.91.1}"
EXAMPLE="committee"
THREADS=""
FEATURES="fhe-bridge,parallel"
TIMING=""
VERIFY=""
FORWARD=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --example) EXAMPLE="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --seq)     FEATURES="fhe-bridge"; shift ;;   # disable rayon/parallel feature
    --timing)  TIMING="1"; shift ;;
    --verify)  VERIFY="1"; shift ;;              # re-verify every fold (~2x slower)
    --n|--h|--t|--recipient|--session)
               FORWARD+=("$1" "$2"); shift 2 ;;
    --help|-h) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$EXAMPLE" in
  committee)    BIN="dkg_fhe_committee_r4" ;;
  multichannel) BIN="dkg_fhe_multichannel_r4" ;;
  full-flow)    BIN="dkg_fhe_full_flow" ;;
  r3)           BIN="dkg_fhe_r3" ;;
  *) echo "unknown --example '$EXAMPLE' (want committee|multichannel|full-flow|r3)" >&2; exit 2 ;;
esac

env=()
[[ -n "$THREADS" ]] && env+=("RAYON_NUM_THREADS=$THREADS")
[[ -n "$TIMING"  ]] && env+=("DKG_PHASE_TIMING=1")
[[ -n "$VERIFY"  ]] && env+=("DKG_VERIFY_FOLDS=1")

set -x
env "${env[@]}" cargo "+$TOOLCHAIN" run --release \
  --manifest-path "$ROOT/Cargo.toml" \
  --example "$BIN" --features "$FEATURES" -- "${FORWARD[@]}"
