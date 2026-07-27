# Native FHE-bridge DKG committee runner (DemoParams / ProdParams)

Self-contained entry point for the native (non-toy) threshold-DKG committee
demonstrations built on the `latticefold` primitives plus the pinned
`fhe.rs` BFV transport. Everything here drives code in
`crates/latticefold/src/fhe_bridge.rs`; this folder is the "how to run it".

## What it demonstrates

A configurable committee (`N` members, `H` honest dealers, threshold `T`) runs:

1. **Channel-native Shamir sharing** — each dealer shares its secret
   polynomial natively per RNS channel (`generate_channel_sharing`), so the
   per-channel sharings are CRT-consistent by construction. The demo set uses
   four 34-bit channels (d=4096, `DemoParams`); production uses four 61-bit
   channels (d=16384, `ProdParams`).
3. **R2 sharing proofs** — one linearized GRS-syndrome relation per dealer
   proves the `N` channel shares form a degree-`T-1` sharing
   (`(N-T)` parity rows + 1 Lagrange-at-zero consistency row).
4. **Proven R3 transport** — the recipient's share moves as its R2-committed
   digits, each encrypted with fhe.rs extended encryption and proven natively
   per transport prime, folded per prime.
5. **Metadata- and session-bound R4 folding** — each received opening is bound
   to `(sender, recipient, channel)` and, via transcript absorption, to
   `(session_id, N, H, T, channel)`; the `H` openings are folded per channel
   with `NIFSProver`/`NIFSVerifier`.
6. **CRT + aggregate reconstruction checks** (multichannel).

## Prerequisites

- **Rust `1.91.1`** — the `fhe.rs` dependency's MSRV. The workspace's default
  `rust-toolchain` pins a nightly for the rest of the crate, so the FHE bridge
  must be run with an explicit `+1.91.1` (the scripts here do this for you):

  ```bash
  rustup toolchain install 1.91.1
  ```

- The `fhe-bridge` cargo feature (opt-in; pulls the `fhe`/`fhe-rand`/`fhe-traits`
  git dependencies). Add `parallel` to enable rayon in the sumcheck/fold paths.

## Quick start

```bash
./run.sh                                     # committee, defaults N=H=5, T=3
./run.sh --example multichannel              # q0/q1/q2, defaults
./run.sh --n 100 --h 51 --t 27 --recipient 3 # full committee
./run.sh --timing                            # per-phase timing breakdown
```

Or call cargo directly:

```bash
cargo +1.91.1 run --release \
  --example dkg_fhe_committee_r4 --features fhe-bridge,parallel \
  -- --n 100 --h 51 --t 27 --recipient 3
```

## CLI options (forwarded to the examples)

| Flag | Meaning | Default |
| --- | --- | --- |
| `--n <N>` | committee size / recipient points | 5 |
| `--h <H>` | honest dealers folded into R4 | 5 |
| `--t <T>` | reconstruction threshold (degree `T-1`) | 3 |
| `--recipient <ID>` | recipient point in `1..=N` | 3 |
| `--session <ID>` | session id bound into every proof | 0 |
| `--help` | print usage | — |

Constraints (validated before any work): `0 < T <= H <= N` and
`1 <= recipient <= N`. An invalid config exits with a clear error.

### `run.sh`-only flags

| Flag | Meaning |
| --- | --- |
| `--example committee\|multichannel` | which demo (default `committee`) |
| `--threads <K>` | cap rayon at `K` cores (`RAYON_NUM_THREADS`) |
| `--seq` | build without the `parallel` feature |
| `--timing` | set `DKG_PHASE_TIMING=1` for per-phase timings |
| `--verify` | set `DKG_VERIFY_FOLDS=1` to re-verify every fold (~2x slower) |

## Performance characteristics

Profiled 2026-07-24 (Apple silicon, 14 cores). For a committee run the wall
clock splits as (example: `--n 24 --h 16 --t 8`):

| Phase | Cost | Parallel |
| --- | --- | --- |
| Z_Q share generation | ~0.3s | serial (cheap) |
| Dealer phase (`H` R2 proofs + BFV + R4 build) | ~1.1s | **yes** — `par_iter` across cores (needs `parallel`) |
| **R4 fold chain (`H-1` folds)** | **~7.5s/fold** | **no** — serial accumulator |

The fold chain dominates (~99%). Each fold splits roughly in half between the
NIFS **prove** (decomposition + folding over the degree-4096 ring) and an
optional **verify** self-check. Notes:

- **The per-fold verify is deferred by default** (folding is the prover's job,
  verification the verifier's), halving the fold chain: ~7.5s/fold prove-only.
  Set `DKG_VERIFY_FOLDS=1` to replay every fold through the NIFS verifier and
  assert each folded accumulator matches (~15s/fold).
- **Multichannel is ~3x faster than 3 sequential channels**: the `q0/q1/q2`
  fold chains run concurrently (`std::thread::scope`). Measured `real 120s` vs
  `user 351s` at `--n 12 --h 8 --t 4` (with per-fold verify on).
- Multithreading the dealer phase gives little end-to-end gain because that
  phase is only ~1-2s; the serial fold chain is the floor.
- `RAYON_NUM_THREADS` caps the pool (e.g. `--threads 13` to leave a core free).

## Other FHE-bridge examples

| Example | What it runs |
| --- | --- |
| `dkg_fhe_share` | single BFV share round-trip |
| `dkg_fhe_r4` | one native q0 R4 commitment opening |
| `dkg_fhe_r2_r4` | single Shamir share → BFV → metadata-bound R4 |
| `dkg_fhe_committee_r4` | full committee, single q0 channel (configurable) |
| `dkg_fhe_multichannel_r4` | full committee across q0/q1/q2 + CRT (configurable) |
| `dkg_fhe_full_flow` | **full P1→P4 protocol**: R1 key contributions → R2/R3/R4 sharing+transport+folded openings → R5 aggregation → Ruser encryption → folded R6 decryption shares → P-track R7 CRT+decode, recovering the user plaintext. `--params n4096` (default) or `--params n8192` (the Noir `secure-8192`-security set: `t=2^20`, 3×58-bit channels, 176-bit P) |
| `dkg_fhe_r3` | **R3 share-encryption proofs + folding benchmark**: digit-form transport with real fhe.rs extended encryption (full `(u,e1,e2)` witness), native per-prime proofs, real decryption, one accumulator per prime. `--dealers 5` at degree 8192 ≈ 15s/instance vs Noir C3 10.76s + recursive aggregation |

Run any of them with `cargo +1.91.1 run --release --example <name> --features fhe-bridge`,
or `./run.sh --example full-flow` (add `--n/--h/--t/--recipient` as usual; the
recipient must be one of the T reconstructing parties).

The custom ring models (N=4096 and N=8192) come from the local `stark-rings`
fork at `../stark-rings` (`interfold` branch, wired via a `[patch]` path
dependency in the workspace `Cargo.toml`; also pushed to `0xjei/stark-rings`).
