# LatticeFold VDKG Exploration

## TL;DR

This repository explores a native-ring implementation of the Interfold-style
verifiable threshold-BFV pipeline:

1. Parties generate threshold-key and smudging-noise contributions.
2. Contributions are Shamir-shared and encrypted between parties.
3. The public key is aggregated.
4. Users encrypt under the threshold key.
5. Parties produce decryption shares.
6. The shares are interpolated, reconstructed with CRT, and decoded.

The current repository contains executable LatticeFold relation examples and a
toy cross-relation chain. It is not yet a complete DKG implementation, a
production BFV integration, or a 128-bit post-quantum parameter set.

The intended architecture now follows the verifiability model described by The
Interfold: every phase is connected by commitments, while C5 and C7 are the
important aggregation proof boundaries.

## References

- Design: `plan.md`
- Operational Interfold model: `guide.md`
- Coordination trilemma article:
  https://blog.theinterfold.com/verifiability-in-the-coordination-trilemma/
- `fhe.rs` development branch:
  https://github.com/gnosisguild/fhe.rs/tree/dev
- Integration revision: `cb83e5e1780ea666f611e3463ab1ad1a68864675`
- Urban and Rambaud threshold BFV:
  https://eprint.iacr.org/2024/1285

The referenced `fhe.rs` development branch currently describes itself as
experimental and unaudited. Its TRBFV module provides Shamir sharing, smudging
noise, encrypted share transport examples, decryption-share computation, and
threshold decryption, but explicitly does not provide complete DKG,
authenticated broadcast, FLSS, or GURS orchestration.

## Current Repository

The LatticeFold examples currently demonstrate:

- R1: native-ring key contribution equations and short witnesses.
- R2: batched Reed-Solomon sharing and digit decomposition.
- R3/Ruser: affine BFV encryption relation shapes.
- R4: commitment-opening folds and digit-vector aggregation.
- R5: public-key aggregation and a thin opening demonstration.
- R6: affine decryption-share computation.
- R7: interpolation, CRT quotient relations, and toy nearest-rounding decode.
- Cheater isolation at an individual folding step.
- A toy R1 -> R2 -> R4 -> R6 -> R7 arithmetic chain.
- Native N=4096 q0/q1/q2 LatticeFold-compatible ring models with CRT/iCRT,
  challenge sets, and Poseidon wiring.

The examples use a mix of Goldilocks stand-ins and the native N=4096 q0/q1/q2
models. The chain still uses stand-ins for the full DKG flow, but the first real
`fhe.rs` BFV transport -> native q0 R4 path is now implemented in `fhe_bridge`.

## Execution

Install the pinned toolchain:

```bash
rustup install nightly-2025-08-19
rustup install 1.91.1
```

Build the workspace and examples:

```bash
cargo build --release --examples
```

Run library tests:

```bash
cargo test -p latticefold --lib
```

Run representative relation examples:

```bash
cargo run --release --example dkg_r1
cargo run --release --example dkg_r2
cargo run --release --example dkg_r3_ruser
cargo run --release --example dkg_r4
cargo run --release --example dkg_chain
cargo run --release --example dkg_r7_decode
cargo run --release --example dkg_n4096_params
```

Run the opt-in real BFV share transport path with the Rust version required by
the pinned `fhe.rs` development revision:

```bash
cargo +1.91.1 check -p latticefold --features fhe-bridge
cargo +1.91.1 run --release --example dkg_fhe_share --features fhe-bridge
cargo +1.91.1 run --release --example dkg_fhe_r4 --features fhe-bridge
cargo +1.91.1 run --release --example dkg_fhe_r2_r4 --features fhe-bridge
cargo +1.91.1 run --release --example dkg_fhe_committee_r4 --features fhe-bridge
cargo +1.91.1 run --release --example dkg_fhe_multichannel_r4 --features fhe-bridge
cargo +1.91.1 run --release --example dkg_p_reconstruction
```

Run the complete example pipeline:

```bash
bash crates/latticefold/examples/run_dkg_pipeline.sh
```

The R3 example folds 2,550 instances and is intentionally expensive.

## Interfold-Style Connection

The coordination-trilemma article describes a chain of C0-C7 ZK circuits
connected by compact commitments. Raw polynomials are private; downstream
circuits receive commitments as public inputs and recompute or validate the
corresponding private values.

The equivalent connection for this repository should be:

| Interfold circuit | LatticeFold relation | Responsibility |
| --- | --- | --- |
| C0 | R0 | Commit individual BFV transport keys. |
| C1 | R1 | Prove threshold-key and smudging-noise contribution generation. |
| C2a/C2b | R2 | Prove Shamir consistency and Reed-Solomon validity. |
| C3a/C3b | R3 | Prove share encryption under the intended recipient key. |
| C4a/C4b | R4 | Prove received shares open the C2 commitments and aggregate them. |
| C5 | R5 | Prove the aggregate public key is the sum of the selected honest keyshares. |
| C6 | R6 | Prove each decryption share from the C4 aggregate and ciphertext. |
| C7 | R7 | Prove interpolation, CRT reconstruction, and final decode. |

### C5

C5 should receive as public inputs:

- The canonical authorized party IDs.
- The C1 public-key contribution commitments.
- The aggregate public-key commitment.
- The aggregate public key, or its private polynomial witness.
- The committee and parameter-domain commitments.

C5 proves that the aggregate public key is the sum of exactly the authorized
and accepted contributions. It must also check that every supplied keyshare
matches its C1 commitment. A proof of the sum alone is insufficient because an
aggregator could sum substituted values.

This replaces the current R5 example's thin public aggregation demonstration.
Ajtai homomorphism can cheaply check the linear sum, but the C5 proof still
needs to bind the selected input commitments, party set, and aggregate output.

### C7

C7 should receive as public inputs:

- The ciphertext domain and ciphertext commitment.
- The sorted, unique reconstruction party IDs.
- The C6 decryption-share commitments.
- The reconstructed plaintext commitment or public plaintext output.
- The threshold public-key and parameter commitments.

C7 proves:

1. The Lagrange coefficients correspond to the supplied party IDs.
2. The interpolated values correspond to the supplied C6 decryption shares.
3. CRT reconstruction is valid across all RNS channels.
4. Centered BFV decoding and plaintext range checks are valid.
5. The final plaintext is bound to the same ciphertext and committee domain.

C7 therefore corresponds to the final part of R7, while C6 corresponds to the
per-party R6 relation. C7 does not replace C6 unless it directly verifies the
C6 statements or receives equivalent commitments and proofs.

### Important ZK Boundary Decision

There are two possible designs:

- **Layered design:** C1-C6 remain independently verifiable ZK proofs, and C5/C7
  aggregate them. This matches the article most closely.
- **Aggregation-boundary design:** C1-C4/C6 artifacts remain private to the
  prover, while C5 and C7 prove the complete upstream relation and commitment
  chain in Noir. This is smaller conceptually but makes C5/C7 substantially
  more complex.

The second design is viable only if private LatticeFold transcripts are never
published and the Noir C5/C7 statements fully bind every upstream commitment.
Publishing the current LatticeFold secret-bearing transcripts would not provide
zero knowledge merely because C5 or C7 is itself a ZK proof.

## Connecting R3 and R4

The completed first integration milestone covers the real BFV transport and
native q0 R4 opening for one channel, one sender, and one recipient:

1. Build the N=4096 individual BFV transport parameters.
2. Generate an individual BFV keypair for the recipient.
3. Encode one polynomial share.
4. Encrypt it under the recipient's public key.
5. Decrypt it with the recipient's secret key.
6. Recover and check all 4,096 polynomial coefficients.
7. Map the recovered coefficients into the native q0 coefficient ring.
8. Create the Ajtai commitment and the R4 opening witness.
9. Run and verify the LatticeFold linearization proof.
10. Reopen the commitment with the same share and reject a tampered share.

The next integration must extend this to the full article flow:

1. Generate an individual BFV keypair for every recipient.
2. Generate real R2 Shamir shares for each contribution.
3. Encrypt each share under the recipient's individual public key using real
   BFV.
4. Decrypt the ciphertext at the recipient using `fhe.rs`.
5. Feed the decrypted share into R4.
6. Require R4 to open the exact R2 commitment associated with the sender and
   recipient.
7. Aggregate the committed digit vectors without re-decomposing them.
8. Feed those exact aggregate digit vectors into R6.

R3 must bind both the recipient key commitment and the share commitment. R4
must bind both the sender/recipient slot and the decrypted value. Otherwise a
prover can produce a valid encryption proof and then substitute a different
share at receipt time.

The first milestone is complete for real `fhe.rs` key generation, encrypted
transport, decryption, native q0 conversion, and one-share R4 opening. The
remaining work is to replace the synthetic share with actual R2 Shamir output,
carry sender/recipient metadata, and fold multiple received shares.

## Parameter Selection

### What `fhe.rs` Provides

The development branch exposes `BfvParametersBuilder` and a
`default_parameters_128` iterator. The default iterator is useful as a BFV
baseline, but its standard primes are not automatically compatible with
LatticeFold's native-ring congruence:

```text
q = 1 mod 2N
q = 1 + 2t mod 4t
```

The branch also includes TRBFV examples using encrypted share transport and
smudging noise. Those examples are useful for the witness bridge, but their
parameters must still be checked against the LatticeFold congruence and a
separate lattice security estimate.

### Do Not Claim 128-Bit Security for N=16

The current custom `InterfoldRing` model is degree 16. It is useful for fast
relation development, but degree 16 cannot provide 128-bit BFV or lattice
security. It must be labeled demo-only.

### Candidate Engineering Set: N=4096

This set is suitable for a smaller production-oriented prototype and satisfies
the native congruence for `t = 2^13`:

```text
N = 4096
t = 8192

q0 = 0x20004c001 = 8590245889
q1 = 0x2000f4001 = 8590934017
q2 = 0x200164001 = 8591392769

Q = q0*q1*q2
  = 634029627889566009658444496897
  = approximately 100 bits
```

Each q passes the repository's fixed-witness probable-prime check, is
NTT-friendly for `X^4096 + 1`, and satisfies:

```text
q = 1 + 2*t mod 4*t
q = 16385 mod 32768
```

A reconstruction-prime candidate for this chain is:

```text
P = 0x80000000000000000000064001
```

This candidate is approximately 104 bits and is greater than `4Q`. It still
requires an independent primality check and a formal no-wraparound proof.

This set is not yet certified as 128-bit post-quantum secure. It is a good
development target because it is much smaller than degree 8192 while retaining
realistic RNS sizes and native LatticeFold compatibility.

### 128-Bit Post-Quantum Target

For an honest 128-bit post-quantum target, use degree 8192 unless a lattice
estimator demonstrates that a smaller degree is sufficient. A compatible
candidate with `t = 2^14` is:

```text
N = 8192
t = 16384

q0 = 0x100098001 = 4295589889
q1 = 0x100248001 = 4297359361
q2 = 0x1002a8001 = 4297752577
q3 = 0x100348001 = 4298407937
q4 = 0x100368001 = 4298539009

Q = approximately 161 bits
```

These q values are approximately 33 bits and satisfy:

```text
q = 1 mod 16384
q = 32769 mod 65536
```

A reconstruction-prime candidate is:

```text
P = 0x4030ee4d5713feef9b45d44ccaf4be4b603938001
```

This is approximately 163 bits and is greater than `4Q` for the candidate
chain. It still requires independent validation.

This is a **parameter-search target**, not a security claim. To claim at least
128-bit post-quantum security, run a current estimator against:

- The exact ring dimension and modulus product.
- The actual secret and error distributions used by `fhe.rs`.
- The BFV multiplication depth and relinearization noise.
- The threshold and smudging-noise bounds.
- The Ajtai/MSIS commitment dimensions and extraction slack.
- Classical and quantum attack estimates.

The `fhe.rs` `default_parameters_128` name should not be treated as proof of
128-bit post-quantum security for a modified LatticeFold parameter set.

### Individual Share-Encryption Parameters

The individual BFV instance must have a plaintext modulus larger than the
largest threshold-BFV q. For the candidate sets above:

```text
share-encryption plaintext modulus: t_share >= 2^34
share-encryption ciphertext moduli: 0x2000000001be0001, 0x2000000001960001
share-encryption degree:             same N as the threshold instance
```

The current bridge builds this exact chain through `fhe.rs`'s parameter
builder, verifies one coefficient-preserving transport round trip, converts the
decoded value into the native q0 ring, and verifies one R4 opening. The
transport chain does not need to be LatticeFold-congruent if its arithmetic is
only used off-chain, but every value entering an R3 proof must be represented
consistently in the threshold channel.

## Implementation Files

- `crates/latticefold/src/vdkg_params.rs`: N=4096 q/P and share-transport
  constants plus arithmetic validation.
- `vendor/stark-rings/crates/ring/src/cyclotomic_ring/models/n4096/`: q0, q1,
  q2, and 104-bit P field configurations with 4096-point negacyclic CRT/iCRT
  and balanced-decomposition support for the two-limb P field.
- `crates/cyclotomic-rings/src/rings/n4096.rs`: public `SuitableRing`,
  challenge-set, and field aliases for the three native channels and P.
- `crates/cyclotomic-rings/src/rings/poseidon/n4096.rs`: per-channel and P
  Poseidon configurations.
- `crates/latticefold/src/fhe_bridge.rs`: real BFV transport, threshold
  (H=5, T=3) Shamir sharing over Z_Q with CRT-congruent channel projections,
  per-channel (q0/q1/q2) GRS-syndrome R2 linearization, Ajtai commitment,
  metadata-bound R4 linearization with per-channel NIFS folding, reopen check,
  and tamper check.
- `crates/latticefold/examples/dkg_fhe_r4.rs`: executable one-share integration.
- `crates/latticefold/examples/dkg_fhe_r2_r4.rs`: executable R2 -> BFV -> R4
  integration.
- `crates/latticefold/examples/dkg_fhe_committee_r4.rs`: full-committee
  (H=5, T=3) R2 -> BFV -> folded R4 integration on q0 using one recipient
  transport key, with aggregated-secret reconstruction.
- `crates/latticefold/examples/dkg_fhe_multichannel_r4.rs`: the same committee
  across all three RNS channels with per-channel folded R4 accumulators and
  coefficient-wise CRT recombination of the transported shares.
- `crates/latticefold/examples/dkg_p_reconstruction.rs`: native P-ring proof
  of the Garner recombination `v = r0 + q0*t1 + q0*q1*t2` with commitment
  reopen/tamper checks.

The R4 integration now covers the full H=5/T=3 committee on all three RNS
channels. Sharing happens once over Z_Q (degree T-1 polynomials per secret
coefficient) and is projected to each channel, so the per-channel shares are
CRT-congruent by construction; the multichannel example asserts that the
transported projections recombine coefficient-wise. The R2 relation uses the
H-T generalized Reed-Solomon syndrome rows (exactly enforcing degree <= T-1)
plus a Lagrange-at-zero consistency row. Each opening binds sender, recipient,
and channel IDs through the canonical public-input tag:

```text
domain_tag = sender_id + 2^16 * recipient_id + 2^32 * channel_id
```

The tag is included in the Ajtai witness and the CCS enforces equality with the
public IDs. The verifier also compares the returned public-input vector with
the expected IDs. All received shares of a channel are transported with one
recipient BFV key and folded into one per-channel R4 accumulator. The
reconstruction-prime P ring (104-bit `FqP`, two-limb `ConvertibleRing`) is now
wired end to end and carries the Garner recombination relation natively;
committee-scale P-side interpolation and the C7 decode chain remain.

## Noir Role

On-chain verification is out of scope for this exploration. Noir remains useful
as an off-chain ZK aggregation backend:

- C5 can prove aggregate public-key correctness and commitment links.
- C7 can prove final decryption, CRT reconstruction, and decoding.
- The Noir public inputs can contain compact Ajtai commitments, party IDs,
  parameter hashes, ciphertext commitments, and output commitments.
- The raw BFV polynomials and secret shares remain private witnesses.

This keeps LatticeFold focused on native relation folding and uses Noir only at
the aggregation boundaries where a self-contained ZK artifact is needed.

## Work Required

| Item | Status | Blocking? |
| --- | --- | --- |
| Goldilocks relation examples | Working | No |
| Degree-16 custom ring | Working for demonstrations | No, demo-only |
| R2 -> threshold Shamir sharing | H=5/T=3 Z_Q sharing with GRS-syndrome R2 linearization on all channels | Complete for demonstration scale |
| R3 -> real BFV encryption | Proven: digit-form transport with real fhe.rs `try_encrypt_extended` witnesses, native per-prime proofs, real decryption; 50 instances folded into one accumulator per prime (~15s/instance vs Noir C3 10.76s + recursion) | Complete for demonstration scale |
| R4 -> commitment opening | Full-committee multi-channel openings, metadata binding, and per-channel NIFS folding working | Complete for demonstration scale |
| R1/R5/R6/Ruser native on N=4096 | Wired into `vdkg_flow` (R1 per dealer per channel, R5 homomorphic aggregation, Ruser per channel, R6 proven + folded per channel) | Complete for demonstration scale |
| Full P1->P4 flow | `dkg_fhe_full_flow` green at N=3/H=3/T=2 and N=H=5/T=3: DKG -> R5 -> user encryption -> folded R6 -> P-track R7 CRT+decode recovers the exact plaintext | Complete for demonstration scale |
| Lattice-estimator certification | Done (`analysis/`): N=8192 BFV ~159-161 bits PQ, N=4096 ~137-139; commitments unconditionally binding at kappa=4; Eq4 formula cross-validated | Complete for these parameter sets |
| C5 commitment-bound aggregate proof | R5 done natively (free homomorphic sum); ZK C5 decider-wrapper prototype in `decider-circuits/c5` (3-track openings + aggregation, 2.39M opcodes @ N=1024, proven+verified); production needs digit-limb witnesses, transcript-challenge binding, per-track recursion | Prototype done; production open |
| C7 commitment-bound final decryption proof | R7 done natively on the P track (interpolation + CRT quotient witnesses + decode); ZK C7 spec'd in `decider-circuits/SPEC.md` | Spec done; wrapper open |
| Real `fhe.rs` witness adapter | R2 polynomial share transport working behind `fhe-bridge` | Yes for production-oriented execution |
| Production ring models for q0/q1/q2 and P | All four wired; P carries the native Garner recombination proof; R7 decode chain now complete | No for demonstrations |
| N=4096 engineering candidate | Module and example validated | No, independent certification remains |
| N=8192 parameter set (Noir `secure-8192` security) | Constants + validation in `vdkg_params.rs` (t=2^20, 3x58-bit, log2 Q=174, P 176-bit safe-form); stark-rings `models/n8192` wired on the fork (pushed); full flow green at N=8192 (H=5/T=3, ~316s) via `--params n8192`; estimator-certified ~159-161 bits PQ | No for demonstrations |
| 128-bit post-quantum certification | Done for the N=8192 parameter set via lattice-estimator (`analysis/SECURITY.md`): ~159-161 bits PQ BFV, commitments binding | Complete for these sets (re-run if parameters change) |
| Noir C5/C7 circuits | Not in this repository | No for current examples, yes for ZK artifact |
| On-chain wrapper | Out of scope | No |
| FHE evaluation correctness | Out of scope in `plan.md` | No |
| Relinearization-key generation | Deferred in `plan.md` | No for the current scope |

## Recommended Order

1. Add and validate the N=4096 parameter module. **Complete for engineering
   checks:** q/P congruence, NTT conditions, product, margin, and fixed-witness
   probable-prime checks pass; independent primality and security certification
   remain.
2. Add the pinned `fhe.rs` development dependency and bridge boundary.
   **Complete:** revision `cb83e5e1...`, opt-in `fhe-bridge` feature, and Rust
   1.91.1 command path.
3. Build one real encrypted-share R3/R4 path for one channel and one sender.
   **Complete for the first slice:** degree-1 q0 Shamir evaluation and
   reconstruction, full-polynomial BFV encode/encrypt/decrypt/recovery, native
   q0 conversion, Ajtai commitment, linearization verification, metadata
   binding, reopen, and tamper rejection work for one sender and recipient.
4. **Complete for demonstration scale:** the full H=5/T=3 committee runs on
   all three RNS channels with one recipient BFV key, per-channel folded R4
   accumulators, CRT-congruent shares, and aggregated-secret reconstruction.
   The P ring natively proves the Garner recombination of channel residues.
5. Carry exact commitment metadata through R1, R2, R3, R4, and R6.
6. Implement C5 as the first commitment-bound Noir aggregation proof.
7. Implement C7 for interpolation, CRT, decode, and C6 commitment binding.
8. Run lattice security estimation before calling any set 128-bit post-quantum
   secure.
9. Only then move the same design to the N=8192 target if the estimator or BFV
   correctness budget requires it.

## Bottom Line

The coordination-trilemma model is implementable here, but the commitment chain
must be treated as the main protocol rather than as example-side assertions.
C5 and C7 are the right ZK aggregation boundaries, but they must consume and
bind the upstream commitments and authorized-party metadata.

The N=4096 candidate is the practical next engineering target. The N=8192
candidate is the more credible 128-bit post-quantum target, but neither should
be labeled 128-bit post-quantum secure until the exact BFV, Ajtai, and folding
parameters have been evaluated with appropriate classical and quantum lattice
estimators.
