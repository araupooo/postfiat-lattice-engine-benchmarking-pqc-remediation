# Claim-to-evidence index

Every material claim in this pack, mapped to the evidence for it.
Claims are split into two sections by provenance and never mixed:

- **(M) Measured** — produced by running the benchmark drivers in
  this pack on the recorded host and toolchain. Evidence is a
  runnable script plus its unedited output file.
- **(S) Source-derived** — taken from a primary source (a standard,
  the pinned tree, or a named sibling pack) or computed by
  arithmetic from measured values and named inputs. Evidence is the
  source file and line, or the derivation.

A claim that cannot be evidenced is listed under
**NOT MEASURED / UNVERIFIED** at the end — never silently dropped
and never filled in with an estimate.

Pinned tree: postfiatd main `0085a1ff885d6a446369cf73a4430f75af22be55`.
Host: AMD EPYC 9D25, gcc 13.3.0, -O2 (`results/environment.json`).

## (M) Measured claims

### M1. Timing medians (liboqs 0.16.0, AVX2 path)

| Claim | Evidence |
|-------|----------|
| ML-KEM-512 keygen 10.036 us, encaps 10.503 us, decaps 12.596 us (medians) | `harness/bench_liboqs.c` run by `harness/run_benchmarks.sh`; `results/raw_liboqs.log:5-10`; `results/benchmark_liboqs.json` entry `ML-KEM-512`; `results/timing_table.csv:2-4` |
| ML-KEM-768 keygen 15.358 us, encaps 16.154 us, decaps 19.673 us | `results/raw_liboqs.log:11-16`; `results/benchmark_liboqs.json` entry `ML-KEM-768`; `results/timing_table.csv:5-7` |
| ML-KEM-1024 keygen 20.433 us, encaps 20.863 us, decaps 26.193 us | `results/raw_liboqs.log:17-22`; `results/benchmark_liboqs.json` entry `ML-KEM-1024`; `results/timing_table.csv:8-10` |
| ML-DSA-44 keygen 28.804 us, sign 99.789 us, verify 32.251 us | `results/raw_liboqs.log:23-28`; `results/benchmark_liboqs.json` entry `ML-DSA-44`; `results/timing_table.csv:11-13` |
| ML-DSA-65 keygen 48.512 us, sign 153.006 us, verify 54.167 us | `results/raw_liboqs.log:29-34`; `results/benchmark_liboqs.json` entry `ML-DSA-65`; `results/timing_table.csv:14-16` |
| ML-DSA-87 keygen 69.719 us, sign 172.875 us, verify 75.730 us | `results/raw_liboqs.log:35-40`; `results/benchmark_liboqs.json` entry `ML-DSA-87`; `results/timing_table.csv:17-19` |
| liboqs runs its x86_64 (AVX2) path on this host | `results/raw_liboqs.log:2` — dispatch probe `AVX2=1 BMI2=1 POPCNT=1 AVX512=1`; the dispatch rule is `src/kem/ml_kem/kem_ml_kem_512.c:79` in the liboqs 0.16.0 source (AVX2+BMI2+POPCNT present → x86_64 path) |

### M2. Timing medians (PQClean clean reference)

| Claim | Evidence |
|-------|----------|
| ML-KEM-512 keygen 59.669 us, encaps 66.205 us, decaps 88.613 us | `harness/bench_pqclean.c` (one binary per parameter set); `results/raw_pqclean.log:2-8`; `results/benchmark_pqclean.json` entry `ML-KEM-512`; `results/timing_table.csv:2-4` |
| ML-KEM-768 keygen 98.814 us, encaps 105.639 us, decaps 133.537 us | `results/raw_pqclean.log:10-17`; `results/benchmark_pqclean.json` entry `ML-KEM-768`; `results/timing_table.csv:5-7` |
| ML-KEM-1024 keygen 155.950 us, encaps 158.274 us, decaps 195.017 us | `results/raw_pqclean.log:19-26`; `results/benchmark_pqclean.json` entry `ML-KEM-1024`; `results/timing_table.csv:8-10` |
| ML-DSA-44 keygen 143.221 us, sign 623.758 us, verify 153.656 us | `results/raw_pqclean.log:28-35`; `results/benchmark_pqclean.json` entry `ML-DSA-44`; `results/timing_table.csv:11-13` |
| ML-DSA-65 keygen 281.217 us, sign 991.558 us, verify 247.327 us | `results/raw_pqclean.log:38-44`; `results/benchmark_pqclean.json` entry `ML-DSA-65`; `results/timing_table.csv:14-16` |
| ML-DSA-87 keygen 407.094 us, sign 1275.185 us, verify 419.090 us | `results/raw_pqclean.log:46-53`; `results/benchmark_pqclean.json` entry `ML-DSA-87`; `results/timing_table.csv:17-19` |

### M3. Timing medians (classical baseline, OpenSSL 3.0.13)

| Claim | Evidence |
|-------|----------|
| ECDSA-secp256k1 keygen 612.995 us, sign 588.125 us, verify 558.113 us; signature 71 bytes DER in this run (at most 72) | `harness/bench_classical.c`; `results/raw_classical.log:3-8`; `results/benchmark_classical.json` entry `ECDSA-secp256k1`; `results/timing_table.csv:20-22` |
| Ed25519 keygen 61.706 us, sign 56.787 us, verify 143.639 us; signature 64 bytes | `results/raw_classical.log:9-14`; `results/benchmark_classical.json` entry `Ed25519`; `results/timing_table.csv:23-25` |
| secp256k1 is ~18x slower than P-256 on this host (P-256 sign 31.039 us, secp256k1 sign 559.471 us in the same minimal program) | Authoring cross-check, minimal OpenSSL program (same method, same host); secp256k1 figure reproduced by the shipped driver (588.125 us). No file shipped for the cross-check program; the shipped driver's own numbers are the evidence. |

### M4. Correctness (14/14 checks PASS)

| Claim | Evidence |
|-------|----------|
| All 6 liboqs parameter sets: encap/decap shared secrets match, tampered ciphertext rejected to a different secret; sign/verify round-trip, tampered signature rejected | `results/raw_liboqs.log:42` — `RESULT: PASS (exit 0)`; per-set `correctness: PASS` lines; `results/benchmark_liboqs.json` `correctness` fields |
| All 6 PQClean parameter sets: same checks | `results/raw_pqclean.log:9,18,27,36,45,54` — six `RESULT: PASS (exit 0)` lines; `results/benchmark_pqclean.json` `correctness` fields |
| Both classical schemes: same checks | `results/raw_classical.log:16` — `RESULT: PASS (exit 0)`; `results/benchmark_classical.json` `correctness` fields |

### M5. Sizes match the standards

| Claim | Evidence |
|-------|----------|
| Every measured ML-KEM size matches FIPS 203 Table 3; every measured ML-DSA size matches FIPS 204 Table 2 (12 rows, all MATCH) | `results/size_table.csv:2-13` (verdict column); `build_derived.py` exits 1 on any mismatch and exited 0; `results/benchmark_liboqs.json` and `results/benchmark_pqclean.json` size fields |

### M6. TLS handshake KEM cost (ML-KEM-768)

| Claim | Evidence |
|-------|----------|
| One handshake's KEM operations (keygen + encaps + decaps): 51.185 us (liboqs), 337.990 us (PQClean clean) | Derived by addition from M1/M2 medians; `results/cost_model.json` `tls_handshake_mlkem768_us`; `results/summary.txt` |

## (S) Source-derived claims

### S1. Standard sizes and categories

| Claim | Evidence |
|-------|----------|
| ML-KEM sizes (FIPS 203 Table 3) and categories 1/3/5; ML-DSA sizes (FIPS 204 Table 2) and categories 2/3/5 | `sources/NIST.FIPS.203.pdf` Table 3 (§8) and `sources/NIST.FIPS.204.pdf` Table 2 (§5); `sources.md` |
| ML-DSA-65 key generation takes a 32-byte random seed | FIPS 204 §6 (cited in `remediation_assessment.md` §1.1) |

### S2. Pinned-tree call sites (all read in the tree at `0085a1ff`)

| Claim | Evidence |
|-------|----------|
| Validation verification is secp256k1-only (signing gate, deserialization gate, `isValid` assertion) | `include/xrpl/protocol/STValidation.h:204,249-250`; `src/libxrpl/protocol/STValidation.cpp:128,136-139` |
| Only `secp256k1` and `ed25519` exist in `KeyType` | `include/xrpl/protocol/KeyType.h:28-31` |
| Proposals are signed with `signDigest` over the signing hash | `src/xrpld/app/consensus/RCLConsensus.cpp:241` |
| Proposal signature buffer is fixed at 72 bytes; constructor asserts ≤ 72 bytes | `src/xrpld/app/consensus/RCLCxPeerPos.h:110`; `src/xrpld/app/consensus/RCLCxPeerPos.cpp:37-44` |
| Inbound proposals are rejected unless the signature is 64-72 bytes and the node key is secp256k1 | `src/xrpld/overlay/detail/PeerImp.cpp:1791-1799` |
| `generateSecretKey` derives Ed25519 from a SHA-512 half of the seed and secp256k1 from a deterministic root key; unknown type is a `LogicError` | `src/libxrpl/protocol/SecretKey.cpp:309-327` |
| `sign()` produces a 64-byte Ed25519 signature or a DER secp256k1 signature of at most 72 bytes | `src/libxrpl/protocol/SecretKey.cpp:230-295` |
| Validator keys load from `[validator_token]` (rotatable) or `[validation_seed]` (same key as master, sequence 0, no rotation path) | `src/xrpld/app/misc/detail/ValidatorKeys.cpp:40-95` |
| A manifest with sequence ≤ stored is rejected; sequence `0xFFFFFFFF` means the master key is revoked | `src/xrpld/app/misc/detail/Manifest.cpp:411,226-240` |
| Default TLS cipher list and TLS 1.2 minimum | `src/libxrpl/basics/make_SSLContext.cpp:104,356-357` |
| Post-fix amendment threshold is 67%; majority hold is 2 weeks | `include/xrpl/protocol/SystemParameters.h:85,88` |
| Validation quorum is `max(ceil(UNL x 0.67), ceil(UNL x 0.6))` | `src/xrpld/app/misc/detail/ValidatorList.cpp:1934` (comment at `:1898-1900`) |
| Amendment votes expire 24 h after a validator's last validation | `src/xrpld/app/misc/detail/AmendmentTable.cpp:167-172` |
| `enable()` has no path that clears an enabled amendment or the blocked flag | `src/xrpld/app/misc/detail/AmendmentTable.cpp:762-781` |
| Unsupported amendment activation halts the node ("server blocked"), re-checked at every ledger close | `src/xrpld/app/tx/detail/Change.cpp:364-368`; `src/xrpld/app/ledger/detail/LedgerMaster.cpp:309-314` |
| The veto is admin-only (`feature` RPC, `vetoed: true`) | `src/xrpld/rpc/handlers/Feature1.cpp:78-87`; `src/xrpld/app/misc/detail/AmendmentTable.cpp:723-761` |
| Validator-list sites refresh every 5 minutes, retry after 30 s on error | `src/xrpld/app/misc/detail/ValidatorSite.cpp:34-35` |
| `doVoting` runs only when trusted validations reach the node's quorum | `src/xrpld/app/consensus/RCLConsensus.cpp:371` |
| The pinned OpenSSL is 1.1.1w | `conanfile.py:30` |

### S3. Cost-model arithmetic (derived from M1-M3 + named network inputs)

| Claim | Evidence |
|-------|----------|
| Per ledger per node: 198 signature verifications (66 validations + 132 proposals at 2 rounds) | Network inputs N=66, 2 proposal rounds: sibling consensus-signature migration pack `cost_model.py` v1.0.0 (live testnet snapshot 2026-11-13; rounds are its assumption A3). Arithmetic: 66 x (1 + 2) = 198. |
| Classical verify 110.506 ms/ledger (2.763% of a 4 s close); ML-DSA-65 (liboqs) 10.725 ms (0.268%); dual 121.231 ms (3.031%); pure ML-DSA-65 bytes 1,041,678/ledger, 22.50 GB/day at 4 s close | `results/cost_model.json` `per_ledger_per_node`; `results/cost_model.csv:2-10`; derivation: 198 x measured median |
| Dual-phase bandwidth 51.6x classical; classical half is 91.2% of dual-phase verify CPU; ML-DSA-65 verify 10.3x faster than secp256k1 (liboqs), 2.3x (PQClean clean) | Arithmetic from M1/M3 medians; `results/cost_model.json` |
| 3.03 s close re-scaling (0.59 / 30.29 / 29.70 GB/day) | 3.03 s measured mean close: sibling amendment-state probe pack (`results/summary.json`); arithmetic in `results/cost_model.json` (`sig_bytes_per_day_3p03s_close`) |
| Threshold arithmetic at N=66: quorum 45, 45 keys to force a majority, 22 to block | Sibling amendment-state probe pack (measured there); quorum formula S2 above: `max(ceil(66 x 0.67), ceil(66 x 0.6)) = 45` |
| Rotation schedule (weekly batches of 9 of 66, 8 weeks; margins) and compromise procedures | Sibling validator key lifecycle pack (56 simulated days, N=66) |
| Dual-manifest size 5,365 B (1,985 B public keys + 3,309 B ML-DSA-65 signature + 72 B classical master signature); classical manifest 177 B | ML-DSA-65 signature size M5; classical sizes from the sibling migration pack |

### S4. Version pins

| Claim | Evidence |
|-------|----------|
| liboqs 0.16.0 tarball SHA-256, byte-identical to the fresh GitHub tag archive | `sources.md`; `results/environment.json` |
| PQClean commit `0586a82…`, no release tag published | `sources.md`; `results/environment.json` (`pqclean_commit`) |
| Host / toolchain | `results/environment.json` |

## NOT MEASURED / UNVERIFIED

| Item | Status | Why, and what would settle it |
|------|--------|-------------------------------|
| OpenSSL 3.5 as a third implementation (ML-KEM / ML-DSA) | NOT MEASURED | The system OpenSSL is 3.0.13 (no native ML-KEM/ML-DSA). Building OpenSSL 3.5 from source was not completed in the time available on this host (shared 1.5-CPU VM, ~540 MB free RAM at authoring). No number is given for it anywhere in this pack. To measure it: build OpenSSL 3.5.x from source, add an `EVP_PKEY`-based driver next to `harness/bench_classical.c`, and re-run. |
| Full TLS handshake cost | NOT MEASURED | Only the ML-KEM operations a handshake would perform were measured (M6). No handshake was run; the X25519 half of a hybrid exchange was not measured. |
| secp256k1 timings from postfiatd itself | NOT MEASURED | The daemon was not compiled or run locally. The classical baseline is OpenSSL 3.0.13's secp256k1 on the same host/toolchain. A validator running libsecp256k1 or assembly-optimized secp256k1 will see faster classical times; the bandwidth figures and the ML-DSA absolute timings are unaffected. |
| OQ-1 ML-DSA key encoding (prefix byte vs length rule vs type field) | UNVERIFIED | Design decision, not a measurement. Needs a deliberate allocation decision. |
| OQ-2 old nodes ignoring unknown fields in deserialized validations/manifests | UNVERIFIED | Must be confirmed by reading the `STObject` deserializer before phase 1 ships. |
| OQ-3 proposal suppression ID (include the ML-DSA signature or not) | UNVERIFIED | Design decision + test needed before the dual phase ships. |
| OQ-4 parameter-set choice (44 vs 65 vs 87) | UNVERIFIED as a decision | Measurements for all three are in `results/timing_table.csv`; the choice is governance, not technical inevitability. ML-DSA-65 is recommended in `remediation_assessment.md` §1.1 with measured reasons. |
| OQ-5 old-node behaviour on unknown key types outside the ignored-field path | UNVERIFIED | Trust path not exhaustively traced. |
| OQ-6 validation size vs relay policy for ~5 KiB validations | UNVERIFIED | No upper bound found in the relay path; the phase-1 soak is the place to measure it. |
| OQ-7 ledger close-time sensitivity | UNVERIFIED | Model uses a 4 s close (re-scaled to the sibling probe's measured 3.03 s); live measurement during the phase-1 soak would pin it down. |
| OQ-8 classical timings are host-specific | MEASURED, with a caveat | See M3: the secp256k1 numbers come from OpenSSL 3.0.13's generic implementation on a ~1.5 GHz shared host. Stated in the remediation assessment §7. |
