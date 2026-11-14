# Lattice Engine Benchmarking and Core-Protocol PQC Remediation Assessment

Measured ML-KEM and ML-DSA costs across every parameter set, from two
independent implementations on one fixed host and toolchain, mapped to
the core-protocol call sites in postfiatd (pinned commit `0085a1ff`),
with a remediation assessment for the post-quantum migration.

## Headline numbers (medians, microseconds per operation)

| Algorithm | liboqs 0.16.0 (AVX2) | PQClean clean (reference C) |
|-----------|----------------------|-----------------------------|
| ML-KEM-512 keygen / encaps / decaps | 10.036 / 10.503 / 12.596 | 59.669 / 66.205 / 88.613 |
| ML-KEM-768 keygen / encaps / decaps | 15.358 / 16.154 / 19.673 | 98.814 / 105.639 / 133.537 |
| ML-KEM-1024 keygen / encaps / decaps | 20.433 / 20.863 / 26.193 | 155.950 / 158.274 / 195.017 |
| ML-DSA-44 keygen / sign / verify | 28.804 / 99.789 / 32.251 | 143.221 / 623.758 / 153.656 |
| ML-DSA-65 keygen / sign / verify | 48.512 / 153.006 / 54.167 | 281.217 / 991.558 / 247.327 |
| ML-DSA-87 keygen / sign / verify | 69.719 / 172.875 / 75.730 | 407.094 / 1275.185 / 419.090 |

Classical baseline, same host (OpenSSL 3.0.13, measured):
ECDSA-secp256k1 keygen 612.995 / sign 588.125 / verify 558.113 us;
Ed25519 61.706 / 56.787 / 143.639 us.

**Headline finding.** On this host the classical scheme is the slow
one: secp256k1 verification costs 558.113 us while ML-DSA-65
verification costs 54.167 us (liboqs) — about 10x faster. The
migration's cost is bandwidth, not CPU: a dual classical + ML-DSA-65
validation carries 51.6x the signature-related bytes of a classical
one per ledger (1,062,270 B vs 20,592 B at N=66, 2 proposal rounds).
ML-KEM-768 for a TLS handshake (keygen + encaps + decaps) costs
51.185 us (liboqs) / 337.990 us (PQClean clean).

All 14 correctness checks pass (6 liboqs + 6 PQClean + 2 classical).
All 12 lattice size rows match FIPS 203 Table 3 / FIPS 204 Table 2.
OpenSSL 3.5 was NOT MEASURED (see `claim_evidence_index.md`).

## Host and toolchain

AMD EPYC 9D25, gcc 13.3.0 (-O2), cmake 3.28.3, Python 3.12.3,
OpenSSL 3.0.13. liboqs 0.16.0 minimal build (ML-KEM + ML-DSA only),
x86_64/AVX2 path (dispatch probe AVX2=1 BMI2=1 POPCNT=1). PQClean
commit `0586a824fc0d49df0b6b6e9179d8d15d06d0974f`, portable-C `clean`
reference implementations. Full record: `results/environment.json`.

## Files

- `docs/index.html` — rendered results page (tables, digest-check
  output and run-log tail inline)
- `results/benchmark_liboqs.json`, `results/benchmark_pqclean.json`,
  `results/benchmark_classical.json` — vendored raw benchmark results
- `results/raw_liboqs.log`, `results/raw_pqclean.log`,
  `results/raw_classical.log` — unedited raw console logs
- `results/timing_table.csv` / `timing_table.md`,
  `results/size_table.csv` / `size_table.md` — derived tables
- `results/cost_model.json` / `cost_model.csv` — derived
  consensus-path cost model (N=66, 2 proposal rounds, 4 s close)
- `results/summary.txt` — headline numbers in plain text
- `results/environment.json` — host, toolchain, versions
- `results/digest_check_output.txt`, `results/run_log.txt` —
  digest-check output, fresh-copy reproduction log
- `harness/bench_liboqs.c`, `harness/bench_pqclean.c`,
  `harness/bench_classical.c` — benchmark drivers
- `harness/build_benchmarks.sh`, `harness/run_benchmarks.sh` —
  build / run scripts
- `call_sites.md` — measurement-to-call-site mapping (pinned tree,
  every file:line read)
- `remediation_assessment.md` — hybrid classical + ML-DSA design,
  key rotation and revocation, phased costs, forward-only
  activation, rollback notes, exposure-ranked remediation
  priorities (P0-P6), monitoring, open questions
- `claim_evidence_index.md` — measured (M) vs source-derived (S)
  claims, separated, with file:line and output-file references,
  plus the NOT MEASURED / UNVERIFIED list
- `sources.md` — primary sources and version pins
- `sources/NIST.FIPS.203.pdf`, `sources/NIST.FIPS.204.pdf` —
  vendored standards
- `build_derived.py` — deterministic derived-output builder
- `run_all.sh`, `verify_digests.sh`, `SHA256SUMS` — offline
  regeneration and digest verification

## Reproduction

```sh
bash run_all.sh
```

Regenerates every derived output offline from the vendored results
JSON, rebuilds `docs/index.html`, and verifies digests. Expected:
exit 0, byte-identical outputs. See `REPRODUCTION.md` for the exact
command and recorded result. To re-run the benchmarks themselves
(timings vary run to run — not part of the offline reproduction),
see `harness/build_benchmarks.sh` and `harness/run_benchmarks.sh`
and `REPRODUCTION.md`.

## Limitations

- Timings are for this host and toolchain only. They do not transfer
  to validator hardware; the ratios between schemes on one host are
  the portable part.
- liboqs uses its optimized AVX2 path; PQClean `clean` is portable C.
  A production deployment would use optimized code for both schemes;
  the PQClean numbers are a conservative upper bound.
- OpenSSL 3.5 was not measured: the system OpenSSL is 3.0.13, which
  has no native ML-KEM/ML-DSA.
- Cost-model network inputs (N=66, 2 proposal rounds) come from the
  sibling migration pack; they are labelled source-derived, not
  measured here.
- No ledger was compiled or run locally; no validation was forged or
  replayed against a live node.
