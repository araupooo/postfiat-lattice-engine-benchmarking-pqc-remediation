# Sources and version pins

Primary sources only. Every size, algorithm fact, and pinned-tree
citation in this pack traces to one of the sources below. No
published benchmark number is presented as a measurement anywhere
in this pack.

## Standards (vendored)

| Source | File in this pack | SHA-256 |
|--------|-------------------|---------|
| NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard, published 13 August 2024 | `sources/NIST.FIPS.203.pdf` | `fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac` |
| NIST FIPS 204, Module-Lattice-Based Digital Signature Standard, published 13 August 2024 | `sources/NIST.FIPS.204.pdf` | `57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b` |

Both PDFs were downloaded from `nvlpubs.nist.gov` (the NIST
publications site) during authoring and are vendored here so the
size tables can be checked offline. Tables used:

- FIPS 203, Table 2 (approved parameter sets, §8, p. 39) and
  Table 3 (sizes in bytes of keys and ciphertexts, §8, p. 39):
  ML-KEM-512 ek 800 / dk 1632 / ct 768 / ss 32; ML-KEM-768
  1184 / 2400 / 1088 / 32; ML-KEM-1024 1568 / 3168 / 1568 / 32.
  Categories 1 / 3 / 5.
- FIPS 204, Table 1 (parameter sets, §5, p. 15) and Table 2
  (sizes in bytes of keys and signatures, §5, p. 16): ML-DSA-44
  sk 2560 / pk 1312 / sig 2420; ML-DSA-65 4032 / 1952 / 3309;
  ML-DSA-87 4896 / 2592 / 4627. Categories 2 / 3 / 5.

## Implementations (pinned)

| Implementation | Pin | Verification |
|----------------|-----|--------------|
| liboqs | 0.16.0, tag `0.16.0` (released 2026-07-09), minimal build: ML-KEM-512/768/1024 + ML-DSA-44/65/87 only | Tarball SHA-256 `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`, verified byte-identical to a fresh download of `github.com/open-quantum-safe/liboqs/archive/refs/tags/0.16.0.tar.gz` at authoring time (the release publishes no checksum file; the tag archive is the verification). Built with cmake 3.28.3, `-DCMAKE_BUILD_TYPE=Release`, `-DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"`. |
| PQClean | Commit `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` (2026-08-04) | No release tag is published upstream (only `round2`/`round3` tags exist); pinned by full commit hash. The `clean` reference implementations for ml-kem-512/768/1024 and ml-dsa-44/65/87 were compiled directly with gcc 13.3.0, `-O2 -std=c99`. The copied sources were verified unmodified against the sibling checkout at that commit (`git status` clean). |
| OpenSSL (classical baseline) | 3.0.13 (system, Ubuntu 24.04) | `openssl version`: `OpenSSL 3.0.13 30 Jan 2024`. Used only for the classical ECDSA-secp256k1 and Ed25519 baselines. |
| OpenSSL 3.5 (third implementation) | — | NOT MEASURED. See the claim index. |

## Pinned source tree

- postfiatd main, commit `0085a1ff885d6a446369cf73a4430f75af22be55`
  (merge of PR #50, 2026-10-10). Worktree used at authoring:
  `/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff`.
  Every file:line citation in `call_sites.md` and
  `remediation_assessment.md` was read in that tree. The pinned
  OpenSSL there is 1.1.1w (`conanfile.py:30`).

## Sibling packs (source-derived inputs, not measurements here)

| Pack | What was taken from it |
|------|------------------------|
| Consensus-signature migration pack (task-f8e5bc7d253e8da32baf2d8a677057f1) | Cost-model network inputs: N=66 validators (live testnet snapshot 2026-11-13), 2 proposal rounds per ledger (assumption A3 in its `assumptions.md`), nominal 4 s close. Its published-estimate timings were NOT reused as measurements; the measured timings in this pack supersede them. |
| Amendment-state probe pack (task-b3ec81af966d76d60292a4c73b36c940) | Threshold arithmetic (45 to force / 22 to block at N=66, 67% rule), measured mean close interval 3.03 s, validator/version inventory (66 validators, 25 in UNL; versions 1.0.0: 2, 1.0.4: 9, 1.0.8: 1, 1.0.9: 54), rotation schedule and compromise procedures (from its key-lifecycle sibling), and the hybrid ML-DSA design pattern adapted in `remediation_assessment.md`. |
| ML-KEM implicit-rejection assessment pack (task-9c5fbe3b) | liboqs build experience (0.12.0 there; 0.16.0 here) and the FIPS 203 reference-C approach. |
| ML-DSA/SLH-DSA release-interop pack (task-7bb5e19b) | PQClean checkout and reference-driver build pattern. |

## Host and toolchain (measured environment)

Recorded in `results/environment.json`: AMD EPYC 9D25 126-Core
Processor, 4 cores visible, 8,124,900 KiB RAM, Linux
7.0.0-44-generic, gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0,
cmake 3.28.3, Python 3.12.3, OpenSSL 3.0.13. CPU flags of note:
AVX2, BMI2, POPCNT, AVX512F/BW/DQ, ADX, AES-NI, SHA-NI.
