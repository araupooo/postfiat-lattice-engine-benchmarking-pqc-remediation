# Timing table (median microseconds per operation)

Host: AMD EPYC 9D25 126-Core Processor; Linux htch-runtime 7.0.0-44-generic; gcc 13.3.0; liboqs 0.16.0; PQClean commit 0586a824fc0d; OpenSSL OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024).
liboqs runs its x86_64 (AVX2) path on this host (dispatch probe:
AVX2=1 BMI2=1 POPCNT=1, see `results/raw_liboqs.log`); PQClean is
the portable-C `clean` reference. The ratio column is therefore a
comparison of an optimized implementation against a reference, not
of two equals. Classical rows are OpenSSL 3.0.13 on the same host.

| Algorithm | Operation | liboqs median (us) | PQClean median (us) | PQClean / liboqs | OpenSSL median (us) |
|---|---|---|---|---|---|
| ML-KEM-512 | keygen | 10.036 | 59.669 | 5.95 | - |
| ML-KEM-512 | encaps | 10.503 | 66.205 | 6.30 | - |
| ML-KEM-512 | decaps | 12.596 | 88.613 | 7.04 | - |
| ML-KEM-768 | keygen | 15.358 | 98.814 | 6.43 | - |
| ML-KEM-768 | encaps | 16.154 | 105.639 | 6.54 | - |
| ML-KEM-768 | decaps | 19.673 | 133.537 | 6.79 | - |
| ML-KEM-1024 | keygen | 20.433 | 155.950 | 7.63 | - |
| ML-KEM-1024 | encaps | 20.863 | 158.274 | 7.59 | - |
| ML-KEM-1024 | decaps | 26.193 | 195.017 | 7.45 | - |
| ML-DSA-44 | keygen | 28.804 | 143.221 | 4.97 | - |
| ML-DSA-44 | sign | 99.789 | 623.758 | 6.25 | - |
| ML-DSA-44 | verify | 32.251 | 153.656 | 4.76 | - |
| ML-DSA-65 | keygen | 48.512 | 281.217 | 5.80 | - |
| ML-DSA-65 | sign | 153.006 | 991.558 | 6.48 | - |
| ML-DSA-65 | verify | 54.167 | 247.327 | 4.57 | - |
| ML-DSA-87 | keygen | 69.719 | 407.094 | 5.84 | - |
| ML-DSA-87 | sign | 172.875 | 1275.185 | 7.38 | - |
| ML-DSA-87 | verify | 75.730 | 419.090 | 5.53 | - |
| ECDSA-secp256k1 | keygen | - | - | - | 612.995 |
| ECDSA-secp256k1 | sign | - | - | - | 588.125 |
| ECDSA-secp256k1 | verify | - | - | - | 558.113 |
| Ed25519 | keygen | - | - | - | 61.706 |
| Ed25519 | sign | - | - | - | 56.787 |
| Ed25519 | verify | - | - | - | 143.639 |
