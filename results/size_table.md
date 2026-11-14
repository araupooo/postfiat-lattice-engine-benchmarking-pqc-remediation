# Size table (bytes)

FIPS 203 Table 3 (ML-KEM) and FIPS 204 Table 2 (ML-DSA), both
published 13 August 2024. Every measured size in this pack
matches the standard's table for its parameter set; the verdict
column is the check, not a claim.

| Algorithm | Implementation | Category | pk | sk | ct / sig | ss | FIPS pk | FIPS sk | FIPS ct / sig | FIPS ss | Verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-KEM-512 | liboqs | 1 | 800 | 1632 | 768 | 32 | 800 | 1632 | 768 | 32 | MATCH |
| ML-KEM-512 | pqclean | 1 | 800 | 1632 | 768 | 32 | 800 | 1632 | 768 | 32 | MATCH |
| ML-KEM-768 | liboqs | 3 | 1184 | 2400 | 1088 | 32 | 1184 | 2400 | 1088 | 32 | MATCH |
| ML-KEM-768 | pqclean | 3 | 1184 | 2400 | 1088 | 32 | 1184 | 2400 | 1088 | 32 | MATCH |
| ML-KEM-1024 | liboqs | 5 | 1568 | 3168 | 1568 | 32 | 1568 | 3168 | 1568 | 32 | MATCH |
| ML-KEM-1024 | pqclean | 5 | 1568 | 3168 | 1568 | 32 | 1568 | 3168 | 1568 | 32 | MATCH |
| ML-DSA-44 | liboqs | 2 | 1312 | 2560 | 2420 | - | 1312 | 2560 | 2420 | - | MATCH |
| ML-DSA-44 | pqclean | 2 | 1312 | 2560 | 2420 | - | 1312 | 2560 | 2420 | - | MATCH |
| ML-DSA-65 | liboqs | 3 | 1952 | 4032 | 3309 | - | 1952 | 4032 | 3309 | - | MATCH |
| ML-DSA-65 | pqclean | 3 | 1952 | 4032 | 3309 | - | 1952 | 4032 | 3309 | - | MATCH |
| ML-DSA-87 | liboqs | 5 | 2592 | 4896 | 4627 | - | 2592 | 4896 | 4627 | - | MATCH |
| ML-DSA-87 | pqclean | 5 | 2592 | 4896 | 4627 | - | 2592 | 4896 | 4627 | - | MATCH |

Classical, measured with OpenSSL 3.0.13 on the same host:

| Algorithm | pk | sk | sig |
|---|---|---|---|
| ECDSA-secp256k1 | 33 (compressed) | 32 | DER, at most 72 (this run: 71) |
| Ed25519 | 32 | 32 | 64 |
