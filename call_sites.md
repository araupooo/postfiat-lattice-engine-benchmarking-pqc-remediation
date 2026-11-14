# Measurement-to-call-site mapping

Every file:line citation below was read in the pinned tree
(postfiatd main, commit `0085a1ff885d6a446369cf73a4430f75af22be55`,
worktree `/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff`).
Every timing is a **measured** median from this pack
(`results/timing_table.csv`, `results/benchmark_*.json`); every size
is a **measured** value that matches FIPS 203 Table 3 / FIPS 204
Table 2 (see `results/size_table.csv`). Host: AMD EPYC 9D25, gcc
13.3.0, -O2; liboqs runs its x86_64 (AVX2) path, PQClean `clean` is
portable C, classical is OpenSSL 3.0.13.

## 1. Validation signing

| Item | Pinned-tree evidence | Measured cost (median) |
|------|----------------------|------------------------|
| Validation verification gate: secp256k1 only | `include/xrpl/protocol/STValidation.h:249-250` — `LogicError("We can only use secp256k1 keys for signing validations")`; deserialization gate at `:204` rejects a non-secp256k1 signing public key; `src/libxrpl/protocol/STValidation.cpp:128` asserts `publicKeyType(getSignerPublic()) == KeyType::secp256k1` and `:136-139` verifies via `verifyDigest` | secp256k1 verify **558.113 us** (OpenSSL); ML-DSA-65 verify **54.167 us** (liboqs) / **247.327 us** (PQClean clean); ML-DSA-44 verify **32.251 / 153.656 us**; ML-DSA-87 verify **75.730 / 419.090 us** |
| Validation signing (one sign per validation per ledger) | Signing passes through `sign()` / `signDigest()` in `src/libxrpl/protocol/SecretKey.cpp:230-295` (Ed25519: 64-byte signature; secp256k1: DER, at most 72 bytes) | secp256k1 sign **588.125 us**; ML-DSA-65 sign **153.006 us** (liboqs) / **991.558 us** (PQClean clean); ML-DSA-44 sign **99.789 / 623.758 us**; ML-DSA-87 sign **172.875 / 1275.185 us** |
| Key types available | `include/xrpl/protocol/KeyType.h:28-31` — only `secp256k1` and `ed25519` exist; no ML-DSA entry | — |

Consequence: a validator signs one validation per ledger and every
node verifies 66 validations per ledger. At the measured medians, the
per-ledger verification CPU for validations alone is 66 x 558.113 us
= **36.835 ms classical**, 66 x 54.167 us = **3.575 ms ML-DSA-65
(liboqs)**, 66 x 247.327 us = **16.324 ms ML-DSA-65 (PQClean clean)**.
ML-DSA-65 verification is 10.3x faster than secp256k1 verification
with liboqs on this host, and 2.3x faster even with the portable-C
reference — the opposite of the usual assumption that the
post-quantum scheme is the slow one. The reason is local to this
host: OpenSSL 3.0.13 has no specialized secp256k1 field arithmetic
(compare P-256 at 31.039 us/sign on the same host, measured during
authoring with the same method in a minimal OpenSSL program;
secp256k1 measured 559.471 us/sign there, 588.125 us/sign in the
shipped driver), and
the CPU runs at ~1.5 GHz. Production validator hardware will differ;
the ratio, not the absolute, is the portable part.

## 2. Consensus proposal signing (the 72-byte cap)

| Item | Pinned-tree evidence | Measured cost (median) |
|------|----------------------|------------------------|
| Proposal signing | `src/xrpld/app/consensus/RCLConsensus.cpp:241` — `signDigest(keys.publicKey, keys.secretKey, proposal.signingHash())` | secp256k1 sign **588.125 us**; ML-DSA-65 sign **153.006 / 991.558 us** |
| Fixed 72-byte signature buffer | `src/xrpld/app/consensus/RCLCxPeerPos.h:110` — `boost::container::static_vector<std::uint8_t, 72> signature_`; constructor assertion `src/xrpld/app/consensus/RCLCxPeerPos.cpp:37-44` ("The maximum allowed size of a signature is 72 bytes") | ML-DSA-44 signature **2,420 B**; ML-DSA-65 **3,309 B**; ML-DSA-87 **4,627 B** — none fits in 72 bytes |
| Inbound proposal size check | `src/xrpld/overlay/detail/PeerImp.cpp:1791-1799` — rejects any proposal signature outside 64-72 bytes ("A DER encoded signature can't be longer than 72 bytes") and requires a secp256k1 node public key | — |
| Proposal verification | `src/xrpld/app/consensus/RCLCxPeerPos.cpp` `checkSign()` verifies via `verifyDigest` | secp256k1 verify **558.113 us**; ML-DSA-65 verify **54.167 / 247.327 us** |

Consequence: with 2 proposal rounds per ledger, each node verifies
132 proposals per ledger in addition to 66 validations (198
verifications per ledger per node; see `results/cost_model.json`).
The 72-byte cap is the hardest single blocker for ML-DSA proposals:
it must be lifted in all three places before any ML-DSA proposal can
flow, and the lift is inert while all signatures are still classical.

## 3. Key generation

| Item | Pinned-tree evidence | Measured cost (median) |
|------|----------------------|------------------------|
| Secret-key generation from seed | `src/libxrpl/protocol/SecretKey.cpp:309-327` — `generateSecretKey(KeyType type, Seed const& seed)`: Ed25519 = SHA-512 half of the seed; secp256k1 = deterministic root-key derivation; unknown type is a `LogicError` | secp256k1 keygen **612.995 us** (OpenSSL, includes parameter generation); Ed25519 keygen **61.706 us**; ML-DSA-65 keygen **48.512 us** (liboqs) / **281.217 us** (PQClean clean); ML-DSA-44 **28.804 / 143.221 us**; ML-DSA-87 **69.719 / 407.094 us** |
| Validator key loading | `src/xrpld/app/misc/detail/ValidatorKeys.cpp:40-95` — `[validator_token]` (manifest + validation secret; derived key must equal the manifest signing key) or `[validation_seed]` (same key as master and signing key, sequence 0, no rotation path); key generation at `:84-85` (`generateSecretKey` + `derivePublicKey`, secp256k1) | ML-KEM keygen is not used on this path today; for scale, ML-KEM-768 keygen is **15.358 us** (liboqs) / **98.814 us** (PQClean clean) |
| Manifest binding | `src/xrpld/app/misc/Manifest.h` / `src/xrpld/app/misc/detail/Manifest.cpp:411` — a manifest with sequence <= stored is rejected; `:226-240` — sequence `0xFFFFFFFF` (max uint32) means the master key is revoked | — |

Consequence: key generation is a rare, offline operation (startup /
rotation), not a per-ledger cost. At the measured medians, generating
an ML-DSA-65 key pair costs less than generating a secp256k1 key pair
with this OpenSSL on this host (48.512 us vs 612.995 us, liboqs).
Key generation is not a migration blocker for any parameter set.

## 4. TLS handshake (peer overlay)

| Item | Pinned-tree evidence | Measured cost (median) |
|------|----------------------|------------------------|
| Cipher list / TLS minimum | `src/libxrpl/basics/make_SSLContext.cpp:104` — default cipher list `"TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL"`; `:356-357` disables TLS 1.0 and 1.1, so TLS 1.2 is the minimum; `:347-367` applies the list via `SSL_CTX_set_cipher_list` | — |
| ML-KEM cost per handshake (one ephemeral keygen + one encaps + one decaps) | No ML-KEM code exists in the pinned tree; the mapping is the cost a hybrid TLS 1.3 key exchange (e.g. X25519MLKEM768) would add | ML-KEM-768: keygen **15.358 us** + encaps **16.154 us** + decaps **19.673 us** = **51.185 us** (liboqs); **98.814 + 105.639 + 133.537 = 337.990 us** (PQClean clean). ML-KEM-512: **33.135 us** (liboqs) / **214.487 us** (PQClean); ML-KEM-1024: **67.489 us** (liboqs) / **509.241 us** (PQClean) |
| Classical handshake baseline | The pinned OpenSSL is 1.1.1w (no ML-KEM/ML-DSA); system OpenSSL here is 3.0.13 (also no native ML-KEM/ML-DSA) | NOT MEASURED as a full handshake — no TLS handshake was run. Only the KEM operations above were measured. The X25519 half of a hybrid exchange was not measured. |

Consequence: the lattice half of a hybrid TLS handshake costs
~50 us (liboqs) to ~334 us (PQClean clean) per handshake for
ML-KEM-768 — negligible against a network round trip. The TLS
migration is gated on the OpenSSL upgrade (3.5+ for native ML-KEM),
not on KEM performance.

## 5. Amendment and quorum mechanics the remediation relies on

| Item | Pinned-tree evidence |
|------|----------------------|
| Post-fix majority threshold 67% | `include/xrpl/protocol/SystemParameters.h:85` — `postFixAmendmentMajorityCalcThreshold` = 67/100 |
| 2-week majority hold | `include/xrpl/protocol/SystemParameters.h:88` — `defaultAmendmentMajorityTime` = 2 weeks |
| Validation quorum | `src/xrpld/app/misc/detail/ValidatorList.cpp:1934` — `max(ceil(effectiveUnlSize x 0.67), ceil(unlSize x 0.6))`; comment at `:1898-1900` notes the 67% choice |
| Vote expiry | `src/xrpld/app/misc/detail/AmendmentTable.cpp:167-172` — votes expire 24 h after a validator's last validation |
| Amendment enable / halt | `src/xrpld/app/misc/detail/AmendmentTable.cpp:762-781` (`enable()` sets `unsupportedEnabled_` for unsupported amendments; no code path clears it); `src/xrpld/app/tx/detail/Change.cpp:364-368` (unsupported amendment activated: "server blocked"); `src/xrpld/app/ledger/detail/LedgerMaster.cpp:309-314` (re-checked at every ledger close) |
| Veto | `src/xrpld/rpc/handlers/Feature1.cpp:78-87` (admin-only `feature` RPC with `vetoed: true`); `src/xrpld/app/misc/detail/AmendmentTable.cpp:723-761` (`veto()` / `persistVote()`) |
| Validator-list refresh | `src/xrpld/app/misc/detail/ValidatorSite.cpp:34-35` — 5-minute default refresh, 30-second retry on error |
| Voting gate | `src/xrpld/app/consensus/RCLConsensus.cpp:371` — `doVoting` runs only when trusted validations reach the node's quorum |

## 6. What was NOT measured

- No full TLS handshake was run (only the ML-KEM operations a
  handshake would perform).
- No secp256k1 timing was taken from postfiatd itself (the daemon
  was not compiled or run); the classical baseline is OpenSSL
  3.0.13's secp256k1 on the same host and toolchain, which is the
  library the pinned tree's cryptography ultimately depends on for
  its secp256k1 implementation.
- OpenSSL 3.5 was not measured: it did not build in the time
  available on this host (see the claim index). The third
  implementation is therefore NOT MEASURED, not estimated.
