# Post-quantum remediation assessment for the PFTL core protocol

How the core protocol moves from secp256k1-only consensus signatures
to hybrid classical + ML-DSA signatures, and from classical-only TLS
to hybrid ML-KEM key exchange — anchored to the lattice benchmarks
measured in this pack, not to published estimates. Pinned tree:
postfiatd main commit `0085a1ff885d6a446369cf73a4430f75af22be55`.
Every file:line citation below was read in that tree. Every number is
labelled **measured** (from the benchmark drivers in this pack,
`results/benchmark_*.json`, `results/timing_table.csv`,
`results/cost_model.json`), **derived** (arithmetic from measured
medians plus the sibling cost model's network inputs — the source is
named), or **source-derived** (from a cited pack or standard, not
measured here). Nothing in this document is a published estimate
presented as a measurement.

## 0. What is being mitigated, and what the measurements change

The consensus path signs and verifies with secp256k1 only. The
verification gate is explicit: `include/xrpl/protocol/STValidation.h:249-250`
(`LogicError("We can only use secp256k1 keys for signing validations")`),
with the deserialization gate at `:204` and the `isValid()` assertion
at `src/libxrpl/protocol/STValidation.cpp:128`. The key-type enum has
only `secp256k1` and `ed25519` (`include/xrpl/protocol/KeyType.h:28-31`).
A quantum adversary that breaks secp256k1 can therefore forge any
validation and any proposal, and one forged validation is one forged
amendment vote.

The threshold arithmetic is unchanged by this design and is taken
source-derived from the sibling amendment-state probe pack (N=66
validators, live 67% rule): forcing an amendment to a majority takes
45 broken validator keys, blocking a unanimous yes vote takes 22.
The migration does not change those numbers; it changes what
"broken" costs — from "break secp256k1" to "break secp256k1 **and**
ML-DSA-65".

Two measured facts shape this design, and both differ from the
published-estimate picture the earlier migration pack worked with:

1. **On this host, the classical scheme is the slow one.** Measured
   medians (OpenSSL 3.0.13, same host and toolchain as the lattice
   measurements): secp256k1 sign **588.125 us**, verify **558.113 us**.
   ML-DSA-65 verify is **54.167 us** (liboqs, 10.3x faster) and
   **247.327 us** (PQClean clean reference, 2.3x faster); ML-DSA-65
   sign is **153.006 us** (liboqs, 3.8x faster) and **991.558 us**
   (PQClean clean, 1.7x slower). The earlier pack's published
   estimates were secp256k1 verify 95.1 us and ML-DSA-65 verify
   47.43 us — the ML-DSA side roughly matches the measurement, but
   the classical side is 5.9x slower than the estimate on this host
   (OpenSSL 3.0.13 has no specialized secp256k1 field arithmetic;
   P-256 signs in 31.039 us on the same host, measured during
   authoring with the same method). Production validator hardware
   will differ; the ratio, not the absolute, is the portable part.
   The consequence stands on either implementation: ML-DSA
   verification is not the bottleneck, and the dual phase's CPU cost
   is dominated by the classical half (91.2% of dual-phase verify
   CPU, derived from the measured medians).
2. **Bandwidth is the cost, and it is ~51x.** A dual classical +
   ML-DSA-65 object carries 5,365 signature-related bytes (33-byte
   compressed public key + 71-byte DER signature + 1,952-byte
   ML-DSA-65 public key + 3,309-byte signature) against 104 bytes
   classical — 51.6x (derived). Per ledger per node at N=66 with 2
   proposal rounds (198 verifications): classical 20,592 B, dual
   1,062,270 B, pure ML-DSA-65 1,041,678 B (derived,
   `results/cost_model.json`). Per day at a 4 s close: 0.44 GB
   classical, 22.95 GB dual, 22.50 GB pure ML-DSA-65; re-scaled to
   the sibling pack's measured 3.03 s mean close: 0.59 GB, 30.29 GB,
   29.70 GB (derived).

## 1. Hybrid classical + ML-DSA validation signatures

### 1.1 Parameter choice: ML-DSA-65

FIPS 204 Table 2 (sizes, measured to match in this pack):

| Set | Category | Public key | Private key | Signature |
|-----|----------|-----------|-------------|-----------|
| ML-DSA-44 | 2 | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | 3 | 1,952 B | 4,032 B | 3,309 B |
| ML-DSA-87 | 5 | 2,592 B | 4,896 B | 4,627 B |

**ML-DSA-65 is the migration target**, and the measurements support
it rather than merely tolerating it. Measured verify medians
(liboqs): ML-DSA-44 **32.251 us**, ML-DSA-65 **54.167 us**, ML-DSA-87
**75.730 us**. ML-DSA-65 costs 68% more verify CPU than ML-DSA-44
and 28% less than ML-DSA-87, for the middle security category (3) —
the general-purpose default. ML-DSA-44 matches the classical security
level the network already has and lands the migration on the minimum;
ML-DSA-87 costs 33% larger keys and 40% larger signatures for a
category the consensus path does not need — a validation is useful
for one ledger close, a few seconds. With the PQClean clean
reference the ordering is the same (153.656 / 247.327 / 419.090 us),
so the choice does not depend on which implementation ships.
ML-DSA-65 key generation takes a 32-byte random seed (FIPS 204 §6),
so the existing 32-byte-seed backup practice for classical keys
carries over, with the parameter set recorded alongside the seed.

### 1.2 Dual-sign design

Each validation carries **two** signatures over the same signing
hash:

1. The classical secp256k1 signature in the existing `sfSignature`
   field, verified exactly as today.
2. An ML-DSA-65 signature in a new field, verified by upgraded
   nodes only.

Verification policy by node version during the dual phase:

- Old nodes verify the classical signature and ignore the new
  field. They keep counting the validator toward quorum.
- New nodes verify **both** signatures and reject the validation if
  either fails. A validation with a forged classical half fails on
  both; a validation with a forged ML-DSA half fails on new nodes
  only.

The same dual structure applies to proposals, which carry the same
signing hash (`src/xrpld/app/consensus/RCLConsensus.cpp:241`,
`signDigest(keys.publicKey, keys.secretKey, proposal.signingHash())`)
and the same 72-byte cap problem (§1.4). The vote itself rides
inside the validation, so a dual-signed validation is a dual-signed
amendment vote: the migration bootstraps its own evidence.

What the second signature must be bound to: the same signing hash
as the classical signature, so that a valid pair cannot be split
across two different validations. Whether the proposal suppression
ID is computed over the classical signature only or over both
signatures is UNVERIFIED as a design decision (see §6, open question
OQ-3): including the second signature makes old and new nodes
compute different suppression IDs for the same proposal; excluding
it leaves the second signature outside the suppression key. The
choice needs an explicit decision and a test before the dual phase
ships.

### 1.3 Sizes and costs at N=66

All figures below are **derived** from the measured medians in this
pack (`results/cost_model.json`) at N=66 validators, 2 proposal
rounds per ledger, 4 s close — 198 signature verifications per
ledger per node (66 validations + 132 proposals). Network inputs
(N, rounds, close) are source-derived from the sibling
consensus-signature migration pack's cost model (v1.0.0). The 3.03 s
figures re-scale the same model to the sibling amendment-state
probe's measured mean close interval.

Per ledger per node (verify CPU):

| Scenario | Verify CPU (liboqs) | % of 4 s close | Verify CPU (PQClean clean) | % of 4 s close |
|----------|--------------------|----------------|---------------------------|----------------|
| Classical (secp256k1) | 110.506 ms | 2.763% | — (same classical) | 2.763% |
| ML-DSA-65 | 10.725 ms | 0.268% | 48.971 ms | 1.224% |
| Dual (classical + ML-DSA-65) | 121.231 ms | 3.031% | 159.477 ms | 3.987% |

Per ledger per node (signature-related bytes: public key + signature
per verified object):

| Scenario | Bytes / ledger | Bytes / day (4 s close) | Bytes / day (3.03 s close) |
|----------|---------------|------------------------|---------------------------|
| Classical | 20,592 B | 0.44 GB | 0.59 GB |
| ML-DSA-65 | 1,041,678 B | 22.50 GB | 29.70 GB |
| Dual | 1,062,270 B | 22.95 GB | 30.29 GB |

Signing cost per validation for the signing validator (3 signs per
ledger: 1 validation + 2 proposals, derived): classical 1.764 ms,
ML-DSA-65 (liboqs) 0.459 ms, dual 2.223 ms.

Three consequences:

1. **CPU is not the bottleneck — and the classical half is the
   expensive part.** Even the dual phase costs under 3% of a ledger
   close on this host with either implementation, and 91.2% of that
   is the classical half. After activation, pure ML-DSA-65 costs
   0.268% (liboqs) — **10x less** verify CPU than classical today.
   No consensus-timing change is needed.
2. **Bandwidth is the cost.** ML-DSA-65 carries ~50x the
   signature-related bytes of classical per ledger. Operators must
   provision for ~23-30 GB/day/node of signature-related traffic
   during the dual phase, against ~0.44-0.59 GB/day today.
3. **Storage is not the cost.** Validations are ephemeral — they are
   not stored as ledger objects — so the size growth is bandwidth
   plus in-memory validation cache, not permanent ledger storage.
   Manifests are the only durable objects that grow (§1.5).

### 1.4 What changes in the validation format and the proposal cap

Four code changes, all in the pinned tree, all verified by reading:

1. **Key-type dispatch.** `KeyType` has only `secp256k1` and
   `ed25519` (`include/xrpl/protocol/KeyType.h:28-31`). Add an
   ML-DSA entry, and teach the length-based `publicKeyType()`
   dispatch (`src/libxrpl/protocol/PublicKey.cpp:224`) to recognise
   a 1,952-byte ML-DSA-65 public key. The encoding of the new key
   type (new prefix byte vs length rule vs explicit type field) is
   UNVERIFIED as a design decision (see §6, OQ-1).
2. **Validation signing gate.** Validations are gated to secp256k1
   in two places: the signing constructor
   (`include/xrpl/protocol/STValidation.h:249-250`,
   `LogicError("We can only use secp256k1 keys for signing
   validations")`) and the deserialization gate
   (`include/xrpl/protocol/STValidation.h:204`, which throws on a
   non-secp256k1 signing public key). Both need an ML-DSA branch,
   and the validation format needs a second signature field for the
   ML-DSA signature. The classical `sfSignature` field is untouched,
   so old nodes parse dual-signed validations exactly as before —
   **provided** old nodes ignore unknown fields on deserialization,
   which is UNVERIFIED (see §6, OQ-2). If old nodes reject unknown
   fields, the dual phase forks the network instead of migrating
   it; this must be confirmed by reading the deserializer before any
   dual-signed validation ships.
3. **The 72-byte proposal cap.** Proposals store their signature in
   a fixed 72-byte buffer
   (`src/xrpld/app/consensus/RCLCxPeerPos.h:110`,
   `boost::container::static_vector<std::uint8_t, 72>`), enforced by
   a constructor assertion
   (`src/xrpld/app/consensus/RCLCxPeerPos.cpp:37-44`, "The maximum
   allowed size of a signature is 72 bytes") and by an inbound size
   check that rejects any proposal signature outside 64-72 bytes
   (`src/xrpld/overlay/detail/PeerImp.cpp:1791-1799`, "A DER encoded
   signature can't be longer than 72 bytes"). All three must be
   lifted before any ML-DSA proposal can flow — to a size that fits
   the largest ML-DSA signature plus headroom (8 KiB covers
   ML-DSA-87 at 4,627 B). Lift the caps **before** any ML-DSA
   signature exists on the network: the change is inert while all
   signatures are still classical, and it removes the hardest
   blocker early. The 8 KiB figure is a design choice, not a
   measured limit.
4. **Shared signing primitives and the OpenSSL gate.** All
   consensus-path signing and verification passes through `sign()` /
   `verify()` / `signDigest()` / `verifyDigest()` in
   `src/libxrpl/protocol/SecretKey.cpp` and
   `src/libxrpl/protocol/PublicKey.cpp`. The ML-DSA branch must be
   additive: transaction signature verification shares these
   primitives, so the classical branches stay untouched. The pinned
   OpenSSL is **1.1.1w** (`conanfile.py:30`), which has no ML-DSA
   (ML-DSA arrived in OpenSSL 3.5); upgrading the pinned OpenSSL to
   3.5 or later — or vendoring liboqs 0.16.0, which is what this
   pack measured — is the gating prerequisite, a build-system
   change, not a protocol change. Note the system OpenSSL on the
   measurement host is 3.0.13, which also has no native ML-KEM or
   ML-DSA; the OpenSSL 3.5 third implementation is NOT MEASURED in
   this pack.

### 1.5 Manifests

A dual-key manifest vouches for both signing keys under the same
master key. Manifest sizes (derived): classical 177 B of
signature-related material (source-derived, sibling migration pack);
dual (classical + ML-DSA-65) **5,365 B** (derived: 1,985 B public
keys + 3,309 B ML-DSA ephemeral signature + 72 B classical master
signature — the ML-DSA-65 signature size is measured here, the
classical sizes are source-derived). Manifests are published once
per rotation, not per ledger, so this is a one-off cost per
validator per rotation, not a recurring cost. This design keeps the
classical master key (§2.6), so the dual-manifest figure above is
the correct one for phases 1-3.

### 1.6 What stays unchanged

- **Quorum and amendment thresholds.** Vote counting is
  scheme-agnostic: it counts validators, not signature schemes.
  Validation quorum stays `max(ceil(UNL x 0.67), ceil(UNL x 0.6))`
  (`src/xrpld/app/misc/detail/ValidatorList.cpp:1934`); at N=66
  that is 45. The amendment minimum stays 45 of 66 under the live
  67% rule (source-derived, sibling probe).
- **The 2-week hold.** `defaultAmendmentMajorityTime` stays 2 weeks
  (`include/xrpl/protocol/SystemParameters.h:88`); the hold branch
  stays `majorityTime + 2 weeks <= closeTime`.
- **The ledger as authority.** Enabled amendments and majority
  timestamps are read from the validated ledger's amendment entry,
  not from any node's local table. The amendment pseudo-transaction
  gate — injected only when trusted validations reach the node's
  quorum (`src/xrpld/app/consensus/RCLConsensus.cpp:371`) — is
  untouched.
- **The veto.** The per-node, admin-only veto
  (`src/xrpld/rpc/handlers/Feature1.cpp:78-87`) is unchanged and
  remains the per-node defence (§4.3).

## 2. Key rotation and revocation procedures

### 2.1 The two keys, and which one rotates

A validator has a **master key** (permanent identity, signs
manifests, never signs validations) and an **ephemeral signing key**
(signs validations), bound by a **manifest**: master public key,
ephemeral signing public key, sequence number, optional domain, and
signatures from both keys. `ManifestCache` stores, per trusted
validator, the most senior valid manifest it has seen, and a manifest
with a sequence number less than or equal to the stored one is
rejected (`src/xrpld/app/misc/detail/Manifest.cpp:411`).

Key material is loaded in exactly one of two configuration forms
(`src/xrpld/app/misc/detail/ValidatorKeys.cpp:40-95`):

- `[validator_token]` — a base64 manifest plus a validation secret.
  The derived secp256k1 public key must equal the manifest's
  signing key or the node fails to start (`:47-59`). This is the
  form that supports rotation.
- `[validation_seed]` — a base58 seed from which the same key is
  used as both master and signing key (`:84-85`,
  `keys.emplace(pk, pk, sk)`, sequence 0). There is no manifest and
  **no rotation path**: rotating the key changes the validator
  identity. Any validator still on the seed form must migrate to
  the token form before it can rotate.

### 2.2 Rotating a signing key without changing the master key

1. Generate the new signing key pair and a new manifest **offline**
   with the master key, sequence = old sequence + 1. The master key
   never leaves the offline machine. For an ML-DSA-65 signing key,
   generation costs **48.512 us** (liboqs, measured) — key
   generation is not a cost factor in rotation.
2. Publish the new manifest to the validator-list site / gossip
   network **at least 7 days before** activating it, and verify it
   is visible on peers before proceeding. The validator keeps
   signing with the old key in the meantime, because it has not
   restarted with the new token.
3. Restart the validator with the new `[validator_token]`. From
   that moment it signs only with the new key, which peers already
   trust.
4. Confirm the validator's validations are accepted before the next
   batch rotates.

The 7-day overlap is an operational procedure, not a protocol
feature: the pinned code has no dual-signing state — a manifest
carries exactly one signing key, and a higher-sequence manifest
supersedes the old key as soon as a peer sees it. The rotation
schedule (source-derived, sibling validator key lifecycle pack,
56 simulated days, N=66) staggers rotation in weekly batches of
~1/8 of the validators (9 of 66 per week), completing a full set
rotation in 8 weeks. With a 7-day overlap the simulation shows
**zero** days without a trusted key even if propagation takes 7
days; with no overlap, a 2-day propagation delay leaves each
rotating validator without a trusted key for 2 days. A single bad
batch (9 validators) leaves 57 signing validators: margin 12 above
the 45 quorum at the 67% rule. A 7-day single-validator outage
leaves quorum intact with margin 20 at 67% (source-derived, same
simulation).

### 2.3 Revocation

A master key is revoked by a manifest with sequence number
`0xFFFFFFFF` (the maximum `uint32_t`), carrying no signing key
(`src/xrpld/app/misc/detail/Manifest.cpp:226-240`). Once peers see
it, no validation from that master key is accepted, and **no
further manifest for that master key is ever accepted**, because no
higher sequence number exists — the identity is permanently dead.
Recovery means creating a new validator identity (new master key)
and getting it added to UNL publisher lists; that is a coordination
task, not a key operation. Revocation is the response to a
compromised **master** key. A compromised **signing** key alone is
handled by rotation (§2.2), not revocation, because the master key
is still safe. For the ML-DSA migration, a compromised ML-DSA
signing key is likewise handled by rotation (publish a higher-
sequence manifest with a fresh ML-DSA key); revocation is reserved
for the classical master key.

### 2.4 UNL update procedure

Trust is distributed through validator-list sites, fetched on a
5-minute default refresh interval with a 30-second retry on error
(`src/xrpld/app/misc/detail/ValidatorSite.cpp:34-35`). Adding or
removing a validator from the trusted set is therefore a publisher
operation, not a protocol operation:

- To add a validator (including a new identity after a revocation):
  the UNL publisher adds the validator's master public key to its
  list; nodes pick it up on the next fetch, minutes later in the
  normal case.
- To remove a validator: the publisher removes the key; removal
  propagates on the next list fetch. The absolute minimum quorum
  floor is 60% of the original UNL size
  (`src/xrpld/app/misc/detail/ValidatorList.cpp:1934`), so exclusion
  never drops the quorum below that floor.
- Multi-day propagation delays are stress cases (validator-list
  site outage, partition), not the normal case. The rotation
  schedule in §2.2 is built on the 5-minute baseline.

### 2.5 In-flight votes during rotation

- A validator's amendment vote is its desired list — the amendments
  it supports, does not veto, and that are not already enabled —
  attached to its validation. Rotation changes the validator's
  **key**, not its desired list, so a rotating validator votes the
  same way before and after.
- Votes expire 24 hours after a validator's last validation
  (`src/xrpld/app/misc/detail/AmendmentTable.cpp:167-172`,
  `expiresAfter = 24h`). A validator offline for a full day has no
  live amendment vote. A validator that restarts with a new key
  resumes voting as soon as peers trust the new manifest; its
  recorded vote in the meantime is the stale one, expiring after 24
  hours.
- While a higher-sequence manifest propagates, peers that have seen
  it reject validations signed with the old key (sequence check,
  `src/xrpld/app/misc/detail/Manifest.cpp:411`); peers that have not
  seen it still accept the old key. There is no instant in which a
  correctly executed rotation leaves the validator with **no**
  trusted key, provided the new manifest was published before
  activation (§2.2, 7-day overlap).
- The tally is re-computed every flag ledger from the latest trusted
  validations, and `doVoting` runs only when trusted validations
  reach the node's quorum (`src/xrpld/app/consensus/RCLConsensus.cpp:371`).
  A rotation batch of 9 cannot move the tally by more than 9 votes,
  and cannot break quorum (§2.2 margins).
- During the dual-sign phase (§3, phase 1), a validator mid-rotation
  is either classical-only (old manifest) or dual-signed (new
  manifest). Old nodes count both; new nodes count both, verifying
  whichever signatures are present. The dangerous configuration is
  a validator that drops its classical signature while old nodes
  still need it — that is phase 3, gated behind the activation
  amendment, not a rotation step.

### 2.6 The master key itself

This design migrates the **ephemeral signing key** (the key that
signs validations and proposals). The master key stays classical
secp256k1 through phases 1-3: it signs manifests only, rarely, and
offline. That is a deliberate sequencing choice, not an oversight,
and it has a cost: until the master key migrates, a quantum
adversary that breaks secp256k1 can forge a manifest for any
validator whose master public key it has harvested. The mitigations
are rotation discipline (§2.2: a forged manifest still needs a
higher sequence number than the operator's last issued one, so
sequence monitoring in §5 detects it) and, as a later step, a
post-quantum master key. The conservative choice for the long-lived
master key is SLH-DSA (hash-only security assumption), at
7,856-49,856-byte signatures (source-derived, FIPS 205), which are
acceptable for the rare manifest-signing operation. ML-DSA is also
a candidate for the master key. The master-key migration is a
separate design with a separate threat model and is not specified
here.

## 3. Phased costs

Phase numbering: phase 0 is the inventory this pack completes;
phase 1 is dual-sign opt-in; phase 2 is the activation amendment;
phase 3 is classical retirement. Costs are per node unless stated
otherwise. Bandwidth is signature-related bytes (public key +
signature) per ledger; CPU is verification CPU per ledger. All cost
figures are **derived** from the measured medians in this pack
(`results/cost_model.json`) at N=66, 2 proposal rounds, 4 s close,
unless labelled otherwise.

### Phase 0 — Inventory (done, this pack)

- What it is: the benchmark harness, the measured timing and size
  tables for every ML-KEM and ML-DSA parameter set from two
  independent implementations plus a measured classical baseline,
  the call-site mapping, and this assessment.
- Cost: zero network-visible change. No bandwidth, CPU, or storage
  cost. The inventory is the baseline every later phase is measured
  against.

### Phase 1 — Dual-sign opt-in

- What it is: validators generate an ML-DSA-65 key pair alongside
  their secp256k1 key, publish a dual-key manifest (higher sequence
  number), and start attaching both signatures to every validation
  and proposal. Old nodes verify the classical signature and ignore
  the new field; new nodes verify both. Opt-in is per validator:
  dual-signed validators count toward quorum for old and new nodes
  alike, so this phase costs nothing in quorum terms.
- Prerequisites (no network-visible change): upgrade the pinned
  OpenSSL to 3.5 or later, or vendor liboqs 0.16.0 (measured here);
  extend key-type dispatch and the signing primitives with an
  ML-DSA branch; lift the 72-byte proposal caps (§1.4); extend the
  offline `validator-keys` tool to generate ML-DSA key pairs and
  sign ML-DSA manifests.
- Bandwidth: 1,062,270 B/ledger (dual row) vs 20,592 B/ledger
  classical — 51.6x. Per day: 22.95 GB vs 0.44 GB at a 4 s close;
  30.29 GB vs 0.59 GB re-scaled to the measured 3.03 s close
  (derived).
- CPU: 121.231 ms/ledger verify with liboqs (3.031% of a 4 s close),
  159.477 ms/ledger with the PQClean clean reference (3.987%),
  vs 110.506 ms classical (2.763%). Signing per validation ≈ 2.223
  ms for the 3 signs a validator performs per ledger (derived).
  CPU is not the binding cost, and the classical half is 91.2% of
  the dual-phase verify CPU on this host.
- Storage: ≈ zero durable growth (validations are ephemeral).
  Manifests grow once per rotation: dual manifest 5,365 B vs
  classical 177 B (derived, §1.5).
- Exit criteria: a majority of validators have published dual-key
  manifests; dual-signed objects are a stable majority of observed
  validations/proposals; no increase in dropped proposals or
  validation failures attributable to the new field. Rollback:
  validators stop attaching the ML-DSA signature (a local
  configuration change); a bad dual-key manifest is replaced by a
  higher-sequence classical-only manifest (§2.2).

### Phase 2 — Activation amendment

- What it is: an amendment that flips verification policy — from
  its activation ledger onward, a validation or proposal from a
  validator with a dual-key manifest is valid **only if** its
  ML-DSA signature verifies. The classical signature may still be
  present but is no longer sufficient on its own.
- Activation uses the existing amendment mechanics, unchanged: the
  amendment needs a majority of trusted validators voting for it —
  **45 of 66** under the live 67% rule (source-derived, sibling
  probe) — and must hold that majority for **2 weeks** before it
  enables (`include/xrpl/protocol/SystemParameters.h:85,88`). The
  2-week hold is the network's notice period: it is the window in
  which laggard operators must upgrade or lose the ability to
  validate. The amendment vote itself rides inside validations, so
  the vote for the migration is itself dual-signed.
- Bandwidth: unchanged from phase 1 during the hold (dual row,
  1,062,270 B/ledger). After activation, validators may stop
  attaching the classical signature: cost drops to the pure
  ML-DSA-65 row, 1,041,678 B/ledger (22.50 GB/day at a 4 s close;
  29.70 GB/day at the measured 3.03 s close).
- CPU: after activation, 10.725 ms/ledger verify with liboqs
  (0.268% of a 4 s close) — **10x less** than the classical
  110.506 ms, because ML-DSA verification is faster than secp256k1
  verification on this host (measured). With the PQClean clean
  reference, 48.971 ms/ledger (1.224%) — still less than half the
  classical cost.
- Storage: ≈ zero durable growth.
- Exit criteria: amendment enabled; ML-DSA-only validations are
  accepted; classical-only validations from dual-key validators
  are rejected. Rollback before enablement: veto the amendment
  (§4.3). Rollback after enablement: none through the amendment
  mechanism (§4.1).

### Phase 3 — Classical retirement

- What it is: a second amendment removes the classical signature
  requirement entirely and allows nodes to drop classical
  verification for validators that have migrated. Old
  (pre-migration) nodes can no longer verify any validation or
  proposal and fall out of consensus — by this point that is
  intended, and it is why phases 1-2 give them a dual-signature
  window plus a 2-week amendment hold to upgrade.
- Bandwidth: pure ML-DSA-65 row, 1,041,678 B/ledger (22.50 GB/day
  at a 4 s close). No further reduction is available from this
  design: the ML-DSA signature is the floor.
- CPU: 10.725 ms/ledger verify with liboqs (0.268% of a 4 s close).
- Storage: manifests may drop the classical signing key at the next
  rotation; an ML-DSA-only manifest with a classical master key is
  5,333 B (derived: 1,952 + 3,309 + 72). The master key itself is a
  separate decision (§2.6).
- Exit criteria: no classical-only validator remains in the trusted
  set; the 72-byte proposal caps and the classical branches in the
  shared primitives are dead code pending removal (removal itself
  is a separate, later change).
- Rollback after enablement: none (§4.1). Forward-only.

### Cost summary

| Phase | Bandwidth / ledger | CPU / ledger (liboqs) | Durable storage |
|-------|-------------------|----------------------|-----------------|
| 0 inventory | 20,592 B (classical) | 110.506 ms | — |
| 1 dual-sign opt-in | 1,062,270 B | 121.231 ms | +5,189 B per dual manifest |
| 2 activation (after) | 1,041,678 B | 10.725 ms | — |
| 3 retirement | 1,041,678 B | 10.725 ms | — |

All figures derived from the measured medians in this pack at N=66,
2 proposal rounds, 4 s close. The phase-1 bandwidth peak (51.6x
classical) is the cost the network pays for the whole dual-sign
window; it is the price of keeping old nodes in consensus while
new nodes gain quantum resistance. The phase-1 CPU peak (3.031% of
a close) is dominated by the classical half; the migration's steady
state is cheaper in CPU than the network it replaces.

### TLS: hybrid ML-KEM key exchange

Separately from consensus signatures, the peer overlay's TLS
handshake migrates to a hybrid classical + ML-KEM key exchange.
Measured cost per handshake for ML-KEM-768 (one ephemeral keygen +
one encaps + one decaps, medians): **51.185 us** (liboqs) /
**337.990 us** (PQClean clean). ML-KEM-512: 33.135 / 214.487 us;
ML-KEM-1024: 67.489 / 509.241 us. Against a network round trip,
the lattice half of the handshake is negligible at any parameter
set. The gate is the same OpenSSL upgrade as §1.4 item 4 (native
ML-KEM arrives in OpenSSL 3.5; the pinned tree uses 1.1.1w and the
measurement host uses 3.0.13, neither of which has it). No full TLS
handshake was measured; the X25519 half of a hybrid exchange was
not measured. The TLS migration is independent of the consensus
migration and can ship in either order.

## 4. Rollback notes

### 4.1 After the activation amendment, there is no protocol rollback

An enabled amendment stays enabled. The `enable()` path
(`src/xrpld/app/misc/detail/AmendmentTable.cpp:762-781`) sets
`s.enabled = true` and, for an unsupported amendment, sets
`unsupportedEnabled_ = true`; there is no production code path that
clears an enabled amendment or clears the blocked flag. Recovery
after a bad activation is therefore **forward-only**: fix the ML-DSA
implementation and ship a new version, or (extreme) coordinate a
validator-set restart. This is why the 2-week hold and the
dual-signature soak in phase 1 must be treated as the real safety
net, not the amendment mechanism. The same applies to phase 3:
forward-only.

Rollback is cheap and local until the activation amendment enables,
and effectively unavailable after it:

| Situation | Rollback |
|-----------|----------|
| Phase 0 fails | Nothing shipped; no network impact. |
| Phase 1: bad dual-key manifest | Publish a higher-sequence manifest with only the classical key (§2.2). |
| Phase 1: dual signatures cause failures | Validators stop attaching the ML-DSA signature (local config). Old nodes never depended on it. |
| Phase 2: amendment voted but not yet enabled | Veto it (§4.3). |
| Phase 2: amendment enabled, migration broken | **No protocol rollback.** Fix forward: ship a corrected implementation, or coordinate a validator-set restart. |
| Phase 3 | Same as above: forward-only. |

### 4.2 What happens to nodes that do not support the amendment

When the activation amendment (or any amendment) enables, a node
that does not support it halts. The mechanism is exact, from the
pinned tree:

1. `Change::applyAmendment` enables the amendment and, if the node
   does not support it, logs "Unsupported amendment activated:
   server blocked" and calls `setAmendmentBlocked()`
   (`src/xrpld/app/tx/detail/Change.cpp:364-368`).
2. The halt is re-checked at every ledger close: a node with any
   unsupported enabled amendment blocks
   (`src/xrpld/app/ledger/detail/LedgerMaster.cpp:309-314`, via
   `hasUnsupportedEnabled()`,
   `src/xrpld/app/misc/detail/AmendmentTable.cpp:799-802`).

During phase 2, the nodes at risk are exactly the nodes that have
not upgraded to a build supporting the activation amendment — which
is why the 2-week hold is the notice period, and why §5 monitors
the version mix.

### 4.3 The veto as the per-node defence

Before enablement, any node operator can veto the activation
amendment (admin RPC `feature` with `vetoed: true`,
`src/xrpld/rpc/handlers/Feature1.cpp:78-87`; `veto()` / `persistVote()`,
`src/xrpld/app/misc/detail/AmendmentTable.cpp:723-761`). A vetoed
amendment is never in that node's desired list, so the node never
votes for it. A veto is local: it changes one node's vote, not the
network's tally, and it is admin-only — it is not reachable by
forging a signature. The veto is the correct response to an
activation amendment proposed too early (for example, before
dual-key manifest coverage reaches the §5 threshold): veto it, and
the amendment cannot gain a majority from that node's vote. After
enablement the veto is useless — it only affects voting, and voting
is over.

### 4.4 Recovering a halted node

A node halted with "server blocked" recovers by restarting with a
build that supports the enabled amendment, so that
`hasUnsupportedEnabled()` returns false at the next ledger close
(`src/xrpld/app/ledger/detail/LedgerMaster.cpp:309-314`). Concretely:

1. Confirm the halt reason in the log ("Unsupported amendment
   activated: server blocked", `src/xrpld/app/tx/detail/Change.cpp:364-368`).
2. Upgrade to a build whose supported-amendment set includes the
   enabled amendment (for the migration, the post-activation
   build).
3. Restart. The node re-joins consensus once its validations verify
   under the new rules; its amendment votes resume from its desired
   list, with the 24-hour vote-expiry rule applying as in §2.5.

There is no configuration flag that un-blocks a node while it still
does not support an enabled amendment. An operator that refuses to
support an enabled amendment cannot rejoin consensus — that is the
intended semantics of the halt, not a bug to work around. If the
amendment itself is the problem (a bad activation), the recovery is
the forward-only path of §4.1, not a per-node unblock.

## 5. Monitoring

Monitor from the ledger (the authority on majorities and
enablement) and from the validator set, not from any single node's
local table.

### 5.1 What to watch

- **Majority timestamps.** Any amendment gaining a majority
  timestamp starts its 2-week clock. The majority timestamp is
  written when a `tfGotMajority` pseudo-transaction applies.
  Baseline (source-derived, sibling probe): 0 amendments with a
  majority timestamp.
- **Enablement ledgers.** Which amendments are enabled and at which
  ledger. Baseline (source-derived, sibling probe): 64 enabled, all
  at ledger 86785. Any new enablement ledger is an event.
- **Amendment vote counts per flag ledger.** How many trusted
  validations vote for each not-yet-enabled amendment, against the
  live threshold (45 of 66, source-derived). The public `feature`
  call returns only enabled / supported / majority; vote counts are
  admin-only.
- **UNL overlap and effective UNL size.** Baseline (source-derived,
  sibling probe): 25 validators in the UNL. Watch the effective UNL
  size after negative-UNL exclusions against the 60% absolute-
  minimum quorum floor (`src/xrpld/app/misc/detail/ValidatorList.cpp:1934`).
- **Validator version mix.** The version mix is the direct measure
  of how many nodes can verify ML-DSA signatures and how many would
  halt on an unsupported activation. Baseline (source-derived,
  sibling probe): 1.0.0: 2, 1.0.4: 9, 1.0.8: 1, 1.0.9: 54.
- **Dual-key manifest coverage.** How many of the 66 validators
  have published a manifest carrying an ML-DSA signing key. This is
  the phase-1 exit metric and the phase-2 go/no-go metric.
- **Manifest sequence numbers.** A sequence jump above the
  operator's own last issued sequence means someone else used the
  master key. Sequence numbers are the only in-protocol compromise
  detector available — nothing in the pinned code alerts on them
  automatically.
- **Validations from superseded keys.** After a rotation,
  validations signed by the old key should stop; if they continue,
  the old key is in someone else's hands.
- **Hybrid-only validator count.** How many validators have dropped
  their classical signature. Old nodes lose the 67% quorum once 22
  validators are ML-DSA-only (source-derived, sibling migration
  pack). This count must stay at zero until phase 2 has enabled.

### 5.2 Alert thresholds

| Signal | Threshold | Action |
|--------|-----------|--------|
| Any amendment gains a majority timestamp | Immediate alert | Start the 2-week clock; identify the amendment; check whether it is the activation amendment or an unexpected one. |
| Amendment vote count reaches 40 of 66 (within 5 of the 45 majority) | Warning | Pre-activation review: confirm the amendment is expected and the version mix supports it. |
| Dual-key manifest coverage below 45 of 66 when the activation amendment is proposed | Block the proposal | Do not propose phase 2 until coverage reaches the majority that must vote for it. |
| Hybrid-only validators ≥ 1 before phase 2 enables | Immediate alert | Investigate: no validator should drop classical signatures before activation. |
| Hybrid-only validators ≥ 22 | Critical | Old nodes are at the 67%-rule quorum boundary; halt further classical drops. |
| Any validator's manifest sequence jumps above its operator's last issued sequence | Immediate alert | Suspected master-key compromise; containment per §2.3. |
| Validations observed from a superseded signing key | Immediate alert | Suspected signing-key compromise; rotate per §2.2. |
| Effective UNL size falls below the 60% absolute-minimum quorum floor | Critical | UNL publisher intervention; negative-UNL exclusions have gone too far. |
| Pre-migration builds (no ML-DSA support) still validating after the activation amendment enables | Immediate alert | Those nodes will halt (§4.2); they need the upgrade-and-restart recovery (§4.4). |
| Amendment vote counts flap across flag ledgers | Warning | Check for a validator offline > 24 h (vote expiry, `src/xrpld/app/misc/detail/AmendmentTable.cpp:167-172`) or a manifest transition in progress (§2.5). |
| Per-node signature-related bandwidth exceeds 35 GB/day during the dual phase | Warning | Re-check against the 30.29 GB/day derived figure at the measured 3.03 s close; investigate unexpected proposal rounds or close-time shortening. |

## 6. Exposure-ranked remediation priorities

Highest exposure first. "Exposure" here means: how much of the
network a quantum adversary can affect, and how early the work
unblocks everything after it.

| Rank | Item | Exposure | Why this rank | Cost (derived/measured) |
|------|------|----------|---------------|------------------------|
| P0 | Lift the 72-byte proposal cap and the secp256k1-only gates (§1.4 items 1-3) | Blocks everything | No ML-DSA signature can exist on the network until the cap and the gates are lifted; the change is inert while signatures are still classical, so it can ship first with zero network risk | Code change only; no runtime cost |
| P1 | Upgrade the pinned OpenSSL to 3.5+ or vendor liboqs 0.16.0 (§1.4 item 4) | Blocks everything | No ML-DSA code can run without a library that implements it; the pinned tree uses OpenSSL 1.1.1w and the measurement host uses 3.0.13 — neither has ML-DSA | Build-system change; liboqs measured here |
| P2 | Dual-sign validations and proposals (ML-DSA-65) (§1.2, phase 1) | The actual quantum-resistance gain | Removes the single-scheme dependency for the vote itself; every later phase depends on dual-signed objects existing | 121.231 ms/ledger verify (3.031% of a 4 s close, liboqs), 22.95 GB/day/node signature traffic |
| P3 | Hybrid ML-KEM-768 TLS for the peer overlay (§3, TLS) | Peer authentication and transport | The overlay authenticates with a secp256k1 node key; a broken node key lets an adversary impersonate a peer. Independent of P2; can ship in either order | 51.185 us per handshake (liboqs) — negligible |
| P4 | Activation amendment (phase 2) | Makes the migration enforceable | Turns dual-signing from opt-in into the rule; gated on dual-key manifest coverage ≥ 45 of 66 and the 2-week hold | No additional runtime cost after activation; CPU drops to 10.725 ms/ledger |
| P5 | Classical retirement (phase 3) | Removes the classical attack surface | Only after P4 has enabled and no classical-only validator remains; forward-only | No additional cost; steady state |
| P6 | Master-key migration (§2.6) | The long-lived identity | The master key stays classical through P2-P5; until it migrates, a forged manifest is possible for any harvested master public key, detectable only by sequence monitoring (§5) | Separate design; SLH-DSA signatures 7,856-49,856 B (source-derived, FIPS 205) for a rare operation |

## 7. What this design does not cover, and open questions

- **Account transaction signatures.** Out of scope. They share the
  signing primitives, so they benefit from the phase-0 work, but
  migrating them is a separate design (account keys live in ledger
  state, not in manifests).
- **The master key.** Migrates later (§2.6). Until it does, the
  manifest authority stays classical, and sequence monitoring (§5)
  is the detection layer for a forged manifest.
- **OQ-1 — ML-DSA key encoding (UNVERIFIED).** How is an ML-DSA
  public key recognised and serialised: new prefix byte, length
  rule, or explicit type field? No prefix byte is assigned for
  ML-DSA in any standard verified here; the allocation needs a
  deliberate decision.
- **OQ-2 — Unknown fields in deserialized objects (UNVERIFIED).**
  Phase 1 assumes old nodes ignore a new ML-DSA key field in a
  manifest and a new ML-DSA signature field in a validation. This
  was not verified against `STObject` deserialization in this pack.
  It must be confirmed by reading the deserializer before phase 1
  ships: if old nodes reject unknown fields, phase 1 forks the
  network.
- **OQ-3 — Proposal suppression ID (UNVERIFIED).** Whether the
  ML-DSA signature is included in the proposal suppression ID
  (§1.2). Either choice needs an explicit decision and a test.
- **OQ-4 — Parameter set.** ML-DSA-65 is recommended (§1.1), but
  the choice between 44/65/87 is a governance decision, not a
  technical inevitability. The measurements for all three are in
  `results/timing_table.csv`.
- **OQ-5 — Old-node behaviour on unknown key types
  (UNVERIFIED).** If a manifest carries an ML-DSA key and an old
  node encounters it outside the ignored-field path, does it ignore
  it, reject the manifest, or fail? No such path was found, but the
  trust path was not exhaustively traced.
- **OQ-6 — Validation size vs relay policy (UNVERIFIED).** No upper
  bound on validation size was found in the relay path, but
  resource-fee and relay-suppression behaviour for ~5 KiB
  validations was not measured. The dual-phase soak in phase 1 is
  the place to find out.
- **OQ-7 — Ledger close-time sensitivity.** The cost model uses a
  4 s close (re-scaled to the sibling probe's measured 3.03 s). If
  the live network closes faster or runs more proposal rounds under
  load, bandwidth per day rises proportionally; live measurement
  during the phase-1 soak would pin it down.
- **OQ-8 — Classical timings are host-specific (MEASURED, with a
  caveat).** The secp256k1 timings in this pack come from OpenSSL
  3.0.13's generic implementation on a ~1.5 GHz shared host. A
  validator running a hardware-accelerated or assembly-optimized
  secp256k1 (e.g. libsecp256k1) will see faster classical times,
  which would change the dual-phase CPU split — but not the
  bandwidth figures, and not the conclusion that ML-DSA verification
  is fast in absolute terms (54.167 us liboqs).

## Sources

- This pack: `results/benchmark_liboqs.json`,
  `results/benchmark_pqclean.json`,
  `results/benchmark_classical.json` (measured), `results/timing_table.csv`,
  `results/size_table.csv`, `results/cost_model.json` (derived),
  `call_sites.md` (measured + pinned-tree citations).
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), both published
  13 August 2024 — vendored in `sources/`.
- Sibling consensus-signature migration pack: `cost_model.py`
  v1.0.0, `results/cost_impact.json` (network inputs N=66, 2
  proposal rounds, 4 s close; published-estimate timings — NOT used
  as measurements here; the measured timings in this pack supersede
  them for the CPU figures).
- Sibling amendment-state probe pack: `threat_model.md`,
  `attack_trees.md`, `mitigation_design.md`,
  `results/summary.json` (threshold arithmetic 45 to force / 22 to
  block at N=66, 3.03 s measured mean close, validator/version
  inventory; rotation schedule and compromise procedures).
- Sibling validator key lifecycle pack: rotation simulation
  (56 simulated days, N=66).
- Pinned source tree: postfiatd main commit
  `0085a1ff885d6a446369cf73a4430f75af22be55`. Every file:line
  citation in this document was read in that tree.
