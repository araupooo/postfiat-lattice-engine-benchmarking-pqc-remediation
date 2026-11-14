#!/bin/bash
# Build the benchmark drivers from pinned sources.
# Usage: bash harness/build_benchmarks.sh [PQClean-checkout-dir] [liboqs-install-dir]
# Defaults: PQClean at ../pqclean-checkout (a checkout of PQClean/PQClean at
# the pinned commit), liboqs install at ../liboqs-install.
# Outputs binaries into ./bin (relative to the task build dir, NOT the pack).
# The liboqs driver needs a liboqs 0.16.0 install; the PQClean drivers
# compile the "clean" reference sources directly.
# Exit 0 only if all 7 binaries build.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TASKDIR="$(cd "$HERE/../.." && pwd)"
PQ="${1:-$TASKDIR/pqclean-checkout}"
OQS="${2:-$TASKDIR/build/liboqs-install}"
OUT="${OUT:-$TASKDIR/build/bin}"
mkdir -p "$OUT"
COMMIT="0586a824fc0d49df0b6b6e9179d8d15d06d0974f"

fail=0
echo "PQClean dir: $PQ"
echo "liboqs install: $OQS"
echo "output dir: $OUT"

# --- classical baseline driver (OpenSSL 3.0.13, secp256k1 + Ed25519) ---
gcc -O2 -std=c99 -Wall -o "$OUT/bench_classical" \
  "$HERE/bench_classical.c" -lcrypto 2>"$OUT/bench_classical.build.log"
echo "built: bench_classical (exit $?)"

# --- liboqs driver (all 6 parameter sets in one binary) ---
if [ -f "$OQS/include/oqs/oqs.h" ] && [ -f "$OQS/lib/liboqs.a" ]; then
  gcc -O2 -std=c99 -Wall -I"$OQS/include" -o "$OUT/bench_liboqs" \
    "$HERE/bench_liboqs.c" -L"$OQS/lib" -loqs -lcrypto
  echo "built: bench_liboqs (exit $?)"
else
  echo "SKIP bench_liboqs: liboqs install not found at $OQS" >&2
  fail=1
fi

# --- PQClean drivers (one binary per parameter set) ---
COMMON="$PQ/common"
build_pqclean() { # $1=kind(kem|sig) $2=dir $3=prefix $4=outname $5...=sources
  local kind="$1" dir="$2" prefix="$3" out="$4"; shift 4
  local def="-DPQ_KEM"
  [ "$kind" = "sig" ] && def="-DPQ_SIG"
  # shellcheck disable=SC2086
  gcc -O2 -std=c99 -Wall -I"$dir" -I"$COMMON" $def \
    -DPREFIX="$prefix" -DPQCLEAN_COMMIT="\"$COMMIT\"" \
    -o "$OUT/$out" "$HERE/bench_pqclean.c" "$@" \
    "$COMMON/fips202.c" "$COMMON/randombytes.c"
  echo "built: $out (exit $?)"
}

KEM_SRC="kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c symmetric-shake.c"
SIG_SRC="sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c symmetric-shake.c"
for L in 512 768 1024; do
  D="$PQ/crypto_kem/ml-kem-$L/clean"
  # shellcheck disable=SC2086
  build_pqclean kem "$D" "PQCLEAN_MLKEM${L}_CLEAN" "bench_pqclean_mlkem$L" \
    $(for f in $KEM_SRC; do echo "$D/$f"; done)
done
for P in 44 65 87; do
  D="$PQ/crypto_sign/ml-dsa-$P/clean"
  # shellcheck disable=SC2086
  build_pqclean sig "$D" "PQCLEAN_MLDSA${P}_CLEAN" "bench_pqclean_mldsa$P" \
    $(for f in $SIG_SRC; do echo "$D/$f"; done)
done

for b in bench_classical bench_liboqs bench_pqclean_mlkem512 bench_pqclean_mlkem768 bench_pqclean_mlkem1024 bench_pqclean_mldsa44 bench_pqclean_mldsa65 bench_pqclean_mldsa87; do
  if [ -x "$OUT/$b" ]; then echo "OK   $b"; else echo "FAIL $b"; fail=1; fi
done
exit $fail
