#!/bin/bash
# Run the full benchmark suite and write raw logs + JSON results.
# Usage: bash harness/run_benchmarks.sh [bin-dir] [results-dir]
# Defaults: bin-dir ../build/bin, results-dir ./results (pack).
# Exit 0 only if every driver exits 0 (all correctness checks pass).
# Raw stdout of every driver is appended verbatim to the raw log files;
# nothing in the logs is edited after the run.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PACK="$(cd "$HERE/.." && pwd)"
BIN="${1:-$PACK/../build/bin}"
RES="${2:-$PACK/results}"
mkdir -p "$RES"
echo "bin dir: $BIN"
echo "results dir: $RES"

fail=0
# --- classical baseline (OpenSSL 3.0.13, secp256k1 + Ed25519) ---
echo "=== classical (OpenSSL) ==="
"$BIN/bench_classical" --json "$RES/benchmark_classical.json" 2>&1 | tee "$RES/raw_classical.log"
rc=${PIPESTATUS[0]}
echo "bench_classical exit: $rc"
[ "$rc" -ne 0 ] && fail=1

# --- liboqs (all 6 parameter sets) ---
echo "=== liboqs ==="
"$BIN/bench_liboqs" --json "$RES/benchmark_liboqs.json" 2>&1 | tee "$RES/raw_liboqs.log"
rc=${PIPESTATUS[0]}
echo "bench_liboqs exit: $rc"
[ "$rc" -ne 0 ] && fail=1

# --- PQClean (one binary per parameter set) ---
echo "=== pqclean ==="
: > "$RES/raw_pqclean.log"
for spec in "mlkem512:ML-KEM-512" "mlkem768:ML-KEM-768" "mlkem1024:ML-KEM-1024" "mldsa44:ML-DSA-44" "mldsa65:ML-DSA-65" "mldsa87:ML-DSA-87"; do
  b="${spec%%:*}"; alg="${spec##*:}"
  out="$RES/benchmark_pqclean_${b}.json"
  echo "--- $alg ---" | tee -a "$RES/raw_pqclean.log"
  "$BIN/bench_pqclean_$b" --json "$out" 2>&1 | tee -a "$RES/raw_pqclean.log"
  rc=${PIPESTATUS[0]}
  echo "bench_pqclean_$b exit: $rc"
  [ "$rc" -ne 0 ] && fail=1
done

# --- merge PQClean per-set JSON into one file ---
python3 - "$RES" <<'PYEOF'
import json, sys, os
res = sys.argv[1]
merged = {"implementation": "pqclean", "results": []}
for b in ["mlkem512", "mlkem768", "mlkem1024", "mldsa44", "mldsa65", "mldsa87"]:
    p = os.path.join(res, "benchmark_pqclean_%s.json" % b)
    with open(p) as f:
        d = json.load(f)
    merged["pqclean_commit"] = d.get("pqclean_commit")
    merged["results"].extend(d["results"])
with open(os.path.join(res, "benchmark_pqclean.json"), "w") as f:
    json.dump(merged, f, indent=2)
    f.write("\n")
print("merged PQClean results: %d entries" % len(merged["results"]))
PYEOF
[ $? -ne 0 ] && fail=1

echo "RESULT: benchmarks $([ $fail -eq 0 ] && echo PASS || echo FAIL) (exit $fail)"
exit $fail
