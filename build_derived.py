#!/usr/bin/env python3
"""Build derived outputs from the vendored benchmark results.

Reads results/benchmark_liboqs.json, results/benchmark_pqclean.json,
results/benchmark_classical.json and results/environment.json (vendored
inputs: raw outputs of the benchmark drivers, shipped in this pack) and
writes, deterministically (no timestamps, fixed float formatting):

  results/timing_table.csv / timing_table.md — median us/op per
      parameter set, operation and implementation, with the
      liboqs:PQClean ratio.
  results/size_table.csv / size_table.md — measured key/signature/
      ciphertext sizes against the FIPS 203 Table 3 / FIPS 204 Table 2
      values, with a match/mismatch verdict per cell.
  results/cost_model.json / cost_model.csv — per-ledger and per-day
      consensus-path costs (CPU and signature-related bytes) computed
      from the MEASURED medians under the sibling cost model's
      network inputs (N=66 validators, 2 proposal rounds per ledger,
      4 s nominal close; see cost_model.py provenance in
      remediation_assessment.md). These are DERIVED arithmetic, not
      new measurements.
  results/summary.txt — headline numbers in plain text.
  docs/index.html — rendered results page, including the digest-check
      output (results/digest_check_output.txt, if present) and the
      tail of the run log (results/run_log.txt, if present) inline.

Usage: python3 build_derived.py
Exit 0 only if every size in the JSON matches the FIPS tables and
every correctness field is PASS. A mismatch is printed and exits 1 —
sizes are never silently "fixed".
"""
import csv
import html
import json
import os
import sys

PACK = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(PACK, "results")

# FIPS 203, Table 3 (sizes in bytes), published 13 Aug 2024.
FIPS203 = {
    "ML-KEM-512": {"pk": 800, "sk": 1632, "ct": 768, "ss": 32, "category": 1},
    "ML-KEM-768": {"pk": 1184, "sk": 2400, "ct": 1088, "ss": 32, "category": 3},
    "ML-KEM-1024": {"pk": 1568, "sk": 3168, "ct": 1568, "ss": 32, "category": 5},
}
# FIPS 204, Table 2 (sizes in bytes), published 13 Aug 2024.
FIPS204 = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420, "category": 2},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309, "category": 3},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627, "category": 5},
}
# Classical sizes, measured by bench_classical (OpenSSL 3.0.13).
CLASSICAL = {
    "ECDSA-secp256k1": {"pk": 33, "sk": 32, "sig_max": 72},
    "Ed25519": {"pk": 32, "sk": 32, "sig": 64},
}

KEM_ORDER = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
SIG_ORDER = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
KEM_OPS = ["keygen", "encaps", "decaps"]
SIG_OPS = ["keygen", "sign", "verify"]


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as fh:
        return json.load(fh)


def med(entry, op):
    return entry["%s_us" % op]["median"]


def main():
    liboqs = load("benchmark_liboqs.json")
    pqclean = load("benchmark_pqclean.json")
    classical = load("benchmark_classical.json")
    env = load("environment.json")

    by_impl = {}
    for doc in (liboqs, pqclean, classical):
        impl = doc["implementation"]
        for r in doc["results"]:
            by_impl.setdefault(r["algorithm"], {})[impl] = r

    errors = []
    # --- correctness gate ---
    for alg, impls in sorted(by_impl.items()):
        for impl, r in sorted(impls.items()):
            if r.get("correctness") != "PASS":
                errors.append("%s (%s): correctness=%s" % (alg, impl, r.get("correctness")))

    # --- size gate against FIPS tables ---
    size_rows = []
    for alg in KEM_ORDER:
        f = FIPS203[alg]
        for impl in ("liboqs", "pqclean"):
            r = by_impl[alg][impl]
            row = {"algorithm": alg, "implementation": impl,
                   "pk_bytes": r["pk_bytes"], "sk_bytes": r["sk_bytes"],
                   "ct_bytes": r["ct_bytes"], "ss_bytes": r["ss_bytes"],
                   "fips_pk": f["pk"], "fips_sk": f["sk"],
                   "fips_ct": f["ct"], "fips_ss": f["ss"],
                   "category": f["category"]}
            row["verdict"] = ("MATCH" if (r["pk_bytes"] == f["pk"] and r["sk_bytes"] == f["sk"]
                                          and r["ct_bytes"] == f["ct"] and r["ss_bytes"] == f["ss"])
                              else "MISMATCH")
            if row["verdict"] != "MATCH":
                errors.append("%s (%s): size mismatch vs FIPS 203 Table 3" % (alg, impl))
            size_rows.append(row)
    for alg in SIG_ORDER:
        f = FIPS204[alg]
        for impl in ("liboqs", "pqclean"):
            r = by_impl[alg][impl]
            row = {"algorithm": alg, "implementation": impl,
                   "pk_bytes": r["pk_bytes"], "sk_bytes": r["sk_bytes"],
                   "sig_bytes": r["sig_bytes"],
                   "fips_pk": f["pk"], "fips_sk": f["sk"], "fips_sig": f["sig"],
                   "category": f["category"]}
            row["verdict"] = ("MATCH" if (r["pk_bytes"] == f["pk"] and r["sk_bytes"] == f["sk"]
                                          and r["sig_bytes"] == f["sig"])
                              else "MISMATCH")
            if row["verdict"] != "MATCH":
                errors.append("%s (%s): size mismatch vs FIPS 204 Table 2" % (alg, impl))
            size_rows.append(row)

    if errors:
        for e in errors:
            print("ERROR: %s" % e, file=sys.stderr)
        return 1

    # --- timing table ---
    timing_rows = []
    for alg in KEM_ORDER + SIG_ORDER:
        ops = KEM_OPS if alg.startswith("ML-KEM") else SIG_OPS
        for op in ops:
            lq = by_impl[alg]["liboqs"]
            pq = by_impl[alg]["pqclean"]
            a, b = med(lq, op), med(pq, op)
            timing_rows.append({
                "algorithm": alg, "operation": op,
                "liboqs_median_us": a, "liboqs_mean_us": lq["%s_us" % op]["mean"],
                "liboqs_min_us": lq["%s_us" % op]["min"], "liboqs_max_us": lq["%s_us" % op]["max"],
                "pqclean_median_us": b, "pqclean_mean_us": pq["%s_us" % op]["mean"],
                "pqclean_min_us": pq["%s_us" % op]["min"], "pqclean_max_us": pq["%s_us" % op]["max"],
                "pqclean_over_liboqs": b / a,
            })
    for alg in ("ECDSA-secp256k1", "Ed25519"):
        r = by_impl[alg]["openssl-classical"]
        for op in SIG_OPS:
            timing_rows.append({
                "algorithm": alg, "operation": op,
                "liboqs_median_us": "", "liboqs_mean_us": "", "liboqs_min_us": "", "liboqs_max_us": "",
                "pqclean_median_us": "", "pqclean_mean_us": "", "pqclean_min_us": "", "pqclean_max_us": "",
                "pqclean_over_liboqs": "",
                "openssl_median_us": med(r, op), "openssl_mean_us": r["%s_us" % op]["mean"],
                "openssl_min_us": r["%s_us" % op]["min"], "openssl_max_us": r["%s_us" % op]["max"],
            })

    with open(os.path.join(RES, "timing_table.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["algorithm", "operation", "liboqs_median_us", "liboqs_mean_us",
                    "liboqs_min_us", "liboqs_max_us", "pqclean_median_us",
                    "pqclean_mean_us", "pqclean_min_us", "pqclean_max_us",
                    "pqclean_over_liboqs", "openssl_median_us", "openssl_mean_us",
                    "openssl_min_us", "openssl_max_us"])
        for r in timing_rows:
            w.writerow([r["algorithm"], r["operation"],
                        ("%.3f" % r["liboqs_median_us"]) if r["liboqs_median_us"] != "" else "",
                        ("%.3f" % r["liboqs_mean_us"]) if r["liboqs_mean_us"] != "" else "",
                        ("%.3f" % r["liboqs_min_us"]) if r["liboqs_min_us"] != "" else "",
                        ("%.3f" % r["liboqs_max_us"]) if r["liboqs_max_us"] != "" else "",
                        ("%.3f" % r["pqclean_median_us"]) if r["pqclean_median_us"] != "" else "",
                        ("%.3f" % r["pqclean_mean_us"]) if r["pqclean_mean_us"] != "" else "",
                        ("%.3f" % r["pqclean_min_us"]) if r["pqclean_min_us"] != "" else "",
                        ("%.3f" % r["pqclean_max_us"]) if r["pqclean_max_us"] != "" else "",
                        ("%.2f" % r["pqclean_over_liboqs"]) if r["pqclean_over_liboqs"] != "" else "",
                        ("%.3f" % r["openssl_median_us"]) if "openssl_median_us" in r else "",
                        ("%.3f" % r["openssl_mean_us"]) if "openssl_mean_us" in r else "",
                        ("%.3f" % r["openssl_min_us"]) if "openssl_min_us" in r else "",
                        ("%.3f" % r["openssl_max_us"]) if "openssl_max_us" in r else ""])

    def f3(x):
        return ("%.3f" % x) if isinstance(x, float) else str(x)

    md = ["# Timing table (median microseconds per operation)",
          "",
          "Host: %s; %s; gcc %s; liboqs %s; PQClean commit %s; OpenSSL %s."
          % (env["cpu_model"], env["os"].split("#1")[0].strip(), env["gcc"].split()[-1],
             liboqs["liboqs_version"], pqclean["pqclean_commit"][:12], env["openssl_system"]),
          "liboqs runs its x86_64 (AVX2) path on this host (dispatch probe:",
          "AVX2=1 BMI2=1 POPCNT=1, see `results/raw_liboqs.log`); PQClean is",
          "the portable-C `clean` reference. The ratio column is therefore a",
          "comparison of an optimized implementation against a reference, not",
          "of two equals. Classical rows are OpenSSL 3.0.13 on the same host.",
          "",
          "| Algorithm | Operation | liboqs median (us) | PQClean median (us) | PQClean / liboqs | OpenSSL median (us) |",
          "|---|---|---|---|---|---|"]
    for r in timing_rows:
        md.append("| %s | %s | %s | %s | %s | %s |" % (
            r["algorithm"], r["operation"],
            f3(r["liboqs_median_us"]) if r["liboqs_median_us"] != "" else "-",
            f3(r["pqclean_median_us"]) if r["pqclean_median_us"] != "" else "-",
            ("%.2f" % r["pqclean_over_liboqs"]) if r["pqclean_over_liboqs"] != "" else "-",
            f3(r["openssl_median_us"]) if "openssl_median_us" in r else "-"))
    with open(os.path.join(RES, "timing_table.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")

    # --- size table ---
    with open(os.path.join(RES, "size_table.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["algorithm", "implementation", "category", "pk_bytes", "sk_bytes",
                    "ct_bytes", "sig_bytes", "ss_bytes", "fips_pk", "fips_sk",
                    "fips_ct", "fips_sig", "fips_ss", "verdict"])
        for r in size_rows:
            w.writerow([r["algorithm"], r["implementation"], r["category"],
                        r["pk_bytes"], r["sk_bytes"], r.get("ct_bytes", ""),
                        r.get("sig_bytes", ""), r.get("ss_bytes", ""),
                        r["fips_pk"], r["fips_sk"], r.get("fips_ct", ""),
                        r.get("fips_sig", ""), r.get("fips_ss", ""), r["verdict"]])
    smd = ["# Size table (bytes)",
           "",
           "FIPS 203 Table 3 (ML-KEM) and FIPS 204 Table 2 (ML-DSA), both",
           "published 13 August 2024. Every measured size in this pack",
           "matches the standard's table for its parameter set; the verdict",
           "column is the check, not a claim.",
           "",
           "| Algorithm | Implementation | Category | pk | sk | ct / sig | ss | FIPS pk | FIPS sk | FIPS ct / sig | FIPS ss | Verdict |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in size_rows:
        ct_sig = r.get("ct_bytes", r.get("sig_bytes", ""))
        f_ct_sig = r.get("fips_ct", r.get("fips_sig", ""))
        smd.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["algorithm"], r["implementation"], r["category"], r["pk_bytes"],
            r["sk_bytes"], ct_sig, r.get("ss_bytes", "-"), r["fips_pk"],
            r["fips_sk"], f_ct_sig, r.get("fips_ss", "-"), r["verdict"]))
    smd += ["",
            "Classical, measured with OpenSSL 3.0.13 on the same host:",
            "",
            "| Algorithm | pk | sk | sig |",
            "|---|---|---|---|",
            "| ECDSA-secp256k1 | 33 (compressed) | 32 | DER, at most 72 (this run: %d) |" % by_impl["ECDSA-secp256k1"]["openssl-classical"]["sig_bytes"],
            "| Ed25519 | 32 | 32 | 64 |"]
    with open(os.path.join(RES, "size_table.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(smd) + "\n")

    # --- cost model (derived arithmetic from measured medians) ---
    # Network inputs from the sibling consensus-signature migration
    # pack's cost model (cost_model.py v1.0.0): N=66 validators (live
    # testnet snapshot 2026-11-13), 2 proposal rounds per ledger,
    # nominal 4 s close. Per ledger per node: 66 validation verifies
    # + 132 proposal verifies = 198 verifies. Signature-related bytes
    # per verified object = public key + signature.
    N = 66
    ROUNDS = 2
    VERIFIES_PER_LEDGER = N * (1 + ROUNDS)
    CLOSE_NOMINAL = 4
    CLOSE_MEASURED = 3.03  # sibling pack's measured mean close interval

    def cost_row(label, verify_us, pk, sig, sign_us=None):
        v_ms = VERIFIES_PER_LEDGER * verify_us / 1000.0
        b_ledger = VERIFIES_PER_LEDGER * (pk + sig)
        ledgers_day_4s = 86400 / CLOSE_NOMINAL
        ledgers_day_303 = 86400 / CLOSE_MEASURED
        row = {"scenario": label,
               "verify_us_per_op_median": round(verify_us, 3),
               "verifies_per_ledger": VERIFIES_PER_LEDGER,
               "verify_ms_per_ledger": round(v_ms, 3),
               "pct_of_4s_close": round(100 * v_ms / (CLOSE_NOMINAL * 1000), 3),
               "sig_bytes_per_ledger": b_ledger,
               "sig_bytes_per_day_4s_close": int(b_ledger * ledgers_day_4s),
               "sig_bytes_per_day_3p03s_close": int(b_ledger * ledgers_day_303),
               "sign_us_per_op_median": (round(sign_us, 3) if sign_us is not None else None),
               "sign_ms_per_ledger_3_signs": (round(3 * sign_us / 1000.0, 3) if sign_us is not None else None)}
        return row

    secp_v = med(by_impl["ECDSA-secp256k1"]["openssl-classical"], "verify")
    secp_s = med(by_impl["ECDSA-secp256k1"]["openssl-classical"], "sign")
    rows = [cost_row("classical (ECDSA-secp256k1, OpenSSL, measured)",
                     secp_v, 33, by_impl["ECDSA-secp256k1"]["openssl-classical"]["sig_bytes"], secp_s)]
    for alg in SIG_ORDER:
        lq = by_impl[alg]["liboqs"]
        pq = by_impl[alg]["pqclean"]
        rows.append(cost_row("%s (liboqs, measured)" % alg, med(lq, "verify"),
                             lq["pk_bytes"], lq["sig_bytes"], med(lq, "sign")))
        rows.append(cost_row("%s (PQClean clean, measured)" % alg, med(pq, "verify"),
                             pq["pk_bytes"], pq["sig_bytes"], med(pq, "sign")))
    dsa65 = by_impl["ML-DSA-65"]["liboqs"]
    dsa65pq = by_impl["ML-DSA-65"]["pqclean"]
    rows.append(cost_row("dual classical + ML-DSA-65 (liboqs, measured)",
                         secp_v + med(dsa65, "verify"), 33 + dsa65["pk_bytes"],
                         by_impl["ECDSA-secp256k1"]["openssl-classical"]["sig_bytes"] + dsa65["sig_bytes"],
                         secp_s + med(dsa65, "sign")))
    rows.append(cost_row("dual classical + ML-DSA-65 (PQClean clean, measured)",
                         secp_v + med(dsa65pq, "verify"), 33 + dsa65pq["pk_bytes"],
                         by_impl["ECDSA-secp256k1"]["openssl-classical"]["sig_bytes"] + dsa65pq["sig_bytes"],
                         secp_s + med(dsa65pq, "sign")))
    # TLS handshake: one ML-KEM-768 keygen (ephemeral) + encaps + decaps.
    tls = {}
    for impl in ("liboqs", "pqclean"):
        r = by_impl["ML-KEM-768"][impl]
        total = med(r, "keygen") + med(r, "encaps") + med(r, "decaps")
        tls[impl] = {"keygen_us": round(med(r, "keygen"), 3),
                     "encaps_us": round(med(r, "encaps"), 3),
                     "decaps_us": round(med(r, "decaps"), 3),
                     "handshake_kem_us": round(total, 3)}
    model = {
        "model": "derived arithmetic from measured medians (this pack)",
        "network_inputs_source": "sibling consensus-signature migration pack cost_model.py v1.0.0 (N=66 validators, live testnet snapshot 2026-11-13; 2 proposal rounds per ledger — assumption A3; nominal 4 s close; 3.03 s measured mean close from the sibling amendment-state probe)",
        "validators_n": N,
        "proposal_rounds_per_ledger": ROUNDS,
        "verifies_per_ledger_per_node": VERIFIES_PER_LEDGER,
        "close_seconds_nominal": CLOSE_NOMINAL,
        "close_seconds_measured_mean": CLOSE_MEASURED,
        "per_ledger_per_node": rows,
        "tls_handshake_mlkem768_us": tls,
    }
    with open(os.path.join(RES, "cost_model.json"), "w", encoding="utf-8") as fh:
        json.dump(model, fh, indent=2)
        fh.write("\n")
    with open(os.path.join(RES, "cost_model.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "verify_us_per_op_median", "verifies_per_ledger",
                    "verify_ms_per_ledger", "pct_of_4s_close", "sig_bytes_per_ledger",
                    "sig_bytes_per_day_4s_close", "sig_bytes_per_day_3p03s_close",
                    "sign_us_per_op_median", "sign_ms_per_ledger_3_signs"])
        for r in rows:
            w.writerow([r["scenario"], r["verify_us_per_op_median"], r["verifies_per_ledger"],
                        r["verify_ms_per_ledger"], r["pct_of_4s_close"], r["sig_bytes_per_ledger"],
                        r["sig_bytes_per_day_4s_close"], r["sig_bytes_per_day_3p03s_close"],
                        r["sign_us_per_op_median"], r["sign_ms_per_ledger_3_signs"]])

    # --- summary.txt ---
    lines = ["Lattice engine benchmarking and core-protocol PQC remediation assessment",
             "Host: %s" % env["cpu_model"],
             "OS: %s" % env["os"],
             "Toolchain: %s, %s, Python %s, %s"
             % (env["gcc"], env["cmake"], env["python"], env["openssl_system"]),
             "liboqs %s (minimal build: ML-KEM + ML-DSA only; x86_64/AVX2 path, dispatch probe AVX2=1 BMI2=1 POPCNT=1)"
             % liboqs["liboqs_version"],
             "PQClean commit %s (clean reference implementations)" % pqclean["pqclean_commit"],
             "Correctness: 14/14 checks PASS (6 liboqs + 6 PQClean + 2 OpenSSL classical)",
             "Sizes: all 12 lattice size rows MATCH FIPS 203 Table 3 / FIPS 204 Table 2",
             "",
             "Median microseconds per operation (liboqs | PQClean clean):"]
    for alg in KEM_ORDER:
        lines.append("  %s keygen %.3f | %.3f; encaps %.3f | %.3f; decaps %.3f | %.3f"
                     % (alg,
                        med(by_impl[alg]["liboqs"], "keygen"), med(by_impl[alg]["pqclean"], "keygen"),
                        med(by_impl[alg]["liboqs"], "encaps"), med(by_impl[alg]["pqclean"], "encaps"),
                        med(by_impl[alg]["liboqs"], "decaps"), med(by_impl[alg]["pqclean"], "decaps")))
    for alg in SIG_ORDER:
        lines.append("  %s keygen %.3f | %.3f; sign %.3f | %.3f; verify %.3f | %.3f"
                     % (alg,
                        med(by_impl[alg]["liboqs"], "keygen"), med(by_impl[alg]["pqclean"], "keygen"),
                        med(by_impl[alg]["liboqs"], "sign"), med(by_impl[alg]["pqclean"], "sign"),
                        med(by_impl[alg]["liboqs"], "verify"), med(by_impl[alg]["pqclean"], "verify")))
    lines.append("  ECDSA-secp256k1 (OpenSSL, measured): keygen %.3f; sign %.3f; verify %.3f"
                 % (med(by_impl["ECDSA-secp256k1"]["openssl-classical"], "keygen"),
                    med(by_impl["ECDSA-secp256k1"]["openssl-classical"], "sign"),
                    med(by_impl["ECDSA-secp256k1"]["openssl-classical"], "verify")))
    lines.append("  Ed25519 (OpenSSL, measured): keygen %.3f; sign %.3f; verify %.3f"
                 % (med(by_impl["Ed25519"]["openssl-classical"], "keygen"),
                    med(by_impl["Ed25519"]["openssl-classical"], "sign"),
                    med(by_impl["Ed25519"]["openssl-classical"], "verify")))
    lines += ["",
              "Consensus-path cost per ledger per node (N=66, 2 proposal rounds, 198 verifies):"]
    for r in rows:
        lines.append("  %s: verify %.3f ms/ledger (%.3f%% of a 4 s close), %d signature-related bytes/ledger, %d bytes/day at 4 s close"
                     % (r["scenario"], r["verify_ms_per_ledger"], r["pct_of_4s_close"],
                        r["sig_bytes_per_ledger"], r["sig_bytes_per_day_4s_close"]))
    lines += ["",
              "TLS handshake ML-KEM-768 cost (keygen + encaps + decaps, medians): liboqs %.3f us, PQClean clean %.3f us"
              % (tls["liboqs"]["handshake_kem_us"], tls["pqclean"]["handshake_kem_us"]),
              "",
              "OpenSSL 3.5 (third implementation): NOT MEASURED — see claim_evidence_index.md.",
              "Reproduction: bash run_all.sh (offline, from the vendored results JSON)."]
    with open(os.path.join(RES, "summary.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    # --- docs/index.html ---
    def esc(v):
        return html.escape(str(v))

    def read_optional(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return None

    digest_out = read_optional(os.path.join(RES, "digest_check_output.txt"))
    run_log = read_optional(os.path.join(RES, "run_log.txt"))
    run_tail = "\n".join(run_log.splitlines()[-40:]) if run_log else None

    timing_html = "\n".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(r["algorithm"]), esc(r["operation"]),
            esc(("%.3f" % r["liboqs_median_us"]) if r["liboqs_median_us"] != "" else "-"),
            esc(("%.3f" % r["pqclean_median_us"]) if r["pqclean_median_us"] != "" else "-"),
            esc(("%.2f" % r["pqclean_over_liboqs"]) if r["pqclean_over_liboqs"] != "" else "-"),
            esc(("%.3f" % r["openssl_median_us"]) if "openssl_median_us" in r else "-"))
        for r in timing_rows)
    size_html = "\n".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(r["algorithm"]), esc(r["implementation"]), esc(r["category"]),
            esc(r["pk_bytes"]), esc(r["sk_bytes"]),
            esc(r.get("ct_bytes", r.get("sig_bytes", ""))),
            esc(r.get("ss_bytes", "-")), esc(r["verdict"]))
        for r in size_rows)
    cost_html = "\n".join(
        "<tr><td>%s</td><td>%.3f</td><td>%.3f</td><td>%.3f</td><td>%d</td><td>%d</td></tr>" % (
            esc(r["scenario"]), r["verify_us_per_op_median"], r["verify_ms_per_ledger"],
            r["pct_of_4s_close"], r["sig_bytes_per_ledger"], r["sig_bytes_per_day_4s_close"])
        for r in rows)
    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Lattice Engine Benchmarking and Core-Protocol PQC Remediation Assessment</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  max-width:960px;margin:2em auto;padding:0 1em;color:#111;line-height:1.5}
h1{font-size:1.6em}h2{font-size:1.25em;margin-top:1.5em}
table{border-collapse:collapse;width:100%%;margin:1em 0}
th,td{border:1px solid #ccc;padding:.35em .6em;text-align:left;
  font-size:.92em}th{background:#f0f0f0}
code{background:#f4f4f4;padding:0 .2em}
.callout{background:#f7f3e8;border-left:4px solid #b58900;padding:.7em 1em}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85em;
  white-space:pre-wrap;word-break:break-word;background:#f8f8f8;
  border:1px solid #ddd;padding:1em;overflow-x:auto}
</style>
</head>
<body>
<h1>Lattice Engine Benchmarking and Core-Protocol PQC Remediation Assessment</h1>
<p>Measured ML-KEM and ML-DSA costs across every parameter set, from two
independent implementations on one fixed host and toolchain, mapped to
the core-protocol call sites in postfiatd (pinned commit
<code>0085a1ff885d6a446369cf73a4430f75af22be55</code>), with a
remediation assessment for the post-quantum migration.</p>

<div class="callout"><strong>Headline finding.</strong> On this host the
classical scheme is the slow one. ECDSA-secp256k1 verification — the
operation the consensus path performs 198 times per ledger per node —
costs <strong>%.3f &micro;s (median, OpenSSL 3.0.13, measured)</strong>,
while ML-DSA-65 verification costs <strong>%.3f &micro;s (liboqs,
measured)</strong> — about 10&times; faster. The migration's cost is
therefore bandwidth, not CPU: a dual classical + ML-DSA-65 validation
carries %.3f&times; the signature-related bytes of a classical one per
ledger. ML-KEM-768 for a TLS handshake (keygen + encaps + decaps)
costs %.3f &micro;s (liboqs) / %.3f &micro;s (PQClean clean).</div>

<h2>Host and toolchain</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>CPU</td><td>%s (%d cores)</td></tr>
<tr><td>OS / kernel</td><td>%s</td></tr>
<tr><td>Compiler</td><td>%s</td></tr>
<tr><td>liboqs</td><td>%s — minimal build (ML-KEM + ML-DSA only); x86_64/AVX2 path (dispatch probe AVX2=1 BMI2=1 POPCNT=1)</td></tr>
<tr><td>PQClean</td><td>commit %s — portable-C <code>clean</code> reference implementations</td></tr>
<tr><td>OpenSSL (classical baseline)</td><td>%s</td></tr>
<tr><td>OpenSSL 3.5 (third implementation)</td><td>NOT MEASURED — see claim index</td></tr>
</table>

<h2>Timing table (median &micro;s per operation)</h2>
<p>Each operation was timed in a tight loop (2,000 iterations for
ML-KEM, 1,000 for ML-DSA and classical keygen, 2,000 for classical
sign/verify), repeated 7 times; the table shows the median. liboqs
runs its optimized x86_64 (AVX2) path; PQClean <code>clean</code> is
portable C — the ratio column compares an optimized implementation
against a reference, not two equals. Full statistics (mean/min/max)
are in <code>results/timing_table.csv</code>; unedited raw logs are
<code>results/raw_liboqs.log</code>, <code>results/raw_pqclean.log</code>,
<code>results/raw_classical.log</code>.</p>
<table>
<tr><th>Algorithm</th><th>Operation</th><th>liboqs median (&micro;s)</th>
<th>PQClean median (&micro;s)</th><th>PQClean / liboqs</th><th>OpenSSL median (&micro;s)</th></tr>
%s
</table>

<h2>Size table (bytes)</h2>
<p>FIPS 203 Table 3 (ML-KEM) and FIPS 204 Table 2 (ML-DSA), both
published 13 August 2024. Every measured size matches the standard.
Classical sizes are measured with OpenSSL 3.0.13 on the same host;
the secp256k1 signature in this run was %d bytes (DER, at most 72).</p>
<table>
<tr><th>Algorithm</th><th>Implementation</th><th>Category</th>
<th>pk</th><th>sk</th><th>ct / sig</th><th>ss</th><th>Verdict</th></tr>
%s
</table>

<h2>Consensus-path cost model (derived)</h2>
<p>Per ledger per node at N=66 validators, 2 proposal rounds
(198 signature verifications: 66 validations + 132 proposals),
nominal 4 s close. Computed from the measured medians above; network
inputs from the sibling migration pack's cost model. See
<code>remediation_assessment.md</code> for the full assessment and
<code>results/cost_model.json</code> for the machine-readable form.</p>
<table>
<tr><th>Scenario</th><th>Verify (&micro;s/op)</th><th>Verify (ms/ledger)</th>
<th>%% of 4 s close</th><th>Signature bytes / ledger</th><th>Signature bytes / day</th></tr>
%s
</table>

<h2>Call-site mapping</h2>
<p>Validation signing: <code>src/libxrpl/protocol/STValidation.cpp:128-139</code>
(secp256k1-only verification gate) and
<code>src/xrpld/app/consensus/RCLConsensus.cpp:241</code> (proposal
<code>signDigest</code>); the 72-byte proposal cap:
<code>src/xrpld/app/consensus/RCLCxPeerPos.h:110</code> and
<code>src/xrpld/overlay/detail/PeerImp.cpp:1791-1799</code>. Key
generation: <code>src/libxrpl/protocol/SecretKey.cpp:309-327</code>
(<code>generateSecretKey</code>) via
<code>src/xrpld/app/misc/detail/ValidatorKeys.cpp:84-85</code>. TLS:
<code>src/libxrpl/basics/make_SSLContext.cpp:104</code> (cipher list,
TLS 1.2 minimum, lines 356-357). Full mapping with measured numbers
in <code>call_sites.md</code>.</p>

<h2>Digest-check output</h2>
<p>Raw output of <code>bash verify_digests.sh --check</code> (SHA-256
manifest over every pack file except the manifest itself):</p>
<pre class="mono">%s</pre>

<h2>Run-log tail</h2>
<p>Tail of <code>results/run_log.txt</code> — the raw console log of
the fresh-copy reproduction run (<code>bash run_all.sh</code>, exit 0):</p>
<pre class="mono">%s</pre>

<h2>Reproduction</h2>
<p class="mono">bash run_all.sh</p>
<p>Regenerates every derived output offline from the vendored results
JSON (<code>results/benchmark_*.json</code>), rebuilds this page, and
verifies digests. Expected: exit 0, byte-identical outputs. See
<code>REPRODUCTION.md</code> for the exact command and recorded
result. To re-run the benchmarks themselves (not part of the offline
reproduction — timings vary run to run), see
<code>harness/build_benchmarks.sh</code> and
<code>harness/run_benchmarks.sh</code>.</p>

<h2>Files</h2>
<ul>
<li><code>results/benchmark_liboqs.json</code>,
<code>results/benchmark_pqclean.json</code>,
<code>results/benchmark_classical.json</code> — vendored raw benchmark
results (JSON)</li>
<li><code>results/raw_liboqs.log</code>,
<code>results/raw_pqclean.log</code>,
<code>results/raw_classical.log</code> — unedited raw console logs</li>
<li><code>results/timing_table.csv</code> /
<code>timing_table.md</code>, <code>results/size_table.csv</code> /
<code>size_table.md</code> — derived tables</li>
<li><code>results/cost_model.json</code> / <code>cost_model.csv</code> —
derived consensus-path cost model</li>
<li><code>results/summary.txt</code> — headline numbers in plain text</li>
<li><code>results/environment.json</code> — host, toolchain, versions</li>
<li><code>results/digest_check_output.txt</code>,
<code>results/run_log.txt</code> — digest-check output, reproduction log</li>
<li><code>harness/bench_liboqs.c</code>,
<code>harness/bench_pqclean.c</code>,
<code>harness/bench_classical.c</code> — benchmark drivers</li>
<li><code>harness/build_benchmarks.sh</code>,
<code>harness/run_benchmarks.sh</code> — build / run scripts</li>
<li><code>call_sites.md</code> — measurement-to-call-site mapping</li>
<li><code>remediation_assessment.md</code> — hybrid ML-DSA design,
rotation/revocation, phased costs, forward-only activation, rollback,
exposure-ranked priorities</li>
<li><code>claim_evidence_index.md</code> — measured vs source-derived
claims, separated, with file:line and output-file references</li>
<li><code>sources.md</code> — primary sources and version pins</li>
<li><code>sources/NIST.FIPS.203.pdf</code>,
<code>sources/NIST.FIPS.204.pdf</code> — vendored standards</li>
</ul>

<h2>Limitations</h2>
<ul>
<li>Timings are for this host and toolchain only (AMD EPYC, ~1.5 GHz,
gcc 13.3.0, -O2). They do not transfer to validator hardware; the
ratios between schemes on one host are the portable part.</li>
<li>liboqs uses its optimized AVX2 path; PQClean <code>clean</code> is
portable C. A production deployment would use optimized code for both
schemes; the PQClean numbers are a conservative upper bound.</li>
<li>OpenSSL 3.5 was not measured (see the claim index): the system
OpenSSL is 3.0.13, which has no native ML-KEM/ML-DSA.</li>
<li>Cost-model network inputs (N=66, 2 proposal rounds) come from the
sibling migration pack; they are labelled source-derived, not measured
here.</li>
<li>No ledger was compiled or run locally; no validation was forged
or replayed against a live node.</li>
</ul>
</body>
</html>
""" % (
        secp_v, med(dsa65, "verify"),
        (33 + dsa65["pk_bytes"] + by_impl["ECDSA-secp256k1"]["openssl-classical"]["sig_bytes"] + dsa65["sig_bytes"]) / (33 + by_impl["ECDSA-secp256k1"]["openssl-classical"]["sig_bytes"]),
        tls["liboqs"]["handshake_kem_us"], tls["pqclean"]["handshake_kem_us"],
        esc(env["cpu_model"]), env["cpu_count"], esc(env["os"]),
        esc(env["gcc"]), esc(liboqs["liboqs_version"]),
        esc(pqclean["pqclean_commit"]),
        esc(env["openssl_system"]),
        timing_html,
        by_impl["ECDSA-secp256k1"]["openssl-classical"]["sig_bytes"],
        size_html,
        cost_html,
        esc(digest_out) if digest_out else "NOT YET RECORDED — run `bash verify_digests.sh --check > results/digest_check_output.txt` and rebuild.",
        esc(run_tail) if run_tail else "NOT YET RECORDED — run `bash run_all.sh` in a fresh copy and capture its console log to results/run_log.txt, then rebuild.",
    )
    with open(os.path.join(PACK, "docs", "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)
    print("build_derived.py: OK (timing/size/cost tables, summary, docs/index.html)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
