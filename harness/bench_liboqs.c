/* bench_liboqs.c — timing + correctness benchmark for ML-KEM and ML-DSA
 * via liboqs 0.16.0 (C API). One binary measures all six parameter sets.
 *
 * Method: for each algorithm, first a correctness check (encap/decap shared
 * secrets equal; sign then verify valid; verify of a tampered signature
 * fails), then timing: each operation is run in a tight loop of N
 * iterations, timed with clock_gettime(CLOCK_MONOTONIC); the loop is
 * repeated REPS times and the median/mean/min/max per-op time in
 * microseconds is reported. The signed message is the fixed 64-byte
 * ASCII string below (deterministic input; ML-DSA signing itself is
 * randomized internally, per FIPS 204 hedged signing).
 *
 * Output: human-readable lines to stdout (captured verbatim as the raw
 * log) and a JSON document to the file named by --json. Exit 0 only if
 * every correctness check passes and every timing loop completes.
 * No timing value is invented: if an algorithm is unavailable in the
 * linked liboqs, it is reported UNAVAILABLE and the run exits 2.
 *
 * Build: gcc -O2 -std=c99 -Wall -I<liboqs-install>/include \
 *          bench_liboqs.c -L<liboqs-install>/lib -loqs -lcrypto -o bench_liboqs
 * (see harness/build_benchmarks.sh)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>

#define REPS 7
#define MSG "PFTL lattice-engine benchmark message, 64 bytes: 0123456789abcde"

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Time op() called N times; returns per-op microseconds (median of REPS
 * runs). Fills stats array {median, mean, min, max}. */
typedef void (*op_fn)(void *ctx);
static void time_op(op_fn op, void *ctx, long n, double stats[4]) {
    double runs[REPS];
    for (int r = 0; r < REPS; r++) {
        double t0 = now_us();
        for (long i = 0; i < n; i++) op(ctx);
        double t1 = now_us();
        runs[r] = (t1 - t0) / (double)n;
    }
    double sorted[REPS];
    memcpy(sorted, runs, sizeof runs);
    qsort(sorted, REPS, sizeof(double), cmp_dbl);
    double mean = 0;
    for (int r = 0; r < REPS; r++) mean += runs[r];
    mean /= REPS;
    stats[0] = sorted[REPS / 2];
    stats[1] = mean;
    stats[2] = sorted[0];
    stats[3] = sorted[REPS - 1];
}

static void print_stats(const char *label, const double s[4], long n) {
    printf("  %-12s n=%ld  median=%9.3f us/op  mean=%9.3f  min=%9.3f  max=%9.3f  ops/s=%.1f\n",
           label, n, s[0], s[1], s[2], s[3], 1e6 / s[0]);
}

/* ---------------- ML-KEM ---------------- */
typedef struct { OQS_KEM *kem; uint8_t *pk, *sk, *ct, *ss1, *ss2; } kem_ctx;

static void op_kem_keypair(void *v) {
    kem_ctx *c = v;
    OQS_KEM_keypair(c->kem, c->pk, c->sk);
}
static void op_kem_encaps(void *v) {
    kem_ctx *c = v;
    OQS_KEM_encaps(c->kem, c->ct, c->ss1, c->pk);
}
static void op_kem_decaps(void *v) {
    kem_ctx *c = v;
    OQS_KEM_decaps(c->kem, c->ss2, c->ct, c->sk);
}

static int bench_kem(const char *name, FILE *jf, int *first) {
    OQS_KEM *kem = OQS_KEM_new(name);
    if (!kem) {
        printf("--- %s (liboqs) ---\n  UNAVAILABLE in this liboqs build\n", name);
        return 2;
    }
    printf("--- %s (liboqs) ---\n", name);
    printf("  sizes: pk=%zu sk=%zu ct=%zu ss=%zu\n",
           kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret);
    kem_ctx c;
    c.kem = kem;
    c.pk = malloc(kem->length_public_key);
    c.sk = malloc(kem->length_secret_key);
    c.ct = malloc(kem->length_ciphertext);
    c.ss1 = malloc(kem->length_shared_secret);
    c.ss2 = malloc(kem->length_shared_secret);
    if (!c.pk || !c.sk || !c.ct || !c.ss1 || !c.ss2) return 2;

    int ok = 1;
    if (OQS_KEM_keypair(kem, c.pk, c.sk) != OQS_SUCCESS) { printf("  CORRECTNESS FAIL: keypair\n"); ok = 0; }
    if (OQS_KEM_encaps(kem, c.ct, c.ss1, c.pk) != OQS_SUCCESS) { printf("  CORRECTNESS FAIL: encaps\n"); ok = 0; }
    if (OQS_KEM_decaps(kem, c.ss2, c.ct, c.sk) != OQS_SUCCESS) { printf("  CORRECTNESS FAIL: decaps\n"); ok = 0; }
    if (memcmp(c.ss1, c.ss2, kem->length_shared_secret) != 0) { printf("  CORRECTNESS FAIL: shared secrets differ\n"); ok = 0; }
    /* Tampered ciphertext must still decapsulate to *some* 32-byte value
     * (implicit rejection) that differs from the valid shared secret. */
    c.ct[0] ^= 0x01;
    uint8_t ss_t[64];
    if (OQS_KEM_decaps(kem, ss_t, c.ct, c.sk) != OQS_SUCCESS) { printf("  CORRECTNESS FAIL: decaps(tampered)\n"); ok = 0; }
    if (memcmp(ss_t, c.ss1, kem->length_shared_secret) == 0) { printf("  CORRECTNESS FAIL: tampered ct gave valid secret\n"); ok = 0; }
    c.ct[0] ^= 0x01;
    printf("  correctness: %s (encap/decap match, tampered ct rejected to a different secret)\n", ok ? "PASS" : "FAIL");

    double s_key[4], s_enc[4], s_dec[4];
    time_op(op_kem_keypair, &c, 2000, s_key);
    time_op(op_kem_encaps, &c, 2000, s_enc);
    time_op(op_kem_decaps, &c, 2000, s_dec);
    print_stats("keygen", s_key, 2000);
    print_stats("encaps", s_enc, 2000);
    print_stats("decaps", s_dec, 2000);

    if (jf) {
        fprintf(jf, "%s\n    {\"algorithm\": \"%s\", \"type\": \"kem\","
                "\"pk_bytes\": %zu, \"sk_bytes\": %zu, \"ct_bytes\": %zu, \"ss_bytes\": %zu,"
                " \"correctness\": \"%s\","
                " \"keygen_us\": {\"median\": %.3f, \"mean\": %.3f, \"min\": %.3f, \"max\": %.3f},"
                " \"encaps_us\": {\"median\": %.3f, \"mean\": %.3f, \"min\": %.3f, \"max\": %.3f},"
                " \"decaps_us\": {\"median\": %.3f, \"mean\": %.3f, \"min\": %.3f, \"max\": %.3f}}",
                *first ? "" : ",", name,
                kem->length_public_key, kem->length_secret_key,
                kem->length_ciphertext, kem->length_shared_secret,
                ok ? "PASS" : "FAIL",
                s_key[0], s_key[1], s_key[2], s_key[3],
                s_enc[0], s_enc[1], s_enc[2], s_enc[3],
                s_dec[0], s_dec[1], s_dec[2], s_dec[3]);
        *first = 0;
    }
    free(c.pk); free(c.sk); free(c.ct); free(c.ss1); free(c.ss2);
    OQS_KEM_free(kem);
    return ok ? 0 : 1;
}

/* ---------------- ML-DSA ---------------- */
typedef struct { OQS_SIG *sig; uint8_t *pk, *sk, *sg; size_t sglen; const uint8_t *msg; size_t msglen; } sig_ctx;

static void op_sig_keypair(void *v) {
    sig_ctx *c = v;
    OQS_SIG_keypair(c->sig, c->pk, c->sk);
}
static void op_sig_sign(void *v) {
    sig_ctx *c = v;
    size_t l = 0;
    OQS_SIG_sign(c->sig, c->sg, &l, c->msg, c->msglen, c->sk);
    c->sglen = l;
}
static void op_sig_verify(void *v) {
    sig_ctx *c = v;
    OQS_SIG_verify(c->sig, c->msg, c->msglen, c->sg, c->sglen, c->pk);
}

static int bench_sig(const char *name, FILE *jf, int *first) {
    OQS_SIG *sig = OQS_SIG_new(name);
    if (!sig) {
        printf("--- %s (liboqs) ---\n  UNAVAILABLE in this liboqs build\n", name);
        return 2;
    }
    printf("--- %s (liboqs) ---\n", name);
    printf("  sizes: pk=%zu sk=%zu sig=%zu\n",
           sig->length_public_key, sig->length_secret_key,
           sig->length_signature);
    sig_ctx c;
    c.sig = sig;
    c.pk = malloc(sig->length_public_key);
    c.sk = malloc(sig->length_secret_key);
    c.sg = malloc(sig->length_signature);
    c.msg = (const uint8_t *)MSG;
    c.msglen = strlen(MSG);
    c.sglen = 0;
    if (!c.pk || !c.sk || !c.sg) return 2;

    int ok = 1;
    if (OQS_SIG_keypair(sig, c.pk, c.sk) != OQS_SUCCESS) { printf("  CORRECTNESS FAIL: keypair\n"); ok = 0; }
    size_t sl = 0;
    if (OQS_SIG_sign(sig, c.sg, &sl, c.msg, c.msglen, c.sk) != OQS_SUCCESS) { printf("  CORRECTNESS FAIL: sign\n"); ok = 0; }
    c.sglen = sl;
    if (OQS_SIG_verify(sig, c.msg, c.msglen, c.sg, c.sglen, c.pk) != OQS_SUCCESS) { printf("  CORRECTNESS FAIL: verify(valid)\n"); ok = 0; }
    c.sg[0] ^= 0x01; /* tampered signature must fail verification */
    if (OQS_SIG_verify(sig, c.msg, c.msglen, c.sg, c.sglen, c.pk) == OQS_SUCCESS) { printf("  CORRECTNESS FAIL: verify(tampered) accepted\n"); ok = 0; }
    c.sg[0] ^= 0x01;
    printf("  correctness: %s (sign/verify round-trip, tampered signature rejected; sig_len=%zu)\n",
           ok ? "PASS" : "FAIL", sl);

    double s_key[4], s_sign[4], s_ver[4];
    time_op(op_sig_keypair, &c, 1000, s_key);
    time_op(op_sig_sign, &c, 1000, s_sign);
    time_op(op_sig_verify, &c, 1000, s_ver);
    print_stats("keygen", s_key, 1000);
    print_stats("sign", s_sign, 1000);
    print_stats("verify", s_ver, 1000);

    if (jf) {
        fprintf(jf, "%s\n    {\"algorithm\": \"%s\", \"type\": \"sig\","
                "\"pk_bytes\": %zu, \"sk_bytes\": %zu, \"sig_bytes\": %zu,"
                " \"correctness\": \"%s\","
                " \"keygen_us\": {\"median\": %.3f, \"mean\": %.3f, \"min\": %.3f, \"max\": %.3f},"
                " \"sign_us\": {\"median\": %.3f, \"mean\": %.3f, \"min\": %.3f, \"max\": %.3f},"
                " \"verify_us\": {\"median\": %.3f, \"mean\": %.3f, \"min\": %.3f, \"max\": %.3f}}",
                *first ? "" : ",", name,
                sig->length_public_key, sig->length_secret_key,
                sig->length_signature,
                ok ? "PASS" : "FAIL",
                s_key[0], s_key[1], s_key[2], s_key[3],
                s_sign[0], s_sign[1], s_sign[2], s_sign[3],
                s_ver[0], s_ver[1], s_ver[2], s_ver[3]);
        *first = 0;
    }
    free(c.pk); free(c.sk); free(c.sg);
    OQS_SIG_free(sig);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *json_path = NULL;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json") && i + 1 < argc) json_path = argv[++i];
    printf("liboqs version: %s\n", OQS_VERSION_TEXT);
    printf("cpu dispatch probe (liboqs OQS_CPU_has_extension): AVX2=%d BMI2=%d POPCNT=%d AVX512=%d\n",
           OQS_CPU_has_extension(OQS_CPU_EXT_AVX2),
           OQS_CPU_has_extension(OQS_CPU_EXT_BMI2),
           OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT),
           OQS_CPU_has_extension(OQS_CPU_EXT_AVX512));
    printf("liboqs selects its x86_64 (AVX2) ML-KEM/ML-DSA path when AVX2+BMI2+POPCNT are all present (src/kem/ml_kem/kem_ml_kem_512.c); otherwise the ref path.\n");
    printf("message: %zu-byte fixed string (see source); ML-DSA signing is hedged/randomized per FIPS 204\n",
           strlen(MSG));
    FILE *jf = NULL;
    if (json_path) {
        jf = fopen(json_path, "w");
        if (!jf) { fprintf(stderr, "cannot open %s\n", json_path); return 2; }
        fprintf(jf, "{\n  \"implementation\": \"liboqs\",\n  \"liboqs_version\": \"%s\",\n  \"results\": [", OQS_VERSION_TEXT);
    }
    int first = 1, rc = 0, r;
    const char *kems[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    for (int i = 0; i < 3; i++) { r = bench_kem(kems[i], jf, &first); if (r) rc = r; }
    const char *sigs[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    for (int i = 0; i < 3; i++) { r = bench_sig(sigs[i], jf, &first); if (r) rc = r; }
    if (jf) { fprintf(jf, "\n  ]\n}\n"); fclose(jf); printf("json written to %s\n", json_path); }
    printf("RESULT: %s (exit %d)\n", rc == 0 ? "PASS" : (rc == 2 ? "UNAVAILABLE" : "FAIL"), rc);
    return rc;
}
