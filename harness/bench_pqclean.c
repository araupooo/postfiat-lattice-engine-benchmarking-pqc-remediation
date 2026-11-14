/* bench_pqclean.c — timing + correctness benchmark for one ML-KEM or
 * ML-DSA parameter set via the PQClean "clean" reference implementation.
 *
 * Compile once per parameter set, e.g.:
 *   gcc -O2 -std=c99 -Wall -I<clean-dir> -I<pqclean>/common \
 *       -DPREFIX=PQCLEAN_MLKEM512_CLEAN -DPQ_KEM \
 *       bench_pqclean.c <clean sources...> <pqclean>/common/fips202.c \
 *       <pqclean>/common/randombytes.c -o bench_pqclean_mlkem512
 * (see harness/build_benchmarks.sh for the exact per-set source lists)
 *
 * Method: identical to bench_liboqs.c — correctness check first
 * (encap/decap shared secrets equal and tampered ciphertext rejected to
 * a different secret; sign/verify round-trip and tampered signature
 * rejected), then each operation timed in a tight loop (N iterations,
 * REPS repeats, median/mean/min/max per-op microseconds via
 * clock_gettime(CLOCK_MONOTONIC)). The signed message is the same fixed
 * 64-byte string used by the liboqs driver.
 *
 * Output: human-readable lines to stdout (captured verbatim as the raw
 * log) and a one-entry JSON document to the file named by --json.
 * Exit 0 = correctness pass; 1 = correctness fail; 2 = build/usage error.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "api.h"

#define REPS 7
#define MSG "PFTL lattice-engine benchmark message, 64 bytes: 0123456789abcde"

#define CAT2(a, b) a##b
#define XCAT(a, b) CAT2(a, b)
#define FN(name) XCAT(PREFIX, name)
#define SZ(name) XCAT(PREFIX, name)

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

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

static void json_stats(FILE *jf, const char *key, const double s[4], int comma) {
    fprintf(jf, "%s\"%s_us\": {\"median\": %.3f, \"mean\": %.3f, \"min\": %.3f, \"max\": %.3f}",
            comma ? ", " : "", key, s[0], s[1], s[2], s[3]);
}

#ifdef PQ_KEM
typedef struct { uint8_t *pk, *sk, *ct, *ss1, *ss2; } ctx_t;
static void op_keypair(void *v) { ctx_t *c = v; FN(_crypto_kem_keypair)(c->pk, c->sk); }
static void op_enc(void *v) { ctx_t *c = v; FN(_crypto_kem_enc)(c->ct, c->ss1, c->pk); }
static void op_dec(void *v) { ctx_t *c = v; FN(_crypto_kem_dec)(c->ss2, c->ct, c->sk); }

int main(int argc, char **argv) {
    const char *json_path = NULL;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json") && i + 1 < argc) json_path = argv[++i];
    const char *alg = SZ(_CRYPTO_ALGNAME);
    printf("--- %s (PQClean clean) ---\n", alg);
    printf("  sizes: pk=%d sk=%d ct=%d ss=%d\n",
           SZ(_CRYPTO_PUBLICKEYBYTES), SZ(_CRYPTO_SECRETKEYBYTES),
           SZ(_CRYPTO_CIPHERTEXTBYTES), SZ(_CRYPTO_BYTES));
    ctx_t c;
    c.pk = malloc(SZ(_CRYPTO_PUBLICKEYBYTES));
    c.sk = malloc(SZ(_CRYPTO_SECRETKEYBYTES));
    c.ct = malloc(SZ(_CRYPTO_CIPHERTEXTBYTES));
    c.ss1 = malloc(SZ(_CRYPTO_BYTES));
    c.ss2 = malloc(SZ(_CRYPTO_BYTES));
    if (!c.pk || !c.sk || !c.ct || !c.ss1 || !c.ss2) return 2;
    int ok = 1;
    if (FN(_crypto_kem_keypair)(c.pk, c.sk) != 0) { printf("  CORRECTNESS FAIL: keypair\n"); ok = 0; }
    if (FN(_crypto_kem_enc)(c.ct, c.ss1, c.pk) != 0) { printf("  CORRECTNESS FAIL: enc\n"); ok = 0; }
    if (FN(_crypto_kem_dec)(c.ss2, c.ct, c.sk) != 0) { printf("  CORRECTNESS FAIL: dec\n"); ok = 0; }
    if (memcmp(c.ss1, c.ss2, SZ(_CRYPTO_BYTES)) != 0) { printf("  CORRECTNESS FAIL: shared secrets differ\n"); ok = 0; }
    c.ct[0] ^= 0x01;
    uint8_t ss_t[64];
    if (FN(_crypto_kem_dec)(ss_t, c.ct, c.sk) != 0) { printf("  CORRECTNESS FAIL: dec(tampered)\n"); ok = 0; }
    if (memcmp(ss_t, c.ss1, SZ(_CRYPTO_BYTES)) == 0) { printf("  CORRECTNESS FAIL: tampered ct gave valid secret\n"); ok = 0; }
    c.ct[0] ^= 0x01;
    printf("  correctness: %s (enc/dec match, tampered ct rejected to a different secret)\n", ok ? "PASS" : "FAIL");
    double s_key[4], s_enc[4], s_dec[4];
    time_op(op_keypair, &c, 2000, s_key);
    time_op(op_enc, &c, 2000, s_enc);
    time_op(op_dec, &c, 2000, s_dec);
    print_stats("keygen", s_key, 2000);
    print_stats("encaps", s_enc, 2000);
    print_stats("decaps", s_dec, 2000);
    if (json_path) {
        FILE *jf = fopen(json_path, "w");
        if (!jf) { fprintf(stderr, "cannot open %s\n", json_path); return 2; }
        fprintf(jf, "{\n  \"implementation\": \"pqclean\",\n  \"pqclean_commit\": \"%s\",\n  \"results\": [\n    {\"algorithm\": \"%s\", \"type\": \"kem\","
                "\"pk_bytes\": %d, \"sk_bytes\": %d, \"ct_bytes\": %d, \"ss_bytes\": %d,"
                " \"correctness\": \"%s\"",
                PQCLEAN_COMMIT, alg,
                SZ(_CRYPTO_PUBLICKEYBYTES), SZ(_CRYPTO_SECRETKEYBYTES),
                SZ(_CRYPTO_CIPHERTEXTBYTES), SZ(_CRYPTO_BYTES),
                ok ? "PASS" : "FAIL");
        json_stats(jf, "keygen", s_key, 1);
        json_stats(jf, "encaps", s_enc, 1);
        json_stats(jf, "decaps", s_dec, 1);
        fprintf(jf, "}\n  ]\n}\n");
        fclose(jf);
        printf("json written to %s\n", json_path);
    }
    printf("RESULT: %s (exit %d)\n", ok ? "PASS" : "FAIL", ok ? 0 : 1);
    return ok ? 0 : 1;
}
#endif /* PQ_KEM */

#ifdef PQ_SIG
typedef struct { uint8_t *pk, *sk, *sg; size_t sglen; const uint8_t *msg; size_t msglen; } ctx_t;
static void op_keypair(void *v) { ctx_t *c = v; FN(_crypto_sign_keypair)(c->pk, c->sk); }
static void op_sign(void *v) {
    ctx_t *c = v;
    size_t l = 0;
    FN(_crypto_sign_signature)(c->sg, &l, c->msg, c->msglen, c->sk);
    c->sglen = l;
}
static void op_verify(void *v) {
    ctx_t *c = v;
    FN(_crypto_sign_verify)(c->sg, c->sglen, c->msg, c->msglen, c->pk);
}

int main(int argc, char **argv) {
    const char *json_path = NULL;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json") && i + 1 < argc) json_path = argv[++i];
    const char *alg = SZ(_CRYPTO_ALGNAME);
    printf("--- %s (PQClean clean) ---\n", alg);
    printf("  sizes: pk=%d sk=%d sig=%d\n",
           SZ(_CRYPTO_PUBLICKEYBYTES), SZ(_CRYPTO_SECRETKEYBYTES),
           SZ(_CRYPTO_BYTES));
    ctx_t c;
    c.pk = malloc(SZ(_CRYPTO_PUBLICKEYBYTES));
    c.sk = malloc(SZ(_CRYPTO_SECRETKEYBYTES));
    c.sg = malloc(SZ(_CRYPTO_BYTES));
    c.msg = (const uint8_t *)MSG;
    c.msglen = strlen(MSG);
    c.sglen = 0;
    if (!c.pk || !c.sk || !c.sg) return 2;
    int ok = 1;
    if (FN(_crypto_sign_keypair)(c.pk, c.sk) != 0) { printf("  CORRECTNESS FAIL: keypair\n"); ok = 0; }
    size_t sl = 0;
    if (FN(_crypto_sign_signature)(c.sg, &sl, c.msg, c.msglen, c.sk) != 0) { printf("  CORRECTNESS FAIL: sign\n"); ok = 0; }
    c.sglen = sl;
    if (FN(_crypto_sign_verify)(c.sg, c.sglen, c.msg, c.msglen, c.pk) != 0) { printf("  CORRECTNESS FAIL: verify(valid)\n"); ok = 0; }
    c.sg[0] ^= 0x01;
    if (FN(_crypto_sign_verify)(c.sg, c.sglen, c.msg, c.msglen, c.pk) == 0) { printf("  CORRECTNESS FAIL: verify(tampered) accepted\n"); ok = 0; }
    c.sg[0] ^= 0x01;
    printf("  correctness: %s (sign/verify round-trip, tampered signature rejected; sig_len=%zu)\n",
           ok ? "PASS" : "FAIL", sl);
    double s_key[4], s_sign[4], s_ver[4];
    time_op(op_keypair, &c, 1000, s_key);
    time_op(op_sign, &c, 1000, s_sign);
    time_op(op_verify, &c, 1000, s_ver);
    print_stats("keygen", s_key, 1000);
    print_stats("sign", s_sign, 1000);
    print_stats("verify", s_ver, 1000);
    if (json_path) {
        FILE *jf = fopen(json_path, "w");
        if (!jf) { fprintf(stderr, "cannot open %s\n", json_path); return 2; }
        fprintf(jf, "{\n  \"implementation\": \"pqclean\",\n  \"pqclean_commit\": \"%s\",\n  \"results\": [\n    {\"algorithm\": \"%s\", \"type\": \"sig\","
                "\"pk_bytes\": %d, \"sk_bytes\": %d, \"sig_bytes\": %d,"
                " \"correctness\": \"%s\"",
                PQCLEAN_COMMIT, alg,
                SZ(_CRYPTO_PUBLICKEYBYTES), SZ(_CRYPTO_SECRETKEYBYTES),
                SZ(_CRYPTO_BYTES),
                ok ? "PASS" : "FAIL");
        json_stats(jf, "keygen", s_key, 1);
        json_stats(jf, "sign", s_sign, 1);
        json_stats(jf, "verify", s_ver, 1);
        fprintf(jf, "}\n  ]\n}\n");
        fclose(jf);
        printf("json written to %s\n", json_path);
    }
    printf("RESULT: %s (exit %d)\n", ok ? "PASS" : "FAIL", ok ? 0 : 1);
    return ok ? 0 : 1;
}
#endif /* PQ_SIG */
