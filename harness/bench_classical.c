/* bench_classical.c — timing + correctness benchmark for the classical
 * baselines the core protocol uses today, via the system OpenSSL 3.0.13
 * (libcrypto): ECDSA over secp256k1 (the validation/proposal signing
 * scheme) and Ed25519 (the other KeyType the protocol recognises).
 *
 * What is measured, and why it matches the protocol:
 * - secp256k1: keygen, sign of a 32-byte digest (the protocol signs a
 *   256-bit signing hash via signDigest), verify of a DER signature.
 *   DER signatures are at most 72 bytes, matching the 72-byte proposal
 *   cap in the pinned tree.
 * - Ed25519: keygen, sign of the same fixed 64-byte message used by
 *   the lattice drivers, verify. Ed25519 signatures are 64 bytes.
 * The point is a same-host, same-toolchain classical baseline for the
 * cost model: no published estimate is used for the classical side.
 *
 * Method: identical to bench_liboqs.c — correctness check first
 * (round-trip sign/verify; tampered signature must fail), then each
 * operation timed in a tight loop (N iterations, REPS repeats,
 * median/mean/min/max per-op microseconds via
 * clock_gettime(CLOCK_MONOTONIC)).
 *
 * Output: human-readable lines to stdout (captured verbatim as the raw
 * log) and a JSON document to the file named by --json. Exit 0 only if
 * every correctness check passes.
 *
 * Build: gcc -O2 -std=c99 -Wall bench_classical.c -lcrypto -o bench_classical
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>

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

/* ---------------- ECDSA secp256k1 ---------------- */
typedef struct { EVP_PKEY *pkey; uint8_t digest[32]; uint8_t *sig; size_t siglen; } ec_ctx;

static void ec_keygen(void *v) {
    ec_ctx *c = v;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_secp256k1);
    EVP_PKEY *params = NULL;
    EVP_PKEY_paramgen(kctx, &params);
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_keygen_init(gctx);
    EVP_PKEY *nk = NULL;
    EVP_PKEY_keygen(gctx, &nk);
    EVP_PKEY_free(c->pkey);
    c->pkey = nk;
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
}

static void ec_sign(void *v) {
    ec_ctx *c = v;
    size_t l = 0;
    /* ECDSA_sign over the 32-byte digest, as signDigest does. */
    ECDSA_sign(0, c->digest, 32, c->sig, (unsigned int *)&l,
               EVP_PKEY_get0_EC_KEY(c->pkey));
    c->siglen = l;
}

static void ec_verify(void *v) {
    ec_ctx *c = v;
    ECDSA_verify(0, c->digest, 32, c->sig, (int)c->siglen,
                 EVP_PKEY_get0_EC_KEY(c->pkey));
}

static int bench_secp256k1(FILE *jf, int *first) {
    printf("--- ECDSA secp256k1 (OpenSSL) ---\n");
    printf("  sizes: pk=33 (compressed) sk=32 sig=DER, at most 72\n");
    ec_ctx c;
    memset(&c, 0, sizeof c);
    for (int i = 0; i < 32; i++) c.digest[i] = (uint8_t)(0xA5 + i);
    c.sig = malloc(80);
    if (!c.sig) return 2;
    c.pkey = NULL;
    ec_keygen(&c);
    int ok = 1;
    if (!c.pkey) { printf("  CORRECTNESS FAIL: keygen\n"); ok = 0; }
    c.siglen = 0;
    ec_sign(&c);
    if (c.siglen == 0 || c.siglen > 72) { printf("  CORRECTNESS FAIL: sign (siglen=%zu)\n", c.siglen); ok = 0; }
    if (ECDSA_verify(0, c.digest, 32, c.sig, (int)c.siglen, EVP_PKEY_get0_EC_KEY(c.pkey)) != 1) {
        printf("  CORRECTNESS FAIL: verify(valid)\n"); ok = 0;
    }
    size_t good_len = c.siglen;
    c.sig[0] ^= 0x01;
    if (ECDSA_verify(0, c.digest, 32, c.sig, (int)c.siglen, EVP_PKEY_get0_EC_KEY(c.pkey)) == 1) {
        printf("  CORRECTNESS FAIL: verify(tampered) accepted\n"); ok = 0;
    }
    c.sig[0] ^= 0x01;
    c.siglen = good_len;
    printf("  correctness: %s (sign/verify round-trip over 32-byte digest, tampered signature rejected; sig_len=%zu, DER, <= 72)\n",
           ok ? "PASS" : "FAIL", good_len);
    double s_key[4], s_sign[4], s_ver[4];
    time_op(ec_keygen, &c, 1000, s_key);
    time_op(ec_sign, &c, 2000, s_sign);
    time_op(ec_verify, &c, 2000, s_ver);
    print_stats("keygen", s_key, 1000);
    print_stats("sign", s_sign, 2000);
    print_stats("verify", s_ver, 2000);
    if (jf) {
        fprintf(jf, "%s\n    {\"algorithm\": \"ECDSA-secp256k1\", \"type\": \"sig\","
                "\"pk_bytes\": 33, \"sk_bytes\": 32, \"sig_bytes\": %zu,"
                " \"correctness\": \"%s\"",
                *first ? "" : ",", good_len, ok ? "PASS" : "FAIL");
        json_stats(jf, "keygen", s_key, 1);
        json_stats(jf, "sign", s_sign, 1);
        json_stats(jf, "verify", s_ver, 1);
        fprintf(jf, "}");
        *first = 0;
    }
    free(c.sig);
    EVP_PKEY_free(c.pkey);
    return ok ? 0 : 1;
}

/* ---------------- Ed25519 ---------------- */
typedef struct { EVP_PKEY *pkey; const uint8_t *msg; size_t msglen; uint8_t *sig; size_t siglen; } ed_ctx;

static void ed_keygen(void *v) {
    ed_ctx *c = v;
    EVP_PKEY *nk = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    EVP_PKEY_free(c->pkey);
    c->pkey = nk;
}

static void ed_sign(void *v) {
    ed_ctx *c = v;
    /* For Ed25519, EVP_DigestSign takes siglen as an in/out parameter:
     * it must hold the buffer capacity (64) on entry. */
    size_t l = 64;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestSignInit(m, NULL, NULL, NULL, c->pkey);
    EVP_DigestSign(m, c->sig, &l, c->msg, c->msglen);
    EVP_MD_CTX_free(m);
    c->siglen = l;
}

static void ed_verify(void *v) {
    ed_ctx *c = v;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(m, NULL, NULL, NULL, c->pkey);
    EVP_DigestVerify(m, c->sig, c->siglen, c->msg, c->msglen);
    EVP_MD_CTX_free(m);
}

static int bench_ed25519(FILE *jf, int *first) {
    printf("--- Ed25519 (OpenSSL) ---\n");
    printf("  sizes: pk=32 sk=32 sig=64\n");
    ed_ctx c;
    memset(&c, 0, sizeof c);
    c.msg = (const uint8_t *)MSG;
    c.msglen = strlen(MSG);
    c.sig = malloc(64);
    if (!c.sig) return 2;
    c.pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    int ok = 1;
    if (!c.pkey) { printf("  CORRECTNESS FAIL: keygen\n"); ok = 0; }
    c.siglen = 0;
    ed_sign(&c);
    if (c.siglen != 64) { printf("  CORRECTNESS FAIL: sign (siglen=%zu)\n", c.siglen); ok = 0; }
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(m, NULL, NULL, NULL, c.pkey);
    if (EVP_DigestVerify(m, c.sig, c.siglen, c.msg, c.msglen) != 1) {
        printf("  CORRECTNESS FAIL: verify(valid)\n"); ok = 0;
    }
    EVP_MD_CTX_free(m);
    c.sig[0] ^= 0x01;
    m = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(m, NULL, NULL, NULL, c.pkey);
    if (EVP_DigestVerify(m, c.sig, c.siglen, c.msg, c.msglen) == 1) {
        printf("  CORRECTNESS FAIL: verify(tampered) accepted\n"); ok = 0;
    }
    EVP_MD_CTX_free(m);
    c.sig[0] ^= 0x01;
    printf("  correctness: %s (sign/verify round-trip over 64-byte message, tampered signature rejected; sig_len=%zu)\n",
           ok ? "PASS" : "FAIL", c.siglen);
    double s_key[4], s_sign[4], s_ver[4];
    time_op(ed_keygen, &c, 1000, s_key);
    time_op(ed_sign, &c, 2000, s_sign);
    time_op(ed_verify, &c, 2000, s_ver);
    print_stats("keygen", s_key, 1000);
    print_stats("sign", s_sign, 2000);
    print_stats("verify", s_ver, 2000);
    if (jf) {
        fprintf(jf, "%s\n    {\"algorithm\": \"Ed25519\", \"type\": \"sig\","
                "\"pk_bytes\": 32, \"sk_bytes\": 32, \"sig_bytes\": 64,"
                " \"correctness\": \"%s\"",
                *first ? "" : ",", ok ? "PASS" : "FAIL");
        json_stats(jf, "keygen", s_key, 1);
        json_stats(jf, "sign", s_sign, 1);
        json_stats(jf, "verify", s_ver, 1);
        fprintf(jf, "}");
        *first = 0;
    }
    free(c.sig);
    EVP_PKEY_free(c.pkey);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *json_path = NULL;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json") && i + 1 < argc) json_path = argv[++i];
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    printf("message: %zu-byte fixed string (same string as the lattice drivers)\n", strlen(MSG));
    FILE *jf = NULL;
    if (json_path) {
        jf = fopen(json_path, "w");
        if (!jf) { fprintf(stderr, "cannot open %s\n", json_path); return 2; }
        fprintf(jf, "{\n  \"implementation\": \"openssl-classical\",\n  \"openssl_version\": \"%s\",\n  \"results\": [", OPENSSL_VERSION_TEXT);
    }
    int first = 1, rc = 0, r;
    r = bench_secp256k1(jf, &first); if (r) rc = r;
    r = bench_ed25519(jf, &first); if (r) rc = r;
    if (jf) { fprintf(jf, "\n  ]\n}\n"); fclose(jf); printf("json written to %s\n", json_path); }
    printf("RESULT: %s (exit %d)\n", rc == 0 ? "PASS" : "FAIL", rc);
    return rc;
}
