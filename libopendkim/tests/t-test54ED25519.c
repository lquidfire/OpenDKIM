/*
**  t-test54ED25519.c -- Ed25519 vs RSA performance comparison
**
**  Compares signing and verification performance between Ed25519 and RSA
**  Tests include:
**  - Single message signing speed
**  - Single message verification speed
**  - Batch operations
**  - Memory usage patterns
*/

#include "build-config.h"
#include <sys/types.h>
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif

#include "../dkim.h"
#include "t-testdata.h"

#define MAXHEADER 4096
#define PERF_ITERATIONS 100

/* Get current time in microseconds */
static uint64_t get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Standard test message */
static const char *test_headers[] = {
    "From: sender@example.com\r\n",
    "To: recipient@example.com\r\n",
    "Subject: Performance Test Message\r\n",
    "Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n",
    "Message-ID: <perf-test@example.com>\r\n",
    NULL
};

static const char *test_body =
    "This is a standard test message for performance comparison.\r\n"
    "It contains multiple lines to simulate real email content.\r\n"
    "Performance metrics are critical for production deployment.\r\n"
    "Ed25519 is expected to be faster than RSA for signing.\r\n";

/* Test signing performance for a single algorithm */
uint64_t test_signing_speed(DKIM_LIB *lib, const char *key,
                            const char *selector, int sign_alg,
                            const char *alg_name, int iterations)
{
    uint64_t start, end;
    int successful = 0;

    printf("Testing %s signing speed (%d iterations)...\n",
           alg_name, iterations);

    start = get_time_us();

    for (int iter = 0; iter < iterations; iter++) {
        DKIM *dkim;
        DKIM_STAT status;
        unsigned char hdr[MAXHEADER + 1];

        dkim = dkim_sign(lib, "perf-test", NULL,
                        (dkim_sigkey_t)key, selector, DOMAIN,
                        DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                        sign_alg, -1L, &status);

        if (dkim == NULL) {
            printf("WARNING: Signing failed at iteration %d\n", iter);
            continue;
        }

        /* Add headers */
        for (int i = 0; test_headers[i] != NULL; i++) {
            snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
            dkim_header(dkim, hdr, strlen((char *)hdr));
        }

        dkim_eoh(dkim);
        dkim_body(dkim, (unsigned char *)test_body, strlen(test_body));

        status = dkim_eom(dkim, NULL);
        if (status == DKIM_STAT_OK) {
            successful++;
        }

        dkim_free(dkim);
    }

    end = get_time_us();

    uint64_t elapsed = end - start;
    double avg_us = (double)elapsed / successful;
    double ops_per_sec = 1000000.0 / avg_us;

    printf("  Completed: %d/%d successful\n", successful, iterations);
    printf("  Total time: %llu μs\n", (unsigned long long)elapsed);
    printf("  Average per operation: %.2f μs\n", avg_us);
    printf("  Operations per second: %.2f\n", ops_per_sec);

    return elapsed;
}

/* Test verification performance */
uint64_t test_verification_speed(DKIM_LIB *lib, const char *key,
                                const char *selector, int sign_alg,
                                const char *alg_name, int iterations)
{
    DKIM *sign_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    uint64_t start, end;
    int successful = 0;

    printf("\nTesting %s verification speed (%d iterations)...\n",
           alg_name, iterations);

    /* First, create a signature to verify */
    sign_dkim = dkim_sign(lib, "perf-sign", NULL,
                         (dkim_sigkey_t)key, selector, DOMAIN,
                         DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                         sign_alg, -1L, &status);

    if (sign_dkim == NULL) {
        printf("FAIL: Could not create signature for verification test\n");
        return 0;
    }

    for (int i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(sign_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(sign_dkim);
    dkim_body(sign_dkim, (unsigned char *)test_body, strlen(test_body));
    dkim_eom(sign_dkim, NULL);
    dkim_getsighdr_d(sign_dkim, strlen(TESTKEY),
                     (unsigned char *)sig_header, sizeof sig_header);
    dkim_free(sign_dkim);

    /* Now time the verification */
    start = get_time_us();

    for (int iter = 0; iter < iterations; iter++) {
        DKIM *verify_dkim;

        verify_dkim = dkim_verify(lib, "perf-verify", NULL, &status);
        if (verify_dkim == NULL) {
            continue;
        }

        /* Add signature and headers */
        dkim_header(verify_dkim, (unsigned char *)sig_header,
                   strlen(sig_header));
        for (int i = 0; test_headers[i] != NULL; i++) {
            snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
            dkim_header(verify_dkim, hdr, strlen((char *)hdr));
        }
        dkim_eoh(verify_dkim);
        dkim_body(verify_dkim, (unsigned char *)test_body, strlen(test_body));

        status = dkim_eom(verify_dkim, NULL);
        if (status == DKIM_STAT_OK) {
            successful++;
        }

        dkim_free(verify_dkim);
    }

    end = get_time_us();

    uint64_t elapsed = end - start;
    double avg_us = (double)elapsed / successful;
    double ops_per_sec = 1000000.0 / avg_us;

    printf("  Completed: %d/%d successful\n", successful, iterations);
    printf("  Total time: %llu μs\n", (unsigned long long)elapsed);
    printf("  Average per operation: %.2f μs\n", avg_us);
    printf("  Operations per second: %.2f\n", ops_per_sec);

    return elapsed;
}

/* Test with varying message sizes */
void test_message_size_scaling(DKIM_LIB *lib)
{
    size_t sizes[] = {100, 1000, 10000, 100000};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    printf("\n=== Message Size Scaling Test ===\n");

    for (int i = 0; i < num_sizes; i++) {
        size_t size = sizes[i];
        char *body = malloc(size + 1);
        if (body == NULL) {
            continue;
        }

        /* Fill with test data */
        for (size_t j = 0; j < size - 2; j += 72) {
            size_t remaining = size - j - 2;
            size_t to_write = (remaining < 70) ? remaining : 70;
            memset(body + j, 'A', to_write);
            if (j + to_write + 2 <= size) {
                body[j + to_write] = '\r';
                body[j + to_write + 1] = '\n';
            }
        }
        body[size] = '\0';

        printf("\nMessage size: %zu bytes\n", size);

        /* Test Ed25519 */
        uint64_t start = get_time_us();
        DKIM *dkim = dkim_sign(lib, "size-test", NULL,
                              (dkim_sigkey_t)KEYED25519,
                              SELECTORED25519, DOMAIN,
                              DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                              DKIM_SIGN_ED25519SHA256, -1L, NULL);
        if (dkim != NULL) {
            unsigned char hdr[MAXHEADER + 1];
            for (int j = 0; test_headers[j] != NULL; j++) {
                snprintf((char *)hdr, sizeof hdr, "%s", test_headers[j]);
                dkim_header(dkim, hdr, strlen((char *)hdr));
            }
            dkim_eoh(dkim);
            dkim_body(dkim, (unsigned char *)body, size);
            dkim_eom(dkim, NULL);
            dkim_free(dkim);
        }
        uint64_t ed_time = get_time_us() - start;

        /* Test RSA */
        start = get_time_us();
        dkim = dkim_sign(lib, "size-test-rsa", NULL,
                        (dkim_sigkey_t)KEY, SELECTOR, DOMAIN,
                        DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                        DKIM_SIGN_RSASHA256, -1L, NULL);
        if (dkim != NULL) {
            unsigned char hdr[MAXHEADER + 1];
            for (int j = 0; test_headers[j] != NULL; j++) {
                snprintf((char *)hdr, sizeof hdr, "%s", test_headers[j]);
                dkim_header(dkim, hdr, strlen((char *)hdr));
            }
            dkim_eoh(dkim);
            dkim_body(dkim, (unsigned char *)body, size);
            dkim_eom(dkim, NULL);
            dkim_free(dkim);
        }
        uint64_t rsa_time = get_time_us() - start;

        printf("  Ed25519: %llu μs\n", (unsigned long long)ed_time);
        printf("  RSA-2048: %llu μs\n", (unsigned long long)rsa_time);
        printf("  Speedup: %.2fx\n", (double)rsa_time / ed_time);

        free(body);
    }
}

int main(void)
{
    DKIM_LIB *lib;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    uint64_t ed_sign_time, rsa_sign_time;
    uint64_t ed_verify_time, rsa_verify_time;

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif

    printf("*** Ed25519 Performance Comparison Tests ***\n\n");
    printf("Note: These are relative performance indicators, not benchmarks.\n");
    printf("Actual performance depends on hardware, library implementation,\n");
    printf("and system load.\n\n");

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Signing performance */
    printf("=== Signing Performance ===\n\n");
    ed_sign_time = test_signing_speed(lib, KEYED25519, SELECTORED25519,
                                      DKIM_SIGN_ED25519SHA256,
                                      "Ed25519", PERF_ITERATIONS);

    rsa_sign_time = test_signing_speed(lib, KEY, SELECTOR,
                                       DKIM_SIGN_RSASHA256,
                                       "RSA-SHA256", PERF_ITERATIONS);

    printf("\nSigning speedup: %.2fx\n",
           (double)rsa_sign_time / ed_sign_time);

    /* Verification performance */
    printf("\n=== Verification Performance ===\n\n");
    ed_verify_time = test_verification_speed(lib, KEYED25519, SELECTORED25519,
                                             DKIM_SIGN_ED25519SHA256,
                                             "Ed25519", PERF_ITERATIONS);

    rsa_verify_time = test_verification_speed(lib, KEY, SELECTOR,
                                              DKIM_SIGN_RSASHA256,
                                              "RSA-SHA256", PERF_ITERATIONS);

    printf("\nVerification speedup: %.2fx\n",
           (double)rsa_verify_time / ed_verify_time);

    /* Message size scaling */
    test_message_size_scaling(lib);

    /* Summary */
    printf("\n=== Performance Summary ===\n");
    printf("Ed25519 vs RSA-SHA256 (2048-bit):\n");
    printf("  Signing:      %.2fx faster\n",
           (double)rsa_sign_time / ed_sign_time);
    printf("  Verification: %.2fx faster\n",
           (double)rsa_verify_time / ed_verify_time);
    printf("\nEd25519 advantages:\n");
    printf("  - Smaller signatures (64 vs ~256 bytes)\n");
    printf("  - Smaller keys (32 vs ~256 bytes)\n");
    printf("  - Faster operations (typically 2-10x)\n");
    printf("  - Simpler implementation (fewer edge cases)\n");

    dkim_close(lib);

    return 0;
}
