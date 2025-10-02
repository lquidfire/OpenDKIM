/*
**  t-test50ED25519.c -- Ed25519 core signing and verification tests
**
**  Tests Ed25519-specific signature behavior across all canonicalizations
**  Purpose: Verify Ed25519 signing/verification works correctly for all
**           canonicalization modes (simple/simple, simple/relaxed,
**           relaxed/simple, relaxed/relaxed)
**
**  Note: Per RFC 8463, Ed25519-SHA256 computes a SHA-256 hash of the
**        canonicalized data (same as RSA), then signs that hash using
**        PureEdDSA Ed25519. Both algorithms sign the same SHA-256 hash,
**        just with different cryptographic signing methods.
*/

#include "build-config.h"
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif

#include "../dkim.h"
#include "t-testdata.h"

#define MAXHEADER 4096

/* Test message with various whitespace scenarios */
static const char *test_headers_simple[] = {
    "From: sender@example.com\r\n",
    "To: recipient@example.com\r\n",
    "Subject: Ed25519 Test Message\r\n",
    "Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n",
    "Message-ID: <ed25519-test@example.com>\r\n",
    NULL
};

static const char *test_body_simple =
    "This is a test message for Ed25519 signature validation.\r\n"
    "Second line of content.\r\n";

/* Test a specific canonicalization mode */
int test_canonicalization(DKIM_LIB *lib,
                          dkim_canon_t header_canon,
                          dkim_canon_t body_canon,
                          const char *canon_name)
{
    DKIM *sign_dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    int i;

    printf("Testing Ed25519 with %s canonicalization...\n", canon_name);

    /* Sign the message */
    sign_dkim = dkim_sign(lib, "test-ed25519", NULL,
                          (dkim_sigkey_t)KEYED25519,
                          SELECTORED25519, DOMAIN,
                          header_canon, body_canon,
                          DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (sign_dkim == NULL) {
        printf("FAIL: dkim_sign() failed for %s\n", canon_name);
        return 0;
    }

    /* Add headers */
    for (i = 0; test_headers_simple[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers_simple[i]);
        status = dkim_header(sign_dkim, hdr, strlen((char *)hdr));
        if (status != DKIM_STAT_OK) {
            printf("FAIL: dkim_header() failed for %s\n", canon_name);
            dkim_free(sign_dkim);
            return 0;
        }
    }

    /* End headers */
    status = dkim_eoh(sign_dkim);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_eoh() failed for %s\n", canon_name);
        dkim_free(sign_dkim);
        return 0;
    }

    /* Add body */
    status = dkim_body(sign_dkim, (unsigned char *)test_body_simple,
                       strlen(test_body_simple));
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_body() failed for %s\n", canon_name);
        dkim_free(sign_dkim);
        return 0;
    }

    /* Finalize signature */
    status = dkim_eom(sign_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_eom() failed for %s (status=%d)\n",
               canon_name, status);
        dkim_free(sign_dkim);
        return 0;
    }

    /* Get the signature header */
    status = dkim_getsighdr_d(sign_dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_getsighdr_d() failed for %s\n", canon_name);
        dkim_free(sign_dkim);
        return 0;
    }

    dkim_free(sign_dkim);

    /* Now verify the signature */
    verify_dkim = dkim_verify(lib, "test-verify-ed25519", NULL, &status);
    if (verify_dkim == NULL) {
        printf("FAIL: dkim_verify() failed for %s\n", canon_name);
        return 0;
    }

    /* Add signature header */
    status = dkim_header(verify_dkim, (unsigned char *)sig_header,
                         strlen(sig_header));
    if (status != DKIM_STAT_OK) {
        printf("FAIL: verify dkim_header() failed for signature in %s\n",
               canon_name);
        dkim_free(verify_dkim);
        return 0;
    }

    /* Add original headers */
    for (i = 0; test_headers_simple[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers_simple[i]);
        status = dkim_header(verify_dkim, hdr, strlen((char *)hdr));
        if (status != DKIM_STAT_OK) {
            printf("FAIL: verify dkim_header() failed for %s\n", canon_name);
            dkim_free(verify_dkim);
            return 0;
        }
    }

    /* End headers */
    status = dkim_eoh(verify_dkim);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: verify dkim_eoh() failed for %s\n", canon_name);
        dkim_free(verify_dkim);
        return 0;
    }

    /* Add body */
    status = dkim_body(verify_dkim, (unsigned char *)test_body_simple,
                       strlen(test_body_simple));
    if (status != DKIM_STAT_OK) {
        printf("FAIL: verify dkim_body() failed for %s\n", canon_name);
        dkim_free(verify_dkim);
        return 0;
    }

    /* Finalize verification */
    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Ed25519 verification failed for %s (status=%d)\n",
               canon_name, status);

        /* Get detailed error info */
        DKIM_SIGINFO *sig = dkim_getsignature(verify_dkim);
        if (sig != NULL) {
            int err = dkim_sig_geterror(sig);
            printf("      Signature error code: %d\n", err);
        }

        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Ed25519 %s verification succeeded\n", canon_name);
    dkim_free(verify_dkim);
    return 1;
}

int main(void)
{
    DKIM_LIB *lib;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    int tests_passed = 0;
    int tests_total = 4;

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif

    printf("*** Ed25519 Core Signing & Verification Tests ***\n\n");

    /* Initialize library */
    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    /* Configure library */
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Test all canonicalization modes */
    tests_passed += test_canonicalization(lib, DKIM_CANON_SIMPLE,
                                          DKIM_CANON_SIMPLE,
                                          "simple/simple");

    tests_passed += test_canonicalization(lib, DKIM_CANON_SIMPLE,
                                          DKIM_CANON_RELAXED,
                                          "simple/relaxed");

    tests_passed += test_canonicalization(lib, DKIM_CANON_RELAXED,
                                          DKIM_CANON_SIMPLE,
                                          "relaxed/simple");

    tests_passed += test_canonicalization(lib, DKIM_CANON_RELAXED,
                                          DKIM_CANON_RELAXED,
                                          "relaxed/relaxed");

    /* Cleanup */
    dkim_close(lib);

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, tests_total);

    if (tests_passed == tests_total) {
        printf("SUCCESS: All Ed25519 canonicalization tests passed\n");
        return 0;
    } else {
        printf("FAILURE: Some Ed25519 tests failed\n");
        return 1;
    }
}
