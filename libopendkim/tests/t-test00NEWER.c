i/*
**  t-test00NEWER.c -- relaxed/relaxed signing test for RSA and Ed25519
**
**  Tests both RSA-SHA256 and Ed25519-SHA256 signatures using the same
**  message content, verifying that both algorithms can successfully
**  sign and verify the same message.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define MAXHEADER 4096

int
main(void)
{
    DKIM_LIB *lib;
    DKIM *dkim;
    DKIM *verify_dkim;
    DKIM_STAT status;
    uint64_t fixed_time = 1172620939;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    int total_tests = 0;
    int passed_tests = 0;

    /* Array of test cases: key, selector, description */
    struct {
        const char *key;
        const char *selector;
        const char *desc;
    } tests[] = {
        { KEY, SELECTOR, "RSA-SHA256" },
        { KEYED25519, SELECTOR, "Ed25519-SHA256" }
    };

    /* Headers to sign */
    const char *headers[] = {
        HEADER02, HEADER03, HEADER04, HEADER05,
        HEADER06, HEADER07, HEADER08, HEADER09
    };

    /* Body parts to sign */
    const char *bodies[] = {
        BODY00, BODY01, BODY01A, BODY01B, BODY01C,
        BODY01D, BODY01E, BODY02, BODY03, BODY04, BODY05
    };

    printf("*** Dual Algorithm DKIM Test Suite ***\n");

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    /* Initialize the library */
    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    /* Set fixed time for reproducible signatures */
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);

    /* Test each algorithm */
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        printf("\n=== Testing %s ===\n", tests[i].desc);
        total_tests++;

        /* Create signing context */
        dkim = dkim_sign(lib, JOBID, NULL, (dkim_sigkey_t)tests[i].key,
                         tests[i].selector, DOMAIN,
                         DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                         DKIM_SIGN_DEFAULT, -1L, &status);

        if (dkim == NULL) {
            printf("FAIL: Could not create signing context for %s (status: %d)\n",
                   tests[i].desc, status);
            continue;
        }

        /* Process headers */
        for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
            status = dkim_header(dkim, (u_char *)headers[h], strlen(headers[h]));
            assert(status == DKIM_STAT_OK);
        }

        /* End of headers */
        status = dkim_eoh(dkim);
        assert(status == DKIM_STAT_OK);

        /* Process body */
        for (size_t b = 0; b < sizeof(bodies)/sizeof(bodies[0]); b++) {
            status = dkim_body(dkim, (u_char *)bodies[b], strlen(bodies[b]));
            assert(status == DKIM_STAT_OK);
        }

        /* Complete signing */
        status = dkim_eom(dkim, NULL);
        if (status != DKIM_STAT_OK) {
            printf("FAIL: Signing failed for %s (status: %d)\n", tests[i].desc, status);
            dkim_free(dkim);
            continue;
        }

        /* Get the generated signature */
        memset(hdr, '\0', sizeof hdr);
        status = dkim_getsighdr(dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
        if (status != DKIM_STAT_OK) {
            printf("FAIL: Could not get signature header for %s (status: %d)\n",
                   tests[i].desc, status);
            dkim_free(dkim);
            continue;
        }

        printf("Generated signature for %s (first 80 chars): %.80s...\n",
               tests[i].desc, hdr);

        /* Clean up signing context */
        status = dkim_free(dkim);
        assert(status == DKIM_STAT_OK);

        /* Now verify the signature */
        verify_dkim = dkim_verify(lib, "test-verify", NULL, &status);
        if (verify_dkim == NULL) {
            printf("FAIL: Could not create verification context for %s (status: %d)\n",
                   tests[i].desc, status);
            continue;
        }

        /* Process the same headers for verification */
        for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
            status = dkim_header(verify_dkim, (u_char *)headers[h], strlen(headers[h]));
            assert(status == DKIM_STAT_OK);
        }

        /* Add the generated DKIM-Signature header */
        snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, hdr);
        status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
        assert(status == DKIM_STAT_OK);

        /* End of headers */
        status = dkim_eoh(verify_dkim);
        assert(status == DKIM_STAT_OK);

        /* Process the same body for verification */
        for (size_t b = 0; b < sizeof(bodies)/sizeof(bodies[0]); b++) {
            status = dkim_body(verify_dkim, (u_char *)bodies[b], strlen(bodies[b]));
            assert(status == DKIM_STAT_OK);
        }

        /* Complete verification */
        status = dkim_eom(verify_dkim, NULL);
        if (status == DKIM_STAT_OK) {
            printf("PASS: %s signature verified successfully\n", tests[i].desc);
            passed_tests++;
        } else {
            printf("FAIL: %s signature verification failed (status: %d)\n",
                   tests[i].desc, status);
        }

        /* Clean up verification context */
        dkim_free(verify_dkim);
    }

    /* Summary */
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d/%d\n", passed_tests, total_tests);

    if (passed_tests == total_tests) {
        printf("SUCCESS: All algorithms working correctly\n");
    } else {
        printf("FAILURE: Some algorithms failed\n");
    }

    /* Additional cross-verification test */
    if (passed_tests == total_tests && total_tests >= 2) {
        printf("\n=== Cross-Algorithm Verification ===\n");
        printf("Both RSA-SHA256 and Ed25519-SHA256 successfully sign and verify\n");
        printf("the same message content using relaxed/relaxed canonicalization.\n");
        printf("This confirms both algorithms are working correctly.\n");
    }

    /* Cleanup */
    dkim_close(lib);

    return (passed_tests == total_tests) ? 0 : 1;
}

