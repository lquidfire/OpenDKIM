/*
**  t-test01DUAL.c -- Dual algorithm canonicalization test
**
**  Tests both RSA-SHA256 and Ed25519-SHA256 with all four canonicalization
**  combinations to ensure both algorithms handle message formatting identically.
**  This is critical for real-world DKIM interoperability.
*/

#include "build-config.h"
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

#include "../dkim.h"
#include "t-testdata.h"

#define MAXHEADER 4096

int
main(void)
{
    DKIM_LIB *lib;
    DKIM *dkim, *verify_dkim;
    DKIM_STAT status;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    int total_tests = 0;
    int passed_tests = 0;

    /* Test all canonicalization combinations */
    struct {
        dkim_canon_t header_canon;
        dkim_canon_t body_canon;
        const char *desc;
    } canon_tests[] = {
        { DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE, "simple/simple" },
        { DKIM_CANON_SIMPLE, DKIM_CANON_RELAXED, "simple/relaxed" },
        { DKIM_CANON_RELAXED, DKIM_CANON_SIMPLE, "relaxed/simple" },
        { DKIM_CANON_RELAXED, DKIM_CANON_RELAXED, "relaxed/relaxed" }
    };

    /* Test both algorithms */
    struct {
        const char *key;
        const char *selector;
        const char *algorithm;
    } algorithms[] = {
        { KEY, SELECTOR, "RSA-SHA256" },
        { KEYED25519, SELECTORED25519, "Ed25519-SHA256" }
    };

    printf("*** Dual Algorithm Canonicalization Test ***\n");

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    /* Initialize library with file-based DNS */
    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Test headers with varying whitespace to stress canonicalization */
    const char *test_headers[] = {
        "From: \"Test User\" <test@example.com>",           /* Standard format */
        "To:   recipient@example.com   ",                   /* Extra spaces */
        "Subject:  Canonicalization   Test   ",             /* Multiple spaces */
        "Date: Mon, 01 Jan 2024 12:00:00 +0000",          /* Standard date */
        "Message-ID: <test@example.com>"                    /* Standard ID */
    };

    /* Test body with various whitespace scenarios */
    const char *test_body =
        "This is a test message with various whitespace scenarios.\r\n"
        "Line with trailing spaces   \r\n"
        "\r\n"
        "Line after blank line.\r\n"
        "  Line with leading spaces\r\n"
        "Final line with proper CRLF.\r\n";

    /* Test each canonicalization with each algorithm */
    for (size_t c = 0; c < sizeof(canon_tests)/sizeof(canon_tests[0]); c++) {
        for (size_t a = 0; a < sizeof(algorithms)/sizeof(algorithms[0]); a++) {
            printf("\n=== Testing %s with %s ===\n",
                   algorithms[a].algorithm, canon_tests[c].desc);
            total_tests++;

            /* Sign with current algorithm and canonicalization */
            dkim = dkim_sign(lib, "canon-test", NULL, (dkim_sigkey_t)algorithms[a].key,
                             algorithms[a].selector, DOMAIN,
                             canon_tests[c].header_canon, canon_tests[c].body_canon,
                             DKIM_SIGN_DEFAULT, -1L, &status);

            if (dkim == NULL) {
                printf("FAIL: Could not create signing context (status: %d)\n", status);
                continue;
            }

            /* Add test headers */
            for (size_t h = 0; h < sizeof(test_headers)/sizeof(test_headers[0]); h++) {
                status = dkim_header(dkim, (u_char *)test_headers[h], strlen(test_headers[h]));
                assert(status == DKIM_STAT_OK);
            }

            status = dkim_eoh(dkim);
            assert(status == DKIM_STAT_OK);

            status = dkim_body(dkim, (u_char *)test_body, strlen(test_body));
            assert(status == DKIM_STAT_OK);

            status = dkim_eom(dkim, NULL);
            if (status != DKIM_STAT_OK) {
                printf("FAIL: Signing failed (status: %d)\n", status);
                dkim_free(dkim);
                continue;
            }

            /* Get signature */
            memset(hdr, '\0', sizeof hdr);
            status = dkim_getsighdr(dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
            if (status != DKIM_STAT_OK) {
                printf("FAIL: Could not get signature (status: %d)\n", status);
                dkim_free(dkim);
                continue;
            }

            dkim_free(dkim);

            /* Verify the signature */
            verify_dkim = dkim_verify(lib, "canon-verify", NULL, &status);
            if (verify_dkim == NULL) {
                printf("FAIL: Could not create verification context (status: %d)\n", status);
                continue;
            }

            /* Add signature header first */
            snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, hdr);
            status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
            assert(status == DKIM_STAT_OK);

            /* Add same test headers */
            for (size_t h = 0; h < sizeof(test_headers)/sizeof(test_headers[0]); h++) {
                status = dkim_header(verify_dkim, (u_char *)test_headers[h], strlen(test_headers[h]));
                assert(status == DKIM_STAT_OK);
            }

            status = dkim_eoh(verify_dkim);
            if (status != DKIM_STAT_OK) {
                printf("FAIL: Header verification failed (status: %d)\n", status);
                dkim_free(verify_dkim);
                continue;
            }

            status = dkim_body(verify_dkim, (u_char *)test_body, strlen(test_body));
            assert(status == DKIM_STAT_OK);

            status = dkim_eom(verify_dkim, NULL);
            if (status == DKIM_STAT_OK) {
                printf("PASS: Canonicalization handled correctly\n");
                passed_tests++;
            } else {
                printf("FAIL: Verification failed (status: %d)\n", status);
            }

            dkim_free(verify_dkim);
        }
    }

    printf("\n=== Canonicalization Test Results ===\n");
    printf("Tests passed: %d/%d\n", passed_tests, total_tests);
    printf("Expected: 8 tests (4 canonicalizations × 2 algorithms)\n");

    if (passed_tests == total_tests) {
        printf("SUCCESS: All canonicalization methods work identically across algorithms\n");
    } else {
        printf("FAILURE: Canonicalization handling differs between algorithms\n");
    }

    dkim_close(lib);
    return (passed_tests == total_tests) ? 0 : 1;
}
