/*
**  t-test-line-endings.c -- Test that DKIM correctly rejects improper line endings
**
**  This test verifies that DKIM fails when messages don't use proper CRLF endings.
**  SUCCESS means the verification FAILS (as it should for non-compliant messages).
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

    printf("*** Line Ending Compliance Test (Should Fail) ***\n");

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Test improper line ending scenarios */
    struct {
        const char *description;
        const char *body;
        const char *expected_result;
    } line_ending_tests[] = {
        {
            "Body without final CRLF",
            "Line 1\r\nLine 2\r\nFinal line without CRLF",
            "Should fail verification"
        },
        {
            "Mixed line endings (Unix LF)",
            "Line 1\r\nLine 2\nLine 3 with Unix LF\r\n",
            "Should fail verification"
        },
        {
            "Body ending with bare LF",
            "Line 1\r\nLine 2\r\nFinal line\n",
            "Should fail verification"
        },
        {
            "Body with bare CR",
            "Line 1\r\nLine 2\rLine 3 with bare CR\r\n",
            "Should fail verification"
        }
    };

    /* Standard headers (proper CRLF) */
    const char *headers[] = {
        "From: test@example.com",
        "To: recipient@example.com",
        "Subject: Line Ending Test",
        "Date: Mon, 01 Jan 2024 12:00:00 +0000",
        "Message-ID: <line-ending-test@example.com>"
    };

    /* Test with RSA (we know this works for comparison) */
    printf("\nTesting improper line endings (RSA baseline):\n");

    for (size_t t = 0; t < sizeof(line_ending_tests)/sizeof(line_ending_tests[0]); t++) {
        printf("  %s: ", line_ending_tests[t].description);
        total_tests++;

        /* Sign with proper headers but improper body */
        dkim = dkim_sign(lib, "line-test", NULL, (dkim_sigkey_t)KEY,
                         SELECTOR, DOMAIN,
                         DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                         DKIM_SIGN_DEFAULT, -1L, &status);

        if (dkim == NULL) {
            printf("FAIL (signing context)\n");
            continue;
        }

        /* Add headers */
        for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
            status = dkim_header(dkim, (u_char *)headers[h], strlen(headers[h]));
            if (status != DKIM_STAT_OK) {
                printf("FAIL (header)\n");
                goto cleanup_sign;
            }
        }

        status = dkim_eoh(dkim);
        if (status != DKIM_STAT_OK) {
            printf("FAIL (EOH)\n");
            goto cleanup_sign;
        }

        /* Add improper body */
        status = dkim_body(dkim, (u_char *)line_ending_tests[t].body,
                           strlen(line_ending_tests[t].body));
        if (status != DKIM_STAT_OK) {
            printf("FAIL (body)\n");
            goto cleanup_sign;
        }

        status = dkim_eom(dkim, NULL);
        if (status != DKIM_STAT_OK) {
            /* This might fail during signing - that's also correct behavior */
            printf("PASS (failed at signing as expected)\n");
            passed_tests++;
            goto cleanup_sign;
        }

        /* Get signature */
        memset(hdr, '\0', sizeof hdr);
        status = dkim_getsighdr(dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
        if (status != DKIM_STAT_OK) {
            printf("PASS (failed to get signature as expected)\n");
            passed_tests++;
            goto cleanup_sign;
        }

        dkim_free(dkim);

        /* If signing succeeded, try verification - it should fail */
        verify_dkim = dkim_verify(lib, "line-verify", NULL, &status);
        if (verify_dkim == NULL) {
            printf("FAIL (verify context)\n");
            continue;
        }

        /* Add signature header */
        snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, hdr);
        status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
        assert(status == DKIM_STAT_OK);

        /* Add same headers */
        for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
            status = dkim_header(verify_dkim, (u_char *)headers[h], strlen(headers[h]));
            assert(status == DKIM_STAT_OK);
        }

        status = dkim_eoh(verify_dkim);
        if (status != DKIM_STAT_OK) {
            printf("PASS (failed at verify EOH as expected)\n");
            passed_tests++;
            goto cleanup_verify;
        }

        /* Add same improper body */
        status = dkim_body(verify_dkim, (u_char *)line_ending_tests[t].body,
                           strlen(line_ending_tests[t].body));
        if (status != DKIM_STAT_OK) {
            printf("PASS (failed at verify body as expected)\n");
            passed_tests++;
            goto cleanup_verify;
        }

        status = dkim_eom(verify_dkim, NULL);
        if (status != DKIM_STAT_OK) {
            printf("PASS (verification failed as expected)\n");
            passed_tests++;
        } else {
            printf("FAIL (verification succeeded when it should have failed)\n");
        }

cleanup_verify:
        dkim_free(verify_dkim);
        continue;

cleanup_sign:
        dkim_free(dkim);
    }

    printf("\n=== Line Ending Compliance Results ===\n");
    printf("Tests passed: %d/%d\n", passed_tests, total_tests);
    printf("Note: 'PASS' means DKIM correctly rejected improper line endings\n");

    if (passed_tests == total_tests) {
        printf("SUCCESS: DKIM correctly enforces line ending compliance\n");
    } else {
        printf("WARNING: DKIM may accept non-compliant line endings\n");
    }

    dkim_close(lib);
    return (passed_tests == total_tests) ? 0 : 1;
}
