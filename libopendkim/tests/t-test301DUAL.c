/*
**  t-test02DUAL.c -- Dual algorithm header handling test
**
**  Tests how both algorithms handle various header scenarios that occur
**  in real email: folded headers, multiple headers of same type, header
**  ordering, and header selection. Critical for email compatibility.
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

    struct {
        const char *key;
        const char *selector;
        const char *algorithm;
    } algorithms[] = {
        { KEY, SELECTOR, "RSA-SHA256" },
        { KEYED25519, SELECTORED25519, "Ed25519-SHA256" }
    };

    printf("*** Dual Algorithm Header Handling Test ***\n");

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

    /* Test scenarios covering real email header issues */
    struct {
        const char *description;
        const char **headers;
        const char *body;
    } test_scenarios[] = {
        {
            "Folded headers (RFC 5322 compliance)",
            (const char*[]){
                "From: \"Very Long Display Name That Exceeds Normal Line Length\" \r\n\t<sender@example.com>",
                "To: recipient1@example.com,\r\n\trecipient2@example.com,\r\n\trecipient3@example.com",
                "Subject: This is a very long subject line that demonstrates\r\n\theader folding behavior in email messages",
                "Date: Mon, 01 Jan 2024 12:00:00 +0000",
                "Message-ID: <folded-test@example.com>",
                NULL
            },
            "Test message for folded headers.\r\n"
        },
        {
            "Multiple Received headers (typical email routing)",
            (const char*[]){
                "Received: from mx1.example.com (mx1.example.com [192.0.2.1]) by mx2.example.com",
                "Received: from client.example.com (client.example.com [192.0.2.2]) by mx1.example.com",
                "Received: from localhost (localhost [127.0.0.1]) by client.example.com",
                "From: sender@example.com",
                "To: recipient@example.com",
                "Subject: Multiple Received Headers Test",
                "Date: Mon, 01 Jan 2024 12:00:00 +0000",
                "Message-ID: <received-test@example.com>",
                NULL
            },
            "Test message with multiple Received headers.\r\n"
        },
        {
            "Header ordering variations",
            (const char*[]){
                "Message-ID: <order-test@example.com>",
                "Date: Mon, 01 Jan 2024 12:00:00 +0000",
                "From: sender@example.com",
                "Subject: Header Order Test",
                "To: recipient@example.com",
                "Reply-To: noreply@example.com",
                "X-Custom-Header: Custom value",
                NULL
            },
            "Test message with non-standard header order.\r\n"
        },
        {
            "Headers with special characters",
            (const char*[]){
                "From: \"Üser Näme\" <user@example.com>",
                "To: recipient@example.com",
                "Subject: =?UTF-8?B?VGVzdCB3aXRoIMO8c2VyIG7DpG1l?=",
                "Date: Mon, 01 Jan 2024 12:00:00 +0000",
                "Message-ID: <utf8-test@example.com>",
                "X-Custom: Header with special chars: !@#$%^&*()",
                NULL
            },
            "Test message with special characters in headers.\r\n"
        }
    };

    /* Test each scenario with both algorithms */
    for (size_t s = 0; s < sizeof(test_scenarios)/sizeof(test_scenarios[0]); s++) {
        printf("\n--- Testing: %s ---\n", test_scenarios[s].description);

        for (size_t a = 0; a < sizeof(algorithms)/sizeof(algorithms[0]); a++) {
            printf("  %s: ", algorithms[a].algorithm);
            total_tests++;

            /* Sign with current algorithm */
            dkim = dkim_sign(lib, "header-test", NULL, (dkim_sigkey_t)algorithms[a].key,
                             algorithms[a].selector, DOMAIN,
                             DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                             DKIM_SIGN_DEFAULT, -1L, &status);

            if (dkim == NULL) {
                printf("FAIL (signing context)\n");
                continue;
            }

            /* Add all headers for this scenario */
            for (int h = 0; test_scenarios[s].headers[h] != NULL; h++) {
                status = dkim_header(dkim, (u_char *)test_scenarios[s].headers[h],
                                     strlen(test_scenarios[s].headers[h]));
                if (status != DKIM_STAT_OK) {
                    printf("FAIL (header %d)\n", h);
                    goto cleanup_sign;
                }
            }

            status = dkim_eoh(dkim);
            if (status != DKIM_STAT_OK) {
                printf("FAIL (EOH)\n");
                goto cleanup_sign;
            }

            status = dkim_body(dkim, (u_char *)test_scenarios[s].body,
                               strlen(test_scenarios[s].body));
            if (status != DKIM_STAT_OK) {
                printf("FAIL (body)\n");
                goto cleanup_sign;
            }

            status = dkim_eom(dkim, NULL);
            if (status != DKIM_STAT_OK) {
                printf("FAIL (EOM)\n");
                goto cleanup_sign;
            }

            /* Get signature */
            memset(hdr, '\0', sizeof hdr);
            status = dkim_getsighdr(dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
            if (status != DKIM_STAT_OK) {
                printf("FAIL (get signature)\n");
                goto cleanup_sign;
            }

            dkim_free(dkim);

            /* Verify the signature */
            verify_dkim = dkim_verify(lib, "header-verify", NULL, &status);
            if (verify_dkim == NULL) {
                printf("FAIL (verify context)\n");
                continue;
            }

            /* Add signature header first */
            snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, hdr);
            status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
            if (status != DKIM_STAT_OK) {
                printf("FAIL (sig header)\n");
                goto cleanup_verify;
            }

            /* Add same headers in same order */
            for (int h = 0; test_scenarios[s].headers[h] != NULL; h++) {
                status = dkim_header(verify_dkim, (u_char *)test_scenarios[s].headers[h],
                                     strlen(test_scenarios[s].headers[h]));
                if (status != DKIM_STAT_OK) {
                    printf("FAIL (verify header %d)\n", h);
                    goto cleanup_verify;
                }
            }

            status = dkim_eoh(verify_dkim);
            if (status != DKIM_STAT_OK) {
                printf("FAIL (verify EOH)\n");
                goto cleanup_verify;
            }

            status = dkim_body(verify_dkim, (u_char *)test_scenarios[s].body,
                               strlen(test_scenarios[s].body));
            if (status != DKIM_STAT_OK) {
                printf("FAIL (verify body)\n");
                goto cleanup_verify;
            }

            status = dkim_eom(verify_dkim, NULL);
            if (status == DKIM_STAT_OK) {
                printf("PASS\n");
                passed_tests++;
            } else {
                printf("FAIL (verify EOM: %d)\n", status);
            }

cleanup_verify:
            dkim_free(verify_dkim);
            continue;

cleanup_sign:
            dkim_free(dkim);
        }
    }

    printf("\n=== Header Handling Test Results ===\n");
    printf("Tests passed: %d/%d\n", passed_tests, total_tests);
    printf("Expected: %zu tests (%zu scenarios × 2 algorithms)\n",
           sizeof(test_scenarios)/sizeof(test_scenarios[0]) * 2,
           sizeof(test_scenarios)/sizeof(test_scenarios[0]));

    if (passed_tests == total_tests) {
        printf("SUCCESS: Both algorithms handle headers identically\n");
        printf("This confirms header processing compatibility for real email scenarios.\n");
    } else {
        printf("FAILURE: Algorithms handle headers differently\n");
        printf("This indicates potential email compatibility issues.\n");
    }

    dkim_close(lib);
    return (passed_tests == total_tests) ? 0 : 1;
}
