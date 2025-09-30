/*
**  t-test05DUAL.c -- Dual algorithm multiple signatures test
**
**  Tests messages with multiple DKIM signatures using different algorithms.
**  This simulates real-world scenarios where organizations deploy both
**  RSA and Ed25519 signatures for maximum compatibility.
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
    DKIM *sign_rsa, *sign_ed25519, *verify_dkim;
    DKIM_STAT status;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    unsigned char rsa_hdr[MAXHEADER + 1];
    unsigned char ed25519_hdr[MAXHEADER + 1];
    char combined_headers[MAXHEADER * 2 + 200];
    int total_tests = 0;
    int passed_tests = 0;

    printf("*** Dual Algorithm Multiple Signatures Test ***\n");

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

    /* Standard message components */
    const char *headers[] = {
        "From: multi-sig@example.com",
        "To: recipient@example.com",
        "Subject: Multiple Signature Test",
        "Date: Mon, 01 Jan 2024 12:00:00 +0000",
        "Message-ID: <multi-sig-test@example.com>",
        "Content-Type: text/plain"
    };

    const char *body_text =
        "This message demonstrates dual algorithm DKIM signatures.\r\n"
        "It will be signed with both RSA-SHA256 and Ed25519-SHA256\r\n"
        "to provide maximum compatibility across different mail servers\r\n"
        "and validation systems.\r\n"
        "\r\n"
        "This approach allows organizations to deploy modern Ed25519\r\n"
        "signatures while maintaining RSA compatibility for older systems.\r\n";

    printf("\n--- Generating RSA signature ---\n");

    /* Phase 1: Generate RSA signature */
    sign_rsa = dkim_sign(lib, "multi-rsa", NULL, (dkim_sigkey_t)KEY,
                         SELECTOR, DOMAIN,
                         DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                         DKIM_SIGN_DEFAULT, -1L, &status);

    if (sign_rsa == NULL) {
        printf("FAIL: Could not create RSA signing context (status: %d)\n", status);
        goto cleanup;
    }

    /* Add headers to RSA signature */
    for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
        status = dkim_header(sign_rsa, (u_char *)headers[h], strlen(headers[h]));
        assert(status == DKIM_STAT_OK);
    }

    status = dkim_eoh(sign_rsa);
    assert(status == DKIM_STAT_OK);

    status = dkim_body(sign_rsa, (u_char *)body_text, strlen(body_text));
    assert(status == DKIM_STAT_OK);

    status = dkim_eom(sign_rsa, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: RSA signing failed (status: %d)\n", status);
        goto cleanup;
    }

    /* Get RSA signature */
    memset(rsa_hdr, '\0', sizeof rsa_hdr);
    status = dkim_getsighdr(sign_rsa, rsa_hdr, sizeof rsa_hdr, strlen(DKIM_SIGNHEADER) + 2);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Could not get RSA signature (status: %d)\n", status);
        goto cleanup;
    }

    printf("RSA signature generated successfully\n");
    dkim_free(sign_rsa);

    printf("\n--- Generating Ed25519 signature ---\n");

    /* Phase 2: Generate Ed25519 signature */
    sign_ed25519 = dkim_sign(lib, "multi-ed25519", NULL, (dkim_sigkey_t)KEYED25519,
                             SELECTORED25519, DOMAIN,
                             DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                             DKIM_SIGN_DEFAULT, -1L, &status);

    if (sign_ed25519 == NULL) {
        printf("FAIL: Could not create Ed25519 signing context (status: %d)\n", status);
        goto cleanup;
    }

    /* Add same headers to Ed25519 signature */
    for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
        status = dkim_header(sign_ed25519, (u_char *)headers[h], strlen(headers[h]));
        assert(status == DKIM_STAT_OK);
    }

    status = dkim_eoh(sign_ed25519);
    assert(status == DKIM_STAT_OK);

    status = dkim_body(sign_ed25519, (u_char *)body_text, strlen(body_text));
    assert(status == DKIM_STAT_OK);

    status = dkim_eom(sign_ed25519, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Ed25519 signing failed (status: %d)\n", status);
        goto cleanup;
    }

    /* Get Ed25519 signature */
    memset(ed25519_hdr, '\0', sizeof ed25519_hdr);
    status = dkim_getsighdr(sign_ed25519, ed25519_hdr, sizeof ed25519_hdr, strlen(DKIM_SIGNHEADER) + 2);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Could not get Ed25519 signature (status: %d)\n", status);
        goto cleanup;
    }

    printf("Ed25519 signature generated successfully\n");
    dkim_free(sign_ed25519);

    /* Phase 3: Verify message with both signatures */
    printf("\n--- Verifying message with dual signatures ---\n");

    struct {
        const char *desc;
        const char *first_sig;
        const char *second_sig;
    } verification_orders[] = {
        {"RSA first, Ed25519 second", (char*)rsa_hdr, (char*)ed25519_hdr},
        {"Ed25519 first, RSA second", (char*)ed25519_hdr, (char*)rsa_hdr}
    };

    for (size_t v = 0; v < sizeof(verification_orders)/sizeof(verification_orders[0]); v++) {
        printf("  Testing: %s\n", verification_orders[v].desc);
        total_tests++;

        verify_dkim = dkim_verify(lib, "multi-verify", NULL, &status);
        if (verify_dkim == NULL) {
            printf("  FAIL: Could not create verification context (status: %d)\n", status);
            continue;
        }

        /* Add both signature headers in the specified order */
        snprintf(combined_headers, sizeof(combined_headers),
                 "%s: %s\r\n%s: %s\r\n",
                 DKIM_SIGNHEADER, verification_orders[v].first_sig,
                 DKIM_SIGNHEADER, verification_orders[v].second_sig);

        /* Add first signature */
        char first_sig_header[MAXHEADER + 100];
        snprintf(first_sig_header, sizeof(first_sig_header),
                 "%s: %s\r\n", DKIM_SIGNHEADER, verification_orders[v].first_sig);
        status = dkim_header(verify_dkim, (u_char *)first_sig_header, strlen(first_sig_header));
        if (status != DKIM_STAT_OK) {
            printf("  FAIL: Could not add first signature header (status: %d)\n", status);
            goto cleanup_verify;
        }

        /* Add second signature */
        char second_sig_header[MAXHEADER + 100];
        snprintf(second_sig_header, sizeof(second_sig_header),
                 "%s: %s\r\n", DKIM_SIGNHEADER, verification_orders[v].second_sig);
        status = dkim_header(verify_dkim, (u_char *)second_sig_header, strlen(second_sig_header));
        if (status != DKIM_STAT_OK) {
            printf("  FAIL: Could not add second signature header (status: %d)\n", status);
            goto cleanup_verify;
        }

        /* Add original message headers */
        for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
            status = dkim_header(verify_dkim, (u_char *)headers[h], strlen(headers[h]));
            if (status != DKIM_STAT_OK) {
                printf("  FAIL: Could not add message header %zu (status: %d)\n", h, status);
                goto cleanup_verify;
            }
        }

        status = dkim_eoh(verify_dkim);
        if (status != DKIM_STAT_OK) {
            printf("  FAIL: Header verification failed (status: %d)\n", status);
            goto cleanup_verify;
        }

        status = dkim_body(verify_dkim, (u_char *)body_text, strlen(body_text));
        if (status != DKIM_STAT_OK) {
            printf("  FAIL: Body processing failed (status: %d)\n", status);
            goto cleanup_verify;
        }

        status = dkim_eom(verify_dkim, NULL);
        if (status == DKIM_STAT_OK) {
            printf("  PASS: Both signatures verified successfully\n");
            passed_tests++;
        } else {
            printf("  FAIL: Verification failed (status: %d)\n", status);
        }

cleanup_verify:
        dkim_free(verify_dkim);
    }

    printf("\n=== Multiple Signatures Test Results ===\n");
    printf("Tests passed: %d/%d\n", passed_tests, total_tests);

    if (passed_tests == total_tests) {
        printf("SUCCESS: Multiple signature verification works correctly\n");
        printf("This confirms compatibility for dual-algorithm deployment strategies.\n");
        printf("\nBenefits of dual signatures:\n");
        printf("- Ed25519 provides modern cryptography and smaller signatures\n");
        printf("- RSA provides compatibility with older verification systems\n");
        printf("- Mail servers can verify either signature for authentication\n");
    } else {
        printf("FAILURE: Multiple signature verification has issues\n");
        printf("This could prevent successful dual-algorithm deployments.\n");
    }

cleanup:
    dkim_close(lib);
    return (passed_tests == total_tests) ? 0 : 1;
}

