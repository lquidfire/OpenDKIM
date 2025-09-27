/*
**  ed25519-simple-debug.c -- Debug Ed25519 simple canonicalization bug
**
**  Compares RSA vs Ed25519 behavior with identical simple canonicalization
**  to isolate where the difference occurs.
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

/* Function to compare signatures step by step */
int debug_algorithm(const char *algorithm, const char *key, const char *selector)
{
    DKIM_LIB *lib;
    DKIM *sign_dkim, *verify_dkim;
    DKIM_STAT status;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];

    printf("\n=== Debugging %s Simple Canonicalization ===\n", algorithm);

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Use minimal, identical content for both algorithms */
    const char *test_headers[] = {
        "From: debug@example.com",
        "To: test@example.com",
        "Subject: Debug Test"
    };
    const char *test_body = "Debug message.\r\n";

    printf("Step 1: Creating signing context with simple/simple canonicalization\n");

    /* Create signing context with simple canonicalization */
    sign_dkim = dkim_sign(lib, "debug-sign", NULL, (dkim_sigkey_t)key,
                          selector, DOMAIN,
                          DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
                          DKIM_SIGN_DEFAULT, -1L, &status);

    if (sign_dkim == NULL) {
        printf("FAIL: Could not create %s signing context (status: %d)\n", algorithm, status);
        dkim_close(lib);
        return 0;
    }
    printf("✓ Signing context created\n");

    printf("Step 2: Adding headers\n");
    for (size_t h = 0; h < sizeof(test_headers)/sizeof(test_headers[0]); h++) {
        status = dkim_header(sign_dkim, (u_char *)test_headers[h], strlen(test_headers[h]));
        if (status != DKIM_STAT_OK) {
            printf("FAIL: Header %zu failed (status: %d)\n", h, status);
            dkim_free(sign_dkim);
            dkim_close(lib);
            return 0;
        }
    }
    printf("✓ Headers added\n");

    printf("Step 3: End of headers\n");
    status = dkim_eoh(sign_dkim);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: EOH failed (status: %d)\n", status);
        dkim_free(sign_dkim);
        dkim_close(lib);
        return 0;
    }
    printf("✓ EOH successful\n");

    printf("Step 4: Adding body\n");
    status = dkim_body(sign_dkim, (u_char *)test_body, strlen(test_body));
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Body failed (status: %d)\n", status);
        dkim_free(sign_dkim);
        dkim_close(lib);
        return 0;
    }
    printf("✓ Body added\n");

    printf("Step 5: Completing signature\n");
    status = dkim_eom(sign_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: EOM failed (status: %d)\n", status);
        dkim_free(sign_dkim);
        dkim_close(lib);
        return 0;
    }
    printf("✓ Signature generated\n");

    printf("Step 6: Retrieving signature header\n");
    memset(hdr, '\0', sizeof hdr);
    status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Get signature failed (status: %d)\n", status);
        dkim_free(sign_dkim);
        dkim_close(lib);
        return 0;
    }
    printf("✓ Signature retrieved\n");
    printf("Signature (first 100 chars): %.100s...\n", hdr);

    dkim_free(sign_dkim);

    printf("Step 7: Creating verification context\n");
    verify_dkim = dkim_verify(lib, "debug-verify", NULL, &status);
    if (verify_dkim == NULL) {
        printf("FAIL: Could not create verification context (status: %d)\n", status);
        dkim_close(lib);
        return 0;
    }
    printf("✓ Verification context created\n");

    printf("Step 8: Adding signature header\n");
    snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, hdr);
    status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Signature header failed (status: %d)\n", status);
        dkim_free(verify_dkim);
        dkim_close(lib);
        return 0;
    }
    printf("✓ Signature header added\n");

    printf("Step 9: Adding same headers for verification\n");
    for (size_t h = 0; h < sizeof(test_headers)/sizeof(test_headers[0]); h++) {
        status = dkim_header(verify_dkim, (u_char *)test_headers[h], strlen(test_headers[h]));
        if (status != DKIM_STAT_OK) {
            printf("FAIL: Verify header %zu failed (status: %d)\n", h, status);
            dkim_free(verify_dkim);
            dkim_close(lib);
            return 0;
        }
    }
    printf("✓ Verification headers added\n");

    printf("Step 10: End of headers (DNS lookup)\n");
    status = dkim_eoh(verify_dkim);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verify EOH failed (status: %d)\n", status);
        dkim_free(verify_dkim);
        dkim_close(lib);
        return 0;
    }
    printf("✓ DNS lookup successful\n");

    printf("Step 11: Adding same body for verification\n");
    status = dkim_body(verify_dkim, (u_char *)test_body, strlen(test_body));
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verify body failed (status: %d)\n", status);
        dkim_free(verify_dkim);
        dkim_close(lib);
        return 0;
    }
    printf("✓ Verification body added\n");

    printf("Step 12: Final verification\n");
    status = dkim_eom(verify_dkim, NULL);
    if (status == DKIM_STAT_OK) {
        printf("✓ VERIFICATION SUCCESSFUL\n");
        dkim_free(verify_dkim);
        dkim_close(lib);
        return 1;
    } else {
        printf("✗ VERIFICATION FAILED (status: %d)\n", status);

        /* Get additional debug info */
        DKIM_SIGINFO *sig = dkim_getsignature(verify_dkim);
        if (sig != NULL) {
            int sig_error = dkim_sig_geterror(sig);
            printf("Signature error code: %d\n", sig_error);

            unsigned int keybits;
            if (dkim_sig_getkeysize(sig, &keybits) == DKIM_STAT_OK) {
                printf("Key size: %u bits\n", keybits);
            }

            dkim_alg_t alg;
            if (dkim_sig_getsignalg(sig, &alg) == DKIM_STAT_OK) {
                printf("Detected algorithm: %d\n", alg);
            }
        }

        dkim_free(verify_dkim);
        dkim_close(lib);
        return 0;
    }
}

int main(void)
{
    int rsa_result, ed25519_result;

    printf("*** Ed25519 Simple Canonicalization Debug ***\n");

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    /* Test RSA first (baseline) */
    rsa_result = debug_algorithm("RSA", KEY, SELECTOR);

    /* Test Ed25519 (problematic) */
    ed25519_result = debug_algorithm("Ed25519", KEYED25519, SELECTORED25519);

    printf("\n=== Comparison Results ===\n");
    printf("RSA simple/simple:      %s\n", rsa_result ? "PASS" : "FAIL");
    printf("Ed25519 simple/simple:  %s\n", ed25519_result ? "PASS" : "FAIL");

    if (rsa_result && !ed25519_result) {
        printf("\nCONCLUSION: Ed25519 simple canonicalization bug confirmed\n");
        printf("RSA and Ed25519 should behave identically but don't.\n");
        printf("This indicates a bug in the Ed25519 simple canonicalization implementation.\n");
    } else if (rsa_result && ed25519_result) {
        printf("\nCONCLUSION: Both algorithms work correctly\n");
    } else {
        printf("\nCONCLUSION: Unexpected result pattern\n");
    }

    return 0;
}
