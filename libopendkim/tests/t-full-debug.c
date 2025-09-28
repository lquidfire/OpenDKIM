/*
**  Full verification debug - trace exactly where verification fails
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
    DKIM *sign_dkim, *verify_dkim;
    DKIM_STAT status;
    DKIM_SIGINFO *sig;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];

    printf("*** Full Verification Debug Test ***\n");

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    /* Initialize the library */
    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    /* Set fixed time */
    status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                          &fixed_time, sizeof fixed_time);
    assert(status == DKIM_STAT_OK);

    /* Configure file-based key lookup */
    status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                          &qtype, sizeof qtype);
    assert(status == DKIM_STAT_OK);

    status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                          KEYFILE, strlen(KEYFILE));
    assert(status == DKIM_STAT_OK);

    /* Test RSA signing and verification */
    printf("\n=== RSA Test ===\n");

    /* Step 1: Sign with RSA */
    sign_dkim = dkim_sign(lib, "test-sign", NULL, (dkim_sigkey_t)KEY,
                          SELECTOR, DOMAIN,
                          DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                          DKIM_SIGN_DEFAULT, -1L, &status);
    assert(sign_dkim != NULL);

    /* Add headers and body */
    status = dkim_header(sign_dkim, (u_char *)HEADER05, strlen(HEADER05));
    assert(status == DKIM_STAT_OK);
    status = dkim_header(sign_dkim, (u_char *)HEADER08, strlen(HEADER08));
    assert(status == DKIM_STAT_OK);
    status = dkim_eoh(sign_dkim);
    assert(status == DKIM_STAT_OK);
    status = dkim_body(sign_dkim, (u_char *)BODY00, strlen(BODY00));
    assert(status == DKIM_STAT_OK);
    status = dkim_eom(sign_dkim, NULL);
    assert(status == DKIM_STAT_OK);

    /* Get signature */
    memset(hdr, '\0', sizeof hdr);
    status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
    assert(status == DKIM_STAT_OK);
    printf("RSA signature generated successfully\n");
    printf("First 120 chars: %.120s...\n", hdr);

    dkim_free(sign_dkim);

    /* Step 2: Verify the RSA signature */
    verify_dkim = dkim_verify(lib, "test-verify", NULL, &status);
    assert(verify_dkim != NULL);

    /* Add DKIM signature header first */
    snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, hdr);
    status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
    printf("Add signature header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

    /* Add the same headers */
    status = dkim_header(verify_dkim, (u_char *)HEADER05, strlen(HEADER05));
    printf("Add From header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");
    status = dkim_header(verify_dkim, (u_char *)HEADER08, strlen(HEADER08));
    printf("Add Subject header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

    /* End of headers - this is where DNS lookup happens and succeeds */
    status = dkim_eoh(verify_dkim);
    printf("End of headers (DNS lookup): %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

    if (status == DKIM_STAT_OK) {
        /* Add the same body */
        status = dkim_body(verify_dkim, (u_char *)BODY00, strlen(BODY00));
        printf("Add body: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

        /* Complete verification - this is where cryptographic verification happens */
        status = dkim_eom(verify_dkim, NULL);
        printf("Complete verification: ");
        if (status == DKIM_STAT_OK) {
            printf("SUCCESS\n");
        } else {
            printf("FAILED (status: %d)\n", status);

            /* Get signature info for debugging */
            sig = dkim_getsignature(verify_dkim);
            if (sig != NULL) {
                int sig_error = dkim_sig_geterror(sig);
                printf("Signature error code: %d\n", sig_error);

                unsigned int keybits;
                if (dkim_sig_getkeysize(sig, &keybits) == DKIM_STAT_OK) {
                    printf("Key size: %u bits\n", keybits);
                }

                dkim_alg_t alg;
                if (dkim_sig_getsignalg(sig, &alg) == DKIM_STAT_OK) {
                    printf("Algorithm: %d\n", alg);
                }
            }
        }
    }

    dkim_free(verify_dkim);

    /* Test Ed25519 with the same process */
    printf("\n=== Ed25519 Test ===\n");

    /* Step 1: Sign with Ed25519 */
    sign_dkim = dkim_sign(lib, "test-sign-ed25519", NULL, (dkim_sigkey_t)KEYED25519,
                          SELECTORED25519, DOMAIN,
                          DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                          DKIM_SIGN_DEFAULT, -1L, &status);
    assert(sign_dkim != NULL);

    /* Add the same headers and body */
    status = dkim_header(sign_dkim, (u_char *)HEADER05, strlen(HEADER05));
    assert(status == DKIM_STAT_OK);
    status = dkim_header(sign_dkim, (u_char *)HEADER08, strlen(HEADER08));
    assert(status == DKIM_STAT_OK);
    status = dkim_eoh(sign_dkim);
    assert(status == DKIM_STAT_OK);
    status = dkim_body(sign_dkim, (u_char *)BODY00, strlen(BODY00));
    assert(status == DKIM_STAT_OK);
    status = dkim_eom(sign_dkim, NULL);
    assert(status == DKIM_STAT_OK);

    /* Get Ed25519 signature */
    memset(hdr, '\0', sizeof hdr);
    status = dkim_getsighdr(sign_dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
    assert(status == DKIM_STAT_OK);
    printf("Ed25519 signature generated successfully\n");
    printf("First 120 chars: %.120s...\n", hdr);

    dkim_free(sign_dkim);

    /* Step 2: Verify the Ed25519 signature */
    verify_dkim = dkim_verify(lib, "test-verify-ed25519", NULL, &status);
    assert(verify_dkim != NULL);

    /* Follow the same verification process */
    snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, hdr);
    status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
    printf("Add signature header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

    status = dkim_header(verify_dkim, (u_char *)HEADER05, strlen(HEADER05));
    printf("Add From header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");
    status = dkim_header(verify_dkim, (u_char *)HEADER08, strlen(HEADER08));
    printf("Add Subject header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

    status = dkim_eoh(verify_dkim);
    printf("End of headers (DNS lookup): %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

    if (status == DKIM_STAT_OK) {
        status = dkim_body(verify_dkim, (u_char *)BODY00, strlen(BODY00));
        printf("Add body: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

        status = dkim_eom(verify_dkim, NULL);
        printf("Complete verification: ");
        if (status == DKIM_STAT_OK) {
            printf("SUCCESS\n");
        } else {
            printf("FAILED (status: %d)\n", status);

            sig = dkim_getsignature(verify_dkim);
            if (sig != NULL) {
                int sig_error = dkim_sig_geterror(sig);
                printf("Signature error code: %d\n", sig_error);

                unsigned int keybits;
                if (dkim_sig_getkeysize(sig, &keybits) == DKIM_STAT_OK) {
                    printf("Key size: %u bits\n", keybits);
                }

                dkim_alg_t alg;
                if (dkim_sig_getsignalg(sig, &alg) == DKIM_STAT_OK) {
                    printf("Algorithm: %d\n", alg);
                }
            }
        }
    }

    dkim_free(verify_dkim);

    printf("\n=== Conclusion ===\n");
    printf("This test shows exactly where verification fails.\n");
    printf("Most likely: signature verification (cryptographic step) is failing.\n");

    dkim_close(lib);
    return 0;
}
