/*
**  t-test00DEBUG.c -- Debug test to verify keyfile contents and DNS lookup
**
**  This test checks what's actually in the keyfile and what the verification
**  is trying to look up, to identify the mismatch causing DKIM_STAT_CANTVRFY
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
    DKIM_STAT status;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    unsigned char hdr[MAXHEADER + 1];
    FILE *keyfile;
    char line[1024];

    printf("*** DKIM Debug Test - Checking Keyfile and DNS Lookup ***\n");

    /* Print the constants we're using */
    printf("\nTest Constants:\n");
    printf("DOMAIN: '%s'\n", DOMAIN);
    printf("SELECTOR: '%s'\n", SELECTOR);
    printf("SELECTORED25519: '%s'\n", SELECTORED25519);
    printf("KEYFILE: '%s'\n", KEYFILE);

    /* Check if keyfile exists and print its contents */
    printf("\nKeyfile Contents:\n");
    keyfile = fopen(KEYFILE, "r");
    if (keyfile == NULL) {
        printf("ERROR: Cannot open keyfile '%s'\n", KEYFILE);
        printf("Have you run 't-setup' first?\n");
        return 1;
    }

    int line_num = 1;
    while (fgets(line, sizeof(line), keyfile) != NULL) {
        printf("Line %d: %s", line_num++, line);
    }
    fclose(keyfile);

    /* Print what the verification will be looking for */
    printf("\nDNS Queries Expected:\n");
    printf("RSA query:     '%s._domainkey.%s'\n", SELECTOR, DOMAIN);
    printf("Ed25519 query: '%s._domainkey.%s'\n", SELECTORED25519, DOMAIN);

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    /* Initialize the library */
    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    /* Set fixed time for reproducible signatures */
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);

    /* Configure file-based key lookup */
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    printf("\nTesting RSA Signing:\n");

    /* Test RSA signing */
    dkim = dkim_sign(lib, JOBID, NULL, (dkim_sigkey_t)KEY,
                     SELECTOR, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_DEFAULT, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not create RSA signing context (status: %d)\n", status);
    } else {
        printf("SUCCESS: RSA signing context created\n");

        /* Add minimal headers and body */
        status = dkim_header(dkim, (u_char *)HEADER05, strlen(HEADER05));
        assert(status == DKIM_STAT_OK);

        status = dkim_eoh(dkim);
        assert(status == DKIM_STAT_OK);

        status = dkim_body(dkim, (u_char *)BODY00, strlen(BODY00));
        assert(status == DKIM_STAT_OK);

        status = dkim_eom(dkim, NULL);
        if (status == DKIM_STAT_OK) {
            printf("SUCCESS: RSA signature generated\n");

            /* Get the signature and print the domain/selector it contains */
            memset(hdr, '\0', sizeof hdr);
            status = dkim_getsighdr(dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
            if (status == DKIM_STAT_OK) {
                printf("RSA signature domain/selector: ");

                /* Look for d= and s= in the signature */
                char *d_pos = strstr((char*)hdr, "d=");
                char *s_pos = strstr((char*)hdr, "s=");

                if (d_pos) {
                    char *d_end = strchr(d_pos + 2, ';');
                    if (d_end) {
                        printf("d=%.*s ", (int)(d_end - d_pos - 2), d_pos + 2);
                    }
                }

                if (s_pos) {
                    char *s_end = strchr(s_pos + 2, ';');
                    if (s_end) {
                        printf("s=%.*s", (int)(s_end - s_pos - 2), s_pos + 2);
                    }
                }
                printf("\n");
            }
        } else {
            printf("FAIL: RSA signature generation failed (status: %d)\n", status);
        }

        dkim_free(dkim);
    }

    printf("\nTesting Ed25519 Signing:\n");

    /* Test Ed25519 signing */
    dkim = dkim_sign(lib, JOBID, NULL, (dkim_sigkey_t)KEYED25519,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_DEFAULT, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not create Ed25519 signing context (status: %d)\n", status);
    } else {
        printf("SUCCESS: Ed25519 signing context created\n");

        /* Add minimal headers and body */
        status = dkim_header(dkim, (u_char *)HEADER05, strlen(HEADER05));
        assert(status == DKIM_STAT_OK);

        status = dkim_eoh(dkim);
        assert(status == DKIM_STAT_OK);

        status = dkim_body(dkim, (u_char *)BODY00, strlen(BODY00));
        assert(status == DKIM_STAT_OK);

        status = dkim_eom(dkim, NULL);
        if (status == DKIM_STAT_OK) {
            printf("SUCCESS: Ed25519 signature generated\n");

            /* Get the signature and print the domain/selector it contains */
            memset(hdr, '\0', sizeof hdr);
            status = dkim_getsighdr(dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
            if (status == DKIM_STAT_OK) {
                printf("Ed25519 signature domain/selector: ");

                /* Look for d= and s= in the signature */
                char *d_pos = strstr((char*)hdr, "d=");
                char *s_pos = strstr((char*)hdr, "s=");

                if (d_pos) {
                    char *d_end = strchr(d_pos + 2, ';');
                    if (d_end) {
                        printf("d=%.*s ", (int)(d_end - d_pos - 2), d_pos + 2);
                    }
                }

                if (s_pos) {
                    char *s_end = strchr(s_pos + 2, ';');
                    if (s_end) {
                        printf("s=%.*s", (int)(s_end - s_pos - 2), s_pos + 2);
                    }
                }
                printf("\n");
            }
        } else {
            printf("FAIL: Ed25519 signature generation failed (status: %d)\n", status);
        }

        dkim_free(dkim);
    }

    printf("\n=== Analysis ===\n");
    printf("1. Check that the keyfile exists and contains entries\n");
    printf("2. Verify that the DNS queries match the keyfile entries\n");
    printf("3. Make sure domain/selector in signatures match what's expected\n");
    printf("\nIf keyfile is missing or empty, run 't-setup' first.\n");
    printf("If queries don't match keyfile entries, there's a mismatch in constants.\n");

    /* Cleanup */
    dkim_close(lib);

    return 0;
}

