/*
**  Debug test for canonicalization issues
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

int main(void)
{
    DKIM_LIB *lib;
    DKIM *dkim;
    DKIM_STAT status;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;

    printf("*** Canonicalization Debug Test ***\n");

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

    /* Test each problematic canonicalization */
    struct {
        dkim_canon_t hcanon;
        dkim_canon_t bcanon;
        const char *desc;
    } tests[] = {
        { DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE, "simple/simple" },
        { DKIM_CANON_SIMPLE, DKIM_CANON_RELAXED, "simple/relaxed" },
        { DKIM_CANON_RELAXED, DKIM_CANON_RELAXED, "relaxed/relaxed" }
    };

    struct {
        const char *key;
        const char *selector;
        const char *alg;
    } algs[] = {
        { KEY, SELECTOR, "RSA" },
        { KEYED25519, SELECTORED25519, "Ed25519" }
    };

    for (size_t t = 0; t < sizeof(tests)/sizeof(tests[0]); t++) {
        printf("\n--- %s ---\n", tests[t].desc);

        for (size_t a = 0; a < sizeof(algs)/sizeof(algs[0]); a++) {
            printf("%s: ", algs[a].alg);

            dkim = dkim_sign(lib, "debug", NULL, (dkim_sigkey_t)algs[a].key,
                             algs[a].selector, DOMAIN,
                             tests[t].hcanon, tests[t].bcanon,
                             DKIM_SIGN_DEFAULT, -1L, &status);

            if (dkim == NULL) {
                printf("FAIL signing context (status: %d)\n", status);
                continue;
            }

            /* Very simple headers */
            status = dkim_header(dkim, (u_char *)"From: test@example.com", 22);
            if (status != DKIM_STAT_OK) {
                printf("FAIL header (status: %d)\n", status);
                dkim_free(dkim);
                continue;
            }

            status = dkim_eoh(dkim);
            if (status != DKIM_STAT_OK) {
                printf("FAIL EOH (status: %d)\n", status);
                dkim_free(dkim);
                continue;
            }

            /* Very simple body */
            status = dkim_body(dkim, (u_char *)"Test.\r\n", 7);
            if (status != DKIM_STAT_OK) {
                printf("FAIL body (status: %d)\n", status);
                dkim_free(dkim);
                continue;
            }

            status = dkim_eom(dkim, NULL);
            if (status != DKIM_STAT_OK) {
                printf("FAIL EOM (status: %d)\n", status);
                dkim_free(dkim);
                continue;
            }

            printf("PASS signing\n");
            dkim_free(dkim);
        }
    }

    dkim_close(lib);
    return 0;
}
