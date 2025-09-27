/*
**  whitespace-isolation.c -- Isolate the specific whitespace issue
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

int test_headers(const char *description, const char **headers, const char *body)
{
    DKIM_LIB *lib;
    DKIM *dkim, *verify_dkim;
    DKIM_STAT status;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    unsigned char rsa_hdr[MAXHEADER + 1];
    unsigned char ed25519_hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    int rsa_result = 0, ed25519_result = 0;

    printf("\n=== Testing: %s ===\n", description);

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Test RSA */
    printf("RSA: ");
    dkim = dkim_sign(lib, "test", NULL, (dkim_sigkey_t)KEY, SELECTOR, DOMAIN,
                     DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE, DKIM_SIGN_DEFAULT, -1L, &status);
    if (dkim == NULL) { printf("FAIL (context)\n"); goto test_ed25519; }

    for (int h = 0; headers[h] != NULL; h++) {
        status = dkim_header(dkim, (u_char *)headers[h], strlen(headers[h]));
        if (status != DKIM_STAT_OK) { printf("FAIL (header %d)\n", h); goto cleanup_rsa; }
    }

    status = dkim_eoh(dkim);
    if (status != DKIM_STAT_OK) { printf("FAIL (EOH)\n"); goto cleanup_rsa; }

    status = dkim_body(dkim, (u_char *)body, strlen(body));
    if (status != DKIM_STAT_OK) { printf("FAIL (body)\n"); goto cleanup_rsa; }

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) { printf("FAIL (EOM)\n"); goto cleanup_rsa; }

    memset(rsa_hdr, '\0', sizeof rsa_hdr);
    status = dkim_getsighdr(dkim, rsa_hdr, sizeof rsa_hdr, strlen(DKIM_SIGNHEADER) + 2);
    if (status != DKIM_STAT_OK) { printf("FAIL (signature)\n"); goto cleanup_rsa; }

    dkim_free(dkim);

    /* Verify RSA */
    verify_dkim = dkim_verify(lib, "verify", NULL, &status);
    if (verify_dkim == NULL) { printf("FAIL (verify context)\n"); goto test_ed25519; }

    snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, rsa_hdr);
    status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
    assert(status == DKIM_STAT_OK);

    for (int h = 0; headers[h] != NULL; h++) {
        status = dkim_header(verify_dkim, (u_char *)headers[h], strlen(headers[h]));
        assert(status == DKIM_STAT_OK);
    }

    status = dkim_eoh(verify_dkim);
    if (status != DKIM_STAT_OK) { printf("FAIL (verify EOH)\n"); goto cleanup_rsa_verify; }

    status = dkim_body(verify_dkim, (u_char *)body, strlen(body));
    assert(status == DKIM_STAT_OK);

    status = dkim_eom(verify_dkim, NULL);
    if (status == DKIM_STAT_OK) {
        printf("PASS\n");
        rsa_result = 1;
    } else {
        printf("FAIL (verify EOM: %d)\n", status);
    }

cleanup_rsa_verify:
    dkim_free(verify_dkim);
    goto test_ed25519;

cleanup_rsa:
    dkim_free(dkim);

test_ed25519:
    /* Test Ed25519 */
    printf("Ed25519: ");
    dkim = dkim_sign(lib, "test", NULL, (dkim_sigkey_t)KEYED25519, SELECTORED25519, DOMAIN,
                     DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE, DKIM_SIGN_DEFAULT, -1L, &status);
    if (dkim == NULL) { printf("FAIL (context)\n"); goto cleanup; }

    for (int h = 0; headers[h] != NULL; h++) {
        status = dkim_header(dkim, (u_char *)headers[h], strlen(headers[h]));
        if (status != DKIM_STAT_OK) { printf("FAIL (header %d)\n", h); goto cleanup_ed25519; }
    }

    status = dkim_eoh(dkim);
    if (status != DKIM_STAT_OK) { printf("FAIL (EOH)\n"); goto cleanup_ed25519; }

    status = dkim_body(dkim, (u_char *)body, strlen(body));
    if (status != DKIM_STAT_OK) { printf("FAIL (body)\n"); goto cleanup_ed25519; }

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) { printf("FAIL (EOM)\n"); goto cleanup_ed25519; }

    memset(ed25519_hdr, '\0', sizeof ed25519_hdr);
    status = dkim_getsighdr(dkim, ed25519_hdr, sizeof ed25519_hdr, strlen(DKIM_SIGNHEADER) + 2);
    if (status != DKIM_STAT_OK) { printf("FAIL (signature)\n"); goto cleanup_ed25519; }

    dkim_free(dkim);

    /* Verify Ed25519 */
    verify_dkim = dkim_verify(lib, "verify", NULL, &status);
    if (verify_dkim == NULL) { printf("FAIL (verify context)\n"); goto cleanup; }

    snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, ed25519_hdr);
    status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
    assert(status == DKIM_STAT_OK);

    for (int h = 0; headers[h] != NULL; h++) {
        status = dkim_header(verify_dkim, (u_char *)headers[h], strlen(headers[h]));
        assert(status == DKIM_STAT_OK);
    }

    status = dkim_eoh(verify_dkim);
    if (status != DKIM_STAT_OK) { printf("FAIL (verify EOH)\n"); goto cleanup_ed25519_verify; }

    status = dkim_body(verify_dkim, (u_char *)body, strlen(body));
    assert(status == DKIM_STAT_OK);

    status = dkim_eom(verify_dkim, NULL);
    if (status == DKIM_STAT_OK) {
        printf("PASS\n");
        ed25519_result = 1;
    } else {
        printf("FAIL (verify EOM: %d)\n", status);
    }

cleanup_ed25519_verify:
    dkim_free(verify_dkim);
    goto cleanup;

cleanup_ed25519:
    dkim_free(dkim);

cleanup:
    dkim_close(lib);
    return (rsa_result == ed25519_result) ? 1 : 0;
}

int main(void)
{
    int total_tests = 0, passed_tests = 0;

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    printf("*** Whitespace Isolation Test ***\n");

    /* Test each problematic element individually */
    struct {
        const char *description;
        const char **headers;
    } tests[] = {
        {
            "Header with trailing spaces",
            (const char*[]){
                "From: test@example.com",
                "To:   recipient@example.com   ",  // This has trailing spaces
                NULL
            }
        },
        {
            "Header with multiple internal spaces",
            (const char*[]){
                "From: test@example.com",
                "Subject:  Multiple   Spaces   Test",  // Multiple spaces
                NULL
            }
        },
        {
            "Header with quoted display name",
            (const char*[]){
                "From: \"Test User\" <test@example.com>",  // Quoted name
                "To: recipient@example.com",
                NULL
            }
        },
        {
            "All problematic headers combined",
            (const char*[]){
                "From: \"Test User\" <test@example.com>",
                "To:   recipient@example.com   ",
                "Subject:  Canonicalization   Test   ",
                "Date: Mon, 01 Jan 2024 12:00:00 +0000",
                "Message-ID: <test@example.com>",
                NULL
            }
        }
    };

    const char *simple_body = "Simple test body.\r\n";

    for (size_t t = 0; t < sizeof(tests)/sizeof(tests[0]); t++) {
        total_tests++;
        if (test_headers(tests[t].description, tests[t].headers, simple_body)) {
            passed_tests++;
        }
    }

    printf("\n=== Whitespace Isolation Results ===\n");
    printf("Tests where both algorithms agree: %d/%d\n", passed_tests, total_tests);

    if (passed_tests == total_tests) {
        printf("All tests show identical behavior - the bug must be elsewhere\n");
    } else {
        printf("Found specific whitespace scenarios where algorithms differ\n");
    }

    return 0;
}
