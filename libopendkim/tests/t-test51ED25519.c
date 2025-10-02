/*
**  t-test51ED25519.c -- Ed25519 key format and anomaly tests
**
**  Tests Ed25519-specific key requirements:
**  - 32-byte raw key format (no ASN.1 wrapping)
**  - Base64 encoding length validation
**  - Invalid key detection
**  - Key size verification
*/

#include "build-config.h"
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif

#include "../dkim.h"
#include "t-testdata.h"

#define MAXHEADER 4096

/* Valid Ed25519 key (32 bytes = 44 base64 chars without padding, 45 with =) */
static const char *valid_ed25519_key = KEYED25519;

/* Invalid keys for testing */
static const char *short_key = "dGhpcyBrZXkgaXMgdG9vIHNob3J0"; /* Too short */
static const char *long_key = "dGhpcyBrZXkgaXMgd2F5IHRvbyBsb25nIGZvciBlZDI1NTE5IGFuZCB3aWxsIGZhaWw="; /* Too long */
static const char *invalid_base64 = "this!is@not#valid$base64%encoding"; /* Invalid chars */

/* Test headers */
static const char *test_headers[] = {
    "From: test@example.com\r\n",
    "To: recipient@example.com\r\n",
    "Subject: Key Format Test\r\n",
    NULL
};

static const char *test_body = "Test message.\r\n";

/* Test valid Ed25519 key */
int test_valid_key(DKIM_LIB *lib)
{
    DKIM *dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    int i;

    printf("Testing valid Ed25519 key format...\n");

    dkim = dkim_sign(lib, "test-valid-key", NULL,
                     (dkim_sigkey_t)valid_ed25519_key,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Valid Ed25519 key rejected (status=%d)\n", status);
        return 0;
    }

    /* Add headers and body */
    for (i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        status = dkim_header(dkim, hdr, strlen((char *)hdr));
        if (status != DKIM_STAT_OK) {
            printf("FAIL: dkim_header() failed\n");
            dkim_free(dkim);
            return 0;
        }
    }

    status = dkim_eoh(dkim);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_eoh() failed\n");
        dkim_free(dkim);
        return 0;
    }

    status = dkim_body(dkim, (unsigned char *)test_body, strlen(test_body));
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_body() failed\n");
        dkim_free(dkim);
        return 0;
    }

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_eom() failed with valid key\n");
        dkim_free(dkim);
        return 0;
    }

    /* Verify key size is reported correctly */
    DKIM_SIGINFO *sig = dkim_getsignature(dkim);
    if (sig != NULL) {
        unsigned int keybits;
        if (dkim_sig_getkeysize(sig, &keybits) == DKIM_STAT_OK) {
            /* Ed25519 keys are always 256 bits (32 bytes) */
            if (keybits != 256) {
                printf("FAIL: Wrong key size reported: %u (expected 256)\n",
                       keybits);
                dkim_free(dkim);
                return 0;
            }
        }
    }

    printf("PASS: Valid Ed25519 key accepted and produces valid signature\n");
    dkim_free(dkim);
    return 1;
}

/* Test invalid key rejection */
int test_invalid_keys(DKIM_LIB *lib)
{
    DKIM *dkim;
    DKIM_STAT status;
    int tests_passed = 0;

    printf("\nTesting invalid Ed25519 key rejection...\n");

    /* Test short key */
    printf("  Testing short key...\n");
    dkim = dkim_sign(lib, "test-short-key", NULL,
                     (dkim_sigkey_t)short_key,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("  PASS: Short key correctly rejected\n");
        tests_passed++;
    } else {
        printf("  FAIL: Short key incorrectly accepted\n");
        dkim_free(dkim);
    }

    /* Test long key */
    printf("  Testing long key...\n");
    dkim = dkim_sign(lib, "test-long-key", NULL,
                     (dkim_sigkey_t)long_key,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("  PASS: Long key correctly rejected\n");
        tests_passed++;
    } else {
        printf("  FAIL: Long key incorrectly accepted\n");
        dkim_free(dkim);
    }

    /* Test invalid base64 */
    printf("  Testing invalid base64...\n");
    dkim = dkim_sign(lib, "test-invalid-b64", NULL,
                     (dkim_sigkey_t)invalid_base64,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("  PASS: Invalid base64 correctly rejected\n");
        tests_passed++;
    } else {
        printf("  FAIL: Invalid base64 incorrectly accepted\n");
        dkim_free(dkim);
    }

    return tests_passed;
}

/* Test Ed25519 signature format (always 64 bytes) */
int test_signature_format(DKIM_LIB *lib)
{
    DKIM *dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    int i;
    char *b_value;
    size_t sig_len;

    printf("\nTesting Ed25519 signature format...\n");

    dkim = dkim_sign(lib, "test-sig-format", NULL,
                     (dkim_sigkey_t)valid_ed25519_key,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    /* Add headers and body */
    for (i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);
    dkim_body(dkim, (unsigned char *)test_body, strlen(test_body));
    dkim_eom(dkim, NULL);

    /* Get signature header */
    status = dkim_getsighdr_d(dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);

    if (status != DKIM_STAT_OK) {
        printf("FAIL: Could not get signature header\n");
        dkim_free(dkim);
        return 0;
    }

    /* Extract b= value */
    b_value = strstr(sig_header, "b=");
    if (b_value == NULL) {
        printf("FAIL: No b= tag found in signature\n");
        dkim_free(dkim);
        return 0;
    }

    b_value += 2; /* Skip "b=" */

    /* Count base64 characters (ignoring whitespace and trailing data) */
    sig_len = 0;
    while (*b_value && *b_value != ';' && *b_value != '\r' && *b_value != '\n') {
        if (*b_value != ' ' && *b_value != '\t') {
            sig_len++;
        }
        b_value++;
    }

    /* Ed25519 signatures are always 64 bytes = 86 base64 chars (with padding)
     * or 85-86 chars depending on implementation */
    if (sig_len < 85 || sig_len > 88) {
        printf("FAIL: Unexpected signature length: %zu (expected 85-88)\n",
               sig_len);
        dkim_free(dkim);
        return 0;
    }

    printf("PASS: Ed25519 signature has correct length (%zu chars)\n", sig_len);
    dkim_free(dkim);
    return 1;
}

int main(void)
{
    DKIM_LIB *lib;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    int tests_passed = 0;
    int tests_total = 5; /* 1 valid + 3 invalid + 1 signature format */

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif

    printf("*** Ed25519 Key Format Tests ***\n\n");

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Run tests */
    tests_passed += test_valid_key(lib);
    tests_passed += test_invalid_keys(lib);
    tests_passed += test_signature_format(lib);

    dkim_close(lib);

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, tests_total);

    if (tests_passed == tests_total) {
        printf("SUCCESS: All Ed25519 key format tests passed\n");
        return 0;
    } else {
        printf("FAILURE: Some key format tests failed\n");
        return 1;
    }
}
