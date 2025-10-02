/*
**  t-test53ED25519.c -- Ed25519 edge case tests
**
**  Tests Ed25519-specific edge cases:
**  - Empty body handling
**  - Very long headers
**  - Multiple whitespace scenarios
**  - Binary content in body
**  - Large message handling
*/

#include "build-config.h"
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif

#include "../dkim.h"
#include "t-testdata.h"

#define MAXHEADER 4096

/* Test empty body */
int test_empty_body(DKIM_LIB *lib)
{
    DKIM *dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];

    static const char *headers[] = {
        "From: test@example.com\r\n",
        "To: recipient@example.com\r\n",
        "Subject: Empty Body Test\r\n",
        NULL
    };

    printf("Testing Ed25519 with empty body...\n");

    /* Sign */
    dkim = dkim_sign(lib, "test-empty-body", NULL,
                     (dkim_sigkey_t)KEYED25519,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    /* Add headers */
    for (int i = 0; headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);

    /* Empty body - just call eom without body */
    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Signing empty body failed\n");
        dkim_free(dkim);
        return 0;
    }

    status = dkim_getsighdr_d(dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    dkim_free(dkim);

    if (status != DKIM_STAT_OK) {
        printf("FAIL: Could not get signature\n");
        return 0;
    }

    /* Verify */
    verify_dkim = dkim_verify(lib, "test-verify-empty", NULL, &status);
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (int i = 0; headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification of empty body failed\n");
        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Empty body handled correctly\n");
    dkim_free(verify_dkim);
    return 1;
}

/* Test very long header */
int test_long_header(DKIM_LIB *lib)
{
    DKIM *dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    char long_subject[2000];

    printf("\nTesting Ed25519 with very long header...\n");

    /* Create a very long subject */
    strcpy(long_subject, "Subject: ");
    for (int i = 0; i < 180; i++) {
        strcat(long_subject, "Test ");
    }
    strcat(long_subject, "\r\n");

    static const char *base_headers[] = {
        "From: test@example.com\r\n",
        "To: recipient@example.com\r\n",
        NULL
    };

    /* Sign */
    dkim = dkim_sign(lib, "test-long-hdr", NULL,
                     (dkim_sigkey_t)KEYED25519,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    /* Add headers including long one */
    for (int i = 0; base_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", base_headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }

    dkim_header(dkim, (unsigned char *)long_subject, strlen(long_subject));
    dkim_eoh(dkim);
    dkim_body(dkim, (unsigned char *)"Test\r\n", 6);

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Signing with long header failed\n");
        dkim_free(dkim);
        return 0;
    }

    status = dkim_getsighdr_d(dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    dkim_free(dkim);

    /* Verify */
    verify_dkim = dkim_verify(lib, "test-verify-long", NULL, &status);
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (int i = 0; base_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", base_headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_header(verify_dkim, (unsigned char *)long_subject, strlen(long_subject));
    dkim_eoh(verify_dkim);
    dkim_body(verify_dkim, (unsigned char *)"Test\r\n", 6);

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification with long header failed\n");
        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Long header handled correctly\n");
    dkim_free(verify_dkim);
    return 1;
}

/* Test various whitespace scenarios */
int test_whitespace_scenarios(DKIM_LIB *lib)
{
    DKIM *dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];

    static const char *headers[] = {
        "From:  multiple  spaces  @example.com\r\n",
        "To:\t\ttabs\t\t@example.com\r\n",
        "Subject:  \tMixed\t  whitespace  \t\r\n",
        NULL
    };

    static const char *body =
        "Line with trailing spaces    \r\n"
        "\t\tLine with leading tabs\r\n"
        "Line  with   multiple    spaces\r\n";

    printf("\nTesting Ed25519 with various whitespace...\n");

    /* Sign with relaxed canonicalization (should normalize whitespace) */
    dkim = dkim_sign(lib, "test-whitespace", NULL,
                     (dkim_sigkey_t)KEYED25519,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    for (int i = 0; headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);
    dkim_body(dkim, (unsigned char *)body, strlen(body));

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Signing with whitespace scenarios failed\n");
        dkim_free(dkim);
        return 0;
    }

    status = dkim_getsighdr_d(dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    dkim_free(dkim);

    /* Verify */
    verify_dkim = dkim_verify(lib, "test-verify-ws", NULL, &status);
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (int i = 0; headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);
    dkim_body(verify_dkim, (unsigned char *)body, strlen(body));

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification with whitespace scenarios failed\n");
        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Whitespace scenarios handled correctly\n");
    dkim_free(verify_dkim);
    return 1;
}

/* Test large message (10KB body) */
int test_large_message(DKIM_LIB *lib)
{
    DKIM *dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    char *large_body;
    size_t body_size = 10240; /* 10KB */

    printf("\nTesting Ed25519 with large message (10KB)...\n");

    /* Allocate and fill large body */
    large_body = malloc(body_size + 1);
    if (large_body == NULL) {
        printf("FAIL: Could not allocate large body\n");
        return 0;
    }

    for (size_t i = 0; i < body_size - 2; i += 72) {
        size_t remaining = body_size - i - 2;
        size_t to_write = (remaining < 70) ? remaining : 70;
        memset(large_body + i, 'A' + (i % 26), to_write);
        if (i + to_write + 2 <= body_size) {
            large_body[i + to_write] = '\r';
            large_body[i + to_write + 1] = '\n';
        }
    }
    large_body[body_size] = '\0';

    static const char *headers[] = {
        "From: test@example.com\r\n",
        "To: recipient@example.com\r\n",
        "Subject: Large Message Test\r\n",
        NULL
    };

    /* Sign */
    dkim = dkim_sign(lib, "test-large", NULL,
                     (dkim_sigkey_t)KEYED25519,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        free(large_body);
        return 0;
    }

    for (int i = 0; headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);
    dkim_body(dkim, (unsigned char *)large_body, body_size);

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Signing large message failed\n");
        dkim_free(dkim);
        free(large_body);
        return 0;
    }

    status = dkim_getsighdr_d(dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    dkim_free(dkim);

    /* Verify */
    verify_dkim = dkim_verify(lib, "test-verify-large", NULL, &status);
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (int i = 0; headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);
    dkim_body(verify_dkim, (unsigned char *)large_body, body_size);

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification of large message failed\n");
        dkim_free(verify_dkim);
        free(large_body);
        return 0;
    }

    printf("PASS: Large message handled correctly\n");
    dkim_free(verify_dkim);
    free(large_body);
    return 1;
}

/* Test binary-like content in body */
int test_binary_content(DKIM_LIB *lib)
{
    DKIM *dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];

    /* Body with non-ASCII characters */
    static const unsigned char binary_body[] = {
        'B', 'i', 'n', 'a', 'r', 'y', ' ', 't', 'e', 's', 't', ':', ' ',
        0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, '\r', '\n',
        'E', 'n', 'd', ' ', 'o', 'f', ' ', 't', 'e', 's', 't', '\r', '\n',
        0x00
    };
    size_t binary_len = sizeof(binary_body) - 1;

    static const char *headers[] = {
        "From: test@example.com\r\n",
        "To: recipient@example.com\r\n",
        "Subject: Binary Content Test\r\n",
        "Content-Type: application/octet-stream\r\n",
        NULL
    };

    printf("\nTesting Ed25519 with binary-like content...\n");

    /* Sign */
    dkim = dkim_sign(lib, "test-binary", NULL,
                     (dkim_sigkey_t)KEYED25519,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    for (int i = 0; headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);
    dkim_body(dkim, binary_body, binary_len);

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Signing binary content failed\n");
        dkim_free(dkim);
        return 0;
    }

    status = dkim_getsighdr_d(dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    dkim_free(dkim);

    /* Verify */
    verify_dkim = dkim_verify(lib, "test-verify-binary", NULL, &status);
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (int i = 0; headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);
    dkim_body(verify_dkim, binary_body, binary_len);

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification of binary content failed\n");
        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Binary content handled correctly\n");
    dkim_free(verify_dkim);
    return 1;
}

int main(void)
{
    DKIM_LIB *lib;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    int tests_passed = 0;
    int tests_total = 5;

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif

    printf("*** Ed25519 Edge Case Tests ***\n\n");

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Run tests */
    tests_passed += test_empty_body(lib);
    tests_passed += test_long_header(lib);
    tests_passed += test_whitespace_scenarios(lib);
    tests_passed += test_large_message(lib);
    tests_passed += test_binary_content(lib);

    dkim_close(lib);

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, tests_total);

    if (tests_passed == tests_total) {
        printf("SUCCESS: All Ed25519 edge case tests passed\n");
        return 0;
    } else {
        printf("FAILURE: Some edge case tests failed\n");
        return 1;
    }
}
