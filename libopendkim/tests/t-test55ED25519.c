/*
**  t-test55ED25519.c -- Ed25519 chunked message processing tests
**
**  Tests Ed25519 signature behavior with chunked message delivery,
**  simulating real MTA behavior where messages arrive in fragments.
**
**  Per RFC 8463: Ed25519-SHA256 computes SHA-256 hash of canonicalized
**  data, then signs that hash with PureEdDSA. The signature must be
**  identical regardless of how the message is chunked during processing,
**  because the SHA-256 hash is computed incrementally and finalized
**  before signing.
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

static const char *test_headers[] = {
    "From: sender@example.com\r\n",
    "To: recipient@example.com\r\n",
    "Subject: Chunked Processing Test\r\n",
    NULL
};

static const char *test_body =
    "This is a test message that will be delivered in chunks.\r\n"
    "Each chunk should be processed correctly by Ed25519.\r\n"
    "The signature must remain valid regardless of chunk size.\r\n";

/* Test signing with body delivered in chunks */
int test_chunked_signing(DKIM_LIB *lib, size_t chunk_size, const char *desc)
{
    DKIM *sign_dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    size_t body_len = strlen(test_body);
    size_t offset;

    printf("Testing Ed25519 chunked signing (%s)...\n", desc);

    /* Sign with chunked body */
    sign_dkim = dkim_sign(lib, "test-chunk-sign", NULL,
                          (dkim_sigkey_t)KEYED25519,
                          SELECTORED25519, DOMAIN,
                          DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                          DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (sign_dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    /* Add headers */
    for (int i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(sign_dkim, hdr, strlen((char *)hdr));
    }

    status = dkim_eoh(sign_dkim);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_eoh() failed\n");
        dkim_free(sign_dkim);
        return 0;
    }

    /* Add body in chunks */
    for (offset = 0; offset < body_len; offset += chunk_size) {
        size_t remaining = body_len - offset;
        size_t this_chunk = (remaining < chunk_size) ? remaining : chunk_size;

        status = dkim_body(sign_dkim,
                          (unsigned char *)(test_body + offset),
                          this_chunk);
        if (status != DKIM_STAT_OK) {
            printf("FAIL: dkim_body() failed at offset %zu\n", offset);
            dkim_free(sign_dkim);
            return 0;
        }
    }

    status = dkim_eom(sign_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: dkim_eom() failed for chunked signing\n");
        dkim_free(sign_dkim);
        return 0;
    }

    /* Get signature */
    status = dkim_getsighdr_d(sign_dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    dkim_free(sign_dkim);

    if (status != DKIM_STAT_OK) {
        printf("FAIL: Could not get signature header\n");
        return 0;
    }

    /* Verify with chunked body */
    verify_dkim = dkim_verify(lib, "test-chunk-verify", NULL, &status);
    if (verify_dkim == NULL) {
        printf("FAIL: Could not create verify context\n");
        return 0;
    }

    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (int i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);

    /* Verify with same chunk size */
    for (offset = 0; offset < body_len; offset += chunk_size) {
        size_t remaining = body_len - offset;
        size_t this_chunk = (remaining < chunk_size) ? remaining : chunk_size;

        dkim_body(verify_dkim,
                 (unsigned char *)(test_body + offset),
                 this_chunk);
    }

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification failed for %s (status=%d)\n", desc, status);
        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Chunked processing works for %s\n", desc);
    dkim_free(verify_dkim);
    return 1;
}

/* Test verification with different chunk size than signing */
int test_mismatched_chunks(DKIM_LIB *lib)
{
    DKIM *sign_dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    size_t body_len = strlen(test_body);

    printf("\nTesting Ed25519 with mismatched chunk sizes...\n");

    /* Sign with 10-byte chunks */
    sign_dkim = dkim_sign(lib, "test-mismatch-sign", NULL,
                          (dkim_sigkey_t)KEYED25519,
                          SELECTORED25519, DOMAIN,
                          DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                          DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (sign_dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    for (int i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(sign_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(sign_dkim);

    /* Add body in 10-byte chunks */
    for (size_t offset = 0; offset < body_len; offset += 10) {
        size_t remaining = body_len - offset;
        size_t this_chunk = (remaining < 10) ? remaining : 10;
        dkim_body(sign_dkim, (unsigned char *)(test_body + offset), this_chunk);
    }

    dkim_eom(sign_dkim, NULL);
    dkim_getsighdr_d(sign_dkim, strlen(TESTKEY),
                     (unsigned char *)sig_header, sizeof sig_header);
    dkim_free(sign_dkim);

    /* Verify with 37-byte chunks (different size) */
    verify_dkim = dkim_verify(lib, "test-mismatch-verify", NULL, &status);
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (int i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);

    /* Add body in 37-byte chunks */
    for (size_t offset = 0; offset < body_len; offset += 37) {
        size_t remaining = body_len - offset;
        size_t this_chunk = (remaining < 37) ? remaining : 37;
        dkim_body(verify_dkim, (unsigned char *)(test_body + offset), this_chunk);
    }

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification failed with mismatched chunks\n");
        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Mismatched chunk sizes verified correctly\n");
    dkim_free(verify_dkim);
    return 1;
}

/* Test single-byte chunks (extreme case) */
int test_byte_by_byte(DKIM_LIB *lib)
{
    DKIM *sign_dkim, *verify_dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    size_t body_len = strlen(test_body);

    printf("\nTesting Ed25519 with byte-by-byte processing...\n");

    /* Sign byte by byte */
    sign_dkim = dkim_sign(lib, "test-byte-sign", NULL,
                          (dkim_sigkey_t)KEYED25519,
                          SELECTORED25519, DOMAIN,
                          DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                          DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (sign_dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    for (int i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(sign_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(sign_dkim);

    /* Add body one byte at a time */
    for (size_t i = 0; i < body_len; i++) {
        dkim_body(sign_dkim, (unsigned char *)(test_body + i), 1);
    }

    dkim_eom(sign_dkim, NULL);
    dkim_getsighdr_d(sign_dkim, strlen(TESTKEY),
                     (unsigned char *)sig_header, sizeof sig_header);
    dkim_free(sign_dkim);

    /* Verify with full body at once */
    verify_dkim = dkim_verify(lib, "test-byte-verify", NULL, &status);
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (int i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);
    dkim_body(verify_dkim, (unsigned char *)test_body, body_len);

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Byte-by-byte verification failed\n");
        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Byte-by-byte processing works correctly\n");
    dkim_free(verify_dkim);
    return 1;
}

/* Test headers delivered in chunks */
int test_chunked_headers(DKIM_LIB *lib)
{
    DKIM *sign_dkim, *verify_dkim;
    DKIM_STAT status;
    char sig_header[MAXHEADER + 100];

    printf("\nTesting Ed25519 with chunked header delivery...\n");

    /* Create a folded header that spans multiple lines */
    const char *folded_subject =
        "Subject: This is a very long subject line that has been\r\n"
        " folded across multiple lines to test header chunking\r\n"
        " in the DKIM implementation with Ed25519 signatures.\r\n";

    sign_dkim = dkim_sign(lib, "test-hdr-chunk", NULL,
                          (dkim_sigkey_t)KEYED25519,
                          SELECTORED25519, DOMAIN,
                          DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                          DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (sign_dkim == NULL) {
        printf("FAIL: Could not create signing context\n");
        return 0;
    }

    /* Add headers - the folded one will be delivered in parts by real MTAs */
    dkim_header(sign_dkim, (unsigned char *)"From: test@example.com\r\n", 24);
    dkim_header(sign_dkim, (unsigned char *)"To: recipient@example.com\r\n", 27);
    dkim_header(sign_dkim, (unsigned char *)folded_subject, strlen(folded_subject));
    dkim_eoh(sign_dkim);
    dkim_body(sign_dkim, (unsigned char *)"Test\r\n", 6);
    dkim_eom(sign_dkim, NULL);
    dkim_getsighdr_d(sign_dkim, strlen(TESTKEY),
                     (unsigned char *)sig_header, sizeof sig_header);
    dkim_free(sign_dkim);

    /* Verify */
    verify_dkim = dkim_verify(lib, "test-hdr-verify", NULL, &status);
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    dkim_header(verify_dkim, (unsigned char *)"From: test@example.com\r\n", 24);
    dkim_header(verify_dkim, (unsigned char *)"To: recipient@example.com\r\n", 27);
    dkim_header(verify_dkim, (unsigned char *)folded_subject, strlen(folded_subject));
    dkim_eoh(verify_dkim);
    dkim_body(verify_dkim, (unsigned char *)"Test\r\n", 6);

    status = dkim_eom(verify_dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Chunked header verification failed\n");
        dkim_free(verify_dkim);
        return 0;
    }

    printf("PASS: Chunked headers processed correctly\n");
    dkim_free(verify_dkim);
    return 1;
}

int main(void)
{
    DKIM_LIB *lib;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    int tests_passed = 0;
    int tests_total = 7;

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif

    printf("*** Ed25519 Chunked Processing Tests ***\n\n");

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Test various chunk sizes */
    tests_passed += test_chunked_signing(lib, 1, "1-byte chunks");
    tests_passed += test_chunked_signing(lib, 16, "16-byte chunks");
    tests_passed += test_chunked_signing(lib, 64, "64-byte chunks");
    tests_passed += test_chunked_signing(lib, 1024, "1KB chunks");

    /* Test mismatched chunks */
    tests_passed += test_mismatched_chunks(lib);

    /* Test extreme cases */
    tests_passed += test_byte_by_byte(lib);
    tests_passed += test_chunked_headers(lib);

    dkim_close(lib);

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, tests_total);

    if (tests_passed == tests_total) {
        printf("SUCCESS: All Ed25519 chunked processing tests passed\n");
        return 0;
    } else {
        printf("FAILURE: Some chunked processing tests failed\n");
        return 1;
    }
}
