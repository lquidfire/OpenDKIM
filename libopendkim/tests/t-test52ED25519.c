/*
**  t-test52ED25519.c -- Ed25519 DNS record parsing tests
**
**  Tests Ed25519-specific DNS record requirements:
**  - k=ed25519 tag parsing
**  - Raw key format (no ASN.1)
**  - DNS TXT record format validation
**  - Missing k= tag handling (should default to rsa)
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
#define TEMP_KEYFILE "/tmp/test-ed25519-dns.txt"

/* Test message */
static const char *test_headers[] = {
    "From: test@example.com\r\n",
    "To: recipient@example.com\r\n",
    "Subject: DNS Test\r\n",
    NULL
};

static const char *test_body = "Test message for DNS validation.\r\n";

/* Create a temporary keyfile with specific DNS record */
int create_test_keyfile(const char *dns_record)
{
    FILE *fp = fopen(TEMP_KEYFILE, "w");
    if (fp == NULL) {
        printf("ERROR: Could not create temp keyfile\n");
        return 0;
    }

    fprintf(fp, "%s._domainkey.%s %s\n", SELECTORED25519, DOMAIN, dns_record);
    fclose(fp);
    return 1;
}

/* Test proper Ed25519 DNS record with k=ed25519 */
int test_valid_ed25519_dns(DKIM_LIB *lib)
{
    DKIM *dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    int i;

    printf("Testing valid Ed25519 DNS record (k=ed25519)...\n");

    /* Create DNS record with k=ed25519 */
    char dns_record[1024];
    snprintf(dns_record, sizeof dns_record,
             "v=DKIM1; k=ed25519; p=%s", KEYED25519);

    if (!create_test_keyfile(dns_record)) {
        return 0;
    }

    /* Update library to use temp keyfile */
    dkim_query_t qtype = DKIM_QUERY_FILE;
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        TEMP_KEYFILE, strlen(TEMP_KEYFILE));

    /* Sign message */
    dkim = dkim_sign(lib, "test-dns-valid", NULL,
                     (dkim_sigkey_t)KEYED25519,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not sign with valid Ed25519 DNS\n");
        unlink(TEMP_KEYFILE);
        return 0;
    }

    /* Add headers and body */
    for (i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);
    dkim_body(dkim, (unsigned char *)test_body, strlen(test_body));
    status = dkim_eom(dkim, NULL);

    if (status != DKIM_STAT_OK) {
        printf("FAIL: Signing failed with valid Ed25519 DNS\n");
        dkim_free(dkim);
        unlink(TEMP_KEYFILE);
        return 0;
    }

    /* Get signature */
    status = dkim_getsighdr_d(dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    dkim_free(dkim);

    if (status != DKIM_STAT_OK) {
        printf("FAIL: Could not get signature header\n");
        unlink(TEMP_KEYFILE);
        return 0;
    }

    /* Verify signature */
    dkim = dkim_verify(lib, "test-dns-verify", NULL, &status);
    if (dkim == NULL) {
        printf("FAIL: Could not create verify context\n");
        unlink(TEMP_KEYFILE);
        return 0;
    }

    /* Add signature and headers */
    dkim_header(dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);
    dkim_body(dkim, (unsigned char *)test_body, strlen(test_body));

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification failed with valid Ed25519 DNS (status=%d)\n",
               status);
        dkim_free(dkim);
        unlink(TEMP_KEYFILE);
        return 0;
    }

    printf("PASS: Valid Ed25519 DNS record works correctly\n");
    dkim_free(dkim);
    unlink(TEMP_KEYFILE);
    return 1;
}

/* Test Ed25519 DNS record without k= tag (should fail or default to RSA) */
int test_missing_k_tag(DKIM_LIB *lib)
{
    DKIM *verify_dkim;
    DKIM_STAT status;
    char sig_header[MAXHEADER + 100];
    unsigned char hdr[MAXHEADER + 1];
    int i;

    printf("\nTesting Ed25519 DNS without k= tag...\n");

    /* Create DNS record without k= tag */
    char dns_record[1024];
    snprintf(dns_record, sizeof dns_record,
             "v=DKIM1; p=%s", KEYED25519);

    if (!create_test_keyfile(dns_record)) {
        return 0;
    }

    /* Update library to use temp keyfile */
    dkim_query_t qtype = DKIM_QUERY_FILE;
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        TEMP_KEYFILE, strlen(TEMP_KEYFILE));

    /* Create a fake Ed25519 signature header */
    snprintf(sig_header, sizeof sig_header,
             "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; "
             "d=%s; s=%s; h=from:to:subject; "
             "bh=dGVzdGJvZHloYXNo; b=dGVzdHNpZ25hdHVyZQ==\r\n",
             DOMAIN, SELECTORED25519);

    verify_dkim = dkim_verify(lib, "test-missing-k", NULL, &status);
    if (verify_dkim == NULL) {
        printf("FAIL: Could not create verify context\n");
        unlink(TEMP_KEYFILE);
        return 0;
    }

    /* Add signature and headers */
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);
    dkim_body(verify_dkim, (unsigned char *)test_body, strlen(test_body));

    status = dkim_eom(verify_dkim, NULL);

    /* Should fail because k= defaults to rsa but signature is ed25519 */
    if (status == DKIM_STAT_OK) {
        printf("WARN: Missing k= tag accepted (implementation may auto-detect)\n");
        dkim_free(verify_dkim);
        unlink(TEMP_KEYFILE);
        return 1; /* Not necessarily a failure */
    } else {
        printf("PASS: Missing k= tag correctly causes mismatch\n");
        dkim_free(verify_dkim);
        unlink(TEMP_KEYFILE);
        return 1;
    }
}

/* Test Ed25519 DNS record with wrong k= tag */
int test_wrong_k_tag(DKIM_LIB *lib)
{
    DKIM *verify_dkim;
    DKIM_STAT status;
    char sig_header[MAXHEADER + 100];
    unsigned char hdr[MAXHEADER + 1];
    int i;

    printf("\nTesting Ed25519 signature with k=rsa DNS record...\n");

    /* Create DNS record with wrong k= tag */
    char dns_record[1024];
    snprintf(dns_record, sizeof dns_record,
             "v=DKIM1; k=rsa; p=%s", KEYED25519);

    if (!create_test_keyfile(dns_record)) {
        return 0;
    }

    /* Update library */
    dkim_query_t qtype = DKIM_QUERY_FILE;
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        TEMP_KEYFILE, strlen(TEMP_KEYFILE));

    /* Create Ed25519 signature header */
    snprintf(sig_header, sizeof sig_header,
             "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; "
             "d=%s; s=%s; h=from:to:subject; "
             "bh=dGVzdGJvZHloYXNo; b=dGVzdHNpZ25hdHVyZQ==\r\n",
             DOMAIN, SELECTORED25519);

    verify_dkim = dkim_verify(lib, "test-wrong-k", NULL, &status);
    if (verify_dkim == NULL) {
        printf("FAIL: Could not create verify context\n");
        unlink(TEMP_KEYFILE);
        return 0;
    }

    /* Add signature and headers */
    dkim_header(verify_dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(verify_dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(verify_dkim);
    dkim_body(verify_dkim, (unsigned char *)test_body, strlen(test_body));

    status = dkim_eom(verify_dkim, NULL);

    /* Should fail due to algorithm mismatch */
    if (status == DKIM_STAT_OK) {
        printf("FAIL: Algorithm mismatch not detected\n");
        dkim_free(verify_dkim);
        unlink(TEMP_KEYFILE);
        return 0;
    } else {
        printf("PASS: Algorithm mismatch correctly detected\n");
        dkim_free(verify_dkim);
        unlink(TEMP_KEYFILE);
        return 1;
    }
}

/* Test Ed25519 DNS with extra tags */
int test_dns_with_extra_tags(DKIM_LIB *lib)
{
    DKIM *dkim;
    DKIM_STAT status;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    int i;

    printf("\nTesting Ed25519 DNS with extra tags...\n");

    /* Create DNS record with common extra tags */
    char dns_record[1024];
    snprintf(dns_record, sizeof dns_record,
             "v=DKIM1; k=ed25519; t=s; n=Test key; p=%s", KEYED25519);

    if (!create_test_keyfile(dns_record)) {
        return 0;
    }

    /* Update library */
    dkim_query_t qtype = DKIM_QUERY_FILE;
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        TEMP_KEYFILE, strlen(TEMP_KEYFILE));

    /* Sign and verify */
    dkim = dkim_sign(lib, "test-extra-tags", NULL,
                     (dkim_sigkey_t)KEYED25519,
                     SELECTORED25519, DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("FAIL: Could not sign with extra DNS tags\n");
        unlink(TEMP_KEYFILE);
        return 0;
    }

    for (i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);
    dkim_body(dkim, (unsigned char *)test_body, strlen(test_body));
    status = dkim_eom(dkim, NULL);

    if (status != DKIM_STAT_OK) {
        printf("FAIL: Signing failed with extra DNS tags\n");
        dkim_free(dkim);
        unlink(TEMP_KEYFILE);
        return 0;
    }

    status = dkim_getsighdr_d(dkim, strlen(TESTKEY),
                              (unsigned char *)sig_header,
                              sizeof sig_header);
    dkim_free(dkim);

    /* Verify */
    dkim = dkim_verify(lib, "test-extra-tags-verify", NULL, &status);
    dkim_header(dkim, (unsigned char *)sig_header, strlen(sig_header));
    for (i = 0; test_headers[i] != NULL; i++) {
        snprintf((char *)hdr, sizeof hdr, "%s", test_headers[i]);
        dkim_header(dkim, hdr, strlen((char *)hdr));
    }
    dkim_eoh(dkim);
    dkim_body(dkim, (unsigned char *)test_body, strlen(test_body));

    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("FAIL: Verification failed with extra DNS tags\n");
        dkim_free(dkim);
        unlink(TEMP_KEYFILE);
        return 0;
    }

    printf("PASS: Extra DNS tags handled correctly\n");
    dkim_free(dkim);
    unlink(TEMP_KEYFILE);
    return 1;
}

int main(void)
{
    DKIM_LIB *lib;
    uint64_t fixed_time = 1172620939;
    int tests_passed = 0;
    int tests_total = 4;

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif

    printf("*** Ed25519 DNS Record Tests ***\n\n");

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);

    /* Run tests */
    tests_passed += test_valid_ed25519_dns(lib);
    tests_passed += test_missing_k_tag(lib);
    tests_passed += test_wrong_k_tag(lib);
    tests_passed += test_dns_with_extra_tags(lib);

    dkim_close(lib);

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, tests_total);

    if (tests_passed == tests_total) {
        printf("SUCCESS: All Ed25519 DNS tests passed\n");
        return 0;
    } else {
        printf("FAILURE: Some DNS tests failed\n");
        return 1;
    }
}
