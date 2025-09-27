/*
**  RFC 8463 ED25519 DKIM Test Vector Validation
**
**  This test implements the exact test vector from RFC 8463 Appendix A
**  to validate ED25519 DKIM signature generation against the official reference.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"

/* RFC 8463 Test Vector Data */
#define RFC_DOMAIN "football.example.com"
#define RFC_SELECTOR "brisbane"

/* RFC 8463 ED25519 keys (base64 encoded) */
#define RFC_PRIVATE_KEY "-----BEGIN PRIVATE KEY-----\n" \
        "MC4CAQAwBQYDK2VwBCIEIG1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcqn9g\n" \
        "-----END PRIVATE KEY-----\n"

#define RFC_PUBLIC_KEY "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

/* Expected signature from RFC 8463 */
#define RFC_EXPECTED_SIG "/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus" \
                        "Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw=="

/* RFC 8463 test message headers */
#define RFC_HEADERS \
        "From: Joe SixPack <joe@football.example.com>\r\n" \
        "To: Suzie Q <suzie@shopping.example.net>\r\n" \
        "Subject: Is dinner ready?\r\n" \
        "Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" \
        "Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n"

/* RFC 8463 test message body */
#define RFC_BODY "Hi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n"

/* Expected body hash from RFC */
#define RFC_EXPECTED_BODY_HASH "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8="

int
main(int argc, char **argv)
{
    DKIM_STAT status;
    DKIM *dkim;
    DKIM_LIB *lib;
    unsigned char hdr[4096];
    char *signature_start, *body_hash_start;

    printf("*** RFC 8463 ED25519 Test Vector Validation\n");

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    /* Initialize the library */
    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    /* Set the fixed timestamp from RFC 8463 test vector */
	uint64_t rfc_timestamp = 1528637909;  /* RFC 8463 specific timestamp */
	status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
			&rfc_timestamp, sizeof rfc_timestamp);
	assert(status == DKIM_STAT_OK);

    /* Create signing context with RFC test parameters */
    dkim = dkim_sign(lib, "rfc8463-test", NULL, RFC_PRIVATE_KEY, RFC_SELECTOR, RFC_DOMAIN,
                     DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                     DKIM_SIGN_ED25519SHA256, -1L, &status);

    if (dkim == NULL) {
        printf("ERROR: dkim_sign() failed with status %d\n", status);
        printf("This likely means ED25519 is not properly implemented\n");
        dkim_close(lib);
        return 1;
    }

    printf("ED25519 signing context created successfully\n");

    /* Process headers exactly as in RFC test */
    status = dkim_header(dkim, "From: Joe SixPack <joe@football.example.com>\r\n",
                        strlen("From: Joe SixPack <joe@football.example.com>\r\n"));
    assert(status == DKIM_STAT_OK);

    status = dkim_header(dkim, "To: Suzie Q <suzie@shopping.example.net>\r\n",
                        strlen("To: Suzie Q <suzie@shopping.example.net>\r\n"));
    assert(status == DKIM_STAT_OK);

    status = dkim_header(dkim, "Subject: Is dinner ready?\r\n",
                        strlen("Subject: Is dinner ready?\r\n"));
    assert(status == DKIM_STAT_OK);

    status = dkim_header(dkim, "Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n",
                        strlen("Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"));
    assert(status == DKIM_STAT_OK);

    status = dkim_header(dkim, "Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n",
                        strlen("Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n"));
    assert(status == DKIM_STAT_OK);

    /* End of headers */
    status = dkim_eoh(dkim);
    assert(status == DKIM_STAT_OK);

    /* Process body exactly as in RFC test */
    status = dkim_body(dkim, RFC_BODY, strlen(RFC_BODY));
    assert(status == DKIM_STAT_OK);

    /* Complete signing */
    status = dkim_eom(dkim, NULL);
    if (status != DKIM_STAT_OK) {
        printf("ERROR: dkim_eom() failed with status %d\n", status);
        dkim_free(dkim);
        dkim_close(lib);
        return 1;
    }

    /* Get the generated signature */
    memset(hdr, '\0', sizeof hdr);
    status = dkim_getsighdr(dkim, hdr, sizeof hdr, strlen("DKIM-Signature: "));

    if (status != DKIM_STAT_OK) {
        printf("ERROR: dkim_getsighdr() failed with status %d\n", status);
        dkim_free(dkim);
        dkim_close(lib);
        return 1;
    }

    printf("\n=== GENERATED SIGNATURE ===\n");
    printf("DKIM-Signature: %s\n", hdr);
    printf("=== END SIGNATURE ===\n\n");

    /* Extract and validate body hash */
    body_hash_start = strstr((char *)hdr, "bh=");
    if (body_hash_start) {
        char *body_hash_end = strchr(body_hash_start + 3, ';');
        if (body_hash_end) {
            int body_hash_len = body_hash_end - (body_hash_start + 3);
            char extracted_body_hash[256];

            strncpy(extracted_body_hash, body_hash_start + 3, body_hash_len);
            extracted_body_hash[body_hash_len] = '\0';

            printf("Generated body hash: %s\n", extracted_body_hash);
            printf("RFC expected:        %s\n", RFC_EXPECTED_BODY_HASH);

            if (strcmp(extracted_body_hash, RFC_EXPECTED_BODY_HASH) == 0) {
                printf("✓ Body hash matches RFC 8463 test vector\n");
            } else {
                printf("✗ Body hash MISMATCH with RFC 8463 test vector\n");
            }
        }
    }

    /* Extract and validate signature */
    signature_start = strstr((char *)hdr, "b=");
    if (signature_start) {
        char *sig_end = strchr(signature_start + 2, ';');
        if (!sig_end) sig_end = (char *)hdr + strlen((char *)hdr);

        int sig_len = sig_end - (signature_start + 2);
        char extracted_signature[512];

        strncpy(extracted_signature, signature_start + 2, sig_len);
        extracted_signature[sig_len] = '\0';

        /* Remove whitespace from extracted signature */
        char clean_signature[512];
        int clean_idx = 0;
        for (int i = 0; extracted_signature[i]; i++) {
            if (extracted_signature[i] != ' ' && extracted_signature[i] != '\t' &&
                extracted_signature[i] != '\r' && extracted_signature[i] != '\n') {
                clean_signature[clean_idx++] = extracted_signature[i];
            }
        }
        clean_signature[clean_idx] = '\0';

        printf("\nGenerated signature: %s\n", clean_signature);
        printf("RFC expected:        %s\n", RFC_EXPECTED_SIG);

        if (strcmp(clean_signature, RFC_EXPECTED_SIG) == 0) {
            printf("✓ Signature matches RFC 8463 test vector EXACTLY\n");
            printf("✓ ED25519 implementation is CORRECT\n");
        } else {
            printf("✗ Signature MISMATCH with RFC 8463 test vector\n");
            printf("✗ ED25519 implementation needs debugging\n");
        }
    }

    /* Cleanup */
    status = dkim_free(dkim);
    assert(status == DKIM_STAT_OK);
    dkim_close(lib);

    printf("\n*** RFC 8463 Test Vector Validation Complete ***\n");
    return 0;
}
