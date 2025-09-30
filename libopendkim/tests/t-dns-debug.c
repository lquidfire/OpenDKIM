/*
**  DNS lookup debug test - check if file-based DNS lookup is working
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
    DKIM *verify_dkim;
    DKIM_STAT status;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];

    printf("*** DNS Lookup Debug Test ***\n");

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif /* USE_GNUTLS */

    /* Initialize the library */
    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    /* Configure file-based key lookup */
    status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                          &qtype, sizeof qtype);
    printf("Set query method to FILE: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");

    status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                          KEYFILE, strlen(KEYFILE));
    printf("Set query info to %s: %s\n", KEYFILE, (status == DKIM_STAT_OK) ? "OK" : "FAILED");

    /* Test 1: Verify a simple RSA signature */
    printf("\n=== Test 1: RSA Signature Verification ===\n");
    
    verify_dkim = dkim_verify(lib, "test-rsa", NULL, &status);
    if (verify_dkim == NULL) {
        printf("FAIL: Could not create RSA verification context (status: %d)\n", status);
    } else {
        /* Create a minimal RSA signature to test with */
        strcpy(sig_header, "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=test; "
               "t=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=; "
               "h=From:Subject; b=dummysignature==\r\n");
        
        status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
        printf("Add DKIM signature header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");
        
        status = dkim_header(verify_dkim, (u_char *)HEADER05, strlen(HEADER05));
        printf("Add From header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");
        
        status = dkim_header(verify_dkim, (u_char *)HEADER08, strlen(HEADER08));
        printf("Add Subject header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");
        
        status = dkim_eoh(verify_dkim);
        printf("End of headers (DNS lookup happens here): ");
        if (status == DKIM_STAT_OK) {
            printf("OK - DNS lookup succeeded\n");
        } else if (status == DKIM_STAT_CANTVRFY) {
            printf("FAILED - Cannot verify (DNS lookup failed)\n");
        } else {
            printf("FAILED - Other error (status: %d)\n", status);
        }
        
        dkim_free(verify_dkim);
    }

    /* Test 2: Verify an Ed25519 signature */
    printf("\n=== Test 2: Ed25519 Signature Verification ===\n");
    
    verify_dkim = dkim_verify(lib, "test-ed25519", NULL, &status);
    if (verify_dkim == NULL) {
        printf("FAIL: Could not create Ed25519 verification context (status: %d)\n", status);
    } else {
        /* Create a minimal Ed25519 signature to test with */
        strcpy(sig_header, "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=ed25519-sha256; "
               "t=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=; "
               "h=From:Subject; b=dummysignature==\r\n");
        
        status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
        printf("Add DKIM signature header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");
        
        status = dkim_header(verify_dkim, (u_char *)HEADER05, strlen(HEADER05));
        printf("Add From header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");
        
        status = dkim_header(verify_dkim, (u_char *)HEADER08, strlen(HEADER08));
        printf("Add Subject header: %s\n", (status == DKIM_STAT_OK) ? "OK" : "FAILED");
        
        status = dkim_eoh(verify_dkim);
        printf("End of headers (DNS lookup happens here): ");
        if (status == DKIM_STAT_OK) {
            printf("OK - DNS lookup succeeded\n");
        } else if (status == DKIM_STAT_CANTVRFY) {
            printf("FAILED - Cannot verify (DNS lookup failed)\n");
        } else {
            printf("FAILED - Other error (status: %d)\n", status);
        }
        
        dkim_free(verify_dkim);
    }

    /* Test 3: Check keyfile format parsing */
    printf("\n=== Test 3: Manual Keyfile Check ===\n");
    FILE *keyfile = fopen(KEYFILE, "r");
    if (keyfile) {
        char line[1024];
        int found_rsa = 0, found_ed25519 = 0;
        
        while (fgets(line, sizeof(line), keyfile)) {
            if (strstr(line, "test._domainkey.example.com") && strstr(line, "k=rsa")) {
                found_rsa = 1;
                printf("Found RSA entry: %.80s...\n", line);
            }
            if (strstr(line, "ed25519-sha256._domainkey.example.com") && strstr(line, "k=ed25519")) {
                found_ed25519 = 1;
                printf("Found Ed25519 entry: %.80s...\n", line);
            }
        }
        fclose(keyfile);
        
        printf("RSA entry found: %s\n", found_rsa ? "YES" : "NO");
        printf("Ed25519 entry found: %s\n", found_ed25519 ? "YES" : "NO");
    } else {
        printf("Cannot open keyfile %s\n", KEYFILE);
    }

    printf("\n=== Analysis ===\n");
    printf("If DNS lookups fail, the issue is likely:\n");
    printf("1. Keyfile format parsing issue in the DKIM library\n");
    printf("2. Missing whitespace or syntax issue in keyfile\n");
    printf("3. Query method not being set correctly\n");

    dkim_close(lib);
    return 0;
}
