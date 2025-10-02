/*
**  t-test04DUAL.c -- Dual algorithm chunked processing test
**
**  Tests how both algorithms handle messages processed in chunks,
**  simulating real MTA behavior where messages arrive in pieces.
**  Critical for mail server integration.
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
    DKIM *dkim, *verify_dkim;
    DKIM_STAT status;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    unsigned char hdr[MAXHEADER + 1];
    char sig_header[MAXHEADER + 100];
    int total_tests = 0;
    int passed_tests = 0;

    struct {
        const char *key;
        const char *selector;
        const char *algorithm;
    } algorithms[] = {
        { KEY, SELECTOR, "RSA-SHA256" },
        { KEYED25519, SELECTORED25519, "Ed25519-SHA256" }
    };

    printf("*** Dual Algorithm Chunked Processing Test ***\n");

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

    /* Test message components */
    const char *headers[] = {
        "From: chunked-test@example.com",
        "To: recipient@example.com",
        "Subject: Chunked Processing Test Message",
        "Date: Mon, 01 Jan 2024 12:00:00 +0000",
        "Message-ID: <chunked-test@example.com>",
        "Content-Type: text/plain"
    };

    const char *body_text =
        "This is a test message that will be processed in chunks.\r\n"
        "Each line represents a different chunk that might arrive\r\n"
        "at different times in a real mail server environment.\r\n"
        "\r\n"
        "Chunk processing is critical for mail server performance\r\n"
        "as it allows processing to begin before the entire message\r\n"
        "has been received from the network.\r\n"
        "\r\n"
        "Both RSA and Ed25519 algorithms must handle this identically\r\n"
        "to ensure consistent DKIM verification results.\r\n";

    /* Test chunking scenarios */
    struct {
        const char *description;
        size_t chunk_sizes[10];  /* 0-terminated */
    } chunk_scenarios[] = {
        {
            "Single byte chunks (worst case)",
            {1, 0}
        },
        {
            "Small chunks (5 bytes)",
            {5, 0}
        },
        {
            "Line-based chunks (typical MTA behavior)",
            {50, 0}  /* Approximate line length */
        },
        {
            "Variable chunks (realistic network)",
            {7, 23, 41, 15, 89, 3, 156, 0}
        },
        {
            "Large chunks (efficient processing)",
            {256, 0}
        }
    };

    /* Test each chunking scenario with both algorithms */
    for (size_t s = 0; s < sizeof(chunk_scenarios)/sizeof(chunk_scenarios[0]); s++) {
        printf("\n--- Testing: %s ---\n", chunk_scenarios[s].description);

        for (size_t a = 0; a < sizeof(algorithms)/sizeof(algorithms[0]); a++) {
            printf("  %s: ", algorithms[a].algorithm);
            total_tests++;

            /* Phase 1: Sign with chunked processing */
            dkim = dkim_sign(lib, "chunk-test", NULL, (dkim_sigkey_t)algorithms[a].key,
                             algorithms[a].selector, DOMAIN,
                             DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
                             DKIM_SIGN_DEFAULT, -1L, &status);

            if (dkim == NULL) {
                printf("FAIL (signing context)\n");
                continue;
            }

            /* Add headers normally (headers usually arrive complete) */
            for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
                status = dkim_header(dkim, (u_char *)headers[h], strlen(headers[h]));
                if (status != DKIM_STAT_OK) {
                    printf("FAIL (header %zu)\n", h);
                    goto cleanup_sign;
                }
            }

            status = dkim_eoh(dkim);
            if (status != DKIM_STAT_OK) {
                printf("FAIL (EOH)\n");
                goto cleanup_sign;
            }

            /* Add body in chunks according to scenario */
            size_t body_pos = 0;
            size_t body_len = strlen(body_text);
            int chunk_idx = 0;

            while (body_pos < body_len && chunk_scenarios[s].chunk_sizes[chunk_idx] > 0) {
                size_t chunk_size = chunk_scenarios[s].chunk_sizes[chunk_idx];
                size_t actual_size = (body_pos + chunk_size > body_len) ?
                                     (body_len - body_pos) : chunk_size;

                status = dkim_body(dkim, (u_char *)(body_text + body_pos), actual_size);
                if (status != DKIM_STAT_OK) {
                    printf("FAIL (body chunk at %zu)\n", body_pos);
                    goto cleanup_sign;
                }

                body_pos += actual_size;

                /* Cycle through chunk sizes if we have multiple */
                if (chunk_scenarios[s].chunk_sizes[chunk_idx + 1] > 0) {
                    chunk_idx++;
                } else if (chunk_scenarios[s].chunk_sizes[1] > 0) {
                    chunk_idx = 0;  /* Cycle back to start for patterns */
                }
            }

            /* Handle any remaining body with the last chunk size */
            while (body_pos < body_len) {
                size_t chunk_size = chunk_scenarios[s].chunk_sizes[chunk_idx > 0 ? chunk_idx : 0];
                size_t actual_size = (body_pos + chunk_size > body_len) ?
                                     (body_len - body_pos) : chunk_size;

                status = dkim_body(dkim, (u_char *)(body_text + body_pos), actual_size);
                if (status != DKIM_STAT_OK) {
                    printf("FAIL (remaining body chunk at %zu)\n", body_pos);
                    goto cleanup_sign;
                }

                body_pos += actual_size;
            }

            status = dkim_eom(dkim, NULL);
            if (status != DKIM_STAT_OK) {
                printf("FAIL (EOM)\n");
                goto cleanup_sign;
            }

            /* Get signature */
            memset(hdr, '\0', sizeof hdr);
            status = dkim_getsighdr(dkim, hdr, sizeof hdr, strlen(DKIM_SIGNHEADER) + 2);
            if (status != DKIM_STAT_OK) {
                printf("FAIL (get signature)\n");
                goto cleanup_sign;
            }

            dkim_free(dkim);

            /* Phase 2: Verify with same chunked processing */
            verify_dkim = dkim_verify(lib, "chunk-verify", NULL, &status);
            if (verify_dkim == NULL) {
                printf("FAIL (verify context)\n");
                continue;
            }

            /* Add signature header first */
            snprintf(sig_header, sizeof(sig_header), "%s: %s\r\n", DKIM_SIGNHEADER, hdr);
            status = dkim_header(verify_dkim, (u_char *)sig_header, strlen(sig_header));
            if (status != DKIM_STAT_OK) {
                printf("FAIL (sig header)\n");
                goto cleanup_verify;
            }

            /* Add same headers */
            for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
                status = dkim_header(verify_dkim, (u_char *)headers[h], strlen(headers[h]));
                if (status != DKIM_STAT_OK) {
                    printf("FAIL (verify header %zu)\n", h);
                    goto cleanup_verify;
                }
            }

            status = dkim_eoh(verify_dkim);
            if (status != DKIM_STAT_OK) {
                printf("FAIL (verify EOH)\n");
                goto cleanup_verify;
            }

            /* Add body in same chunks for verification */
            body_pos = 0;
            chunk_idx = 0;

            while (body_pos < body_len && chunk_scenarios[s].chunk_sizes[chunk_idx] > 0) {
                size_t chunk_size = chunk_scenarios[s].chunk_sizes[chunk_idx];
                size_t actual_size = (body_pos + chunk_size > body_len) ?
                                     (body_len - body_pos) : chunk_size;

                status = dkim_body(verify_dkim, (u_char *)(body_text + body_pos), actual_size);
                if (status != DKIM_STAT_OK) {
                    printf("FAIL (verify body chunk at %zu)\n", body_pos);
                    goto cleanup_verify;
                }

                body_pos += actual_size;

                if (chunk_scenarios[s].chunk_sizes[chunk_idx + 1] > 0) {
                    chunk_idx++;
                } else if (chunk_scenarios[s].chunk_sizes[1] > 0) {
                    chunk_idx = 0;
                }
            }

            /* Handle remaining body */
            while (body_pos < body_len) {
                size_t chunk_size = chunk_scenarios[s].chunk_sizes[chunk_idx > 0 ? chunk_idx : 0];
                size_t actual_size = (body_pos + chunk_size > body_len) ?
                                     (body_len - body_pos) : chunk_size;

                status = dkim_body(verify_dkim, (u_char *)(body_text + body_pos), actual_size);
                if (status != DKIM_STAT_OK) {
                    printf("FAIL (verify remaining body chunk at %zu)\n", body_pos);
                    goto cleanup_verify;
                }

                body_pos += actual_size;
            }

            status = dkim_eom(verify_dkim, NULL);
            if (status == DKIM_STAT_OK) {
                printf("PASS\n");
                passed_tests++;
            } else {
                printf("FAIL (verify EOM: %d)\n", status);
            }

cleanup_verify:
            dkim_free(verify_dkim);
            continue;

cleanup_sign:
            dkim_free(dkim);
        }
    }

    printf("\n=== Chunked Processing Test Results ===\n");
    printf("Tests passed: %d/%d\n", passed_tests, total_tests);
    printf("Expected: %zu tests (%zu scenarios × 2 algorithms)\n",
           sizeof(chunk_scenarios)/sizeof(chunk_scenarios[0]) * 2,
           sizeof(chunk_scenarios)/sizeof(chunk_scenarios[0]));

    if (passed_tests == total_tests) {
        printf("SUCCESS: Both algorithms handle chunked processing identically\n");
        printf("This confirms compatibility with real mail server processing patterns.\n");
    } else {
        printf("FAILURE: Algorithms handle chunks differently\n");
        printf("This could cause verification failures in production mail servers.\n");
    }

    dkim_close(lib);
    return (passed_tests == total_tests) ? 0 : 1;
}
