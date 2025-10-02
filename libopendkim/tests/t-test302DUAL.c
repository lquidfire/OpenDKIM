/*
 * *  t-test03DUAL.c -- Dual algorithm body handling test
 **
 **  Tests how both algorithms handle various message body scenarios:
 **  empty bodies, large bodies, binary attachments, and body length limits.
 **  Focuses on real-world email body processing issues.
 */
#include "build-config.h"
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

#include "../dkim.h"
#include "t-testdata.h"

#define MAXHEADER 4096
#define LARGE_BODY_SIZE 8192

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
	char *large_body = NULL;
	int total_tests = 0;
	int passed_tests = 0;
	int phase;

	struct {
		const char *key;
		const char *selector;
		const char *algorithm;
	} algorithms[] = {
		{ KEY, SELECTOR, "RSA-SHA256" },
		{ KEYED25519, SELECTORED25519, "Ed25519-SHA256" }
	};

	printf("*** Dual Algorithm Body Handling Test ***\n");

	#ifdef USE_GNUTLS
	(void) gnutls_global_init();
	#endif /* USE_GNUTLS */

	/* Standard headers for all tests */
	const char *standard_headers[] = {
		"From: sender@example.com",
		"To: recipient@example.com",
		"Subject: Body Handling Test",
		"Date: Mon, 01 Jan 2024 12:00:00 +0000",
		"Message-ID: <body-test@example.com>",
		"Content-Type: text/plain; charset=utf-8"
	};

	/* Test scenarios for different body types */
	struct {
		const char *description;
		const char *body;
		size_t body_len;
		int use_generated_body;
		int requires_fixcrlf;  /* 1 if this test needs FIXCRLF to pass */
	} body_scenarios[] = {
		{
			"Empty body",
			"",
			0,
			0,
			0
		},
		{
			"Single line body",
			"Simple test message.\r\n",
			0,
			0,
			0
		},
		{
			"Multi-line body with varying line endings",
			"Line 1\r\n"
			"Line 2\n"
			"Line 3\r\n"
			"\r\n"
			"Line after blank\r\n"
			"Final line without CRLF",
			0,
			0,
			1  /* This test requires FIXCRLF */
		},
		{
			"Body with trailing whitespace",
			"Line with trailing spaces   \r\n"
			"Another line with tabs\t\t\r\n"
			"Line with mixed   \t  whitespace\r\n",
			0,
			0,
			0
		},
		{
			"Large body (8KB)",
			NULL,
			LARGE_BODY_SIZE,
			1,
			0
		},
		{
			"Body with binary-like content",
			"Content with binary-like data:\r\n"
			"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\r\n"
			"Back to normal text.\r\n"
			"More binary: \xFF\xFE\xFD\xFC\r\n"
			"End of binary test.\r\n",
			0,
			0,
			0
		}
	};

	/* Generate large body if needed */
	large_body = malloc(LARGE_BODY_SIZE + 1);
	if (large_body) {
		memset(large_body, 0, LARGE_BODY_SIZE + 1);
		for (int i = 0; i < LARGE_BODY_SIZE - 100; i += 50) {
			snprintf(large_body + i, LARGE_BODY_SIZE - i,
					 "This is line %d of the large body test message.\r\n", i/50 + 1);
		}
		/* Ensure proper termination */
		strncat(large_body, "End of large body.\r\n", LARGE_BODY_SIZE - strlen(large_body) - 1);
	}

	/* Two-phase testing: Phase 0 = without FIXCRLF, Phase 1 = with FIXCRLF */
	for (phase = 0; phase < 2; phase++) {
		int with_fixcrlf = (phase == 1);

		if (phase == 0) {
			printf("\n=== Phase 1: Testing WITHOUT FIXCRLF (strict RFC 5322 mode) ===\n");
		} else {
			printf("\n=== Phase 2: Testing WITH FIXCRLF (forgiving mode) ===\n");
		}

		lib = dkim_init(NULL, NULL);
		assert(lib != NULL);

		(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
							&fixed_time, sizeof fixed_time);
		(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
							&qtype, sizeof qtype);
		(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
							KEYFILE, strlen(KEYFILE));

		/* Enable FIXCRLF in phase 1 */
		if (with_fixcrlf) {
			u_int flags = DKIM_LIBFLAGS_FIXCRLF;
			(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
								&flags, sizeof flags);
		}

		/* Test each body scenario with both algorithms */
		for (size_t s = 0; s < sizeof(body_scenarios)/sizeof(body_scenarios[0]); s++) {
			/* In phase 0, only test the malformed line endings scenario */
			/* In phase 1, test all scenarios */
			if (!with_fixcrlf && !body_scenarios[s].requires_fixcrlf) {
				continue;
			}

			printf("\n--- Testing: %s ---\n", body_scenarios[s].description);

			/* Skip large body test if allocation failed */
			if (body_scenarios[s].use_generated_body && !large_body) {
				printf("  Skipping large body test (allocation failed)\n");
				continue;
			}

			const char *test_body = body_scenarios[s].use_generated_body ?
			large_body : body_scenarios[s].body;
			size_t test_body_len = body_scenarios[s].use_generated_body ?
			strlen(large_body) :
			(body_scenarios[s].body_len ? body_scenarios[s].body_len : strlen(body_scenarios[s].body));

			for (size_t a = 0; a < sizeof(algorithms)/sizeof(algorithms[0]); a++) {
				printf("  %s: ", algorithms[a].algorithm);
				total_tests++;

				/* Sign with current algorithm */
				dkim = dkim_sign(lib, "body-test", NULL, (dkim_sigkey_t)algorithms[a].key,
								 algorithms[a].selector, DOMAIN,
					 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
					 DKIM_SIGN_DEFAULT, -1L, &status);
				if (dkim == NULL) {
					printf("FAIL (signing context)\n");
					continue;
				}

				/* Add standard headers */
				for (size_t h = 0; h < sizeof(standard_headers)/sizeof(standard_headers[0]); h++) {
					status = dkim_header(dkim, (u_char *)standard_headers[h], strlen(standard_headers[h]));
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

				/* Add body (handle empty body case) */
				if (test_body_len > 0) {
					status = dkim_body(dkim, (u_char *)test_body, test_body_len);

					/* Without FIXCRLF, malformed body should fail */
					if (!with_fixcrlf && body_scenarios[s].requires_fixcrlf) {
						if (status != DKIM_STAT_OK) {
							printf("PASS (Expected failure as RFC 5322 requires proper CRLF)\n");
							passed_tests++;
							dkim_free(dkim);
							continue;
						} else {
							printf("FAIL (expected failure without FIXCRLF)\n");
							goto cleanup_sign;
						}
					}

					if (status != DKIM_STAT_OK) {
						printf("FAIL (body)\n");
						goto cleanup_sign;
					}
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

				/* Verify the signature */
				verify_dkim = dkim_verify(lib, "body-verify", NULL, &status);
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
				for (size_t h = 0; h < sizeof(standard_headers)/sizeof(standard_headers[0]); h++) {
					status = dkim_header(verify_dkim, (u_char *)standard_headers[h], strlen(standard_headers[h]));
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

				/* Add same body */
				if (test_body_len > 0) {
					status = dkim_body(verify_dkim, (u_char *)test_body, test_body_len);
					if (status != DKIM_STAT_OK) {
						printf("FAIL (verify body)\n");
						goto cleanup_verify;
					}
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

		dkim_close(lib);
	}

	printf("\n=== Body Handling Test Results ===\n");
	printf("Tests passed: %d/%d\n", passed_tests, total_tests);
	printf("Expected: %d tests (6 scenarios × 2 algorithms, plus 2 RFC compliance tests)\n",
		   (sizeof(body_scenarios)/sizeof(body_scenarios[0]) + 1) * 2);

	if (passed_tests == total_tests) {
		printf("SUCCESS: Both algorithms handle message bodies identically\n");
		printf("This confirms body processing compatibility for various email content types.\n");
	} else {
		printf("FAILURE: Algorithms handle bodies differently\n");
		printf("This indicates potential issues with email content processing.\n");
	}

	if (large_body) {
		free(large_body);
	}

	return (passed_tests == total_tests) ? 0 : 1;
}
