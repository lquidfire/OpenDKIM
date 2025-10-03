/*
 * *  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
 **    All rights reserved.
 **
 **  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
 **
 **  Copyright 2025 OpenDKIM contributors.
 */


#define	CRLF		"\r\n"
#define	SP		" "

#define	LARGEBODYSIZE	65536
#define	LARGELINESIZE	4100

#define	KEYFILE		"/var/tmp/testkeys"

#define	JOBID		"testing"
#define	SELECTOR	"test"
#define	SELECTOR2	"brisbane"
#define	SELECTOR256	"sha256only"
#define	SELECTORED25519	"ed25519-sha256"
#define	SELECTORBADH	"badh"
#define	SELECTORBADK	"badk"
#define	SELECTORBADV	"badv"
#define	SELECTORNOK	"nok"
#define	SELECTORNOP	"nop"
#define	SELECTOREMPTYP	"emptyp"
#define	SELECTORCORRUPTP "corruptp"
#define	DOMAIN		"example.com"
#define	DOMAIN2		"sendmail.com"
#define	REPLYADDRESS	"postmaster"
#define	SMTPTOKENENC	"=5BDKIM=20error=5D"
#define	SMTPTOKEN	"[DKIM error]"
#define	USER		"msk"

#define	HEADER01	"Received: received data 0"
#define	HEADER02	"Received: received data 1"
#define	HEADER03	"Received: received data 2"
#define	HEADER04	"Received: received data 3 part 1\r\n\t data 3 part 2"
#define	HEADER04UNWRAP	"Received: received data 3 part 1 data 3 part 2"
#define	HEADER05	"From: Murray S. Kucherawy <msk@sendmail.com>"
#define	HEADER06	"To: Sendmail Test Address <sa-test@sendmail.net>"
#define	HEADER07	"Date: Thu, 05 May 2005 11:59:09 -0700"
#define	HEADER07XLEADSP	"Date:   Thu, 05 May 2005 11:59:09 -0700"
#define	HEADER07NOLEADSP "Date:Thu, 05 May 2005 11:59:09 -0700"
#define	HEADER08	"Subject: DKIM test message"
#define	HEADER09	"Message-ID: <439094BF.5010709@sendmail.com>"
#define	HEADER10	"Cc: user@example.com"

#define	BODY00		"This is a message body.  Fun!\r\n"
#define	BODY01		"Here is a second line.\r\n"
#define	BODY01A		"Here is a line"
#define	BODY01B		" that is broken up across calls.\r"
#define	BODY01C		"\n"
#define	BODY01D		"Now we can try something interesting, like a\r\nmulti-line buffer.  This should not be mangled.\r\n"
#define	BODY01E		"And a line with a trailing space: \r\n"
#define	BODY02		"Next we'll try a blank.\r\n"
#define	BODY03		"\r\n"
#define	BODY04		"Next we'll try multiple blanks.\r\n"
#define	BODY05		"Finally we'll try multiple trailing blanks.\r\n"
#define	BODY06		"Surprise, more data!\r\n"

#define	NBODY00		"This is a message body.  Fun!\n"
#define	NBODY01		"Here is a second line.\r"
#define	NBODY01A	"Here is a line"
#define	NBODY01B	" that is broken up across calls.\r"
#define	NBODY01C	"\n"
#define	NBODY01D	"Now we can try something interesting, like a\nmulti-line buffer.  This should not be mangled.\r\n"
#define	NBODY01E	"And a line with a trailing space: \n"
#define	NBODY02		"Next we'll try a blank.\r"
#define	NBODY03		"\r\n"
#define	NBODY04		"Next we'll try multiple blanks.\r\n"
#define	NBODY05		"Finally we'll try multiple trailing blanks.\r"

#define THEADER00	"Received: from client1.football.example.com  [192.0.2.1]\r\n" \
"      by submitserver.example.com with SUBMISSION;\r\n" \
"      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)"
#define	THEADER01	"From: Joe SixPack <joe@football.example.com>"
#define THEADER02	"To: Suzie Q <suzie@shopping.example.net>"
#define THEADER03	"Subject: Is dinner ready?"
#define THEADER04	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)"
#define	THEADER05	"Message-ID: <20030712040037.46341.5F8J@football.example.com>"
#define	TBODY		"Hi.\r\n" \
"\r\n" \
"We lost the game. Are you hungry yet?\r\n" \
"\r\n" \
"Joe.\r\n"

#define KEY		"-----BEGIN RSA PRIVATE KEY-----\n" \
"MIICXQIBAAKBgQC4GUGr+d/6SFNzVLYpphnRd0QPGKz2uWnV65RAxa1Pw352Bqiz\n" \
"qiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFgF0gu3UJbNnu3+cd8k/kiQj+q\n" \
"4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3Dyc079gSLtnSrgXb+gQIDAQAB\n" \
"AoGAemlI0opm1Kvs2T4VliH8/tvX5FXbBH8LEZQAUwVeFTB/UQlieXyCV39pIxZO\n" \
"0Sa50qm8YNL9rb5HTSZiHQFOwyAKNqS4m/7JCsbuH4gQkPgPF561BHNL9oKfYgJq\n" \
"9P4kEFfDTBoXKBMxwWtT7AKV8dYvCa3vYzPQ/1BnqQdw2zECQQDyscdgR9Ih59PQ\n" \
"b72ddibdsxS65uXS2vzYLe7SKl+4R5JgJzw0M6DTAnoYFf6JAsKGZM15PCC0E16t\n" \
"RRo47U9VAkEAwjEVrlQ0/8yPACbDggDJg/Zz/uRu1wK0zjqj4vKjleubaX4SEvj7\n" \
"r6xxZm9hC1pMJAC9y3bbkbgCRBjXfyY6fQJBANe5aq2MaZ41wTOPf45NjbKXEiAo\n" \
"SbUpboKCIbyyaa8V/2h0t7D3C0dE9l4efsguqdZoF7Rh2/f1F70QpYRgfJkCQQCH\n" \
"oRrAeGXP50JVW72fNgeJGH/pnghgOa6of0JpxwhENJuGMZxUDfxTtUA6yD3iXP3j\n" \
"A3WL/wbaHsfOYf9Y+g1NAkAGLhx67Ah+uBNK4Xvfz0YPGINX20m+CMsxAw7FOaNv\n" \
"IW2oWFfZCB4APkIis79Ql45AHpavwx5XodBMzZwJUvlL\n" \
"-----END RSA PRIVATE KEY-----\n"
#define KEYED25519		"-----BEGIN PRIVATE KEY-----\n" \
"MC4CAQAwBQYDK2VwBCIEIAUaY76CjnuKE8eHZzjDZvuPlrKPnJsvS0XbARwh30HX\n" \
"-----END PRIVATE KEY-----\n"
#define SMALLKEY	"-----BEGIN RSA PRIVATE KEY-----\n" \
"MIIBOwIBAAJBAKmXwtw3FU/88TPoOpYR3FKkD4ViDLQZOSitce6cJzdoksJ2Vs9T\n" \
"l6d1V9OIOsvktC1nmaZ8Xs5I7oMkJF8PbXUCAwEAAQJBAJxAG6NDCNrKY/x8AMZV\n" \
"LFXjm/07KhMgjh4hNzAtJKCRs3NscczUlR/iA//ZmkccSJONmV6WWLo54H5lJPWi\n" \
"jmECIQDS3m6eOt4WY4W4WWC2eMuYeOOIzSK71aWuX4qJVgYZLQIhAM3jzTlssVyh\n" \
"y34LCV4Wap5e2eH/wlpLnHWsVD3sR8JpAiBbxJNtZv8JzUv/e14caxtngoy7F1Mb\n" \
"XZIZ/dhDhl1nDQIhAK3rADDB4BCfm4WdTQxtYyLkfKiro0EjHcdJCuBD91oBAiB3\n" \
"dJk2Cl+yMP+oIqR6bDZQY5lzuaE5v3GMRSSWC94B6A==\n" \
"-----END RSA PRIVATE KEY-----\n"
#define	PUBLICKEY	"v=DKIM1; k=rsa; t=y:s; h=sha256; p=" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4GUGr+d/6SFNzVLYpphnRd0QP" \
"GKz2uWnV65RAxa1Pw352BqizqiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFg" \
"F0gu3UJbNnu3+cd8k/kiQj+q4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3D" \
"yc079gSLtnSrgXb+gQIDAQAB"
#define	PUBLICKEYNOS	"v=DKIM1; k=rsa; t=y; p=" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4GUGr+d/6SFNzVLYpphnRd0QP" \
"GKz2uWnV65RAxa1Pw352BqizqiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFg" \
"F0gu3UJbNnu3+cd8k/kiQj+q4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3D" \
"yc079gSLtnSrgXb+gQIDAQAB"
#define	PUBLICKEY2	"v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" \
"KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt" \
"IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v" \
"/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi" \
"tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"
#define	PUBLICKEYBADV	"v=DKIM0; k=rsa; t=y:s; h=sha256; p=" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4GUGr+d/6SFNzVLYpphnRd0QP" \
"GKz2uWnV65RAxa1Pw352BqizqiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFg" \
"F0gu3UJbNnu3+cd8k/kiQj+q4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3D" \
"yc079gSLtnSrgXb+gQIDAQAB"
#define	PUBLICKEY256	"v=DKIM1; k=rsa; t=y:s; h=sha256; p=" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4GUGr+d/6SFNzVLYpphnRd0QP" \
"GKz2uWnV65RAxa1Pw352BqizqiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFg" \
"F0gu3UJbNnu3+cd8k/kiQj+q4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3D" \
"yc079gSLtnSrgXb+gQIDAQAB"
#define	PUBLICKEYED25519	"v=DKIM1; k=ed25519; p=" \
"KZqCOx27eW/3EwXhE2uHfQo3ZD68+R/2f0jKmUwiMjk="
#define	PUBLICKEYBADH	"v=DKIM1; k=rsa; t=y:s; h=sha0; p=" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4GUGr+d/6SFNzVLYpphnRd0QP" \
"GKz2uWnV65RAxa1Pw352BqizqiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFg" \
"F0gu3UJbNnu3+cd8k/kiQj+q4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3D" \
"yc079gSLtnSrgXb+gQIDAQAB"
#define	PUBLICKEYNOK	"v=DKIM1; t=y:s; p=" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4GUGr+d/6SFNzVLYpphnRd0QP" \
"GKz2uWnV65RAxa1Pw352BqizqiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFg" \
"F0gu3UJbNnu3+cd8k/kiQj+q4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3D" \
"yc079gSLtnSrgXb+gQIDAQAB"
#define	PUBLICKEYBADK	"v=DKIM1; k=xxx; t=y:s; sha256; p=" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4GUGr+d/6SFNzVLYpphnRd0QP" \
"GKz2uWnV65RAxa1Pw352BqizqiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFg" \
"F0gu3UJbNnu3+cd8k/kiQj+q4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3D" \
"yc079gSLtnSrgXb+gQIDAQAB"
#define	PUBLICKEYEMPTYP	"v=DKIM1; k=rsa; t=y:s; sha256; p="
#define	PUBLICKEYNOP	"v=DKIM1; k=rsa; t=y:s; sha256"
#define	PUBLICKEYCORRUPTP	"v=DKIM1; k=rsa; t=y:s; sha256; p=" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4GUGr+d/6SFNzVLYpphnRd0QP" \
"GKz2uWnV65RAxa1Pw352BqizqiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFg" \
"F0gu3UJbNnu3+cd8k/kiQj+q4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3D" \
"yc079gSLtnSrgXb+gQIDAQ"
#define	REPORTRECORD	"ra=postmaster; rs=" SMTPTOKENENC

#define	GIBBERISH	"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 !@#$%^&*()_+|-={}[];':,./<>?`~\r\n"


/* Common test setup functions */

/*
 * *  DKIM_TEST_DNS_SETUP -- Configure DKIM library for file-based DNS lookups
 **
 **  Parameters:
 **  	lib -- DKIM_LIB handle to configure
 **
 **  Return value:
 **  	DKIM_STAT_OK on success, error code on failure
 **
 **  Notes:
 **  	This function configures the DKIM library to use file-based DNS lookups
 **  	instead of real DNS queries. It should be called after dkim_init() but
 **  	before any verification operations. The KEYFILE path is used automatically.
 */
static DKIM_STAT
dkim_test_dns_setup(DKIM_LIB *lib)
{
	dkim_query_t qtype = DKIM_QUERY_FILE;
	DKIM_STAT status;

	assert(lib != NULL);

	/* Configure file-based key lookup */
	status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
						  &qtype, sizeof qtype);
	if (status != DKIM_STAT_OK)
		return status;

	status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
						  KEYFILE, strlen(KEYFILE));
	return status;
}

/*
 * *  DKIM_TEST_LIB_SETUP -- Complete DKIM library setup for tests
 **
 **  Parameters:
 **  	lib -- DKIM_LIB handle to configure
 **  	fixed_time -- fixed timestamp for reproducible signatures (optional, 0 to skip)
 **
 **  Return value:
 **  	DKIM_STAT_OK on success, error code on failure
 **
 **  Notes:
 **  	This function performs common DKIM library setup that most tests need:
 **  	- Configures file-based DNS lookups
 **  	- Sets fixed time if requested
 **  	- Can be extended with other common test configurations
 */
static DKIM_STAT
dkim_test_lib_setup(DKIM_LIB *lib, uint64_t fixed_time)
{
	DKIM_STAT status;

	assert(lib != NULL);

	/* Set up file-based DNS lookups */
	status = dkim_test_dns_setup(lib);
	if (status != DKIM_STAT_OK)
		return status;

	/* Set fixed time if requested */
	if (fixed_time != 0) {
		status = dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
							  &fixed_time, sizeof fixed_time);
		if (status != DKIM_STAT_OK)
			return status;
	}

	return DKIM_STAT_OK;
}

/*
 * *  DKIM_TEST_INIT_GNUTLS -- Initialize GnuTLS if needed
 **
 **  Parameters:
 **  	None
 **
 **  Return value:
 **  	None
 **
 **  Notes:
 **  	This function initializes GnuTLS if the library was built with GnuTLS support.
 **  	It's safe to call multiple times.
 */
static void
dkim_test_init_gnutls(void)
{
	#ifdef USE_GNUTLS
	(void) gnutls_global_init();
	#endif /* USE_GNUTLS */
}

/*
 * *  DKIM_TEST_SETUP_ALL -- Complete test initialization
 **
 **  Parameters:
 **  	lib -- pointer to DKIM_LIB handle (will be allocated)
 **  	fixed_time -- fixed timestamp for reproducible signatures (optional, 0 to skip)
 **
 **  Return value:
 **  	DKIM_STAT_OK on success, error code on failure
 **
 **  Notes:
 **  	This function performs all common test setup:
 **  	- Initializes GnuTLS if needed
 **  	- Allocates and initializes DKIM library
 **  	- Configures file-based DNS lookups
 **  	- Sets fixed time if requested
 **
 **  	Example usage:
 **  		DKIM_LIB *lib;
 **  		DKIM_STAT status = dkim_test_setup_all(&lib, 1172620939);
 **  		assert(status == DKIM_STAT_OK);
 */
static DKIM_STAT
dkim_test_setup_all(DKIM_LIB **lib, uint64_t fixed_time)
{
	DKIM_STAT status;

	assert(lib != NULL);

	/* Initialize crypto library if needed */
	dkim_test_init_gnutls();

	/* Initialize the DKIM library */
	*lib = dkim_init(NULL, NULL);
	if (*lib == NULL)
		return DKIM_STAT_NORESOURCE;

	/* Perform common library setup */
	status = dkim_test_lib_setup(*lib, fixed_time);
	if (status != DKIM_STAT_OK) {
		dkim_close(*lib);
		*lib = NULL;
		return status;
	}

	return DKIM_STAT_OK;
}
