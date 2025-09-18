/*
 **  Copyright (c) 2005, 2008 Sendmail, Inc. and its suppliers.
 **    All rights reserved.
 **
 **  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
 **
 **  Copyright 2025 OpenDKIM contributors.
 **
 **  Changelog:
 **    202509: Use OpenSSL BIO functions instead of custom base64 code.
 */

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>

/* OpenSSL includes */
#include <openssl/bio.h>
#include <openssl/evp.h>

/* libopendkim includes */
#include "base64.h"

#ifndef NULL
# define NULL	0
#endif /* ! NULL */

/*
 **  DKIM_BASE64_DECODE -- decode a base64 blob
 **
 **  Parameters:
 **  	str -- string to decode
 **  	buf -- where to write it
 **  	buflen -- bytes available at "buf"
 **
 **  Return value:
 **  	>= 0 -- success; length of what was decoded is returned
 **  	-1 -- corrupt input
 **  	-2 -- not enough space at "buf" or internal error
 */

int
dkim_base64_decode(u_char *str, u_char *buf, size_t buflen)
{
	int retval = -2;
	size_t len;
	BIO *bmem;
	BIO *b64;

	assert(str != NULL);
	assert(buf != NULL);

	/* check input format - must be multiple of 4 characters */
	len = strlen((const char *) str);
	if (len % 4 > 0)
	{
		return -1;
	}

	/* rough check for buffer space (base64 expands by ~4/3) */
	if (len / 4 * 3 > buflen)
	{
		return -2;
	}

	/* create memory BIO from input string */
	bmem = BIO_new_mem_buf(str, -1);
	if (bmem == NULL)
	{
		return retval;
	}

	/* create base64 decoder and chain it to memory BIO */
	b64 = BIO_push(BIO_new(BIO_f_base64()), bmem);
	if (b64 == bmem)
	{
		goto error;
	}

	/* configure base64 decoder to handle data without newlines */
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	/* decode the data */
	retval = BIO_read(b64, buf, buflen);

	error:
	BIO_free_all(b64);
	return retval;
}

/*
 **  DKIM_BASE64_ENCODE -- encode base64 data
 **
 **  Parameters:
 **  	data -- data to encode
 **  	datalen -- bytes at "data" to encode
 **  	buf -- where to write the encoding
 **  	buflen -- bytes available at "buf"
 **
 **  Return value:
 **  	>= 0 -- success; number of bytes written to "buf" returned
 **   	-1 -- failure (not enough space at "buf" or internal error)
 */

int
dkim_base64_encode(u_char *data, size_t datalen, u_char *buf, size_t buflen)
{
	int retval = -1;
	BIO *bmem;
	BIO *b64;

	assert(data != NULL);
	assert(buf != NULL);

	/* create memory BIO for output */
	bmem = BIO_new(BIO_s_mem());
	if (bmem == NULL)
	{
		return retval;
	}

	/* create base64 encoder and chain it to memory BIO */
	b64 = BIO_push(BIO_new(BIO_f_base64()), bmem);
	if (b64 == bmem)
	{
		goto error;
	}

	/* configure base64 encoder to generate data without newlines */
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	/* encode the data */
	BIO_write(b64, data, datalen);
	BIO_flush(b64);

	/* read the encoded result */
	retval = BIO_read(bmem, buf, buflen);

	/* check if we read everything (no truncation) */
	if (retval > 0 && BIO_eof(bmem) != 1)
	{
		retval = -1;
	}

	error:
	BIO_free_all(b64);
	return retval;
}
