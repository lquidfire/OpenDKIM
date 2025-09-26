/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, 2013, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _DKIM_CACHE_H_
#define _DKIM_CACHE_H_

#include "build-config.h"

#include "dkim-internal.h"

#ifdef QUERY_CACHE

/* libdb includes */
#include <db.h>

/* prototypes */
extern void dkim_cache_close(DB *);
extern int dkim_cache_expire(DB *, int, int *);
extern DB *dkim_cache_init(int *, char *);
extern int dkim_cache_insert(DB *, char *, char *, int, int *);
extern int dkim_cache_query(DB *, char *, int, char *, size_t *, int *);
extern void dkim_cache_stats(DB *, u_int *, u_int *, u_int *, u_int *,
                                  _Bool);

#endif /* QUERY_CACHE */

#endif /* ! _DKIM_CACHE_H_ */
