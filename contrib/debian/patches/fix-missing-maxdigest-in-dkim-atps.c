Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 opendkim (3.0.0~beta1-1) UNRELEASED; urgency=medium
 .
   * New upstream release (3.0.0-beta1 from GitHub/lquidfire).
Author: builder <edmund@proteamail.com>

---
The information above should follow the Patch Tagging Guidelines, please
checkout https://dep.debian.net/deps/dep3/ to learn about the format. Here
are templates for supplementary fields that you might want to add:

Origin: (upstream|backport|vendor|other), (<patch-url>|commit:<commit-id>)
Bug: <upstream-bugtracker-url>
Bug-Debian: https://bugs.debian.org/<bugnumber>
Bug-Ubuntu: https://launchpad.net/bugs/<bugnumber>
Forwarded: (no|not-needed|<patch-forwarded-url>)
Applied-Upstream: <version>, (<commit-url>|commit:<commid-id>)
Reviewed-By: <name and email of someone who approved/reviewed the patch>
Last-Update: 2025-09-22

--- opendkim-3.0.0~beta1.orig/libopendkim/dkim-atps.c
+++ opendkim-3.0.0~beta1/libopendkim/dkim-atps.c
@@ -54,7 +54,7 @@ extern void dkim_error __P((DKIM *, cons
 
 #define	DKIM_ATPS_QUERYLENGTH	64
 #define	DKIM_ATPS_VALID		"v=ATPS1"
-
+#define MAXDIGEST		EVP_MAX_MD_SIZE
 
 /*
 **  DKIM_ATPS_CHECK -- check for Authorized Third Party Signing
@@ -143,7 +143,7 @@ dkim_atps_check(DKIM *dkim, DKIM_SIGINFO
 	switch (hash)
 	{
 	  case DKIM_HASHTYPE_SHA256:
-		diglen = SHA256_DIGEST_LENGTH;
+		diglen = EVP_MD_size(EVP_sha256());
 		break;
 
 	  case DKIM_HASHTYPE_UNKNOWN:
