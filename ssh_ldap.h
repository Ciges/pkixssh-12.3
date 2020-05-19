#ifndef SSH_LDAP_H
#define SSH_LDAP_H
/*
 * Copyright (c) 2004-2019 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
#ifndef LDAP_ENABLED
#  include "error: LDAP is disabled"
#endif

#ifndef LDAP_DEPRECATED
   /* to suppress warnings in some 2.3x versions */
#  define LDAP_DEPRECATED 0
#endif
#include <ldap.h>

int	ssh_ldap_bind_s(LDAP *ld);
int	ssh_ldap_unbind_s(LDAP *ld);

int	ssh_ldap_search_s(LDAP *ld, LDAP_CONST char *base, int scope,
	    LDAP_CONST char *filter, char **attrs, int attrsonly,
	    LDAPMessage **res);
void	ssh_ldap_parse_result (LDAP *ld, LDAPMessage *res);


void	crypto_add_ldap_error(int err);
int	parse_ldap_version(const char *ver);


/* LDAP connection details */
typedef struct ldaphost_s ldaphost;
struct ldaphost_s {
	char        *url;
	char        *binddn;
	char        *bindpw;
	LDAPURLDesc *ldapurl;
	LDAP        *ld;
};

ldaphost* ldaphost_new(const char *url);
void ldaphost_free(ldaphost *p);


char*
X509_NAME_ldapfilter(X509_NAME *name, const char *attribute);


/* LDAP result iterator */
typedef struct ldapsearch_result_st ldapsearch_result;
struct ldapsearch_result_st {
	LDAP *ld;
	LDAPMessage *entry;	/* pointer to current message */
	/* loop on attribute */
	char *attr;		/* pointer to current attribute */
	BerElement *attr_ber;
	/* loop on attribute values */
	struct berval **p;	/* pointer to current value */
	struct berval **vals;
	int eom;
};

ldapsearch_result*
ldapsearch_iterator(LDAP *ld, LDAPMessage *res);

int/*bool*/
ldapsearch_advance(ldapsearch_result* r);


#undef USE_LDAP_STORE
#if defined(USE_OPENSSL_ENGINE) && defined(HAVE_OSSL_STORE_OPEN)
#  define USE_LDAP_STORE	1

int/*bool*/	set_ldap_version(const char *ver);
#endif


#undef TRACE_BY_LDAP_ENABLED
#ifdef TRACE_BY_LDAP
# undef TRACE_BY_LDAP
# define TRACE_BY_LDAP_ENABLED 1
void	TRACE_BY_LDAP(const char *f, const char *fmt, ...);
#else
static inline void
TRACE_BY_LDAP(const char *f, const char *fmt, ...) {
	UNUSED(f);
	UNUSED(fmt);
}
#endif

#endif /*ndef SSH_LDAP_H*/
