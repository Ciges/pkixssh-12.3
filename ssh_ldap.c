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

#include "ssh_ldap.h"

#include <openssl/x509.h>
#include <openssl/err.h>


#ifdef TRACE_BY_LDAP_ENABLED
void
TRACE_BY_LDAP(const char *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("TRACE_BY_LDAP ", stderr);
    fputs(f, stderr);
    fputs(":  ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputs("\n", stderr);
}
#endif /*def TRACE_BY_LDAP_ENABLED*/


/* ================================================================== */
/* wrappers for some LDAP-functions */

int
ssh_ldap_bind_s(LDAP *ld) {
	int result;

	/* anonymous bind - data must be retrieved by anybody */
#ifdef HAVE_LDAP_SASL_BIND_S
{
	static struct berval	cred = { 0, (char*)"" };

	result = ldap_sasl_bind_s(
		ld, NULL/*dn*/, LDAP_SASL_SIMPLE, &cred,
		NULL, NULL, NULL);
}
#else
	result = ldap_simple_bind_s(ld, NULL/*binddn*/, NULL/*bindpw*/);
#endif

TRACE_BY_LDAP(__func__, "ldap_XXX_bind_s return 0x%x(%s)"
, result, ldap_err2string(result));
	return result;
}


int
ssh_ldap_unbind_s(LDAP *ld) {
	int result;
#ifdef HAVE_LDAP_UNBIND_EXT_S
	result = ldap_unbind_ext_s(ld, NULL, NULL);
#else
	result = ldap_unbind_s(ld);
#endif

TRACE_BY_LDAP(__func__, "ldap_XXX_unbind_s return 0x%x(%s)"
, result, ldap_err2string(result));
	return result;
}


int
ssh_ldap_search_s(
	LDAP *ld,
	LDAP_CONST char *base,
	int scope,
	LDAP_CONST char *filter,
	char **attrs,
	int attrsonly,
	LDAPMessage **res
) {
	int result;
#ifdef HAVE_LDAP_SEARCH_EXT_S
	result = ldap_search_ext_s(ld, base,
		scope, filter, attrs, attrsonly,
		NULL, NULL, NULL, 0, res);
#else
	result = ldap_search_s(ld, base, scope, filter, attrs, attrsonly, res);
#endif

TRACE_BY_LDAP(__func__, "..."
"\n  base: '%s'\n  filter: '%s'\n  ldap_search_{XXX}s return 0x%x(%s)"
, base, filter, result, ldap_err2string(result));
	return result;
}


void
ssh_ldap_parse_result (
	LDAP *ld,
	LDAPMessage *res
) {
	static const int freeit = 0;
	int result;
#ifdef HAVE_LDAP_PARSE_RESULT
	int ret;
	char *matcheddn;
	char *errmsg;

	ret = ldap_parse_result(ld, res, &result, &matcheddn, &errmsg, NULL, NULL, freeit);
	if (ret == LDAP_SUCCESS) {
		if (errmsg) ERR_add_error_data(1, errmsg);
	}
	if (matcheddn) ldap_memfree(matcheddn);
	if (errmsg)    ldap_memfree(errmsg);
#else
	result = ldap_result2error(ld, res, freeit);
	crypto_add_ldap_error(result);
#endif
}


/* ================================================================== */
/* Crypto library error management */
extern void ERR_load_SSHLDAP_strings(void);
extern void ERR_load_X509byLDAP_strings(void);

/* Function codes. */
#define SSHLDAP_F_LDAPHOST_NEW				101
#define SSHLDAP_F_LDAPSEARCH_ITERATOR			102

/* Reason codes. */
#define SSHLDAP_R_NOT_LDAP_URL				101
#define SSHLDAP_R_INVALID_URL				102
#define SSHLDAP_R_INITIALIZATION_ERROR			103
#define SSHLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION	104
#define SSHLDAP_R_UNABLE_TO_COUNT_ENTRIES		105


#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA SSHLDAP_str_functs[] = {
	{ ERR_PACK(0, SSHLDAP_F_LDAPHOST_NEW, 0)	, "LDAPHOST_NEW" },
	{ ERR_PACK(0, SSHLDAP_F_LDAPSEARCH_ITERATOR, 0)	, "LDAPSEARCH_ITERATOR" },
	{ 0, NULL }
};

static ERR_STRING_DATA SSHLDAP_str_reasons[] = {
	{ ERR_PACK(0, 0, SSHLDAP_R_NOT_LDAP_URL)			, "not ldap url" },
	{ ERR_PACK(0, 0, SSHLDAP_R_INVALID_URL)				, "invalid ldap url" },
	{ ERR_PACK(0, 0, SSHLDAP_R_INITIALIZATION_ERROR)		, "ldap initialization error" },
	{ ERR_PACK(0, 0, SSHLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION)	, "unable to get ldap protocol version" },
	{ ERR_PACK(0, 0, SSHLDAP_R_UNABLE_TO_COUNT_ENTRIES)		, "unable to count ldap entries" },
	{ 0, NULL }
};

static ERR_STRING_DATA SSHLDAP_lib_name[] = {
	{ 0, "SSHLDAP" },
	{ 0, NULL }
};

#endif /*ndef OPENSSL_NO_ERR*/


static int ERR_LIB_SSHLDAP = 0;

static inline void
SSHLDAP_PUT_error(int function, int reason, const char *file, int line, const char *funcname) {
	if (ERR_LIB_SSHLDAP == 0)
		ERR_LIB_SSHLDAP = ERR_get_next_error_library();

#ifdef OPENSSL_NO_FILENAMES /* OpenSSL 1.1+ */
	file = NULL;
	line = 0;
#endif
#ifdef ERR_raise_data
	UNUSED(function);
	ERR_new();
	ERR_set_debug(file, line, funcname);
	ERR_set_error(ERR_LIB_SSHLDAP, reason, NULL);
#else
	UNUSED(funcname);
	ERR_PUT_error(ERR_LIB_SSHLDAP, function, reason, file, line);
#endif /*ndef ERR_raise_data*/
}

#define SSHLDAPerr(f,r) SSHLDAP_PUT_error((f),(r),__FILE__,__LINE__, __func__)


void
ERR_load_SSHLDAP_strings(void) {
#ifndef OPENSSL_NO_ERR
{	static int loaded = 0;
	if (loaded) return;
	loaded = 1;
}
	if (ERR_LIB_SSHLDAP == 0)
		ERR_LIB_SSHLDAP = ERR_get_next_error_library();

	ERR_load_strings(ERR_LIB_SSHLDAP, SSHLDAP_str_functs);
	ERR_load_strings(ERR_LIB_SSHLDAP, SSHLDAP_str_reasons);

	SSHLDAP_lib_name[0].error = ERR_PACK(ERR_LIB_SSHLDAP, 0, 0);
	ERR_load_strings(0, SSHLDAP_lib_name);
#endif /*ndef OPENSSL_NO_ERR*/
	ERR_load_X509byLDAP_strings();
}


/* ================================================================== */
/* LDAP connection details */

ldaphost*
ldaphost_new(const char *url) {
	ldaphost *p;
	int ret;

TRACE_BY_LDAP(__func__, "url: '%s')", url);
	p = OPENSSL_malloc(sizeof(ldaphost));
	if (p == NULL) return NULL;

	memset(p, 0, sizeof(ldaphost));

	p->url = OPENSSL_malloc(strlen(url) + 1);
	if (p->url == NULL) goto error;
	strcpy(p->url, url);

	/*ldap://hostport/dn[?attrs[?scope[?filter[?exts]]]] */
	ret = ldap_is_ldap_url(url);
	if (ret < 0) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_NOT_LDAP_URL);
		goto error;
	}

	ret = ldap_url_parse(p->url, &p->ldapurl);
	if (ret != 0) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_INVALID_URL);
		crypto_add_ldap_error(ret);
		goto error;
	}
#ifdef TRACE_BY_LDAP_ENABLED
{
char *uri = ldap_url_desc2str(p->ldapurl);
TRACE_BY_LDAP(__func__, "ldap_url_desc2str: '%s'", uri);
ldap_memfree(uri);
}
#endif /*def TRACE_BY_LDAP_ENABLED*/
TRACE_BY_LDAP(__func__, "ldapurl: '%s://%s:%d'", p->ldapurl->lud_scheme, p->ldapurl->lud_host, p->ldapurl->lud_port);

	/* allocate connection without to open */
#ifdef HAVE_LDAP_INITIALIZE
	ret = ldap_initialize(&p->ld, p->url);
	if (ret != LDAP_SUCCESS) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_INITIALIZATION_ERROR);
		crypto_add_ldap_error(ret);
		goto error;
	}
#else /*ndef HAVE_LDAP_INITIALIZE*/
	p->ld = ldap_init(p->ldapurl->lud_host, p->ldapurl->lud_port);
	if(p->ld == NULL) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_INITIALIZATION_ERROR);
		goto error;
	}
#endif /*ndef HAVE_LDAP_INITIALIZE*/

{	int version = -1;

	ret = ldap_get_option(p->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (ret != LDAP_OPT_SUCCESS) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION );
		goto error;
	}
TRACE_BY_LDAP(__func__, "using protocol v%d (default)", version);
}

	return p;
error:
	ldaphost_free(p);
	return NULL;
}


void
ldaphost_free(ldaphost *p) {
TRACE_BY_LDAP(__func__, "...");
	if (p == NULL) return;
	if (p->url    != NULL) OPENSSL_free(p->url);
	if (p->binddn != NULL) OPENSSL_free(p->binddn);
	if (p->bindpw != NULL) OPENSSL_free(p->bindpw);
	if (p->ldapurl != NULL) {
		ldap_free_urldesc(p->ldapurl);
		p->ldapurl = NULL;
	}
	if (p->ld != NULL) {
		(void)ssh_ldap_unbind_s(p->ld);
		p->ld = NULL;
	}
	OPENSSL_free(p);
}


/* ================================================================== */
/* LDAP search filter */

static char*
ldapsearch_ASN1_STRING(ASN1_STRING *nv) {
	char *p = NULL;
	int k;
	BIO *mbio;

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return NULL;

	k = ASN1_STRING_print_ex(mbio, nv, XN_FLAG_RFC2253);
	p = OPENSSL_malloc(k + 1);
	if (p == NULL) goto done;

	k = BIO_read(mbio, p, k);
	p[k] = '\0';

done:
	BIO_free_all(mbio);
	return p;
}


char*
X509_NAME_ldapfilter(X509_NAME *name, const char *attribute) {
	char *p = NULL;
	int k;
	BIO *mbio;

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return NULL;

	BIO_puts(mbio, "(&");

	k = X509_NAME_entry_count(name);
	for (--k; k >= 0; k--) {
		X509_NAME_ENTRY *ne;
		ASN1_STRING     *nv;
		int nid;

		ne = X509_NAME_get_entry(name, k);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne));

		if (
			(nid != NID_organizationName) &&
			(nid != NID_organizationalUnitName) &&
			(nid != NID_commonName)
		) continue;

		BIO_puts(mbio, "(");
		BIO_puts(mbio, OBJ_nid2sn(nid));
		BIO_puts(mbio, "=");
		nv = X509_NAME_ENTRY_get_data(ne);
		{
			char *q, *s;

			q = ldapsearch_ASN1_STRING(nv);
TRACE_BY_LDAP(__func__, "ldapsearch_ASN1_STRING(nv) return '%s'", (q ? q : "<?>"));
			if (q == NULL) goto done;
			/* escape some charecters according to RFC2254 */
			for (s=q; *s; s++) {
				if ((*s == '*') ||
				    (*s == '(') ||
				    (*s == ')')
				    /* character '\' should be already escaped ! */
				) {
					/* RFC2254 recommendation */
					BIO_printf(mbio, "\\%02X", (int)*s);
					continue;
				}
				BIO_write(mbio, s, 1);
			}

			OPENSSL_free(q);
		}
		BIO_puts(mbio, ")");
	}

	if (attribute != NULL) {
		BIO_puts(mbio, "(");
		BIO_puts(mbio, attribute);
		BIO_puts(mbio, "=*)");
	}

	BIO_puts(mbio, ")");
	(void)BIO_flush(mbio);

	k = BIO_pending(mbio);
	p = OPENSSL_malloc(k + 1);
	if (p == NULL) goto done;

	k = BIO_read(mbio, p, k);
	p[k] = '\0';
TRACE_BY_LDAP(__func__, "result: '%.1024s'%s", p, (k > 1024 ? "...": ""));

done:
	BIO_free_all(mbio);
	return p;
}


/* ================================================================== */
/* LDAP result iterator */

ldapsearch_result*
ldapsearch_iterator(LDAP *ld, LDAPMessage *res) {
{	int k = ldap_count_entries(ld, res);
TRACE_BY_LDAP(__func__, "ldap_count_entries: %d", k);
	if (k < 0) {
		SSHLDAPerr(SSHLDAP_F_LDAPSEARCH_ITERATOR, SSHLDAP_R_UNABLE_TO_COUNT_ENTRIES);
		ssh_ldap_parse_result (ld, res);
		return NULL;
	}
}
{
	ldapsearch_result *ret = OPENSSL_malloc(sizeof(ldapsearch_result));
	if (ret == NULL) return NULL;

	memset(ret, 0, sizeof(ldapsearch_result));

	ret->ld = ld;
	ret->entry = ldap_first_entry(ld, res);
	return ret;
}
}


int/*bool*/
ldapsearch_advance(ldapsearch_result* r) {
	while(r->entry != NULL) {
#ifdef TRACE_BY_LDAP_ENABLED
{
char *dn = ldap_get_dn(r->ld, r->entry);
TRACE_BY_LDAP(__func__, "ldap_get_dn: '%s'", dn);
ldap_memfree(dn);
}
#endif /*def TRACE_BY_LDAP_ENABLED*/
		if (r->attr == NULL)
			r->attr = ldap_first_attribute(r->ld, r->entry, &r->attr_ber);

		while(r->attr != NULL) {
TRACE_BY_LDAP(__func__, "attr: '%s'", r->attr);

			if (r->p == NULL) {
				r->vals = ldap_get_values_len(r->ld, r->entry, r->attr);
				/* silently ignore error if return value is NULL */
				if (r->vals == NULL) goto next_attr;

				r->p = r->vals;
TRACE_BY_LDAP(__func__, "r->p[0]=%p'", *r->p);
				/* just in case */
				if (*r->p == NULL) goto end_vals;

				/* advance to first value / index zero */
				return 1;
			}

			/* advance to next value */
			r->p++;
TRACE_BY_LDAP(__func__, "r->p[x]=%p'", *r->p);
			if (*r->p != NULL)
				return 1;

end_vals:
			ldap_value_free_len(r->vals);
			r->p = NULL;

next_attr:
			ldap_memfree(r->attr);
			r->attr = ldap_next_attribute(r->ld, r->entry, r->attr_ber);
		}

		ber_free(r->attr_ber, 0);

		r->entry = ldap_next_entry(r->ld, r->entry);
	}
TRACE_BY_LDAP(__func__, "end");
	return 0;
}


/* ================================================================== */

static inline char*
ldap_errormsg(char *buf, size_t len, int err) {
	snprintf(buf, len, "ldaperror=0x%x(%.256s)", err, ldap_err2string(err));
	return buf;
}


void
crypto_add_ldap_error(int err) {
	char	buf[512];
	ERR_add_error_data(1, ldap_errormsg(buf, sizeof(buf), err));
}


int
parse_ldap_version(const char *ver) {
	long n;

	if (ver == NULL) return -1;

{	char *endptr = NULL;
	n = strtol(ver, &endptr, 10);
	if (*endptr != '\0') return -1;
}
	if ((n < LDAP_VERSION_MIN) || (n > LDAP_VERSION_MAX)) return -1;

	return (int) n;
}
