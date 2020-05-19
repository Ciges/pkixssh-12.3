/*
 * Copyright (c) 2019 Roumen Petrov.  All rights reserved.
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

#ifdef USE_LDAP_STORE

#include <openssl/store.h>
#include <openssl/engine.h>
#include <openssl/err.h>

/* engine store */

static const char ldap_store_scheme[] = "ldap";

static void ENGINE_load_ldap(void);

/* NOTE: Cannot set LDAP protocol version using STORE-API!
 * Let use global static variable.
 */
static int ldap_version = -1;

int/*bool*/
set_ldap_version(const char *ver) {
{	static int load_ldap = 1;
	if (load_ldap) {
		load_ldap = 0;
		ENGINE_load_ldap();
	}
}

	if (ver != NULL) {
		int n = parse_ldap_version(ver);
		if (n < 0) return 0;
		ldap_version = n;
	}

	return 1;
}


struct ossl_store_loader_ctx_st {
	ldaphost *lh;
	int result;
	LDAPMessage *res;
	ldapsearch_result *it;

	int expected;
	X509_NAME *name;
};


static OSSL_STORE_LOADER_CTX*
OSSL_STORE_LOADER_CTX_new(void) {
	OSSL_STORE_LOADER_CTX *ctx;

	ctx = OPENSSL_malloc(sizeof(OSSL_STORE_LOADER_CTX));
	if (ctx == NULL) return NULL;

	ctx->lh = NULL;
	ctx->result = LDAP_SUCCESS;
	ctx->res = NULL;
	ctx->it = NULL;

	ctx->expected = -1;
	ctx->name = NULL;

	return ctx;
}


static void
OSSL_STORE_LOADER_CTX_free(OSSL_STORE_LOADER_CTX* ctx) {
TRACE_BY_LDAP(__func__, "ctx=%p", (void*)ctx);
	if (ctx == NULL) return;

	OPENSSL_free(ctx->it);
	ldap_msgfree(ctx->res);
	ldaphost_free(ctx->lh);

	X509_NAME_free(ctx->name);

	OPENSSL_free(ctx);
}


static OSSL_STORE_LOADER_CTX*
ldap_store_open(
    const OSSL_STORE_LOADER *loader, const char *uri,
    const UI_METHOD *ui_method, void *ui_data
) {
	OSSL_STORE_LOADER_CTX *ctx;
	ldaphost *lh;

TRACE_BY_LDAP(__func__, "uri='%s'", uri);
	UNUSED(loader);
	UNUSED(ui_method);
	UNUSED(ui_data);

	ctx = OSSL_STORE_LOADER_CTX_new();
	if (ctx == NULL) return NULL;

	ctx->lh = lh = ldaphost_new(uri);
	if (ldap_version > 0) {
		/*TODO: LDAP protocol version*/
		ctx->result = ldap_set_option(ctx->lh->ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
		if (ctx->result != LDAP_OPT_SUCCESS)
			return ctx;
	}
	ctx->result = ssh_ldap_bind_s(lh->ld);

	return ctx;
}


static int
ldap_store_search_iterator(OSSL_STORE_LOADER_CTX *ctx, char *filter, char **attrs) {
	ldaphost *lh = ctx->lh;

	ctx->result = ssh_ldap_search_s(lh->ld, lh->ldapurl->lud_dn,
		LDAP_SCOPE_SUBTREE, filter, attrs, 0, &ctx->res);

	if (ctx->result != LDAP_SUCCESS) {
TRACE_BY_LDAP(__func__, "ldap_search_s()  url=\"%s://%s:%d\"  ldaperror=0x%x(%.256s)"
, lh->ldapurl->lud_scheme, lh->ldapurl->lud_host, lh->ldapurl->lud_port
, ctx->result, ldap_err2string(ctx->result));
		return 0;
	}

	ctx->it = ldapsearch_iterator(lh->ld, ctx->res);
	return ctx->it != NULL;
}


static int
ldap_store_expect(OSSL_STORE_LOADER_CTX *ctx, int expected) {

	switch (expected) {
	case OSSL_STORE_INFO_CERT:
	case OSSL_STORE_INFO_CRL: break;
	default: return 0;
	}

	ctx->expected = expected;
	return 1;
}


static int
ldap_store_find(OSSL_STORE_LOADER_CTX *ctx, OSSL_STORE_SEARCH *criterion) {
	int type;

	type = OSSL_STORE_SEARCH_get_type(criterion);
TRACE_BY_LDAP(__func__, "type=%d", type);
	if (type != OSSL_STORE_SEARCH_BY_NAME) return 0;

	ctx->name = X509_NAME_dup(OSSL_STORE_SEARCH_get0_name(criterion));

	return 0;
}


static OSSL_STORE_INFO*
ldap_store_load(
    OSSL_STORE_LOADER_CTX *ctx,
    const UI_METHOD *ui_method, void *ui_data
) {
	static char *ATTR_CACERT = "cACertificate";
	static char *ATTR_CACRL = "certificateRevocationList";
	ldapsearch_result *it;
	BIO *mbio = NULL;
	OSSL_STORE_INFO *ret = NULL;

TRACE_BY_LDAP(__func__, "ctx=%p, ui_method=%p, ui_data=%p"
, (void*)ctx, (void*)ui_method, ui_data);

	if (ctx == NULL) return NULL;
	it = ctx->it;
	if (it == NULL) {
		char *attrs[2] = { NULL, NULL };
		char *filter = NULL;

		if (ctx->name == NULL) return NULL;

		switch(ctx->expected) {
		case OSSL_STORE_INFO_CERT: attrs[0] = ATTR_CACERT; break;
		case OSSL_STORE_INFO_CRL: attrs[0] = ATTR_CACRL; break;
		}

		filter = X509_NAME_ldapfilter(ctx->name, attrs[0]);
TRACE_BY_LDAP(__func__, "filter: '%s'", filter);
		if (filter == NULL) return NULL;

		ldap_store_search_iterator(ctx, filter, attrs);
		OPENSSL_free(filter);
		it = ctx->it;
	}
	if (it == NULL) return NULL;

	while (ldapsearch_advance(it)) {
		struct berval *q = *it->p;

		mbio = BIO_new_mem_buf(q->bv_val, q->bv_len);
		if (mbio == NULL) return NULL;

		if (strncmp(it->attr, ATTR_CACERT, strlen(ATTR_CACERT)) == 0) {
			X509 *x509;

			if ((ctx->expected >= 0) && (ctx->expected != OSSL_STORE_INFO_CERT))
				continue;

			x509 = d2i_X509_bio(mbio, NULL);
			if (x509 == NULL) goto exit;

			ret = OSSL_STORE_INFO_new_CERT(x509);
			break;
		}

		if (strncmp(it->attr, ATTR_CACRL, strlen(ATTR_CACRL)) == 0) {
			X509_CRL *crl;

			if ((ctx->expected >= 0) && (ctx->expected != OSSL_STORE_INFO_CRL))
				continue;

			crl = d2i_X509_CRL_bio(mbio, NULL);
			if (crl == NULL) goto exit;

			ret = OSSL_STORE_INFO_new_CRL(crl);
			break;
		}
	}

exit:
	BIO_free_all(mbio);
TRACE_BY_LDAP(__func__, "return %p", (void*)ret);
	return ret;
}


static int
ldap_store_eof(OSSL_STORE_LOADER_CTX *ctx) {
TRACE_BY_LDAP(__func__, "ctx=%p, res=%p, it=%p"
, (void*)ctx, (void*)(ctx ? ctx->res: NULL), (void*)(ctx ? ctx->it: NULL));

	if (ctx->res == NULL) return 0;
{	ldapsearch_result *it = ctx->it;
	if (it != NULL)
		return it->entry == NULL;
}

TRACE_BY_LDAP(__func__, "return: %ld != %ld"
, (long)ctx->result, (long)LDAP_SUCCESS);
	return ctx->result != LDAP_SUCCESS;
}


static int
ldap_store_error(OSSL_STORE_LOADER_CTX *ctx) {
TRACE_BY_LDAP(__func__, "ctx=%p", (void*)ctx);

TRACE_BY_LDAP(__func__, "return: %ld != %ld"
, (long)ctx->result, (long)LDAP_SUCCESS);
	return ctx->result != LDAP_SUCCESS;
}


static int
ldap_store_close(OSSL_STORE_LOADER_CTX *ctx) {
TRACE_BY_LDAP(__func__, "ctx=%p", (void*)ctx);

	OSSL_STORE_LOADER_CTX_free(ctx);
	return 1;
}


static int/*bool*/
bind_ldap_store(ENGINE *e) {
	OSSL_STORE_LOADER *loader = OSSL_STORE_LOADER_new(e, ldap_store_scheme);

TRACE_BY_LDAP(__func__, "e=%p", (void*)e);
	if (loader == NULL) return 0;

	if (!OSSL_STORE_LOADER_set_open(loader, ldap_store_open)
	||  !OSSL_STORE_LOADER_set_expect(loader, ldap_store_expect)
	||  !OSSL_STORE_LOADER_set_find(loader, ldap_store_find)
	||  !OSSL_STORE_LOADER_set_load(loader, ldap_store_load)
	||  !OSSL_STORE_LOADER_set_eof(loader, ldap_store_eof)
	||  !OSSL_STORE_LOADER_set_error(loader, ldap_store_error)
	||  !OSSL_STORE_LOADER_set_close(loader, ldap_store_close)
	||  !OSSL_STORE_register_loader(loader)
	)
		goto err;

	return 1;
err:
	OSSL_STORE_LOADER_free(loader);
	return 0;
}


static void
destroy_ldap_store(ENGINE *e) {
	OSSL_STORE_LOADER *loader;

TRACE_BY_LDAP(__func__, "e=%p", (void*)e);
	loader = OSSL_STORE_unregister_loader(ldap_store_scheme);

	OSSL_STORE_LOADER_free(loader);
}


/* engine */
static const char *e_ldap_id = "e_ldap";
static const char *e_ldap_name = "LDAP engine";


static int/*bool*/
e_ldap_init(ENGINE *e) {
TRACE_BY_LDAP(__func__, "e=%p", (void*)e);

	return 1;
}


static int
e_ldap_finish(ENGINE *e) {
TRACE_BY_LDAP(__func__, "e=%p", (void*)e);

	return 1;
}


static int
e_ldap_destroy(ENGINE *e) {
TRACE_BY_LDAP(__func__, "e=%p", (void*)e);

	destroy_ldap_store(e);

#if 0
	ERR_unload_LDAP_strings();
#endif

	return 1;
}


static int/*bool*/
bind_ldap(ENGINE *e) {
TRACE_BY_LDAP(__func__, "e=%p", (void*)e);

	if (!ENGINE_set_id(e, e_ldap_id)
	||  !ENGINE_set_name(e, e_ldap_name)
	||  !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL)
	||  !ENGINE_set_init_function(e, e_ldap_init)
	||  !ENGINE_set_finish_function(e, e_ldap_finish)
	||  !ENGINE_set_destroy_function(e, e_ldap_destroy)
	)
		return 0;

	if (!bind_ldap_store(e))
		return 0;

#if 0
	/* ensure the engine error handling is set up */
	ERR_load_LDAP_strings();
#endif

    return 1;
}


static ENGINE*
engine_ldap(void) {
	ENGINE *e;

TRACE_BY_LDAP(__func__, "");

	e = ENGINE_new();
	if (e == NULL) return NULL;

	if (!bind_ldap(e)) {
		ENGINE_free(e);
		return NULL;
	}
	return e;
}


static void
ENGINE_load_ldap(void) {
	ENGINE *e;

TRACE_BY_LDAP(__func__, "");

	e = engine_ldap();
	if (e == NULL) return;

	ERR_set_mark();
	ENGINE_add(e);
	ENGINE_free(e);
	ERR_pop_to_mark();
}

#else /*def USE_LDAP_STORE*/

typedef int e_ldap_empty_translation_unit;

#endif
