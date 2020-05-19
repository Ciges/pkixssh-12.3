/* $OpenBSD: ssh-pkcs11.c,v 1.46 2019/10/01 10:22:53 djm Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
 * Copyright (c) 2011 Kenneth Robinette.  All rights reserved.
 * Copyright (c) 2013 Andrew Cooke.  All rights reserved.
 * Copyright (c) 2016-2019 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef ENABLE_PKCS11

#ifndef HAVE_RSA_PKCS1_OPENSSL
# undef RSA_PKCS1_OpenSSL
# define RSA_PKCS1_OpenSSL RSA_PKCS1_SSLeay
#endif

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <stdarg.h>
#include <stdio.h>

#include <string.h>
#include <dlfcn.h>

#include "openbsd-compat/sys-queue.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include "evp-compat.h"

#define CRYPTOKI_COMPAT
#include "pkcs11.h"

#include "log.h"
#include "misc.h"
#include "ssh-x509.h"
#include "ssherr.h"
#include "ssh-pkcs11.h"
#include "xmalloc.h"

struct pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	int			logged_in;
};

struct pkcs11_provider {
	char			*name;
	void			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	struct pkcs11_slotinfo	*slotinfo;
	int			valid;
	int			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

static void
pkcs11_provider_free(struct pkcs11_provider *p) {
	if (p == NULL) return;

	free(p->name);
	free(p->slotlist);
	free(p->slotinfo);
	free(p);
}

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;


static inline void
crypto_pkcs11_error(CK_RV err) {
	char buf[64];
	snprintf(buf, sizeof(buf), "pkcs#11 result 0x%lx", (unsigned long)err);
	ERR_add_error_data(1, buf);
}


/*
 * Constants used when creating the context extra data
 */
static int ssh_pkcs11_rsa_ctx_index = -1;
static int ssh_pkcs11_dsa_ctx_index = -1;
#ifdef OPENSSL_HAS_ECC
static int ssh_pkcs11_ec_ctx_index = -1;
#endif /*def OPENSSL_HAS_ECC*/

struct pkcs11_key {
	struct pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	char			*keyid;
	int			keyid_len;
};

static void pkcs11_provider_unref(struct pkcs11_provider *p);

static struct pkcs11_key *
pkcs11_key_create(
    struct pkcs11_provider *provider,
    CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib
) {
	struct pkcs11_key *k11;

	k11 = xcalloc(1, sizeof(*k11)); /*fatal on error*/
	k11->provider = provider;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ulValueLen;
	if (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len); /*fatal on error*/
		memcpy(k11->keyid, keyid_attrib->pValue, k11->keyid_len);
	}

	return k11;
}

static void
pkcs11_key_free(struct pkcs11_key *k11) {
	if (k11 == NULL) return;

	if (k11->provider)
		pkcs11_provider_unref(k11->provider);
	free(k11->keyid);
	free(k11);
}

static void
CRYPTO_EX_pkcs11_key_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad, long argl, void *argp
) {
	(void)parent;
	pkcs11_key_free(ptr);
	(void)ad;
	(void)argl;
	(void)argp;
}

static void
CRYPTO_EX_pkcs11_rsa_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp
) {
	if (idx == ssh_pkcs11_rsa_ctx_index)
		CRYPTO_EX_pkcs11_key_free(parent, ptr, ad, argl, argp);
}

static void
CRYPTO_EX_pkcs11_dsa_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp
) {
	if (idx == ssh_pkcs11_dsa_ctx_index)
		CRYPTO_EX_pkcs11_key_free(parent, ptr, ad, argl, argp);
}

#ifdef OPENSSL_HAS_ECC
static void
CRYPTO_EX_pkcs11_ec_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp
) {
	if (idx == ssh_pkcs11_ec_ctx_index)
		CRYPTO_EX_pkcs11_key_free(parent, ptr, ad, argl, argp);
}
#endif /*def OPENSSL_HAS_ECC*/


int pkcs11_interactive = 0;

int
pkcs11_init(int interactive)
{
	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	return (0);
}

static int/*bool*/
pkcs11_login(
    struct pkcs11_slotinfo *si,
    CK_FUNCTION_LIST *f
) {
	char *pin = NULL;

	if (!(si->token.flags & CKF_LOGIN_REQUIRED))	return 1;

	if (si->logged_in) return 1;

	if (!pkcs11_interactive) {
		error("need pin entry%s", (si->token.flags &
		    CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		return 0;
	}

	if (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	else {
		char prompt[1024];

		snprintf(prompt, sizeof(prompt),
		    "Enter PIN for '%s': ", si->token.label);
		pin = read_passphrase(prompt, RP_ALLOW_EOF);
		if (pin == NULL) return 0;
	}

{	CK_RV rv;
	CK_ULONG lpin = (pin != NULL) ? strlen(pin) : 0;

	rv = f->C_Login(si->session, CKU_USER, (CK_UTF8CHAR_PTR)pin, lpin);
	if (pin != NULL) {
		explicit_bzero(pin, strlen(pin));
		free(pin);
	}
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
		error("C_Login failed: %lu", rv);
		PKCS11err(PKCS11_LOGIN, PKCS11_C_LOGIN_FAIL);
		crypto_pkcs11_error(rv);
		return 0;
	}
}
	si->logged_in = 1;

	return 1;
}

static int/*bool*/
pkcs11_reauthenticate(
    struct pkcs11_slotinfo *si,
    CK_FUNCTION_LIST *f,
    CK_OBJECT_HANDLE obj
) {
	CK_RV rv;
	char obj_label[1024];

	if (!si->logged_in) return 0;

{	/* check if re-authentication is required */
	CK_BBOOL always_authenticate = CK_FALSE;
	CK_ATTRIBUTE attribs[1] = {
	    { CKA_ALWAYS_AUTHENTICATE, NULL, sizeof(always_authenticate) }
	};

	/* compiler work-around */
	attribs[0].pValue = &always_authenticate;

	rv = f->C_GetAttributeValue(si->session, obj, attribs, 1);
	if (rv != CKR_OK) return 0;

	/* if re-authentication is not required */
	if (always_authenticate == CK_FALSE) return 1;
}

{	/* get key label */
	CK_ATTRIBUTE attribs[1] = {
	    { CKA_LABEL, NULL, (sizeof(obj_label)-1) }
	};

	/* compiler work-around */
	attribs[0].pValue = obj_label;

	memset(obj_label, '\0', sizeof(obj_label));
	f->C_GetAttributeValue(si->session, obj, attribs, 1);
}

{	/* context login, i.e. re-authentication */
	char *pin = NULL;
	CK_ULONG lpin;

	if (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring context PIN entry to reader keypad.");
	else {
		char prompt[1024];

		snprintf(prompt, sizeof(prompt),
		    "Enter context PIN for '%s': ", obj_label);
		pin = read_passphrase(prompt, RP_ALLOW_EOF);
	}
	lpin = (pin != NULL) ? strlen(pin) : 0;

	rv = f->C_Login(si->session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin, lpin);
	if (pin != NULL) {
		explicit_bzero(pin, strlen(pin));
		free(pin);
	}
	if (rv != CKR_OK) {
		PKCS11err(PKCS11_REAUTHENTICATE, PKCS11_C_LOGIN_FAIL);
		crypto_pkcs11_error(rv);
		return 0;
	}
}

	return 1;
}

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
static void
pkcs11_provider_finalize(struct pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug("pkcs11_provider_finalize: %p refcount %d valid %d",
	    (void*)p, p->refcount, p->valid);
	if (!p->valid)
		return;
	for (i = 0; i < p->nslots; i++) {
		if (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	if ((rv = p->function_list->C_Finalize(NULL)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = NULL;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
static void
pkcs11_provider_unref(struct pkcs11_provider *p)
{
	debug("pkcs11_provider_unref: %p refcount %d", (void*)p, p->refcount);
	if (--p->refcount <= 0) {
		if (p->valid)
			error("pkcs11_provider_unref: %p still valid", (void*)p);
		pkcs11_provider_free(p);
	}
}

/* unregister all providers, keys might still point to the providers */
void
pkcs11_terminate(void)
{
	struct pkcs11_provider *p;

	while ((p = TAILQ_FIRST(&pkcs11_providers)) != NULL) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/* lookup provider by name */
static struct pkcs11_provider *
pkcs11_provider_lookup(char *provider_id)
{
	struct pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check %p %s", (void*)p, p->name);
		if (!strcmp(provider_id, p->name))
			return (p);
	}
	return (NULL);
}

/* unregister provider by name */
int
pkcs11_del_provider(char *provider_id)
{
	struct pkcs11_provider *p;

	if ((p = pkcs11_provider_lookup(provider_id)) != NULL) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		return (0);
	}
	return (-1);
}


/* find a single 'obj' for given attributes */
static int
pkcs11_find(struct pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f = p->function_list;
	CK_SESSION_HANDLE	session = p->slotinfo[slotidx].session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	int			ret = -1;

	if ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		return (-1);
	}
	if ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} else
		ret = 0;
	if ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	return (ret);
}

static int/*bool*/
pkcs11_get_key(
    struct pkcs11_key *k11,
    CK_OBJECT_HANDLE *pobj
) {
	CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
	CK_BBOOL        true_val = CK_TRUE;
	CK_ATTRIBUTE    key_filter[] = {
		{CKA_CLASS, NULL, sizeof(private_key_class) },
		{CKA_ID, NULL, 0},
		{CKA_SIGN, NULL, sizeof(true_val) }
	};

	/* some compilers complain about non-constant initializer so we
	   use NULL in CK_ATTRIBUTE above and set the values here */
	key_filter[0].pValue = &private_key_class;
	key_filter[2].pValue = &true_val;

	key_filter[1].pValue = k11->keyid;
	key_filter[1].ulValueLen = k11->keyid_len;

	/* try to find object w/CKA_SIGN first, retry w/o */
	if (pkcs11_find(k11->provider, k11->slotidx, key_filter, 3, pobj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, key_filter, 2, pobj) < 0) {
		PKCS11err(PKCS11_GET_KEY, PKCS11_FINDKEY_FAIL);
		return 0;
	}
	return 1;
}

/* openssl callback doing the actual signing operation */
static int
pkcs11_rsa_private_encrypt(int flen, const u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		tlen = 0;
	CK_RV			rv;
	CK_MECHANISM		mech = {
		CKM_RSA_PKCS, NULL_PTR, 0
	};
	int			rval = -1;

	UNUSED(padding);

	k11 = RSA_get_ex_data(rsa, ssh_pkcs11_rsa_ctx_index);
	if (k11 == NULL) {
		error("RSA_get_ex_data failed for rsa %p", (void*)rsa);
		return (-1);
	}
	if (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider for rsa %p", (void*)rsa);
		return (-1);
	}
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	if (!pkcs11_login(si, f)) return -1;
	if (!pkcs11_get_key(k11, &obj)) return -1;

	if ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		PKCS11err(PKCS11_RSA_PRIVATE_ENCRYPT, PKCS11_C_SIGNINIT_FAIL);
		crypto_pkcs11_error(rv);
	} else {
		(void)pkcs11_reauthenticate(si, f, obj);
		/* XXX handle CKR_BUFFER_TOO_SMALL */
		tlen = RSA_size(rsa);
		rv = f->C_Sign(si->session, (CK_BYTE *)from, flen, to, &tlen);
		if (rv == CKR_OK)
			rval = tlen;
		else {
			PKCS11err(PKCS11_RSA_PRIVATE_ENCRYPT, PKCS11_C_SIGN_FAIL);
			crypto_pkcs11_error(rv);
		}
	}
	return (rval);
}

static int
pkcs11_rsa_private_decrypt(int flen, const u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	(void)flen;
	(void)from;
	(void)to;
	(void)rsa;
	(void)padding;
	return (-1);
}

static RSA_METHOD*
ssh_pkcs11_rsa_method(void)  {
	static RSA_METHOD *meth = NULL;

	if (meth == NULL) {
		const RSA_METHOD *def = RSA_PKCS1_OpenSSL();

		meth = RSA_meth_new("SSH PKCS#11 RSA method",
		#ifdef RSA_FLAG_FIPS_METHOD
			RSA_FLAG_FIPS_METHOD |
		#endif
			0);
		if (meth == NULL) return NULL;

		if (!RSA_meth_set_priv_enc(meth, pkcs11_rsa_private_encrypt)
		||  !RSA_meth_set_priv_dec(meth, pkcs11_rsa_private_decrypt)
		)
			goto err;

		if (!RSA_meth_set_pub_enc(meth, RSA_meth_get_pub_enc(def))
		||  !RSA_meth_set_pub_dec(meth, RSA_meth_get_pub_dec(def))
		||  !RSA_meth_set_mod_exp(meth, RSA_meth_get_mod_exp(def))
		||  !RSA_meth_set_bn_mod_exp(meth, RSA_meth_get_bn_mod_exp(def))
		)
			goto err;
	}

	/* ensure RSA context index */
	if (ssh_pkcs11_rsa_ctx_index < 0)
		ssh_pkcs11_rsa_ctx_index = RSA_get_ex_new_index(0,
		    NULL, NULL, NULL, CRYPTO_EX_pkcs11_rsa_free);
	if (ssh_pkcs11_rsa_ctx_index < 0)
		return NULL;

	return meth;

err:
	RSA_meth_free(meth);
	meth = NULL;
	return NULL;
}

/* redirect private key operations for rsa key to pkcs11 token */
static int
pkcs11_rsa_wrap(struct pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, RSA *rsa)
{
	RSA_METHOD *rsa_method = ssh_pkcs11_rsa_method();
	struct pkcs11_key *k11;

	if (rsa_method == NULL) return -1;

	k11 = pkcs11_key_create(provider, slotidx, keyid_attrib);

	RSA_set_method(rsa, rsa_method);
	RSA_set_ex_data(rsa, ssh_pkcs11_rsa_ctx_index, k11);
	return 0;
}

static DSA_SIG*
parse_DSA_SIG(char *buf, CK_ULONG blen) {
	DSA_SIG *sig;
	BIGNUM *ps, *pr;
	int  k = blen >> 1;

	pr = BN_bin2bn(buf    , k, NULL);
	ps = BN_bin2bn(buf + k, k, NULL);
	if ((pr == NULL) || (ps == NULL)) goto parse_err;

	sig = DSA_SIG_new();
	if (sig == NULL) goto parse_err;

	if (DSA_SIG_set0(sig, pr, ps))
		return (sig);

/*error*/
	DSA_SIG_free(sig);
parse_err:
	BN_free(pr);
	BN_free(ps);
	return (NULL);
}

/* redirect private key operations for dsa key to pkcs11 token */
static DSA_SIG*
pkcs11_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		tlen = 0;
	CK_RV			rv;
	CK_MECHANISM		mech = {
		CKM_DSA, NULL_PTR, 0
	};
	DSA_SIG			*sig = NULL;

	debug3("pkcs11_dsa_do_sign");

	k11 = DSA_get_ex_data(dsa, ssh_pkcs11_dsa_ctx_index);
	if (k11 == NULL) {
		error("DSA_get_ex_data failed for dsa %p", (void*)dsa);
		return NULL;
	}
	if (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider for dsa %p", (void*)dsa);
		return NULL;
	}
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	if (!pkcs11_login(si, f)) return NULL;
	if (!pkcs11_get_key(k11, &obj)) return NULL;

	if ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		PKCS11err(PKCS11_DSA_DO_SIGN, PKCS11_C_SIGNINIT_FAIL);
		crypto_pkcs11_error(rv);
	} else {
		char rs[(2*SHA_DIGEST_LENGTH)];
		(void)pkcs11_reauthenticate(si, f, obj);
		tlen = (2*SHA_DIGEST_LENGTH);
		rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dlen, rs, &tlen);
		if (rv == CKR_OK)
			sig = parse_DSA_SIG(rs, tlen);
		else {
			PKCS11err(PKCS11_DSA_DO_SIGN, PKCS11_C_SIGN_FAIL);
			crypto_pkcs11_error(rv);
		}
	}
	return (sig);
}


static DSA_METHOD*
ssh_pkcs11_dsa_method(void) {
	static DSA_METHOD *meth = NULL;

	if (meth == NULL) {
		const DSA_METHOD *def = DSA_OpenSSL();

		meth = DSA_meth_new("SSH PKCS#11 DSA method",
		#ifdef DSA_FLAG_FIPS_METHOD
			DSA_FLAG_FIPS_METHOD |
		#endif
			0);
		if (meth == NULL) return NULL;

		if (!DSA_meth_set_sign(meth, pkcs11_dsa_do_sign))
			goto err;

		if (!DSA_meth_set_verify(meth, DSA_meth_get_verify(def))
		||  !DSA_meth_set_mod_exp(meth, DSA_meth_get_mod_exp(def))
		||  !DSA_meth_set_bn_mod_exp(meth, DSA_meth_get_bn_mod_exp(def))
		)
			goto err;
	}

	/* ensure DSA context index */
	if (ssh_pkcs11_dsa_ctx_index < 0)
		ssh_pkcs11_dsa_ctx_index = DSA_get_ex_new_index(0,
		    NULL, NULL, NULL, CRYPTO_EX_pkcs11_dsa_free);
	if (ssh_pkcs11_dsa_ctx_index < 0)
		return NULL;

	return meth;

err:
	DSA_meth_free(meth);
	meth = NULL;
	return NULL;
}

static int
pkcs11_dsa_wrap(struct pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, DSA *dsa)
{
	DSA_METHOD *dsa_method = ssh_pkcs11_dsa_method();
	struct pkcs11_key *k11;

	if (dsa_method == NULL) return -1;

	k11 = pkcs11_key_create(provider, slotidx, keyid_attrib);

	DSA_set_method(dsa, dsa_method);
	DSA_set_ex_data(dsa, ssh_pkcs11_dsa_ctx_index, k11);
	return 0;
}


#ifdef OPENSSL_HAS_ECC
static ECDSA_SIG*
parse_ECDSA_SIG(char *buf, CK_ULONG blen) {
	ECDSA_SIG *sig;
	BIGNUM *ps, *pr;
	int  k = blen >> 1;

	pr = BN_bin2bn(buf    , k, NULL);
	ps = BN_bin2bn(buf + k, k, NULL);
	if ((pr == NULL) || (ps == NULL)) goto parse_err;

	sig = ECDSA_SIG_new();
	if (sig == NULL) goto parse_err;

	if (ECDSA_SIG_set0(sig, pr, ps))
		return (sig);

/*error*/
	ECDSA_SIG_free(sig);
parse_err:
	BN_free(pr);
	BN_free(ps);
	return (NULL);
}


/* redirect private key operations for ec key to pkcs11 token */
static ECDSA_SIG*
pkcs11_ecdsa_do_sign(
	const unsigned char *dgst, int dlen,
	const BIGNUM *inv, const BIGNUM *rp,
	EC_KEY *ec
) {
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		tlen = 0;
	CK_RV			rv;
	CK_MECHANISM		mech = {
		CKM_ECDSA, NULL_PTR, 0
	};
	ECDSA_SIG		*sig = NULL;

	debug3("pkcs11_ecdsa_do_sign");

	UNUSED(inv);
	UNUSED(rp);

	k11 = EC_KEY_get_ex_data(ec, ssh_pkcs11_ec_ctx_index);
	if (k11 == NULL) {
		error("EC_KEY_get_ex_data failed for ec %p", (void*)ec);
		return NULL;
	}
	if (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider for ec %p", (void*)ec);
		return NULL;
	}
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	if (!pkcs11_login(si, f)) return NULL;
	if (!pkcs11_get_key(k11, &obj)) return NULL;

	if ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		PKCS11err(PKCS11_ECDSA_DO_SIGN, PKCS11_C_SIGNINIT_FAIL);
		crypto_pkcs11_error(rv);
	} else {
		char rs[(1024>>2)/*> 2*[521/8]=2*66 */];
		(void)pkcs11_reauthenticate(si, f, obj);
		tlen = sizeof(rs);
		rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dlen, rs, &tlen);
		if (rv == CKR_OK)
			sig = parse_ECDSA_SIG(rs, tlen);
		else {
			PKCS11err(PKCS11_ECDSA_DO_SIGN, PKCS11_C_SIGN_FAIL);
			crypto_pkcs11_error(rv);
		}
	}
	return (sig);
}


#ifdef HAVE_EC_KEY_METHOD_NEW
static int
pkcs11_ecdsa_sign(int type,
	const unsigned char *dgst, int dlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *inv, const BIGNUM *rp,
	EC_KEY *ec
) {
	ECDSA_SIG *s;

	debug3("pkcs11_ecdsa_sign");
	(void)type;

	s = pkcs11_ecdsa_do_sign(dgst, dlen, inv, rp, ec);
	if (s == NULL) {
		*siglen = 0;
		return (0);
	}

	*siglen = i2d_ECDSA_SIG(s, &sig);

	ECDSA_SIG_free(s);
	return (1);
}
#endif /*def HAVE_EC_KEY_METHOD_NEW*/


static EC_KEY_METHOD*
ssh_pkcs11_ec_method(void) {
	static EC_KEY_METHOD *meth = NULL;

	if (meth == NULL) {
	#ifdef HAVE_EC_KEY_METHOD_NEW
		meth = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
		if (meth == NULL) return NULL;

		EC_KEY_METHOD_set_sign(meth,
		    pkcs11_ecdsa_sign,
		    NULL /* *sign_setup */,
		    pkcs11_ecdsa_do_sign
		);
	#else
		meth = ECDSA_METHOD_new(ECDSA_OpenSSL());
		if (meth == NULL) return NULL;

		ECDSA_METHOD_set_sign(meth,
		    pkcs11_ecdsa_do_sign
		);
	#endif
	}

	/* ensure EC context index */
	if (ssh_pkcs11_ec_ctx_index < 0)
		ssh_pkcs11_ec_ctx_index = EC_KEY_get_ex_new_index(0,
		    NULL, NULL, NULL, CRYPTO_EX_pkcs11_ec_free);
	if (ssh_pkcs11_ec_ctx_index < 0)
		return NULL;

	return meth;
}

static int
pkcs11_ec_wrap(struct pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, EC_KEY *ec)
{
	EC_KEY_METHOD *ec_method = ssh_pkcs11_ec_method();
	struct pkcs11_key *k11;

	if (ec_method == NULL) return -1;

	k11 = pkcs11_key_create(provider, slotidx, keyid_attrib);

	EC_KEY_set_method(ec, ec_method);
	EC_KEY_set_ex_data(ec, ssh_pkcs11_ec_ctx_index, k11);
	return 0;
}
#endif /*def OPENSSL_HAS_ECC*/


/* remove trailing spaces */
static void
rmspace(u_char *buf, size_t len)
{
	size_t i;

	if (!len)
		return;
	for (i = len - 1;  i > 0; i--)
		if (i == len - 1 || buf[i] == ' ')
			buf[i] = '\0';
		else
			break;
}

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
static int
pkcs11_open_session(struct pkcs11_provider *p, CK_ULONG slotidx, char *pin,
    CK_USER_TYPE user_type)
{
	CK_RV			rv;
	struct pkcs11_slotinfo	*si = &p->slotinfo[slotidx];
	CK_FUNCTION_LIST	*f = p->function_list;
	CK_SESSION_HANDLE	session;
	int			login_required, ret;

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;
	if (login_required && pin != NULL && strlen(pin) == 0) {
		error("pin required");
		return SSH_PKCS11_ERR_PIN_REQUIRED;
	}
	if ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, NULL, NULL, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		return SSH_PKCS11_ERR_GENERIC;
	}
	if (login_required && pin != NULL) {
		rv = f->C_Login(session, user_type,
		    (u_char *)pin, strlen(pin));
		if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    SSH_PKCS11_ERR_PIN_LOCKED :
			    SSH_PKCS11_ERR_LOGIN_FAIL;
			if ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			return ret;
		}
		si->logged_in = 1;
	}
	si->session = session;
	return 0;
}

static struct sshkey*
pkcs11_get_x509key(
    struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE obj
) {
	CK_FUNCTION_LIST *f = p->function_list;
	CK_SESSION_HANDLE session = p->slotinfo[slotidx].session;
	CK_RV rv;
	/* NOTE: for certificate retrieve ID, Subject(*) and Value
	 * (*) not used yet
	 */
	CK_ATTRIBUTE attribs[] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_SUBJECT, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	};
	struct sshkey *key = NULL;
	int i;

	rv = f->C_GetAttributeValue(session, obj, attribs, 3);
	if (rv != CKR_OK) {
		error("%s: C_GetAttributeValue failed: %lu", __func__, rv);
		return NULL;
	}
	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 */
	if (attribs[1].ulValueLen == 0 ||
	    attribs[2].ulValueLen == 0)
		return NULL;

	/* allocate buffers for attributes */
	for (i = 0; i < 3; i++) {
		if (attribs[i].ulValueLen == 0) continue;
		attribs[i].pValue = xmalloc(attribs[i].ulValueLen);
	}

	/* retrieve ID, subject and value for certificate */
	rv = f->C_GetAttributeValue(session, obj, attribs, 3);
	if (rv != CKR_OK) {
		error("%s: C_GetAttributeValue failed: %lu", __func__, rv);
		goto done;
	}

{	const u_char *blob = attribs[2].pValue;
	size_t blen = attribs[2].ulValueLen;
	int r;

	if (attribs[2].ulValueLen != (unsigned long) blen) {
		debug3("%s: invalid attribute length", __func__);
		goto done;
	}

	r = X509key_from_blob(blob, blen, &key);
	if (r != SSH_ERR_SUCCESS) {
		debug3("%s: X509key_from_blob fail", __func__);
		goto done;
	}
}

{	int rv_wrap = -1;

	switch(key->type) {
	case KEY_RSA:
		rv_wrap = pkcs11_rsa_wrap(p, slotidx, attribs, key->rsa);
		break;
	case KEY_DSA:
		rv_wrap = pkcs11_dsa_wrap(p, slotidx, attribs, key->dsa);
		break;
#ifdef OPENSSL_HAS_ECC
	case KEY_ECDSA:
		rv_wrap = pkcs11_ec_wrap(p, slotidx, attribs, key->ecdsa);
		break;
#endif /*def OPENSSL_HAS_ECC*/
	}

	if (rv_wrap == 0)
		key->flags |= SSHKEY_FLAG_EXT;
	else {
		sshkey_free(key);
		key = NULL;
	}
}

done:
	for (i = 0; i < 3; i++)
		free(attribs[i].pValue);

	return key;
}

static void
pkcs11_push_key(struct sshkey *key,
    struct sshkey ***keysp, int *nkeys)
{
	if (key == NULL) return;

{	struct sshkey **sp = *keysp;
	int i;
	for (i = 0; i < *nkeys; i++, sp++)
		if (sshkey_equal_public(key, *sp))
			return;
}

	/* expand key array and add key */
	*keysp = xreallocarray(*keysp, *nkeys + 1, sizeof(struct sshkey *));
	(*keysp)[*nkeys] = key;
	*nkeys = *nkeys + 1;
	debug("have %d keys", *nkeys);
}

/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
static int
pkcs11_fetch_certs(struct pkcs11_provider *p, CK_ULONG slotidx,
    struct sshkey ***keysp, int *nkeys)
{
	CK_FUNCTION_LIST *f = p->function_list;
	CK_SESSION_HANDLE session = p->slotinfo[slotidx].session;
	CK_RV rv;

{	/* setup a filter that looks for certificates */
	/* Find objects with cert class and X.509 cert type. */
	CK_OBJECT_CLASS		cert_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE	type = CKC_X_509;
	CK_ATTRIBUTE		filter[] = {
		{ CKA_CLASS, NULL, sizeof(cert_class) }
	,	{ CKA_CERTIFICATE_TYPE, NULL, sizeof(type) }
	};
	/* some compilers complain about non-constant initializer so we
	   use NULL in CK_ATTRIBUTE above and set the value here */
	filter[0].pValue = &cert_class;
	filter[1].pValue = &type;

	rv = f->C_FindObjectsInit(session, filter, 2);
	if (rv != CKR_OK) {
		error("%s: C_FindObjectsInit failed: %lu", __func__, rv);
		return -1;
	}
}

	while (1) {
		CK_OBJECT_HANDLE obj;
		CK_ULONG nfound;
		struct sshkey *key;

		rv = f->C_FindObjects(session, &obj, 1, &nfound);
		if (rv != CKR_OK) {
			error("%s: C_FindObjects failed: %lu", __func__, rv);
			break;
		}
		if (nfound == 0)
			break;

		key = pkcs11_get_x509key(p, slotidx, obj);
		pkcs11_push_key(key, keysp, nkeys);
	}

	rv = f->C_FindObjectsFinal(session);
	if (rv != CKR_OK)
		error("%s: C_FindObjectsFinal failed: %lu", __func__, rv);

	return 0;
}

static struct sshkey*
pkcs11_get_pubkey_rsa(
    struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE obj)
{
	CK_FUNCTION_LIST *f = p->function_list;
	CK_SESSION_HANDLE session = p->slotinfo[slotidx].session;
	CK_RV rv;
	/* NOTE: for RSA public key retrieve ID,
	 * modulus "m" and public exponent "e"
	 */
	CK_ATTRIBUTE attribs[3] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 }
	};
	struct sshkey *key = NULL;
	int i;

	rv = f->C_GetAttributeValue(session, obj, attribs, 3);
	if (rv != CKR_OK) {
		error("%s: C_GetAttributeValue failed: %lu", __func__, rv);
		return NULL;
	}
	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 */
	if (attribs[1].ulValueLen == 0 ||
	    attribs[2].ulValueLen == 0)
		return NULL;

	/* allocate buffers for attributes */
	for (i = 0; i < 3; i++) {
		if (attribs[i].ulValueLen == 0) continue;
		attribs[i].pValue = xmalloc(attribs[i].ulValueLen);
	}

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_GetAttributeValue(session, obj, attribs, 3);
	if (rv != CKR_OK) {
		error("%s: C_GetAttributeValue failed: %lu", __func__, rv);
		goto done;
	}

	key = sshkey_new(KEY_RSA);
	if (key == NULL) {
		error("%s: sshkey_new failed", __func__);
		goto done;
	}

{	BIGNUM *rsa_n = NULL, *rsa_e = NULL;

	rsa_n = BN_bin2bn(attribs[1].pValue, attribs[1].ulValueLen, NULL);
	rsa_e = BN_bin2bn(attribs[2].pValue, attribs[2].ulValueLen, NULL);
	if (rsa_n == NULL || rsa_e == NULL) {
		BN_free(rsa_n);
		BN_free(rsa_e);
		error("%s: BN_bin2bn failed", __func__);
		goto fail;
	}
	if (!RSA_set0_key(key->rsa, rsa_n, rsa_e, NULL)) {
		BN_free(rsa_n);
		BN_free(rsa_e);
		error("%s: RSA_set0_key failed", __func__);
		goto fail;
	}
}

	if (pkcs11_rsa_wrap(p, slotidx, attribs, key->rsa) == 0) {
		key->flags |= SSHKEY_FLAG_EXT;
		goto done;
	}

fail:
	sshkey_free(key);
	key = NULL;

done:
	for (i = 0; i < 3; i++)
		free(attribs[i].pValue);

	return key;
}

#ifdef OPENSSL_HAS_ECC
static struct sshkey*
pkcs11_get_pubkey_ec(
    struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE obj
) {
	CK_FUNCTION_LIST *f = p->function_list;
	CK_SESSION_HANDLE session = p->slotinfo[slotidx].session;
	CK_RV rv;
	/* NOTE: for EC public key retrieve ID,
	 * point "q" and curve parameters
	 */
	CK_ATTRIBUTE attribs[3] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_EC_POINT, NULL, 0 }
	};
	struct sshkey *key = NULL;
	int i;

	rv = f->C_GetAttributeValue(session, obj, attribs, 3);
	if (rv != CKR_OK) {
		error("%s: C_GetAttributeValue failed: %lu", __func__, rv);
		return NULL;
	}
	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 */
	if (attribs[1].ulValueLen == 0 ||
	    attribs[2].ulValueLen == 0)
		return NULL;

	/* allocate buffers for attributes */
	for (i = 0; i < 3; i++) {
		if (attribs[i].ulValueLen == 0) continue;
		attribs[i].pValue = xmalloc(attribs[i].ulValueLen);
	}

	/* retrieve ID, point and curve parameters of EC key */
	rv = f->C_GetAttributeValue(session, obj, attribs, 3);
	if (rv != CKR_OK) {
		error("%s: C_GetAttributeValue failed: %lu", __func__, rv);
		goto done;
	}

	key = sshkey_new(KEY_ECDSA);
	if (key == NULL) {
		error("%s: sshkey_new failed", __func__);
		goto done;
	}

{	const unsigned char *q;
	/* DER-encoding of an ANSI X9.62 Parameters value */

	q = attribs[1].pValue;
	if (d2i_ECParameters(&key->ecdsa, &q, attribs[1].ulValueLen) == NULL) {
		error("%s: d2i_ECParameters failed", __func__);
		goto fail;
	}
}
{	const unsigned char *q;
	/* "DER-encoding of ANSI X9.62 ECPoint value Q" */
	ASN1_OCTET_STRING *point;
	EC_KEY *ec;

	rv = CKR_GENERAL_ERROR;

	q = attribs[2].pValue;
	point = d2i_ASN1_OCTET_STRING(NULL, &q, attribs[2].ulValueLen);
	if (point == NULL)  {
		error("%s: d2i_ASN1_OCTET_STRING failed", __func__);
		goto fail;
	}

	q = point->data;
	ec = o2i_ECPublicKey(&key->ecdsa, &q, point->length);
	ASN1_STRING_free(point);
	if (ec != NULL) goto wrap;

	/* try raw data (broken PKCS#11 module) */
	q = attribs[2].pValue;
	ec = o2i_ECPublicKey(&key->ecdsa, &q, attribs[2].ulValueLen);
	if (ec == NULL) {
		error("%s: o2i_ECPublicKey failed", __func__);
		goto fail;
	}
}

wrap:
	key->ecdsa_nid  = sshkey_ecdsa_key_to_nid(key->ecdsa);
	if (key->ecdsa_nid  < 0) {
		error("couldn't get curve nid");
		goto fail;
	}
	if (pkcs11_ec_wrap(p, slotidx, attribs, key->ecdsa) == 0) {
		key->flags |= SSHKEY_FLAG_EXT;
		goto done;
	}

fail:
	sshkey_free(key);
	key = NULL;

done:
	for (i = 0; i < 3; i++)
		free(attribs[i].pValue);

	return key;
}

#endif /* OPENSSL_HAS_ECC */

static struct sshkey*
pkcs11_get_pubkey(
    struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE obj)
{
	CK_FUNCTION_LIST *f = p->function_list;
	CK_SESSION_HANDLE session = p->slotinfo[slotidx].session;
	CK_RV rv;
	CK_KEY_TYPE type;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_KEY_TYPE, NULL, sizeof(type) }
	};

	/* some compilers complain about non-constant initializer so we
	   use NULL in CK_ATTRIBUTE above and set the value here */
	attribs[0].pValue = &type;

	rv = f->C_GetAttributeValue(session, obj, attribs, 1);
	if (rv != CKR_OK) {
		error("%s: C_GetAttributeValue failed: %lu", __func__, rv);
		return NULL;
	}

	switch (type) {
	case CKK_RSA:
		return pkcs11_get_pubkey_rsa(p, slotidx, obj);
#ifdef OPENSSL_HAS_ECC
	case CKK_ECDSA:
		return pkcs11_get_pubkey_ec(p, slotidx, obj);
#endif /* OPENSSL_HAS_ECC */
	default:
		error("%s: unsupported key type: %lu", __func__, type);
	}

	return NULL;
}

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
static int
pkcs11_fetch_keys(struct pkcs11_provider *p, CK_ULONG slotidx,
    struct sshkey ***keysp, int *nkeys)
{
	CK_FUNCTION_LIST *f = p->function_list;
	CK_SESSION_HANDLE session = p->slotinfo[slotidx].session;
	CK_RV rv;

{	/* setup a filter that looks for public keys */
	/* Find objects with public key class. */
	CK_OBJECT_CLASS		key_class = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE		filter[] = {
		{ CKA_CLASS, NULL, sizeof(key_class) }
	};
	/* some compilers complain about non-constant initializer so we
	   use NULL in CK_ATTRIBUTE above and set the value here */
	filter[0].pValue = &key_class;

	rv = f->C_FindObjectsInit(session, filter, 1);
	if (rv != CKR_OK) {
		error("%s: C_FindObjectsInit failed: %lu", __func__, rv);
		return -1;
	}
}

	while (1) {
		CK_OBJECT_HANDLE obj;
		CK_ULONG nfound;
		struct sshkey *key;

		rv = f->C_FindObjects(session, &obj, 1, &nfound);
		if (rv != CKR_OK) {
			error("%s: C_FindObjects failed: %lu", __func__, rv);
			break;
		}
		if (nfound == 0)
			break;

		key = pkcs11_get_pubkey(p, slotidx, obj);
		pkcs11_push_key(key, keysp, nkeys);
	}

	rv = f->C_FindObjectsFinal(session);
	if (rv != CKR_OK)
		error("%s: C_FindObjectsFinal failed: %lu", __func__, rv);

	return 0;
}

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
static int
pkcs11_register_provider(char *provider_id, char *pin, struct sshkey ***keyp,
    struct pkcs11_provider **providerp, CK_ULONG user)
{
	int nkeys, need_finalize = 0;
	int ret = SSH_PKCS11_ERR_GENERIC;
	struct pkcs11_provider *p = NULL;
	void *handle = NULL;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = NULL;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	if (providerp == NULL)
		goto fail;
	*providerp = NULL;

	if (pkcs11_provider_lookup(provider_id) != NULL) {
		debug("%s: provider already registered: %s",
		    __func__, provider_id);
		goto fail;
	}
	/* open shared pkcs11-library */
	if ((handle = dlopen(provider_id,
		#ifdef RTLD_LOCAL
			RTLD_LOCAL |
		#endif
		#ifdef RTLD_LAZY
			RTLD_LAZY
		#else
			RTLD_NOW
		#endif
		)) == NULL) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		goto fail;
	}
	if ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == NULL) {
		error("dlsym(C_GetFunctionList) failed: %s", dlerror());
		goto fail;
	}
	p = xcalloc(1, sizeof(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* setup the pkcs11 callbacks */
	if ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		goto fail;
	}
	p->function_list = f;
	if ((rv = f->C_Initialize(NULL)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		goto fail;
	}
	need_finalize = 1;
	if ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		goto fail;
	}
	rmspace(p->info.manufacturerID, sizeof(p->info.manufacturerID));
	rmspace(p->info.libraryDescription, sizeof(p->info.libraryDescription));
	debug("provider %s: manufacturerID <%s> cryptokiVersion %d.%d"
	    " libraryDescription <%s> libraryVersion %d.%d",
	    provider_id,
	    p->info.manufacturerID,
	    p->info.cryptokiVersion.major,
	    p->info.cryptokiVersion.minor,
	    p->info.libraryDescription,
	    p->info.libraryVersion.major,
	    p->info.libraryVersion.minor);
	if ((rv = f->C_GetSlotList(CK_TRUE, NULL, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		ret = SSH_PKCS11_ERR_NO_SLOTS;
		goto fail;
	}
	if (p->nslots == 0) {
		debug("%s: provider %s returned no slots", __func__,
		    provider_id);
		ret = SSH_PKCS11_ERR_NO_SLOTS;
		goto fail;
	}
	p->slotlist = xcalloc(p->nslots, sizeof(CK_SLOT_ID));
	if ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		ret = SSH_PKCS11_ERR_NO_SLOTS;
		goto fail;
	}
	p->slotinfo = xcalloc(p->nslots, sizeof(struct pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	for (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		if ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (unsigned long)i, rv);
			continue;
		}
		if ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2("%s: ignoring uninitialised token in "
			    "provider %s slot %lu", __func__,
			    provider_id, (unsigned long)i);
			continue;
		}
		rmspace(token->label, sizeof(token->label));
		rmspace(token->manufacturerID, sizeof(token->manufacturerID));
		rmspace(token->model, sizeof(token->model));
		rmspace(token->serialNumber, sizeof(token->serialNumber));
		debug("provider %s slot %lu: label <%s> manufacturerID <%s> "
		    "model <%s> serial <%s> flags 0x%lx",
		    provider_id, (unsigned long)i,
		    token->label, token->manufacturerID, token->model,
		    token->serialNumber, token->flags);
		/*
		 * open session, login with pin if required and
		 * retrieve public keys
		 */
	{	int r = pkcs11_open_session(p, i, pin, user);
		if (r != 0) {
			error("pkcs11_open_session for provider %s slot %lu "
			    "failed: %s", provider_id, (unsigned long)i,
			    ssh_err(r));
			continue;
		}
	}
		pkcs11_fetch_certs(p, i, keyp, &nkeys);
		pkcs11_fetch_keys(p, i, keyp, &nkeys);

		/*
		 * Some tokens could mark public keys as private object.
		 * Usually certificates are marked as public object.
		 * So if no key are loaded above and if session is
		 * interactive try to login and fetch "private" objects.
		 */
		if (nkeys != 0 || !pkcs11_interactive || p->slotinfo[i].logged_in)
			continue;

		if (!pkcs11_login(&p->slotinfo[i], f))
			continue;

		/*try to fetch certificate just in case*/
		pkcs11_fetch_certs(p, i, keyp, &nkeys);
		pkcs11_fetch_keys(p, i, keyp, &nkeys);
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	return nkeys;
fail:
	if (need_finalize && (rv = f->C_Finalize(NULL)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	pkcs11_provider_free(p);
	if (handle)
		dlclose(handle);
	return ret;
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
int
pkcs11_add_provider(char *provider_id, char *pin, struct sshkey ***keyp)
{
	struct pkcs11_provider *p = NULL;
	int nkeys;

	if (keyp == NULL)
		return -1;
	*keyp = NULL;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	if (nkeys <= 0 && p != NULL) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	if (nkeys == 0)
		debug("%s: provider %s returned no keys", __func__,
		    provider_id);

	return nkeys;
}

#else /* ENABLE_PKCS11 */

#include "ssh-pkcs11.h"

int
pkcs11_init(int interactive)
{
	UNUSED(interactive);
	return -1;
}

void
pkcs11_terminate(void)
{
	return;
}

#endif /* ENABLE_PKCS11 */
