/* $OpenBSD: ssh-rsa.c,v 1.67 2018/07/03 11:39:54 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011-2018 Roumen Petrov.  All rights reserved.
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

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdarg.h>
#include <string.h>

#include "evp-compat.h"
#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "xmalloc.h"
#include "log.h"

static const char *
rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";
#ifdef HAVE_EVP_SHA256
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";
#endif /*def HAVE_EVP_SHA256*/
	}
	return NULL;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
static int
rsa_hash_id_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0)
		return SSH_DIGEST_SHA1;
#ifdef HAVE_EVP_SHA256
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
#endif /*def HAVE_EVP_SHA256*/
	return -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
static int
rsa_hash_id_from_keyname(const char *alg)
{
	int r;

	if ((r = rsa_hash_id_from_ident(alg)) != -1)
		return r;
	if (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

static int
rsa_hash_alg_nid(int type)
{
	switch (type) {
	case SSH_DIGEST_SHA1:
		return NID_sha1;
	case SSH_DIGEST_SHA256:
		return NID_sha256;
	case SSH_DIGEST_SHA512:
		return NID_sha512;
	default:
		return -1;
	}
}

int
sshrsa_verify_length(int bits) {
	return bits < SSH_RSA_MINIMUM_MODULUS_SIZE
	    ? SSH_ERR_KEY_LENGTH : 0;
}

int
sshrsa_check_length(const RSA *rsa) {
	const BIGNUM *n = NULL;
	RSA_get0_key(rsa, &n, NULL, NULL);
	return sshrsa_verify_length(BN_num_bits(n));
}

#ifndef BN_FLG_CONSTTIME
#  define BN_FLG_CONSTTIME 0x0 /* OpenSSL < 0.9.8 */
#endif
int
sshrsa_complete_crt_parameters(struct sshkey *key, const BIGNUM *rsa_iqmp)
{
	BN_CTX *ctx = NULL;
	BIGNUM *aux = NULL, *d = NULL;
	BIGNUM *dmq1 = NULL, *dmp1 = NULL, *iqmp = NULL;
	int r;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((aux = BN_new()) == NULL ||
	    (iqmp = BN_dup(rsa_iqmp)) == NULL ||
	    (dmq1 = BN_new()) == NULL ||
	    (dmp1 = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);

{	const BIGNUM *p, *q;
	RSA *rsa = key->rsa;
	RSA_get0_factors(rsa, &p, &q);
	{	const BIGNUM *key_d;
		RSA_get0_key(rsa, NULL, NULL, &key_d);
		if ((d = BN_dup(key_d)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		BN_set_flags(d, BN_FLG_CONSTTIME);
	}

	if ((BN_sub(aux, q, BN_value_one()) == 0) ||
	    (BN_mod(dmq1, d, aux, ctx) == 0) ||
	    (BN_sub(aux, p, BN_value_one()) == 0) ||
	    (BN_mod(dmp1, d, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}
	if (!RSA_set0_crt_params(key->rsa, dmp1, dmq1, iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	dmp1 = dmq1 = iqmp = NULL; /* transferred */

	r = SSH_ERR_SUCCESS;
 out:
	BN_clear_free(aux);
	BN_clear_free(d);
	BN_clear_free(dmp1);
	BN_clear_free(dmq1);
	BN_clear_free(iqmp);
	BN_CTX_free(ctx);
	return r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	u_char *sig = NULL;
	size_t slen = 0;
	u_int len;
	int nid, hash_alg, ret;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg_ident == NULL || strlen(alg_ident) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_id_from_keyname(alg_ident);
	debug3("%s  hash_alg=%d/%s", __func__, hash_alg, rsa_hash_alg_ident(hash_alg));
	if (key == NULL || key->rsa == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	ret = sshrsa_check_length(key->rsa);
	if (ret != 0) return ret;

	slen = RSA_size(key->rsa);
	if (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;

	/* hash the data */
	nid = rsa_hash_alg_nid(hash_alg);

{	/* EVP_Sign... */
	const EVP_MD *evp_md;
	EVP_PKEY *pkey = NULL;
	int ok = -1;

	sig = NULL;

	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error("%s: EVP_get_digestbynid %d failed", __func__, nid);
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto evp_end;
	}

	EVP_PKEY_set1_RSA(pkey, key->rsa);

	slen = EVP_PKEY_size(pkey);
	sig = xmalloc(slen);	/*fatal on error*/

{	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (md == NULL) {
		error("%s: out of memory", __func__);
		goto evp_end;
	}

	ok = EVP_SignInit_ex(md, evp_md, NULL);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignInit_ex fail with errormsg='%s'"
		    , __func__, ebuf);
#endif
		goto evp_md_end;
	}

	ok = EVP_SignUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignUpdate fail with errormsg='%s'"
		    , __func__, ebuf);
#endif
		goto evp_md_end;
	}

	ok = EVP_SignFinal(md, sig, &len, pkey);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: SignFinal fail with errormsg='%s'"
		    , __func__, ebuf);
#endif
		goto evp_md_end;
	}

evp_md_end:
	EVP_MD_CTX_free(md);
}
evp_end:
	EVP_PKEY_free(pkey);

	if (ok <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}

	if (len < slen) {
		size_t diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} else if (len > slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;

	ret = SSH_ERR_SUCCESS;
 out:
	freezero(sig, slen);
	sshbuf_free(b);
	return ret;
}

int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t datalen,
    const char *alg)
{
	char *sigtype = NULL;
	int hash_alg, ret;
	size_t len = 0, diff, modlen;
	struct sshbuf *b = NULL;
	u_char *osigblob, *sigblob = NULL;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	ret = sshrsa_check_length(key->rsa);
	if (ret != 0) return ret;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	debug3("%s  hash_alg=%d/%s", __func__, hash_alg, rsa_hash_alg_ident(hash_alg));
	/*
	 * For legacy reasons allow ssh-rsa-cert-v01 certs to accept SHA2 signatures
	 * but otherwise the signature algorithm should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		int want_alg;
		if ((want_alg = rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = RSA_size(key->rsa);
	if (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} else if (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		if ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

{	/* EVP_Verify... */
	int nid;
	const EVP_MD *evp_md;
	EVP_PKEY *pkey;
	int ok = -1;

	nid = rsa_hash_alg_nid(hash_alg);
	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error("%s: EVP_get_digestbynid %d failed", __func__, nid);
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto evp_end;
	}

	EVP_PKEY_set1_RSA(pkey, key->rsa);

{	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (md == NULL) {
		error("%s: out of memory", __func__);
		goto evp_end;
	}

	ok = EVP_VerifyInit(md, evp_md);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyInit fail with errormsg='%s'"
		    , __func__, ebuf);
#endif
		goto evp_md_end;
	}

	ok = EVP_VerifyUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyUpdate fail with errormsg='%s'"
		    , __func__, ebuf);
#endif
		goto evp_md_end;
	}

	ok = EVP_VerifyFinal(md, sigblob, len, pkey);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyFinal fail with errormsg='%s'"
		    , __func__, ebuf);
#endif
		goto evp_md_end;
	}

evp_md_end:
	EVP_MD_CTX_free(md);
}
evp_end:
	EVP_PKEY_free(pkey);

	if (ok <= 0) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
}

	ret = SSH_ERR_SUCCESS;
 out:
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	return ret;
}

#endif /* WITH_OPENSSL */
