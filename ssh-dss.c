/* $OpenBSD: ssh-dss.c,v 1.37 2018/02/07 02:06:51 jsing Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011 Roumen Petrov.  All rights reserved.
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

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "evp-compat.h"
#include "xmalloc.h"
#include "log.h"

#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

/* caller must free result */
static DSA_SIG*
ssh_DSA_sign(DSA *dsa, const u_char *data, u_int datalen)
{
	DSA_SIG *sig = NULL;

	EVP_PKEY *pkey = NULL;
	u_char *tsig = NULL;
	u_int slen, len;
	int ret;

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto done;
	}

	EVP_PKEY_set1_DSA(pkey, dsa);

	slen = EVP_PKEY_size(pkey);
	tsig = xmalloc(slen);	/*fatal on error*/

{
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		ret = -1;
		error("%s: out of memory", __func__);
		goto clean;
	}

	ret = EVP_SignInit_ex(md, EVP_dss1(), NULL);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignInit_ex fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		goto clean;
	}

	ret = EVP_SignUpdate(md, data, datalen);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignUpdate fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		goto clean;
	}

	ret = EVP_SignFinal(md, tsig, &len, pkey);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: sign failed: %s", __func__, ebuf);
#endif
		goto clean;
	}

clean:
	EVP_MD_CTX_free(md);
}

	if (ret > 0) {
		/* decode DSA signature */
		const u_char *psig = tsig;
		sig = d2i_DSA_SIG(NULL, &psig, len);
	}

done:
	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', slen);
		free(tsig);
	}

	if (pkey != NULL) EVP_PKEY_free(pkey);

	return sig;
}


int
ssh_dss_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	DSA_SIG *sig = NULL;
	u_char sigblob[SIGBLOB_LEN];
	size_t rlen, slen, len, dlen = ssh_digest_bytes(SSH_DIGEST_SHA1);
	struct sshbuf *b = NULL;
	int ret = SSH_ERR_INVALID_ARGUMENT;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->dsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_DSA)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen == 0)
		return SSH_ERR_INTERNAL_ERROR;

	sig = ssh_DSA_sign(key->dsa, data, datalen);
	if (sig == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

{	const BIGNUM *ps, *pr;
	DSA_SIG_get0(sig, &pr, &ps);

	rlen = BN_num_bytes(pr);
	slen = BN_num_bytes(ps);
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	explicit_bzero(sigblob, SIGBLOB_LEN);
	BN_bn2bin(pr, sigblob + SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(ps, sigblob + SIGBLOB_LEN - slen);
}

	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, "ssh-dss")) != 0 ||
	    (ret = sshbuf_put_string(b, sigblob, SIGBLOB_LEN)) != 0)
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
	ret = 0;
 out:
	DSA_SIG_free(sig);
	sshbuf_free(b);
	return ret;
}


static int
ssh_DSA_verify(DSA *dsa, DSA_SIG *sig, const u_char *data, u_int datalen)
{
	int ret = -1;
	u_char *tsig = NULL;
	u_int len;
	EVP_PKEY *pkey = NULL;

	/* Sig is in DSA_SIG structure, convert to encoded buffer */

	len = i2d_DSA_SIG(sig, NULL);
	tsig = xmalloc(len);	/*fatal on error*/

	{ /* encode a DSA signature */
		u_char *psig = tsig;
		i2d_DSA_SIG(sig, &psig);
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto done;
	}
	EVP_PKEY_set1_DSA(pkey, dsa);

{ /* now verify signature */
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		ret = -1;
		error("%s: out of memory", __func__);
		goto clean;
	}

	ret = EVP_VerifyInit(md, EVP_dss1());
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyInit fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		goto clean;
	}

	ret = EVP_VerifyUpdate(md, data, datalen);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyUpdate fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		goto clean;
	}

	ret = EVP_VerifyFinal(md, tsig, len, pkey);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyFinal fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		goto clean;
	}
clean:
	EVP_MD_CTX_free(md);
}

done:
	if (pkey != NULL) EVP_PKEY_free(pkey);

	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', len);
		free(tsig);
	}

	return ret <= 0
		? SSH_ERR_LIBCRYPTO_ERROR
		: SSH_ERR_SUCCESS;
}


int
ssh_dss_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	DSA_SIG *sig = NULL;
	u_char *sigblob = NULL;
	size_t len, dlen = ssh_digest_bytes(SSH_DIGEST_SHA1);
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *ktype = NULL;

	if (key == NULL || key->dsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_DSA ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen == 0)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp("ssh-dss", ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	if (len != SIGBLOB_LEN) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

{	/* parse signature */
	BIGNUM *pr, *ps;

	ret = 0;
	pr = BN_bin2bn(sigblob, INTBLOB_LEN, NULL);
	ps = BN_bin2bn(sigblob+ INTBLOB_LEN, INTBLOB_LEN, NULL);
	if ((pr == NULL) || (ps == NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto parse_out;
	}

	sig = DSA_SIG_new();
	if (sig == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto parse_out;
	}

	if (!DSA_SIG_set0(sig, pr, ps))
		ret = SSH_ERR_LIBCRYPTO_ERROR;

parse_out:
	if (ret != 0) {
		BN_free(pr);
		BN_free(ps);
		goto out;
	}
}

	ret = ssh_DSA_verify(key->dsa, sig, data, datalen);

 out:
	DSA_SIG_free(sig);
	sshbuf_free(b);
	free(ktype);
	if (sigblob != NULL) {
		explicit_bzero(sigblob, len);
		free(sigblob);
	}
	return ret;
}
#endif /* WITH_OPENSSL */
