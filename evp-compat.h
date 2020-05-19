#ifndef EVP_COMPAT_H
#define EVP_COMPAT_H
/*
 * Copyright (c) 2011-2016 Roumen Petrov.  All rights reserved.
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
#include "openbsd-compat/openssl-compat.h"
#ifdef OPENSSL_HAS_ECC
# include <openssl/ec.h>
# include <openssl/ecdsa.h>
#endif
#include <string.h>	/*for memset*/
#include <openssl/buffer.h>	/*for BUF_strdup*/


#ifndef HAVE_EVP_MD_CTX_NEW		/* OpenSSL < 1.1 */
static inline EVP_MD_CTX*
EVP_MD_CTX_new(void) {
	EVP_MD_CTX *ctx;

	ctx = OPENSSL_malloc(sizeof(EVP_MD_CTX));
	if (ctx != NULL) {
		EVP_MD_CTX_init(ctx);
	}
	return(ctx);
}


static inline void
EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
	EVP_MD_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}
#endif/* ndef HAVE_EVP_MD_CTX_NEW	OpenSSL < 1.1 */


#ifndef HAVE_EVP_MD_FLAGS		/* OpenSSL < 1.0 */
static inline unsigned long
EVP_MD_flags(const EVP_MD *md) {
	return md->flags;
}
#endif /* ndef HAVE_EVP_MD_FLAGS	OpenSSL < 1.0 */


#ifndef HAVE_EVP_CIPHER_CTX_NEW		/* OpenSSL < 0.9.8 */
static inline EVP_CIPHER_CTX*
EVP_CIPHER_CTX_new(void) {
	EVP_CIPHER_CTX *ctx;

	ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX));
	if (ctx != NULL) {
		EVP_CIPHER_CTX_init(ctx);
	}
	return(ctx);
}


static inline void
EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx) {
	if (ctx == NULL) return;

	EVP_CIPHER_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}
#endif /* ndef HAVE_EVP_CIPHER_CTX_NEW	OpenSSL < 0.9.8 */


#ifndef HAVE_EVP_CIPHER_CTX_IV		/* OpenSSL < 1.1 */
static inline const unsigned char*
EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx) {
	return(ctx->iv);
}


static inline unsigned char*
EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
	return(ctx->iv);
}


#ifndef HAVE_EVP_CIPHER_CTX_ENCRYPTING
static inline int
EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx)
{
	return(ctx->encrypt);
}
#endif /*ndef HAVE_EVP_CIPHER_CTX_ENCRYPTING*/


static inline void*
EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx)
{
	return(ctx->cipher_data);
}
#endif /* ndef HAVE_EVP_CIPHER_CTX_IV	OpenSSL < 1.1 */


#ifndef HAVE_EVP_CIPHER_METH_NEW	/* OpenSSL < 1.1 */
static inline int
EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *e)
{
	return(e->ctx_size);
}


static inline EVP_CIPHER*
EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len)
{
	EVP_CIPHER *cipher = (EVP_CIPHER*) OPENSSL_malloc(sizeof(EVP_CIPHER));

	if (cipher != NULL) {
		memset(cipher, 0, sizeof(*cipher));
		cipher->nid = cipher_type;
		cipher->block_size = block_size;
		cipher->key_len = key_len;
	}
	return(cipher);
}


static inline EVP_CIPHER*
EVP_CIPHER_meth_dup(const EVP_CIPHER *cipher)
{
	EVP_CIPHER *to = (EVP_CIPHER*) OPENSSL_malloc(sizeof(EVP_CIPHER));

	if (to != NULL)
		memcpy(to, cipher, sizeof(*to));
	return(to);
}


static inline int
EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len)
{
	cipher->iv_len = iv_len;
	return(1);
}


static inline int
EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags) {
	cipher->flags = flags;
	return(1);
}


static inline int
EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
	int (*init) (EVP_CIPHER_CTX *ctx,
		const unsigned char *key,
		const unsigned char *iv,
		int enc)
) {
    cipher->init = init;
	return(1);
}


typedef int (*do_cipher_f) (EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, LIBCRYPTO_EVP_INL_TYPE inl);


static inline int
EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher, do_cipher_f do_cipher) {
	cipher->do_cipher = do_cipher;
	return(1);
}


static inline do_cipher_f
EVP_CIPHER_meth_get_do_cipher(const EVP_CIPHER *cipher) {
	return cipher->do_cipher;
}

static inline int
EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher, int (*cleanup) (EVP_CIPHER_CTX*)) {
	cipher->cleanup = cleanup;
	return(1);
}
#endif /* ndef HAVE_EVP_CIPHER_METH_NEW		OpenSSL < 1.1 */


#ifndef OPENSSL_NO_RSA
#ifndef HAVE_RSA_METH_NEW		/* OpenSSL < 1.1 */
/* Partial backport of opaque RSA from OpenSSL >= 1.1 by commits
 * "Make the RSA_METHOD structure opaque", "RSA, DSA, DH: Allow some
 * given input to be NULL on already initialised keys" and etc.
 */

/* opaque RSA method structure */
static inline RSA_METHOD*
RSA_meth_new(const char *name, int flags) {
	RSA_METHOD *meth;

	meth = OPENSSL_malloc(sizeof(RSA_METHOD));
	if (meth == NULL) return NULL;

	memset(meth, 0, sizeof(*meth));
	/* unlike OPENSSL_strdup (0.8.k+), BUF_strdup is defined in
	 * all OpenSSL versions (SSLeay 0.8.1) */
	meth->name = BUF_strdup(name);
	meth->flags = flags;

	return(meth);
}


static inline void
RSA_meth_free(RSA_METHOD *meth) {
	if (meth == NULL) return;

	if (meth->name != NULL)
		OPENSSL_free((char*)meth->name);
	OPENSSL_free(meth);
}


static inline RSA_METHOD*
RSA_meth_dup(const RSA_METHOD *meth) {
	RSA_METHOD *ret;

	if (meth == NULL) return NULL;

	ret = OPENSSL_malloc(sizeof(RSA_METHOD));
	if (ret == NULL) return NULL;

	memcpy(ret, meth, sizeof(*meth));
	ret->name = BUF_strdup(meth->name);

	return(ret);
}
#endif /*ndef HAVE_RSA_METH_NEW*/


#ifndef HAVE_RSA_METH_SET1_NAME
static inline int
RSA_meth_set1_name(RSA_METHOD *meth, const char *name) {
	if (meth->name != NULL)
		OPENSSL_free((char*)meth->name);
	meth->name = BUF_strdup(name);

	return meth->name != NULL;
}
#endif /*ndef HAVE_RSA_METH_SET1_NAME*/


#ifndef HAVE_RSA_METH_SET_PRIV_ENC
typedef int (*priv_enc_f) (int flen, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);

static inline int
RSA_meth_set_priv_enc(RSA_METHOD *meth, priv_enc_f priv_enc) {
	meth->rsa_priv_enc = priv_enc;
	return 1;
}


typedef int (*priv_dec_f) (int flen, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);

static inline int
RSA_meth_set_priv_dec(RSA_METHOD *meth, priv_dec_f priv_dec) {
	meth->rsa_priv_dec = priv_dec;
	return 1;
}


typedef int (*finish_f) (RSA *rsa);

static inline int
RSA_meth_set_finish(RSA_METHOD *meth, finish_f finish) {
	meth->finish = finish;
	return 1;
}
#endif /*ndef HAVE_RSA_METH_SET_PRIV_ENC*/


#ifndef HAVE_RSA_METH_GET_PUB_ENC
typedef int (*pub_enc_f) (int flen, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);

static inline pub_enc_f
RSA_meth_get_pub_enc(const RSA_METHOD *meth) { return meth->rsa_pub_enc; }

static inline int
RSA_meth_set_pub_enc(RSA_METHOD *meth, pub_enc_f pub_enc) {
	meth->rsa_pub_enc = pub_enc;
	return 1;
}


typedef int (*pub_dec_f) (int flen, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);

static inline pub_dec_f
RSA_meth_get_pub_dec(const RSA_METHOD *meth) { return meth->rsa_pub_dec; }

static inline int
RSA_meth_set_pub_dec(RSA_METHOD *meth, pub_dec_f pub_dec) {
	meth->rsa_pub_dec = pub_dec;
	return 1;
}


typedef int (*rsa_mod_exp_f) (BIGNUM *r0, const BIGNUM *I, RSA *rsa,
	BN_CTX *ctx);

static inline rsa_mod_exp_f
RSA_meth_get_mod_exp(const RSA_METHOD *meth) { return meth->rsa_mod_exp; }

static inline int
RSA_meth_set_mod_exp(RSA_METHOD *meth, rsa_mod_exp_f rsa_mod_exp ) {
	meth->rsa_mod_exp = rsa_mod_exp;
	return 1;
}


typedef int (*rsa_bn_mod_exp_f) (BIGNUM *r, const BIGNUM *a,
	const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
	BN_MONT_CTX *m_ctx);

static inline rsa_bn_mod_exp_f
RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth) { return meth->bn_mod_exp; }

static inline int
RSA_meth_set_bn_mod_exp(RSA_METHOD *meth, rsa_bn_mod_exp_f bn_mod_exp) {
	meth->bn_mod_exp = bn_mod_exp;
	return 1;
}
#endif /*ndef HAVE_RSA_METH_GET_PUB_ENC*/


#ifndef HAVE_RSA_GET0_KEY
/* opaque RSA key structure */
static inline void
RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
	if (n != NULL) *n = rsa->n;
	if (e != NULL) *e = rsa->e;
	if (d != NULL) *d = rsa->d;
}

static inline int
RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
/* If the fields in r are NULL, the corresponding input parameters MUST
 * be non-NULL for n and e.  d may be left NULL (in case only the
 * public key is used).
 *
 * It is an error to give the results from get0 on r as input
 * parameters.
 */
	if (n == rsa->n || e == rsa->e
	|| (rsa->d != NULL && d == rsa->d))
		return 0;

	if (n != NULL) { BN_free(rsa->n); rsa->n = n; }
	if (e != NULL) { BN_free(rsa->e); rsa->e = e; }
	if (d != NULL) { BN_free(rsa->d); rsa->d = d; }

	return 1;
}


static inline void
RSA_get0_crt_params(const RSA *rsa, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp) {
	if (dmp1 != NULL) *dmp1 = rsa->dmp1;
	if (dmq1 != NULL) *dmq1 = rsa->dmq1;
	if (iqmp != NULL) *iqmp = rsa->iqmp;
}

static inline int
RSA_set0_crt_params(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp) {
/* If the fields in r are NULL, the corresponding input parameters MUST
 * be non-NULL.
 *
 * It is an error to give the results from get0 on r as input
 * parameters.
 */
	if (dmp1 == rsa->dmp1 || dmq1 == rsa->dmq1 || iqmp == rsa->iqmp)
		return 0;

	if (dmp1 != NULL) { BN_free(rsa->dmp1); rsa->dmp1 = dmp1; }
	if (dmq1 != NULL) { BN_free(rsa->dmq1); rsa->dmq1 = dmq1; }
	if (iqmp != NULL) { BN_free(rsa->iqmp); rsa->iqmp = iqmp; }

	return 1;
}


static inline void
RSA_get0_factors(const RSA *rsa, const BIGNUM **p, const BIGNUM **q) {
	if (p != NULL) *p = rsa->p;
	if (q != NULL) *q = rsa->q;
}


static inline int
RSA_set0_factors(RSA *rsa, BIGNUM *p, BIGNUM *q) {
/* If the fields in r are NULL, the corresponding input parameters MUST
 * be non-NULL.
 *
 * It is an error to give the results from get0 on r as input
 * parameters.
 */
	if (p == rsa->p || q == rsa->q)
		return 0;

	if (p != NULL) { BN_free(rsa->p); rsa->p = p; }
	if (q != NULL) { BN_free(rsa->q); rsa->q = q; }

	return 1;
}
#endif /*ndef HAVE_RSA_GET0_KEY*/
#endif /*ndef OPENSSL_NO_RSA*/


#ifndef OPENSSL_NO_DSA
#ifndef HAVE_DSA_METH_NEW		/* OpenSSL < 1.1 */
/* Partial backport of opaque DSA from OpenSSL >= 1.1, commits
 * "Make DSA_METHOD opaque", "Various DSA opacity fixups",
 * "RSA, DSA, DH: Allow some given input to be NULL on already
 * initialised keys" and etc.
 */

/* opaque DSA method structure */
static inline DSA_METHOD*
DSA_meth_new(const char *name, int flags) {
	DSA_METHOD *meth;

	meth = OPENSSL_malloc(sizeof(DSA_METHOD));
	if (meth == NULL) return NULL;

	memset(meth, 0, sizeof(*meth));
	/* unlike OPENSSL_strdup (0.8.k+), BUF_strdup is defined in
	 * all OpenSSL versions (SSLeay 0.8.1) */
	meth->name = BUF_strdup(name);
	meth->flags = flags;

	return(meth);
}


static inline void
DSA_meth_free(DSA_METHOD *meth) {
	if (meth == NULL) return;

	if (meth->name != NULL)
		OPENSSL_free((char*)meth->name);
	OPENSSL_free(meth);
}


typedef DSA_SIG* (*dsa_sign_f) (const unsigned char*, int, DSA*);

static inline int
DSA_meth_set_sign(DSA_METHOD *meth, dsa_sign_f sign) {
	meth->dsa_do_sign = sign;
	return 1;
}
#endif /*ndef HAVE_DSA_METH_NEW*/


#ifndef HAVE_DSA_METH_GET_VERIFY
typedef int (*dsa_verify_f) (const unsigned char*, int, DSA_SIG*, DSA*);

static inline dsa_verify_f
DSA_meth_get_verify(const DSA_METHOD *meth) { return meth->dsa_do_verify; }

static inline int
DSA_meth_set_verify(DSA_METHOD *meth, dsa_verify_f verify) {
	meth->dsa_do_verify = verify;
	return 1;
}


typedef int (*mod_exp_f) (DSA*, BIGNUM*, BIGNUM*, BIGNUM*,
	BIGNUM*, BIGNUM*, BIGNUM*, BN_CTX*, BN_MONT_CTX*);

static inline mod_exp_f
DSA_meth_get_mod_exp(const DSA_METHOD *meth) { return meth->dsa_mod_exp; }

static inline int
DSA_meth_set_mod_exp(DSA_METHOD *meth, mod_exp_f mod_exp) {
	meth->dsa_mod_exp = mod_exp;
	return 1;
}


typedef int (*bn_mod_exp_f) (DSA*, BIGNUM*, BIGNUM*,
	const BIGNUM*, const BIGNUM*, BN_CTX*, BN_MONT_CTX*);

static inline bn_mod_exp_f
DSA_meth_get_bn_mod_exp(const DSA_METHOD *meth) { return meth->bn_mod_exp; }

static inline int
DSA_meth_set_bn_mod_exp(DSA_METHOD *meth, bn_mod_exp_f bn_mod_exp) {
	meth->bn_mod_exp = bn_mod_exp;
	return 1;
}
#endif /*ndef HAVE_DSA_METH_GET_VERIFY*/


#ifndef HAVE_DSA_METH_SET_FINISH
typedef int (*dsa_finish_f) (DSA*);

static inline int
DSA_meth_set_finish(DSA_METHOD *meth, dsa_finish_f finish) {
	meth->finish = finish;
	return 1;
}
#endif /*ndef HAVE_DSA_METH_SET_FINISH*/


#ifndef HAVE_DSA_GET0_KEY
/* opaque DSA key structure */
static inline void
DSA_get0_key(const DSA *dsa, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key  != NULL) *pub_key  = dsa->pub_key;
	if (priv_key != NULL) *priv_key = dsa->priv_key;
}

static inline int
DSA_set0_key(DSA *dsa, BIGNUM *pub_key, BIGNUM *priv_key) {
/* If the pub_key in d is NULL, the corresponding input parameters MUST
 * be non-NULL.  The priv_key field may be left NULL.
 *
 * It is an error to give the results from get0 on d as input
 * parameters.
 */
	if (pub_key == dsa->pub_key
	|| (dsa->priv_key != NULL && priv_key == dsa->priv_key)
	)
		return 0;

	if (pub_key  != NULL) { BN_free(dsa->pub_key ); dsa->pub_key  = pub_key ; }
	if (priv_key != NULL) { BN_free(dsa->priv_key); dsa->priv_key = priv_key; }

	return 1;
}


static inline void
DSA_get0_pqg(const DSA *dsa, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p != NULL) *p = dsa->p;
	if (q != NULL) *q = dsa->q;
	if (g != NULL) *g = dsa->g;
}

static inline int
DSA_set0_pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
	/* If the fields in d are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 *
	 * It is an error to give the results from get0 on d
	 * as input parameters.
	 */
	if (p == dsa->p || q == dsa->q || g == dsa->g)
		return 0;

	if (p != NULL) { BN_free(dsa->p); dsa->p = p; }
	if (q != NULL) { BN_free(dsa->q); dsa->q = q; }
	if (g != NULL) { BN_free(dsa->g); dsa->g = g; }

	return 1;
}
#endif /*ndef HAVE_DSA_GET0_KEY*/

#ifndef HAVE_DSA_SIG_GET0		/* OpenSSL < 1.1 */
static inline void
DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
	if (pr != NULL) *pr = sig->r;
	if (ps != NULL) *ps = sig->s;
}
#endif /*ndef HAVE_DSA_SIG_GET0	OpenSSL < 1.1 */

#ifndef HAVE_DSA_SIG_SET0		/* OpenSSL < 1.1 */
static inline int/*bool*/
DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
	if (r == NULL || s == NULL) return 0;

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);

	sig->r = r;
	sig->s = s;
	return 1;
}
#endif /*ndef HAVE_DSA_SIG_SET0	OpenSSL < 1.1 */
#endif /*ndef OPENSSL_NO_DSA*/


#ifdef OPENSSL_HAS_ECC
#ifndef HAVE_ECDSA_SIG_GET0		/* OpenSSL < 1.1 */
static inline void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
    if (pr != NULL) *pr = sig->r;
    if (ps != NULL) *ps = sig->s;
}
#endif /*ndef HAVE_ECDSA_SIG_GET0	OpenSSL < 1.1 */

#ifndef HAVE_ECDSA_SIG_SET0		/* OpenSSL < 1.1 */
static inline int/*bool*/
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
	if (r == NULL || s == NULL) return 0;

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);

	sig->r = r;
	sig->s = s;
	return 1;
}
#endif /*ndef HAVE_ECDSA_SIG_SET0	OpenSSL < 1.1 */
#endif /*OPENSSL_HAS_ECC*/


#ifdef OPENSSL_HAS_ECC
# ifndef HAVE_EC_KEY_METHOD_NEW		/* OpenSSL < 1.1 */
#  ifndef HAVE_ECDSA_METHOD_NEW		/* OpenSSL < 1.0.2 */

#   ifndef HAVE_ECDSA_METHOD_NAME
/*declared in some OpenSSL compatible headers*/
struct ecdsa_method {
    const char *name;
    ECDSA_SIG *(*ecdsa_do_sign) (const unsigned char *dgst, int dgst_len,
                                 const BIGNUM *inv, const BIGNUM *rp,
                                 EC_KEY *eckey);
    int (*ecdsa_sign_setup) (EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                             BIGNUM **r);
    int (*ecdsa_do_verify) (const unsigned char *dgst, int dgst_len,
                            const ECDSA_SIG *sig, EC_KEY *eckey);
# if 0
    int (*init) (EC_KEY *eckey);
    int (*finish) (EC_KEY *eckey);
# endif
    int flags;
    void *app_data;
};
#   endif /*ndef HAVE_ECDSA_METHOD_NAME*/


static inline ECDSA_METHOD*
ECDSA_METHOD_new(const ECDSA_METHOD *ecdsa_method)
{
    (void)ecdsa_method;
    return(OPENSSL_malloc(sizeof(ECDSA_METHOD)));
}

static inline void
ECDSA_METHOD_set_sign(
    ECDSA_METHOD *ecdsa_method,
    ECDSA_SIG *(*ecdsa_do_sign) (
        const unsigned char *dgst, int dgst_len,
        const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey)
) {
    ecdsa_method->ecdsa_do_sign = ecdsa_do_sign;
}

#  endif /*ndef HAVE_ECDSA_METHOD_NEW		OpenSSL < 1.0.2 */
# endif /*ndef HAVE_EC_KEY_METHOD_NEW		OpenSSL < 1.1 */
#endif /*OPENSSL_HAS_ECC*/


#ifndef HAVE_DH_GET0_KEY		/* OpenSSL < 1.1 */
/* Partial backport of opaque DH from OpenSSL >= 1.1, commits
 * "Make DH opaque", "RSA, DSA, DH: Allow some given input to be NULL
 * on already initialised keys" and etc.
 */

static inline void
DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key  != NULL) *pub_key  = dh->pub_key;
	if (priv_key != NULL) *priv_key = dh->priv_key;
}


static int
DH_set_length(DH *dh, long length) {
	dh->length = length;
	return 1;
}


static inline void
DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p != NULL) *p = dh->p;
	if (q != NULL) *q = dh->q;
	if (g != NULL) *g = dh->g;
}


static inline int
DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
/* If the fields p and g in d are NULL, the corresponding input
 * parameters MUST be non-NULL.  q may remain NULL.
 *
 * It is an error to give the results from get0 on d as input
 * parameters.
 */
	if (p == dh->p || (dh->q != NULL && q == dh->q) || g == dh->g)
		return 0;

	if (p != NULL) { BN_free(dh->p); dh->p = p; }
	if (q != NULL) { BN_free(dh->q); dh->q = q; }
	if (g != NULL) { BN_free(dh->g); dh->g = g; }

	if (q != NULL)
	        (void)DH_set_length(dh, BN_num_bits(q));

	return 1;
}
#endif /*ndef HAVE_DH_GET0_KEY*/


#ifndef HAVE_EVP_PKEY_ID
/* OpenSSL >= 1.0 */
static inline int EVP_PKEY_id(const EVP_PKEY *pkey) { return pkey->type; }
#endif /*ndef HAVE_EVP_PKEY_ID */


#ifndef HAVE_EVP_PKEY_GET0_EC_KEY
/* OpenSSL >= 1.1 by commit "Add EVP_PKEY_get0_* functions." */
#ifdef OPENSSL_HAS_ECC
static inline EC_KEY* EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey) { return pkey->pkey.ec ; }
#endif
static inline DSA*    EVP_PKEY_get0_DSA   (const EVP_PKEY *pkey) { return pkey->pkey.dsa; }
static inline RSA*    EVP_PKEY_get0_RSA   (const EVP_PKEY *pkey) { return pkey->pkey.rsa; }
#endif /*ndef HAVE_EVP_PKEY_GET0_EC_KEY*/


#ifndef HAVE_EC_POINT_GET_AFFINE_COORDINATES		/* OpenSSL < 1.1.1 */
#ifdef OPENSSL_HAS_ECC
/* Functions are available even in 0.9.7* but EC is not activated
 * as NIST curves are not supported yet.
 */
static inline int
EC_POINT_get_affine_coordinates(
    const EC_GROUP *group, const EC_POINT *p,
    BIGNUM *x, BIGNUM *y, BN_CTX *ctx
) {
	return EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
}

static inline int
EC_POINT_set_affine_coordinates(
    const EC_GROUP *group, EC_POINT *p,
    const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx
) {
	return EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
}
#endif /*def OPENSSL_HAS_ECC*/
#endif /*ndef HAVE_EC_POINT_GET_AFFINE_COORDINATES*/


#ifndef HAVE_EVP_DSS1
/* removed in OpenSSL 1.1 */
static inline const EVP_MD* EVP_dss1(void) { return EVP_sha1(); }
#endif

#if !HAVE_DECL_UTF8_GETC
/* hidden in some OpenSSL compatible libraries */
int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);
#endif

#endif /* ndef EVP_COMPAT_H*/
