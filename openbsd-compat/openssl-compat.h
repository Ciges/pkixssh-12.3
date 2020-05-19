/*
 * Copyright (c) 2005 Darren Tucker <dtucker@zip.com.au>
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
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _OPENSSL_COMPAT_H
#define _OPENSSL_COMPAT_H

#include "includes.h"
#ifdef WITH_OPENSSL

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif

int ssh_compatible_openssl(long, long);

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x00907000L)
# error "OpenSSL 0.9.7 or greater is required"
#endif

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x00908000L)
/* Workaround for bug in some openssl versions before 0.9.8f
 * We will not use configure check as 0.9.7x define correct
 * macro or some verdors patch their versions.
 */
#undef EVP_CIPHER_CTX_key_length
#define EVP_CIPHER_CTX_key_length ssh_EVP_CIPHER_CTX_key_length

static inline int
ssh_EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx) {
	return ctx->key_len;
}
#endif

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)
# define LIBCRYPTO_EVP_INL_TYPE unsigned int
#else
# define LIBCRYPTO_EVP_INL_TYPE size_t
#endif

#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS	16384
#endif
#ifndef OPENSSL_DSA_MAX_MODULUS_BITS
# define OPENSSL_DSA_MAX_MODULUS_BITS	10000
#endif

#ifndef OPENSSL_HAVE_EVPCTR
# define EVP_aes_128_ctr evp_aes_128_ctr
# define EVP_aes_192_ctr evp_aes_128_ctr
# define EVP_aes_256_ctr evp_aes_128_ctr
const EVP_CIPHER *evp_aes_128_ctr(void);
void ssh_aes_ctr_iv(EVP_CIPHER_CTX *, int, u_char *, size_t);
#endif

/* Avoid some #ifdef. Code that uses these is unreachable without GCM */
#if !defined(OPENSSL_HAVE_EVPGCM) && !defined(EVP_CTRL_GCM_SET_IV_FIXED)
# define EVP_CTRL_GCM_SET_IV_FIXED -1
# define EVP_CTRL_GCM_IV_GEN -1
# define EVP_CTRL_GCM_SET_TAG -1
# define EVP_CTRL_GCM_GET_TAG -1
#endif

#if defined(HAVE_EVP_RIPEMD160)
# if defined(OPENSSL_NO_RIPEMD) || defined(OPENSSL_NO_RMD160)
#  undef HAVE_EVP_RIPEMD160
# endif
#endif


#ifndef HAVE_BN_IS_NEGATIVE	/*macro before OpenSSL 1.1*/
# ifndef BN_is_negative		/*not defined before OpenSSL 0.9.8*/
#  define BN_is_negative(a) ((a)->neg != 0)
#endif
#endif

#ifndef HAVE_BN_IS_PRIME_EX
int BN_is_prime_ex(const BIGNUM *, int, BN_CTX *, void *);
#endif

#ifndef HAVE_RSA_GENERATE_KEY_EX
int RSA_generate_key_ex(RSA *, int, BIGNUM *, void *);
#endif

#ifndef HAVE_DSA_GENERATE_PARAMETERS_EX
int DSA_generate_parameters_ex(DSA *, int, const unsigned char *, int, int *,
    unsigned long *, void *);
#endif

extern int  ssh_FIPS_mode(int onoff);

extern void ssh_OpenSSL_startup(void);
extern void ssh_OpenSSL_shuthdown(void);

#ifndef HAVE_OPENSSL_INIT_CRYPTO
# include <openssl/err.h>
#endif
static inline void
ssh_OpenSSL_load_error_strings(void) {
#ifdef HAVE_OPENSSL_INIT_CRYPTO
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#else
	ERR_load_crypto_strings();
#endif
}

#endif /* WITH_OPENSSL */

static inline const char*
ssh_OpenSSL_version_text(void) {
#ifndef WITH_OPENSSL
    return "without OpenSSL";
#else
# ifndef HAVE_OPENSSL_INIT_CRYPTO	/* OpenSSL < 1.1 */
    return SSLeay_version(SSLEAY_VERSION);
# else
    return OpenSSL_version(OPENSSL_VERSION);
# endif
#endif
}

#endif /* _OPENSSL_COMPAT_H */
