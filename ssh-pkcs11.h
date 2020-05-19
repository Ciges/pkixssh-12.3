#ifndef SSH_PKCS11_H
#define SSH_PKCS11_H
/* $OpenBSD: ssh-pkcs11.h,v 1.5 2019/01/20 22:51:37 djm Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
 * Copyright (c) 2018-2019 Roumen Petrov.  All rights reserved.
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

#include "sshkey.h"

int	pkcs11_init(int);
void	pkcs11_terminate(void);

#ifdef ENABLE_PKCS11
/* Errors for pkcs11_add_provider() */
#define	SSH_PKCS11_ERR_GENERIC			-1
#define	SSH_PKCS11_ERR_LOGIN_FAIL		-2
#define	SSH_PKCS11_ERR_NO_SLOTS			-3
#define	SSH_PKCS11_ERR_PIN_REQUIRED		-4
#define	SSH_PKCS11_ERR_PIN_LOCKED		-5

int	pkcs11_add_provider(char *, char *, struct sshkey ***);
int	pkcs11_del_provider(char *);

/* crypto library errors */
/* Function codes. */
#define PKCS11_LOGIN			100
#define PKCS11_REAUTHENTICATE		101
#define PKCS11_RSA_PRIVATE_ENCRYPT	110
#define PKCS11_DSA_DO_SIGN		111
#define PKCS11_ECDSA_DO_SIGN		112
#define PKCS11_GET_KEY			113
/* Reason codes. */
#define PKCS11_SIGNREQ_FAIL		100
#define PKCS11_C_SIGNINIT_FAIL		101
#define PKCS11_C_SIGN_FAIL		102
#define PKCS11_C_LOGIN_FAIL		103
#define PKCS11_FINDKEY_FAIL		104

void ERR_PKCS11_PUT_error(int function, int reason, char *file, int line, const char* funcname);
#define PKCS11err(f,r) ERR_PKCS11_PUT_error((f),(r),__FILE__,__LINE__, __func__)

void ERR_load_PKCS11_strings(void);


#ifdef OPENSSL_HAS_ECC
# ifndef HAVE_EC_KEY_METHOD_NEW	/* OpenSSL < 1.1 */
/* mimic some ECDSA functions in OpenSSL API v1.1 style */
#  include <openssl/ecdsa.h>

typedef ECDSA_METHOD EC_KEY_METHOD;

static inline int
EC_KEY_set_method(EC_KEY *key, const EC_KEY_METHOD *meth) {
	return ECDSA_set_method(key, /*ECDSA_METHOD*/meth);
}

/* NOTE: In OpenSSL 1.1 EC_KEY_get_ex_new_index(...) is define to
 * CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY, ...)
 */
static inline int
EC_KEY_get_ex_new_index(long argl, void *argp,
	CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func,
	CRYPTO_EX_free *free_func
) {
	return ECDSA_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
}

static inline void*
EC_KEY_get_ex_data(const EC_KEY *key, int idx) {
	return ECDSA_get_ex_data((EC_KEY *)key, idx);
}

static inline int
EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg) {
	return ECDSA_set_ex_data(key, idx, arg);
}

# endif /*def HAVE_EC_KEY_METHOD_NEW*/
#endif /*def OPENSSL_HAS_ECC*/

#endif /*def ENABLE_PKCS11*/
#endif /*ndef SSH_PKCS11_H*/
