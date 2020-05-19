/* $OpenBSD: cipher.c,v 1.113 2019/09/06 05:23:55 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
 * Copyright (c) 1999, 2000 Markus Friedl.  All rights reserved.
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

#include <sys/types.h>

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "cipher.h"
#include "misc.h"
#include "xmalloc.h"
#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"

#ifdef WITH_OPENSSL
# include "evp-compat.h"
#else
# define EVP_CIPHER_CTX void
#endif

#if defined(HAVE_OPENSSL_INIT_CRYPTO) && !defined(LIBRESSL_VERSION_NUMBER)
/* NOTE: OpenSSL 1.1.* resets EVP_CIPHER_CTX on each call of
 * EVP_CipherInit()! It is init function. ;)
 * Remark: Pre 1.1.0 behaviour is restored in 1.1.0g (issue #4613).
 * We will use single init for OpenSSL 1.1+. This includes 1.1.1+.
 */
#  define SINGLE_EVP_CIPHERINIT_CALL
#endif



struct sshcipher_ctx {
	int	plaintext;
	int	encrypt;
	EVP_CIPHER_CTX *evp;
	struct chachapoly_ctx cp_ctx; /* XXX union with evp? */
	struct aesctr_ctx ac_ctx; /* XXX union with evp? */
	const struct sshcipher *cipher;
};

struct sshcipher {
	char	*name;
	u_int	block_size;
	u_int	key_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	const EVP_CIPHER	*(*evptype)(void);
#else
	void	*ignored;
#endif
};

static const struct sshcipher ciphers[] = {
#ifdef WITH_OPENSSL
#ifndef OPENSSL_NO_DES
	{ "3des-cbc",		8, 24, 0, 0, CFLAG_CBC, EVP_des_ede3_cbc },
#endif
	{ "aes128-cbc",		16, 16, 0, 0, CFLAG_CBC, EVP_aes_128_cbc },
	{ "aes192-cbc",		16, 24, 0, 0, CFLAG_CBC, EVP_aes_192_cbc },
	{ "aes256-cbc",		16, 32, 0, 0, CFLAG_CBC, EVP_aes_256_cbc },
	{ "rijndael-cbc@lysator.liu.se",
				16, 32, 0, 0, CFLAG_CBC, EVP_aes_256_cbc },
	{ "aes128-ctr",		16, 16, 0, 0, 0, EVP_aes_128_ctr },
	{ "aes192-ctr",		16, 24, 0, 0, 0, EVP_aes_192_ctr },
	{ "aes256-ctr",		16, 32, 0, 0, 0, EVP_aes_256_ctr },
# ifdef OPENSSL_HAVE_EVPGCM
	{ "aes128-gcm@openssh.com",
				16, 16, 12, 16, 0, EVP_aes_128_gcm },
	{ "aes256-gcm@openssh.com",
				16, 32, 12, 16, 0, EVP_aes_256_gcm },
# endif /* OPENSSL_HAVE_EVPGCM */
#else
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, NULL },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, NULL },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, NULL },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, NULL },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, NULL },

	{ NULL,			0, 0, 0, 0, 0, NULL }
};

/*--*/

static inline int/*bool*/
cipher_allowed(const struct sshcipher *c) {
#ifdef OPENSSL_FIPS
	if (FIPS_mode()) {
		const EVP_CIPHER *evp = NULL;
		if (c->evptype == NULL) return(0);
		evp = c->evptype();
		if (evp == NULL) return(0);
		if ((EVP_CIPHER_flags(evp) & EVP_CIPH_FLAG_FIPS) == 0)
			return(0);
	}
#else
	(void) c;
#endif
	return(1);
}

/* Returns a comma-separated list of supported ciphers. */
char *
cipher_alg_list(char sep, int auth_only)
{
	char *tmp, *ret = NULL;
	size_t nlen, rlen = 0;
	const struct sshcipher *c;

	for (c = ciphers; c->name != NULL; c++) {
		if ((c->flags & CFLAG_INTERNAL) != 0)
			continue;
		if (auth_only && c->auth_len == 0)
			continue;
		if (!cipher_allowed(c))
			continue;
		if (ret != NULL)
			ret[rlen++] = sep;
		nlen = strlen(c->name);
		if ((tmp = realloc(ret, rlen + nlen + 2)) == NULL) {
			free(ret);
			return NULL;
		}
		ret = tmp;
		memcpy(ret + rlen, c->name, nlen + 1);
		rlen += nlen;
	}
	return ret;
}

u_int
cipher_blocksize(const struct sshcipher *c)
{
	return (c->block_size);
}

u_int
cipher_keylen(const struct sshcipher *c)
{
	return (c->key_len);
}

u_int
cipher_seclen(const struct sshcipher *c)
{
	if (strcmp("3des-cbc", c->name) == 0)
		return 14;
	return cipher_keylen(c);
}

u_int
cipher_authlen(const struct sshcipher *c)
{
	return (c->auth_len);
}

u_int
cipher_ivlen(const struct sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	return (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(const struct sshcipher *c)
{
	return (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_ctx_is_plaintext(struct sshcipher_ctx *cc)
{
	return cc->plaintext;
}

/* NOTE: "none" is not allowed in FIPS mode, so temporary
 * work-around for "none"-cipher used in ssh_packet_set_connection()
 */
const struct sshcipher * cipher_none(void);

const struct sshcipher *
cipher_none(void)
{
	const struct sshcipher *c;
	for (c = ciphers; c->name != NULL; c++)
		if (strcmp(c->name, "none") == 0)
			return c;
	return NULL;
}

const struct sshcipher *
cipher_by_name(const char *name)
{
	const struct sshcipher *c;
	for (c = ciphers; c->name != NULL; c++)
		if (strcmp(c->name, name) == 0)
		{
			if (!cipher_allowed(c))
				continue;
			return c;
		}
	return NULL;
}

#define	CIPHER_SEP	","
int
ciphers_valid(const char *names)
{
	const struct sshcipher *c;
	char *cipher_list, *cp;
	char *p;

	if (names == NULL || strcmp(names, "") == 0)
		return 0;
	if ((cipher_list = cp = strdup(names)) == NULL)
		return 0;
	for ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		if (c == NULL || (c->flags & CFLAG_INTERNAL) != 0) {
			free(cipher_list);
			return 0;
		}
	}
	free(cipher_list);
	return 1;
}

#ifdef OPENSSL_FIPS
char*
only_fips_valid_ciphers(const char* names)
{
	struct sshbuf *b;
	char *fips_names, *cp, *p;
	int r;

	if (names == NULL || *names == '\0')
		return NULL;

	b = sshbuf_new();
	if (b == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	/* default set in myproposals.h */
	cp = xstrdup(names);
	for (p = strsep(&cp, CIPHER_SEP);
	     p && *p != '\0';
	     p = strsep(&cp, CIPHER_SEP)
	) {
		if (cipher_by_name(p) == NULL) continue;

		if (sshbuf_len(b) > 0) {
			r = sshbuf_put(b, ",", 1);
			if (r != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		r = sshbuf_put(b, p, strlen(p));
		if (r != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	r = sshbuf_put(b, "\0", 1);
	if (r != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	fips_names = xstrdup(sshbuf_ptr(b));

	sshbuf_free(b);

	debug3("%s: ciphers: [%s]", __func__, fips_names);
	return fips_names;
}
#endif

const char *
cipher_warning_message(const struct sshcipher_ctx *cc)
{
	if (cc == NULL || cc->cipher == NULL)
		return NULL;
	/* XXX repurpose for CBC warning */
	return NULL;
}

int
cipher_init(struct sshcipher_ctx **ccp, const struct sshcipher *cipher,
    const u_char *key, u_int keylen, const u_char *iv, u_int ivlen,
    int do_encrypt)
{
	struct sshcipher_ctx *cc = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	const EVP_CIPHER *type;
	int klen;
#endif

	*ccp = NULL;
	if ((cc = calloc(sizeof(*cc), 1)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	if (keylen < cipher->key_len ||
	    (iv != NULL && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	cc->cipher = cipher;
	if ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ret = chachapoly_init(&cc->cp_ctx, key, keylen);
		goto out;
	}
	if ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		goto out;
	}
#ifndef WITH_OPENSSL
	if ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, key, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		goto out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	goto out;
#else /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	if ((cc->evp = EVP_CIPHER_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
#ifndef SINGLE_EVP_CIPHERINIT_CALL
	if (EVP_CipherInit(cc->evp, type, NULL, (u_char *)iv,
#else
	if (EVP_CipherInit(cc->evp, type, key, (u_char *)iv,
#endif /*ndef SINGLE_EVP_CIPHERINIT_CALL*/
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (cipher_authlen(cipher) &&
	    !EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	klen = EVP_CIPHER_CTX_key_length(cc->evp);
	if (klen > 0 && keylen != (u_int)klen) {
		if (EVP_CIPHER_CTX_set_key_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
#ifndef SINGLE_EVP_CIPHERINIT_CALL
	if (EVP_CipherInit(cc->evp, NULL, (u_char *)key, NULL, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#endif /*ndef SINGLE_EVP_CIPHERINIT_CALL*/

	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	if (ret == 0) {
		/* success */
		*ccp = cc;
	} else {
		if (cc != NULL) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
			cc->evp = NULL;
#endif /* WITH_OPENSSL */
			explicit_bzero(cc, sizeof(*cc));
			free(cc);
		}
	}
	return ret;
}

/*
 * cipher_crypt() operates as following:
 * Copy 'aadlen' bytes (without en/decryption) from 'src' to 'dest'.
 * Theses bytes are treated as additional authenticated data for
 * authenticated encryption modes.
 * En/Decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'.
 * Use 'authlen' bytes at offset 'len'+'aadlen' as the authentication tag.
 * This tag is written on encryption and verified on decryption.
 * Both 'aadlen' and 'authlen' can be set to 0.
 */
int
cipher_crypt(struct sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   const u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	if ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		return chachapoly_crypt(&cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	if ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		return 0;
	}
#ifndef WITH_OPENSSL
	if ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		if (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		return 0;
	}
	return SSH_ERR_INVALID_ARGUMENT;
#else
	if (authlen) {
		u_char lastiv[1];

		if (authlen != cipher_authlen(cc->cipher))
			return SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		if (!EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv))
			return SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decyption */
		if (!cc->encrypt &&
		    !EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len))
			return SSH_ERR_LIBCRYPTO_ERROR;
	}
	if (aadlen) {
		if (authlen &&
		    EVP_Cipher(cc->evp, NULL, (u_char *)src, aadlen) < 0)
			return SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	if (len % cc->cipher->block_size)
		return SSH_ERR_INVALID_ARGUMENT;
	if (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		if (EVP_Cipher(cc->evp, NULL, NULL, 0) < 0)
			return cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		if (cc->encrypt &&
		    !EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len))
			return SSH_ERR_LIBCRYPTO_ERROR;
	}
	return 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
int
cipher_get_length(struct sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    const u_char *cp, u_int len)
{
	if ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		return chachapoly_get_length(&cc->cp_ctx, plenp, seqnr,
		    cp, len);
	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	return 0;
}

void
cipher_free(struct sshcipher_ctx *cc)
{
	if (cc == NULL)
		return;
	if ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		explicit_bzero(&cc->cp_ctx, sizeof(cc->cp_ctx));
	else if ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, sizeof(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = NULL;
#endif
	explicit_bzero(cc, sizeof(*cc));
	free(cc);
}

/*
 * Exports an IV from the sshcipher_ctx required to export the key
 * state back from the unprivileged child to the privileged parent
 * process.
 */
int
cipher_get_keyiv_len(const struct sshcipher_ctx *cc)
{
	const struct sshcipher *c = cc->cipher;

	if ((c->flags & CFLAG_CHACHAPOLY) != 0)
		return 0;
	else if ((c->flags & CFLAG_AESCTR) != 0)
		return sizeof(cc->ac_ctx.ctr);
#ifdef WITH_OPENSSL
	return EVP_CIPHER_CTX_iv_length(cc->evp);
#else
	return 0;
#endif
}

int
cipher_get_keyiv(struct sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	const struct sshcipher *c = cc->cipher;
	int evplen;
#endif

	if ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		if (len != 0)
			return SSH_ERR_INVALID_ARGUMENT;
		return 0;
	}
	if ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		if (len != sizeof(cc->ac_ctx.ctr))
			return SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		return 0;
	}
	if ((cc->cipher->flags & CFLAG_NONE) != 0)
		return 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	if (evplen == 0)
		return 0;
	else if (evplen < 0)
		return SSH_ERR_LIBCRYPTO_ERROR;
	if ((size_t)evplen != len)
		return SSH_ERR_INVALID_ARGUMENT;
#ifndef OPENSSL_HAVE_EVPCTR
	if (c->evptype == evp_aes_128_ctr)
		ssh_aes_ctr_iv(cc->evp, 0, iv, len);
	else
#endif
	if (cipher_authlen(c)) {
		if (!EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		   evplen, iv))
		       return SSH_ERR_LIBCRYPTO_ERROR;
	} else
		memcpy(iv, EVP_CIPHER_CTX_iv(cc->evp), len);
#endif
	return 0;
}

#if 0 /*UNUSED*/
int
cipher_set_keyiv(struct sshcipher_ctx *cc, const u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	const struct sshcipher *c = cc->cipher;
	int evplen = 0;
#endif

	if ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		return 0;
	if ((cc->cipher->flags & CFLAG_NONE) != 0)
		return 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	if (evplen <= 0)
		return SSH_ERR_LIBCRYPTO_ERROR;
	if ((size_t)evplen != len)
		return SSH_ERR_INVALID_ARGUMENT;
#ifndef OPENSSL_HAVE_EVPCTR
	/* XXX iv arg is const, but ssh_aes_ctr_iv isn't */
	if (c->evptype == evp_aes_128_ctr)
		ssh_aes_ctr_iv(cc->evp, 1, (u_char *)iv, len);
	else
#endif
	if (cipher_authlen(c)) {
		/* XXX iv arg is const, but EVP_CIPHER_CTX_ctrl isn't */
		if (!EVP_CIPHER_CTX_ctrl(cc->evp,
		    EVP_CTRL_GCM_SET_IV_FIXED, -1, (void *)iv))
			return SSH_ERR_LIBCRYPTO_ERROR;
	} else
		memcpy(EVP_CIPHER_CTX_iv_noconst(cc->evp), iv, len);
#endif
	return 0;
}
#endif /*UNUSED*/
