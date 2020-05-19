/*
 * Copyright (c) 2002-2019 Roumen Petrov.  All rights reserved.
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

#include "ssh-x509.h"
#include <ctype.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include "evp-compat.h"

#include "ssh-xkalg.h"
#include "x509store.h"
#include "compat.h"
#include "xmalloc.h"
#include "ssherr.h"
#include "log.h"

#ifndef ISSPACE
#  define ISSPACE(ch) (isspace((int)(unsigned char)(ch)))
#endif

/* pointer to x509store function to minimize build dependencies */
int (*pssh_x509store_verify_cert)(X509 *_cert, STACK_OF(X509) *_chain) = NULL;
STACK_OF(X509)* (*pssh_x509store_build_certchain)(X509 *cert, STACK_OF(X509) *untrusted) = NULL;


static int xkey_to_buf2(const SSHX509KeyAlgs *xkalg, const struct sshkey *key, struct sshbuf *b);


static inline int
check_rsa2048_sha256(const SSHX509KeyAlgs *xkalg, const struct sshkey *key) {
#ifdef HAVE_EVP_SHA256
	/* extra check for algorithms like x509v3-rsa2048-sha256 */
	if (
	    /* TODO generic */
	    (key->type == KEY_RSA) &&
	    (sshkey_size(key) < 2048) &&
	    (EVP_MD_size(xkalg->dgst.evp) >= SHA256_DIGEST_LENGTH)
	)
		return 0;
#else
	UNUSED(xkalg);
	UNUSED(key);
#endif /*def HAVE_EVP_SHA256*/
	return 1;
}


struct ssh_x509_st {
	X509           *cert;  /* key certificate */
	STACK_OF(X509) *chain; /* reserved for future use */
};


SSH_X509*
SSH_X509_new() {
	SSH_X509 *xd;

	xd = xmalloc(sizeof(SSH_X509)); /*fatal on error*/
	xd->cert = NULL;
	xd->chain = NULL;

	return xd;
}


static inline void
SSH_X509_free_data(SSH_X509* xd) {
	if (xd->cert != NULL) {
		X509_free(xd->cert);
		xd->cert = NULL;
	}

	if (xd->chain != NULL) {
		sk_X509_pop_free(xd->chain, X509_free);
		xd->chain = NULL;
	}
}


void
SSH_X509_free(SSH_X509* xd) {
	if (xd == NULL) return;

	SSH_X509_free_data(xd);
	free(xd);
}


X509*
SSH_X509_get_cert(SSH_X509 *xd) {
	return (xd != NULL) ? xd->cert : NULL;
}


int
ssh_X509_NAME_print(BIO* bio, X509_NAME *xn) {
	static u_long print_flags =	((XN_FLAG_ONELINE & \
					  ~ASN1_STRFLGS_ESC_MSB & \
					  ~XN_FLAG_SPC_EQ & \
					  ~XN_FLAG_SEP_MASK) | \
					 XN_FLAG_SEP_COMMA_PLUS);

	if (xn == NULL) return -1;

	X509_NAME_print_ex(bio, xn, 0, print_flags);
	(void)BIO_flush(bio);

	return BIO_pending(bio);
}


char*
ssh_X509_NAME_oneline(X509_NAME *xn) {
	char *buf = NULL;
	int size;
	BIO* mbio = NULL;

	if (xn == NULL) return NULL;

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return buf;

	size = ssh_X509_NAME_print(mbio, xn);
	if (size <= 0) {
		error("ssh_X509_NAME_oneline: no data in buffer");
		goto done;
	}

	buf = xmalloc(size + 1); /*fatal on error*/

	/* we should request one byte more !?!? */
	if (size != BIO_gets(mbio, buf, size + 1)) {
		error("ssh_X509_NAME_oneline: cannot get data from buffer");
		goto done;
	}
	buf[size] = '\0';

done:
	/* This call will walk the chain freeing all the BIOs */
	BIO_free_all(mbio);

	return buf;
}


static inline int
ssh_x509_support_plain_type(int k_type) {
	return (
	    (k_type == KEY_RSA) ||
#ifdef OPENSSL_HAS_ECC
	    (k_type == KEY_ECDSA) ||
#endif
	    (k_type == KEY_DSA)
	) ? 1 : 0;
}


static const char*
x509key_find_subject(const char* s) {
	static const char *keywords[] = {
		"subject",
		"distinguished name",
		"distinguished-name",
		"distinguished_name",
		"distinguishedname",
		"dn",
		NULL
	};
	const char **q, *p;
	size_t len;

	if (s == NULL) {
		error("x509key_find_subject: no input data");
		return NULL;
	}
	for (; *s && ISSPACE(*s); s++)
	{/*skip space*/}

	for (q=keywords; *q; q++) {
		len = strlen(*q);
		if (strncasecmp(s, *q, len) != 0) continue;

		for (p = s + len; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		if (!*p) {
			error("x509key_find_subject: no data after keyword");
			return NULL;
		}
		if (*p == ':' || *p == '=') {
			for (p++; *p && ISSPACE(*p); p++)
			{/*skip space*/}
			if (!*p) {
				error("x509key_find_subject: no data after separator");
				return NULL;
			}
		}
		if (*p == '/' || *p == ',') {
			/*skip leading [Relative]DistinguishedName elements separator*/
			for (p++; *p && ISSPACE(*p); p++)
			{/*skip space*/}
			if (!*p) {
				error("x509key_find_subject: no data");
				return NULL;
			}
		}
		return p;
	}
	return NULL;
}


static unsigned long
ssh_hctol(u_char ch) {
/* '0'-'9' = 0x30 - 0x39 (ascii) */
/* 'A'-'F' = 0x41 - 0x46 (ascii) */
/* 'a'-'f' = 0x61 - 0x66 (ascii) */
/* should work for EBCDIC */
	if (('0' <= ch) && (ch <= '9')) return (long)(ch - '0');
	if (('A' <= ch) && (ch <= 'F')) return (long)(ch - ('A' - 10));
	if (('a' <= ch) && (ch <= 'f')) return (long)(ch - ('a' - 10));

	return -1;
}


static unsigned long
ssh_hatol(const u_char *str, size_t maxsize) {
	int k;
	long v, ret = 0;

	for(k = maxsize; k > 0; k--, str++) {
		v = ssh_hctol(*str);
		if (v < 0) return -1;
		ret = (ret << 4) + v;
	}
	return ret;
}


static int
get_escsymbol(const u_char* str, size_t len, u_long *value) {
	const char ch = *str;
	long v;

	if (len < 1) {
		error("get_escsymbol:"
		" missing characters in escape sequence");
		return -1;
	}

	/*escape formats:
		"{\\}\\W%08lX"
		"{\\}\\U%04lX"
		"{\\}\\%02X"
		"{\\}\\x%02X" - X509_NAME_oneline format
	*/
	if (ch == '\\') {
		if (value) *value = ch;
		return 1;
	}
	if (ch == 'W') {
		if (len < 9) {
			error("get_escsymbol:"
			" to short 32-bit escape sequence");
			return -1;
		}
		v = ssh_hatol(++str, 8);
		if (v < 0) {
			error("get_escsymbol:"
			" invalid character in 32-bit hex sequence");
			 return -1;
		}
		if (value) *value = v;
		return 9;
	}
	if (ch == 'U') {
		if (len < 5) {
			error("get_escsymbol:"
			" to short 16-bit escape sequence");
			return -1;
		}
		v = ssh_hatol(++str, 4);
		if (v < 0) {
			error("get_escsymbol:"
			" invalid character in 16-bit hex sequence");
			 return -1;
		}
		if (value) *value = v;
		return 5;
	}
	v = ssh_hctol(*str);
	if (v < 0) {
		/*a character is escaped ?*/
		if (*str > 127) { /*ASCII comparison !*/
			/* there is no reason symbol above 127
                           to be escaped in this way */
			error("get_escsymbol:"
			" non-ascii character in escape sequence");
			return -1;
		}
		if (value) *value = *str;
		return 1;
	}

	/*two hex numbers*/
	{
		long vlo;
		if (len < 2) {
			error("get_escsymbol:"
			" to short 8-bit escape sequence");
			return -1;
		}
		vlo = ssh_hctol(*++str);
		if (vlo < 0) {
			error("get_escsymbol:"
			" invalid character in 8-bit hex sequence");
			 return -1;
		}
		v = (v << 4) + vlo;
	}
	if (value) *value = v;
	return 2;
}


static int/*bool*/
ssh_X509_NAME_add_entry_by_NID(X509_NAME* name, int nid, const u_char* str, size_t len) {
/* default maxsizes:
  C: 2
  L, ST: 128
  O, OU, CN: 64
  emailAddress: 128
*/
	u_char  buf[129*6+1]; /*enough for 128 UTF-8 symbols*/
	int     ret = 0;
	int     type = MBSTRING_ASC;
	u_long  ch;
	u_char *p;
	const u_char *q;
	size_t  k;

	/*this is internal method and we don't check validity of some arguments*/

	p = buf;
	q = str;
	k = sizeof(buf);

	while ((len > 0) && (k > 0)) {
		int ch_utf8 = 1;
		if (*q == '\0') {
			error("ssh_X509_NAME_add_entry_by_NID:"
			" unsupported zero(NIL) symbol in name");
			return 0;
		}
		if (*q == '\\') {
			len--;
			if (len <= 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" escape sequence without data");
				return 0;
			}

			ret = get_escsymbol(++q, len, &ch);
			if (ret < 0) return 0;
			if (ret == 2) {
				/*escaped two hex numbers*/
				ch_utf8 = 0;
			}
		} else {
			ret = UTF8_getc(q, len, &ch);
			if(ret < 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" cannot get next symbol(%.32s)"
				, q);
				return 0;
			}
		}
		len -= ret;
		q += ret;

		if (ch_utf8) {
			/* UTF8_putc return negative if buffer is too short */
			ret = UTF8_putc(p, k, ch);
			if (ret < 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" UTF8_putc fail for symbol %ld", ch);
				return 0;
			}
		} else {
			*p = (u_char)ch;
			ret = 1;
		}
		k -= ret;
		p += ret;
	}
	if (len > 0) {
		error("ssh_X509_NAME_add_entry_by_NID:"
		" too long data");
		return 0;
	}
	*p = '\0';

	for (p = buf; *p; p++) {
		if (*p > 127) {
			type = MBSTRING_UTF8;
			break;
		}
	}
	k = strlen((char*)buf);

	/* this method will fail if string exceed max size limit for nid */
	ret = X509_NAME_add_entry_by_NID(name, nid, type, buf, (int)k, -1, 0);
	if (!ret) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: X509_NAME_add_entry_by_NID fail for nid=%d/%.32s"
		    " with errormsg '%s' and data='%.512s'"
		    , __func__, nid, OBJ_nid2ln(nid), ebuf, str);
	}
	return ret;
}


static int/*bool*/
x509key_str2X509NAME(const char* _str, X509_NAME *_name) {
	int   ret = 1;
	char *str = NULL;
	char *p, *q, *token;
	int   has_more = 0;

	str = xmalloc(strlen(_str) + 1); /*fatal on error*/
	strcpy(str, _str);

	p = (char*)str;
	while (*p) {
		int nid;
		for (; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		if (!*p) break;

		/* get shortest token */
		{
			char *tokenA = strchr(p, ',');
			char *tokenB = strchr(p, '/');

			if (tokenA == NULL) {
				token = tokenB;
			} else if (tokenB == NULL) {
				token = tokenA;
			} else {
				token = (tokenA < tokenB) ? tokenA : tokenB;
			}
		}
		if (token) {
			has_more = 1;
			*token = 0;
		} else {
			has_more = 0;
			token = p + strlen(p);
		}
		q = strchr(p, '=');
		if (!q) {
			error("x509key_str2X509NAME: cannot parse '%.200s' ...", p);
			ret = 0;
			break;
		}
		{
			char *s = q;
			for(--s; ISSPACE(*s) && (s > p); s--)
			{/*skip trailing space*/}
			*++s = 0;
		}
		nid = OBJ_txt2nid(p);
#ifdef SSH_OPENSSL_DN_WITHOUT_EMAIL
		if (nid == NID_undef) {
			/* work around for OpenSSL 0.9.7+ */
			if (strcasecmp(p, "Email") == 0) {
				nid = OBJ_txt2nid("emailAddress");
			}
		}
#endif /* def SSH_OPENSSL_DN_WITHOUT_EMAIL */
		if (nid == NID_undef) {
			error("x509key_str2X509NAME: cannot get nid from string '%.200s'", p);
			ret = 0;
			break;
		}

		p = q + 1;
		if (!*p) {
			error("x509key_str2X509NAME: no data");
			ret = 0;
			break;
		}

		for (; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		for (q = token - 1; (q >= p) && ISSPACE(*q); q--)
		{/*skip unexpected \n, etc. from end*/}
		*++q = 0;

		ret = ssh_X509_NAME_add_entry_by_NID(_name, nid, (u_char*)p, (size_t)(q - p));
		if (!ret) {
			break;
		}

		p = token;
		if (has_more) p++;
	}

	free(str);
	debug3("x509key_str2X509NAME: return %d", ret);
	return ret;
}


static struct sshkey*
x509key_from_subject(int basetype, const char* _cp) {
	const char *subject;
	struct sshkey *key;
	X509       *x;

	debug3("x509key_from_subject(%d, [%.1024s]) called",
		basetype, (_cp ? _cp : ""));
	subject = x509key_find_subject(_cp);
	if (subject == NULL)
		return NULL;

	debug3("x509key_from_subject: subject=[%.1024s]", subject);
	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL) {
		error("x509key_from_subject: out of memory");
		return NULL;
	}

	x = X509_new();
	if (x == NULL) {
		error("%s: out of memory X509_new()", __func__);
		goto err;
	}


	{	/*set distinguished name*/
		X509_NAME  *xn = X509_get_subject_name(x);

		if (xn == NULL) {
			error("%s: X.509 certificate without subject", __func__);
			goto err;
		}

		if (!x509key_str2X509NAME(subject, xn)) {
			error("%s: x509key_str2X509NAME fail", __func__);
			goto err;
		}
	}

	key->type = basetype;
	if (!ssh_x509_set_cert(key, x, NULL)) {
		error("%s: ssh_x509_set_cert fail", __func__);
		goto err;
	}
	goto done;

err:
	if (x != NULL)
		X509_free(x);
	if (key != NULL) {
		sshkey_free(key);
		key = NULL;
	}

done:
	debug3("x509key_from_subject: return %p", (void*)key);
	return key;
}


struct sshkey*
X509key_from_subject(const char *pkalg, const char *cp, char **ep) {
	struct sshkey *ret;

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return NULL;

	ret = x509key_from_subject(p->basetype, cp);
}

	if (ret != NULL && ep != NULL) {
		/* NOTE line with subject lack comment part */
		*ep = (char*)cp + strlen(cp);
	}

	return ret;
}


static struct sshkey*
x509_to_key(X509 *x509) {
	struct sshkey *key = NULL;
	EVP_PKEY *env_pkey;

	env_pkey = X509_get_pubkey(x509);
	if (env_pkey == NULL) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: X509_get_pubkey fail: '%s'"
		    , __func__, ebuf);
		return NULL;
	}
	/*else*/
	debug3("x509_to_key: X509_get_pubkey done!");

	switch (EVP_PKEY_id(env_pkey)) {
	case EVP_PKEY_RSA:
		key = sshkey_new(KEY_UNSPEC);
		key->rsa = EVP_PKEY_get1_RSA(env_pkey);
		key->type = KEY_RSA;
		(void)ssh_x509_set_cert(key, x509, NULL);
#ifdef DEBUG_PK
		RSA_print_fp(stderr, key->rsa, 8);
#endif
		break;

	case EVP_PKEY_DSA:
		key = sshkey_new(KEY_UNSPEC);
		key->dsa = EVP_PKEY_get1_DSA(env_pkey);
		key->type = KEY_DSA;
		(void)ssh_x509_set_cert(key, x509, NULL);
#ifdef DEBUG_PK
		DSA_print_fp(stderr, key->dsa, 8);
#endif
		break;

#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC: {
		const EC_POINT *q = NULL;

		key = sshkey_new(KEY_UNSPEC);
		key->ecdsa = EVP_PKEY_get1_EC_KEY(env_pkey);
		key->type = KEY_ECDSA;
		key->ecdsa_nid = sshkey_ecdsa_key_to_nid(key->ecdsa);
		if (key->ecdsa_nid < 0) {
			error("%s: unsupported elliptic curve", __func__);
			goto err;
		}
		q = EC_KEY_get0_public_key(key->ecdsa);
		if (q == NULL) {
			error("%s: cannot get public ec key ", __func__);
			goto err;
		}
		if (sshkey_ec_validate_public(EC_KEY_get0_group(key->ecdsa), q) != 0) {
			debug3("%s: cannot validate public ec key ", __func__);
			goto err;
		}
		(void)ssh_x509_set_cert(key, x509, NULL);
#ifdef DEBUG_PK
		sshkey_dump_ec_point(EC_KEY_get0_group(key->ecdsa), q);
#endif
		} break;
#endif /*def OPENSSL_HAS_ECC*/

	default:
		error("%s: unsupported EVP_PKEY type %d", __func__, EVP_PKEY_id(env_pkey));
	}

	EVP_PKEY_free(env_pkey);
	return key;

err:
	EVP_PKEY_free(env_pkey);
	sshkey_free(key);
	return NULL;
}


static int
X509_from_blob(const u_char *blob, size_t blen, X509 **xp) {
	int r;
	BIO *mbio;
	X509 *x;

	if (xp != NULL) *xp = NULL;

	if (blob == NULL) return SSH_ERR_INVALID_ARGUMENT;
	if (!(blen > 0)) return SSH_ERR_INVALID_ARGUMENT;

{	int mlen = (int)blen;
	if ((size_t)mlen != blen) return SSH_ERR_INVALID_ARGUMENT;

	mbio = BIO_new_mem_buf((void*)blob, mlen);
	if (mbio == NULL) return SSH_ERR_ALLOC_FAIL;
}

	/* read X509 certificate from BIO data */
	x = d2i_X509_bio(mbio, NULL);
	if (x == NULL) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		debug3("%s: can not read X.509 from memory BIO: '%s'"
		    , __func__, ebuf);
		r = SSH_ERR_INVALID_FORMAT;
		goto done;
	}

{	size_t k = BIO_ctrl_pending(mbio);
	if (k > 0) {
		error("%s: remaining bytes in X.509 blob %d", __func__, (int) k);
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto done;
	}
}

	if (xp != NULL) {
		*xp = x;
		x = NULL;
	}
	r = SSH_ERR_SUCCESS;

done:
	/* This call will walk the chain freeing all the BIOs */
	BIO_free_all(mbio);
	X509_free(x);
	return r;
}


int
X509key_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp) {
	int r;
	X509 *x = NULL;
	struct sshkey *key = NULL;

	if (keyp != NULL) *keyp = NULL;

	r = X509_from_blob(blob, blen, &x);
	if (r != SSH_ERR_SUCCESS) return r;

	key = x509_to_key(x);
	if (key == NULL) {
		X509_free(x);
		return SSH_ERR_ALLOC_FAIL;
	}

	if (keyp != NULL)
		*keyp = key;
	else
		sshkey_free(key);

	return SSH_ERR_SUCCESS;
}


static int
X509key_from_buf2_common(struct sshbuf *b, struct sshkey **keyp, char **pkalgp) {
	int r;
	u_int nc, no, k;
	const SSHX509KeyAlgs *xkalg = NULL;
	char  *pkalg = NULL;
	struct sshkey *key = NULL;

if ((SSHX_RFC6187_MISSING_KEY_IDENTIFIER & xcompat) == 0) {
	/* RFC6187: string  "algorithm-identifier" */
	r = sshbuf_get_cstring(b, &pkalg, NULL);
	if (r != 0) return SSH_ERR_INVALID_FORMAT;

{	/* check if algorithm is supported */
	int loc = -1;
	while ((loc = ssh_xkalg_nameind(pkalg, &xkalg, loc)) >= 0) {
		if (xkalg->chain) break;
	}
	if (loc < 0) {
		free(pkalg);
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}
}
}

	/* RFC6187: uint32  certificate-count */
	r = sshbuf_get_u32(b, &nc);
	if (r != 0) goto err;
	debug3("%s: certificate-count: %u", __func__, nc);

	if (nc > 100) {
		error("%s: the number of X.509 certificates"
		    " exceed limit(%d > 100)", __func__, nc);
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}
	if (nc < 1) {
		error("%s: at least one X.509 certificate"
		    " must present", __func__);
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}

{	/* RFC6187: string  certificate[1..certificate-count] */
	const u_char *xs;
	size_t        xlen;

	X509 *x;
	STACK_OF(X509) *pchain;

	r = sshbuf_get_string_direct(b, &xs, &xlen);
	if (r != SSH_ERR_SUCCESS) goto err;

	r = X509_from_blob(xs, xlen, &x);
	if (r != SSH_ERR_SUCCESS) goto err;

	debug3("%s: certificate[0]=%p", __func__, (void*)x);

	key = x509_to_key(x);
	if (key == NULL) {
		X509_free(x);
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}

	if (xkalg != NULL) {
		/* check if key match algorithm */
		if (
		    (key->type != xkalg->basetype) ||
		    (key->ecdsa_nid != xkalg->subtype)
		) {
			r = SSH_ERR_KEY_TYPE_MISMATCH;
			goto err;
		}
	} else {
		/* check if algorithm is supported (compatibility case) */
		if (ssh_xkalg_typeformind(key->type, key->ecdsa_nid,
			X509FORMAT_RFC6187, &xkalg, -1) < 0
		) {
			r = SSH_ERR_KEY_TYPE_UNKNOWN;
			goto err;
		}
	}

	if (!check_rsa2048_sha256(xkalg, key)) {
		r = SSH_ERR_KEY_LENGTH;
		goto err;
	}

{	SSH_X509 *xd = key->x509_data;

	if (xd == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	pchain = sk_X509_new_null();
	if (pchain == NULL) {
		error("X509key_from_buf2_common: out of memory (chain)");
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	xd->chain = pchain;
}

	for (k = 1; k < nc; k++) {
		r = sshbuf_get_string_direct(b, &xs, &xlen);
		if (r != SSH_ERR_SUCCESS) goto err;

		r = X509_from_blob(xs, xlen, &x);
		debug3("%s: certificate[%d]=%p", __func__, k, (void*)x);
		if (r != SSH_ERR_SUCCESS) goto err;

		sk_X509_insert(pchain, x, -1 /*last*/);
	}
}

	/* RFC6187: uint32  ocsp-response-count */
	r = sshbuf_get_u32(b, &no);
	if (r != 0) goto err;
	debug3("%s: ocsp-response-count: %u", __func__, no);

	/* The number of OCSP responses MUST NOT exceed the number of certificates. */
	if (no > nc) {
		error("%s: the number of OCSP responses(%d)"
		    " exceed the number of certificates(%d)",
		      __func__, no, nc);
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}

	/* RFC6187: string  ocsp-response[0..ocsp-response-count] */
	for (k = 0; k < no; k++) {
		const u_char *os;
		r = sshbuf_get_string_direct(b, &os, NULL);
		if (r != 0) goto err;

		/* nop */
	}

{	size_t l = sshbuf_len(b);
	if (l > 0) {
		error("%s: remaining bytes in key blob %zu", __func__, l);
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
	}
}

err:
	if (r != SSH_ERR_SUCCESS) {
		sshkey_free(key);
		free(pkalg);
		return r;
	}

	if (keyp != NULL)
		*keyp = key;
	if (pkalgp != NULL) {
		/* compatibility: if key identifier is missing */
		if (pkalg == NULL)
			pkalg = xstrdup(xkalg->name);
		*pkalgp = pkalg;
		pkalg = NULL;
	}
	free(pkalg);
	return SSH_ERR_SUCCESS;
}


static int
X509key_from_blob2(const char *pkalg, const u_char *blob, size_t blen, struct sshkey **keyp) {
	int r;
	struct sshkey *key = NULL;
	char *xpkalg = NULL;

	if (keyp != NULL) *keyp = NULL;

{	struct sshbuf *b = sshbuf_from(blob, blen);
	if (b == NULL) return SSH_ERR_ALLOC_FAIL;

	r = X509key_from_buf2_common(b, &key, &xpkalg);
	sshbuf_free(b);
}
	if (r != SSH_ERR_SUCCESS) goto done;

	if (strcmp(pkalg, xpkalg) != 0) {
		error("%s: public-key algorithm mismatch:"
		    " expected %.100s extracted %.100s",
		    __func__, pkalg, xpkalg);
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto done;
	}

	if (keyp != NULL) {
		*keyp = key;
		key= NULL;
	}

done:
	free(xpkalg);
	return r;
}


static int
x509key_check(const char* method, const struct sshkey *key) {
	SSH_X509 *xd;

	if (key == NULL)
		{ error("%.50s: no key", method); return 0; }

	if (!sshkey_is_x509(key))
		{ error("%.50s: cannot handle key type %d", method, key->type); return 0; }

	xd = key->x509_data;
	if (xd == NULL)
		{ error("%.50s: no X.509 identity", method); return 0; }

	if (xd->cert == NULL)
		{ error("%.50s: no X.509 certificate", method); return 0; }

	return 1;
}


static int
sshbuf_put_x509_f(
	struct sshbuf *b, X509 *x,
	int (*f)(struct sshbuf *, const void *, size_t)
) {
	void   *p;
	int     l, k;
	int     r;

	l = i2d_X509(x, NULL);
	p = xmalloc(l); /*fatal on error*/
	{
		u_char *q = p;
		k = i2d_X509(x, &q);
	}

	if (l == k)
		r = f(b, p, l);
	else
		r = SSH_ERR_ALLOC_FAIL;

	free(p);

	return r;
}


static inline int
sshbuf_put_x509(struct sshbuf *b, X509 *x) {
	return sshbuf_put_x509_f(b, x, sshbuf_put_string);
}


int
X509key_encode_identity(const char *pkalg, const struct sshkey *key, struct sshbuf *b) {
	const SSHX509KeyAlgs *xkalg;
	int ret;

	if (!sshkey_is_x509(key))
		return SSH_ERR_SUCCESS;

	if (ssh_xkalg_nameind(pkalg, &xkalg, -1) < 0)
		return SSH_ERR_SUCCESS;

	if (xkalg->chain) { /* RFC6187 format */
		struct sshbuf *d;

		d = sshbuf_new();
		if (d == NULL)
			return SSH_ERR_ALLOC_FAIL;

		ret = xkey_to_buf2(xkalg, key, d);
		if (ret != SSH_ERR_SUCCESS)
			debug3("%s: xkey_to_buf2 fail" , __func__);

		if (ret == SSH_ERR_SUCCESS)
			ret = sshbuf_put_stringb(b, d);

		sshbuf_free(d);
	} else
		ret = sshbuf_put_x509(b, key->x509_data->cert);

	return ret;
}


int
X509key_decode_identity(const char *pkalg, struct sshbuf *b, struct sshkey *k) {
	int RFC6187_format;
	struct sshkey *tkey = NULL;
	int ret;

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return SSH_ERR_SUCCESS;

	RFC6187_format = p->chain;
}

{	/* fetch X.509 key */
	u_char *blob = NULL;
	size_t blen;

	ret = sshbuf_get_string(b, &blob, &blen);
	if (ret != SSH_ERR_SUCCESS) goto end_key;

	ret = RFC6187_format
		? X509key_from_blob2(pkalg, blob, blen, &tkey)
		: X509key_from_blob(blob, blen, &tkey);
end_key:
	free(blob);
}
	if (ret == SSH_ERR_SUCCESS) {
		SSH_X509_free(k->x509_data);
		k->x509_data = tkey->x509_data;
		tkey->x509_data = NULL;
	}
	sshkey_free(tkey);

	return ret;
}


void
x509key_move_identity(struct sshkey *from, struct sshkey *to) {
	/* Temporary controls for key types based on enumerate.
	 *
	 * Caller is responsible to perform all controls before to call this
	 * method. For instance public key of X.509 certificate has to match
	 * plain public key.
	 * NOTE X.509 certificate may contain only distinguished name!
	 */
	if (!x509key_check("move_identity", from)) return;

	SSH_X509_free(to->x509_data);
	to->x509_data = from->x509_data;
	from->x509_data = NULL;
}


void
x509key_copy_identity(const struct sshkey *from, struct sshkey *to) {
	X509 *x;
	SSH_X509 *xd;
	STACK_OF(X509) *chain;
	STACK_OF(X509) *pchain;
	int n;

	if (!sshkey_is_x509(from)) return;

	if (!x509key_check("copy_identity", from))
		fatal("x509key_copy_identity: no X.509 identity");

	xd = to->x509_data;
	if (xd)
		SSH_X509_free_data(xd);
	else {
		xd = SSH_X509_new(); /*fatal on error*/
		to->x509_data = xd;
	}

	x = X509_dup(from->x509_data->cert);
	if (x == NULL)
		fatal("x509key_copy_identity: X509_dup failed");
	xd->cert = x;

	/* legacy keys does not use chain */
	chain = from->x509_data->chain;
	if (chain == NULL)
		return;

	pchain = sk_X509_new_null();
	if (pchain == NULL)
		fatal("x509key_copy_identity: sk_X509_new_null failed");
	xd->chain = pchain;

	for (n = 0; n < sk_X509_num(chain); n++) {
		x = sk_X509_value(chain, n);
		x = X509_dup(x);
		if (x == NULL)
			fatal("x509key_copy_identity: X509_dup failed");
		sk_X509_insert(pchain, x, -1 /*last*/);
	}
}


void
x509key_demote(const struct sshkey *k, struct sshkey *pk) {
	x509key_copy_identity(k, pk);
}


int
X509key_to_buf(const struct sshkey *key, struct sshbuf *b) {
	X509 *x;

	/* ensure that caller checks for non-null key argument */
{	SSH_X509 *xd;
	xd = key->x509_data;
	if (xd == NULL) return SSH_ERR_INVALID_FORMAT;
	if (xd->cert == NULL) return SSH_ERR_INVALID_FORMAT;
	x = xd->cert;
}
	return sshbuf_put_x509_f(b, x, sshbuf_put);
}


static int
xkey_to_buf2(const SSHX509KeyAlgs *xkalg, const struct sshkey *key, struct sshbuf *b) {
	STACK_OF(X509) *chain;
	int   r;
	u_int n;

	if (!x509key_check("xkey_to_buf2", key)) return 0;

	if (!check_rsa2048_sha256(xkalg, key))
		return SSH_ERR_KEY_LENGTH;

	/* RFC6187 key format */
	chain = key->x509_data->chain;
	if (chain == NULL) {
		/* NOTE Historic key algorithm use only one X.509
		 * certificate. Empty chain is protocol error for
		 * keys in RFC6187 format, but we accept them.
		 */
		verbose("X.509 certificate chain is not set."
		    " Remote host may refuse key.");
	}

	/* NOTE: sk_num returns -1 if argument is null */
	n = chain ? sk_X509_num(chain) : 0;

if ((SSHX_RFC6187_MISSING_KEY_IDENTIFIER & xcompat) == 0) {
	/* string  "algorithm-identifier" */
	r = sshbuf_put_cstring(b, xkalg->name);
	if (r != 0) goto end;
}

	/* uint32  certificate-count */
	r = sshbuf_put_u32(b, 1 + n);
	if (r != 0) goto end;

{	/* string  certificate[1..certificate-count] */
	X509  *x;
	u_int  i;

	x = key->x509_data->cert;
	r = sshbuf_put_x509(b, x);
	if (r != 0) goto end;
	for (i = 0; i < n; i++) {
		x = sk_X509_value(chain, i);
		r = sshbuf_put_x509(b, x);
		if (r != 0) goto end;
	}
}

	/* uint32  ocsp-response-count */
	r = sshbuf_put_u32(b, 0);
	if (r != 0) goto end;

	/* string  ocsp-response[0..ocsp-response-count] */
	/* nop */

end:
	return r;
}


char*
x509key_subject(const struct sshkey *key) {
	X509_NAME *dn;

	if (!x509key_check("x509key_subject", key)) return NULL;

	/* match format used in Xkey_write_subject */
	dn = X509_get_subject_name(key->x509_data->cert);
	return ssh_X509_NAME_oneline(dn);
}


int
x509key_write(const struct sshkey *key, struct sshbuf *b) {
	int r;
	struct sshbuf *b64;
	char *uu = NULL;

	b64 = sshbuf_new();
	if (b64 == NULL) return SSH_ERR_ALLOC_FAIL;

	r = X509key_to_buf(key, b64);
	if (r != 0) goto done;

	uu = sshbuf_dtob64_string(b64, 0);
	if (uu == NULL) goto done;

	r = sshbuf_putf(b, "%s %s", sshkey_ssh_name(key), uu);

done:
	free(uu);
	sshbuf_free(b64);

	return r;
}


int
Xkey_write_subject(const char *pkalg, const struct sshkey *key, FILE *f) {
	BIO  *out;

	if (!x509key_check("Xkey_write_subject", key)) return 0;

	if (pkalg == NULL) pkalg = sshkey_ssh_name(key);

	out = BIO_new_fp(f, BIO_NOCLOSE);
	if (out == NULL) return 0;
#ifdef VMS
	{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		out = BIO_push(tmpbio, out);
	}
#endif

	BIO_puts(out, pkalg);
	BIO_puts(out, " Subject:");
	ssh_X509_NAME_print(out, X509_get_subject_name(key->x509_data->cert));

	BIO_free_all(out);
	return 1;
}


static int
x509key_load_certs_bio(struct sshkey *key, BIO *bio) {
	int ret = 0;
	STACK_OF(X509) *chain;

	chain = sk_X509_new_null();
	if (chain == NULL) {
		fatal("x509key_load_certs_bio: out of memory");
		return -1; /*unreachable code*/
	}

	do {
		X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (x == NULL) break;

		sk_X509_insert(chain, x, -1 /*last*/);
	} while (1);
	debug3("%s loaded %d certificates", __func__, sk_X509_num(chain));

	/* clear OpenSSL "error buffer" */
	ERR_clear_error();

	key->x509_data->chain = chain;

	x509key_build_chain(key);

	ret = sk_X509_num(chain);

	return ret;
}


void
x509key_parse_cert(struct sshkey *key, EVP_PKEY *pk, BIO *bio) {
	X509 *x;
	SSH_X509 *xd;

	if (key == NULL) return;

	if (!ssh_x509_support_plain_type(key->type))
		return;

	debug3("read X.509 certificate begin");
	x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (x == NULL) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		debug3("%s: PEM_read_X509 fail: '%s'"
		    , __func__, ebuf);
		return;
	}

	if (!X509_check_private_key(x, pk)) {
		fatal("X.509 certificate don't match private key");
		/*unreachable code*/
	}

	xd = key->x509_data = SSH_X509_new(); /*fatal on error*/
	xd->cert = x;

	(void)x509key_load_certs_bio(key, bio);

	debug3("read X.509 certificate done: type %.40s", sshkey_type(key));
	return;
}


void
x509key_load_certs(const char *pkalg, struct sshkey *key, const char *filename) {
	size_t len;

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return;

#if 0
/* NOTE always load extra certificates as key may be used in either
 * in legacy format or in RFC6187 format!
 */
	/* return if public key algorithm is not in RFC6187 format */
	if (!p->chain)
		return;
#endif
}

	len = strlen(filename);
	if ((len > 9) &&
	    (strcmp (filename + len - 9,"-cert.pub") == 0)
	)	return;
	if ((len > 4) &&
	    (strcmp (filename + len - 4,".pub") != 0)
	)	return;

{	/* Remove .pub suffix and try to extract certificates from
	 * "private" key file. Note that for pkcs11 module we may
	 * have only "public" part.
	 */
	char file[PATH_MAX];

	if (strlcpy(file, filename, sizeof(file)) < len) {
		fatal("x509key_load_certs: length of filename exceed PATH_MAX");
		return; /*unreachable code*/
	}
	file[len - 4] = '\0';

{	BIO *bio = BIO_new_file(file, "r");
	if (bio != NULL) {
		(void)x509key_load_certs_bio(key, bio);
		BIO_free_all(bio);
	}
}
}

	return;
}


void
x509key_build_chain(struct sshkey *key) {
	SSH_X509 *x509_data;
	STACK_OF(X509)* chain;

	if (pssh_x509store_build_certchain == NULL) return;

	x509_data = key->x509_data;
	if (x509_data == NULL) return;

	chain = (*pssh_x509store_build_certchain)(x509_data->cert, x509_data->chain);
	if (chain == NULL) return;

	sk_X509_pop_free(x509_data->chain, X509_free);
	x509_data->chain = chain;

	debug3("%s length=%d", __func__, sk_X509_num(chain));
}


static int
x509key_write_bio_cert(BIO *out, X509 *x509) {
	int  ret = 0;

	BIO_puts(out, "issuer= ");
	ssh_X509_NAME_print(out, X509_get_issuer_name(x509));
	BIO_puts(out, "\n");

	BIO_puts(out, "subject= ");
	ssh_X509_NAME_print(out, X509_get_subject_name(x509));
	BIO_puts(out, "\n");

	{
		const char *alstr = (const char*)X509_alias_get0(x509, NULL);
		if (alstr == NULL) alstr = "<No Alias>";
		BIO_puts(out, alstr);
		BIO_puts(out, "\n");
	}

	ret = PEM_write_bio_X509(out, x509);
	if (!ret) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: PEM_write_bio_X509 fail: '%s'",
		    __func__, ebuf);
	}

	return ret;
}


int/*bool*/
x509key_write_identity_bio_pem(
	BIO *bio,
	const struct sshkey *key
) {
	int flag = 0;
	X509 *x;
	STACK_OF(X509) *chain;
	int k;

	if (!x509key_check("save_identity_pem", key)) return 0;

	x = key->x509_data->cert;
	flag = x509key_write_bio_cert(bio, x);
	if (!flag)
		goto done;

	chain = key->x509_data->chain;
	if (chain == NULL)
		goto done;

	for (k = 0; k < sk_X509_num(chain); k++) {
		x = sk_X509_value(chain, k);
		flag = x509key_write_bio_cert(bio, x);
		if (!flag)
			goto done;
	}

done:
	return flag;
}


/*
 * We can check only by Subject (Distinguished Name):
 *   - sshd receive from client only x509 certificate !!!
 *   - sshadd -d ... send only x509 certificate !!!
 *   - otherwise key might contain private key
 */
int
ssh_x509_equal(const struct sshkey *a, const struct sshkey *b) {
	X509 *xa;
	X509 *xb;

	if (!x509key_check("ssh_x509_equal", a)) return 1;
	if (!x509key_check("ssh_x509_equal", b)) return -1;

	xa = a->x509_data->cert;
	xb = b->x509_data->cert;
#if 1
/*
 * We must use own method to compare two X509_NAMEs instead of OpenSSL
 * function[s]! See notes before body of "ssh_X509_NAME_cmp()".
 */
	{
		X509_NAME *nameA = X509_get_subject_name(xa);
		X509_NAME *nameB = X509_get_subject_name(xb);
		return ssh_X509_NAME_cmp(nameA, nameB);
	}
#else
	return X509_subject_name_cmp(xa, xb);
#endif
}


int
ssh_x509key_type(const char *name) {
	const SSHX509KeyAlgs *p;

	if (name == NULL) {
		fatal("ssh_x509key_type: name is NULL");
		return KEY_UNSPEC; /*unreachable code*/
	}

	if (ssh_xkalg_nameind(name, &p, -1) < 0)
		return KEY_UNSPEC;

	return p->basetype;
}


const char*
ssh_x509key_name(const struct sshkey *k) {
	const SSHX509KeyAlgs *p;
	int n;

	if (k == NULL) {
		fatal("ssh_x509key_name: key is NULL");
		return NULL; /*unreachable code*/
	}
	if (!sshkey_is_x509(k)) return NULL;

	n = ssh_xkalg_typeind(k->type, k->ecdsa_nid, &p, -1);
	if (n >= 0) return p->name;

	return NULL;
}


const char**
Xkey_algoriths(const struct sshkey *key) {
	const char **ret;
	int n;

	if (key == NULL) return NULL;

	/* array with (n + 1) items, last item is always NULL */
	ret = xmalloc(sizeof(*ret)); /*fatal on error*/
	n = 0;
	ret[n] = NULL;

	if (!sshkey_is_x509(key)) goto plain_alg;
{	/* list all X.509 algorithms first */
	const SSHX509KeyAlgs *xkalg;
	int loc;

	for (
	    loc = ssh_xkalg_typeind(key->type, key->ecdsa_nid, &xkalg, -1);
	    loc >= 0;
	    loc = ssh_xkalg_typeind(key->type, key->ecdsa_nid, &xkalg, loc)
	) {
		const char *s = xkalg->name;
		int k;

		if (!check_rsa2048_sha256(xkalg, key))
			continue;

		/* avoid duplicates */
		for (k = 0; k < n; k++) {
			if (strcmp(s, ret[k]) == 0)
				break;
		}
		if (k < n) continue;

		ret = realloc(ret, sizeof(*ret) * (n + 2));
		if (ret == NULL) return NULL;
		ret[n++] = s;
		ret[n] = NULL;
	}
}

plain_alg:
{	/* add plain algorithm */
	ret = realloc(ret, sizeof(*ret) * (n + 2));
	if (ret == NULL) return NULL;

	ret[n++] = sshkey_name_from_types(key->type, key->ecdsa_nid);
	ret[n] = NULL;

	/* add extra algorithms */
#ifdef HAVE_EVP_SHA256
	switch (key->type) {
	case KEY_RSA: {
		/* for RSA we also support SHA2 algorithms */
		ret = realloc(ret, sizeof(*ret) * (n + 3));
		if (ret == NULL) return NULL;

		ret[n++] = "rsa-sha2-256";
		ret[n++] = "rsa-sha2-512";
		ret[n] = NULL;
		} break;
	}
#endif /*def HAVE_EVP_SHA256*/
}

	return ret;
}


static int
ssh_x509_EVP_PKEY_sign(
	EVP_PKEY *privkey, const ssh_x509_md *dgst,
	u_char *sigret, u_int *siglen,
	const u_char *data, u_int datalen
) {
	int ret;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		error("ssh_x509_EVP_PKEY_sign: out of memory");
		return -1;
	}

	ret = EVP_SignInit_ex(ctx, dgst->evp, NULL);
	if (ret <= 0) {
		error("%s: init fail", __func__);
		goto done;
	}

	ret = EVP_SignUpdate(ctx, data, datalen);
	if (ret <= 0) {
		error("%s: update fail", __func__);
		goto done;
	}

	ret = dgst->SignFinal(ctx, sigret, siglen, privkey);
	if (ret <= 0) {
		error("%s: final fail", __func__);
		goto done;
	}

done:
	EVP_MD_CTX_free(ctx);
	return ret;
}


static int
ssh_x509_sign(
	const SSHX509KeyAlgs *xkalg, ssh_sign_ctx *ctx,
	u_char **sigp, size_t *lenp, const u_char *data, size_t datalen
) {
	int r;
	const struct sshkey *key = ctx->key;
	int  keylen = 0;
	u_char *sigret = NULL;
	u_int  siglen;

	debug3("ssh_x509_sign: key alg/type/name: %s/%s/%s",
	    ctx->alg, sshkey_type(key), sshkey_ssh_name(key));
	debug3("ssh_x509_sign: compatibility: { 0x%08x, 0x%08x }",
	    ctx->compat->datafellows, ctx->compat->extra);

{	/* compute signature */
	EVP_PKEY *privkey = EVP_PKEY_new();
	int res = -1;

	if (privkey == NULL) {
		error("ssh_x509_sign: out of memory - EVP_PKEY_new");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}
	r = SSH_ERR_SUCCESS;

	if (key->rsa)
		res = EVP_PKEY_set1_RSA(privkey, key->rsa);
	else if (key->dsa)
		res = EVP_PKEY_set1_DSA(privkey, key->dsa);
#ifdef OPENSSL_HAS_ECC
	else if (key->ecdsa)
		res = EVP_PKEY_set1_EC_KEY(privkey, key->ecdsa);
#endif
	else {
		error("ssh_x509_sign: missing private key");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto end_sign_pkey;
	}

	if (!res) { /*EVP_PKEY_set1_... returns boolean*/
		error("ssh_x509_sign: EVP_PKEY_set1_XXX: fail");
		log_crypto_errors(SYSLOG_LEVEL_ERROR, __func__);
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto end_sign_pkey;
	}

	keylen = EVP_PKEY_size(privkey);
	if (keylen <= 0) {
		error("ssh_x509_sign: cannot get key size");
		log_crypto_errors(SYSLOG_LEVEL_ERROR, __func__);
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto end_sign_pkey;
	}

	/* NOTE:
	 * allocate extra size as signature like this for ecdsa
	 * keys contain bytes with size of encoded items
	 */
	sigret = xmalloc(keylen+20/*?*/); /*fatal on error*/

	debug3("ssh_x509_sign: alg=%.50s, md=%.30s", xkalg->name, xkalg->dgst.name);

{	u_int len = datalen;

	if ((size_t)len != datalen) {
		r = SSH_ERR_INVALID_FORMAT;
		goto end_sign_pkey;
	}
{	ssh_x509_md dgst;
	ssh_xkalg_dgst_compat(&dgst, &xkalg->dgst, ctx->compat);

	res = ssh_x509_EVP_PKEY_sign(privkey, &dgst, sigret, &siglen, data, len);
}
	if (res <= 0) {
		log_crypto_errors(SYSLOG_LEVEL_ERROR, __func__);
		r = SSH_ERR_LIBCRYPTO_ERROR;
	}
}

end_sign_pkey:
	EVP_PKEY_free(privkey);
}
	if (r != SSH_ERR_SUCCESS) goto done;

{	/* create ssh signature blob */
	struct sshbuf *buf;
	const char *signame;

	buf = sshbuf_new();
	if (buf == NULL) {
		error("ssh_x509_sign: out of memory - sshbuf_new");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	signame = X509PUBALG_SIGNAME(xkalg);
	debug3("ssh_x509_sign: signame=%.50s", signame);

	r = sshbuf_put_cstring(buf, signame);
	if (r != 0) goto end_sign_blob;

	r = sshbuf_put_string(buf, sigret, siglen);
	if (r != 0) goto end_sign_blob;

{	size_t len = sshbuf_len(buf);
	if (sigp != NULL) {
		*sigp = xmalloc(len); /*fatal on error*/
		memcpy(*sigp, sshbuf_ptr(buf), len);
	}
	if (lenp != NULL)
		*lenp = len;
}

end_sign_blob:
	sshbuf_free(buf);
}

done:
	if (sigret != NULL) {
		memset(sigret, 's', keylen+20);
		free(sigret);
	}

	debug3("ssh_x509_sign: return %d", r);
	return r;
}


static int
ssh_xkalg_verify(
	EVP_PKEY* pubkey, const ssh_x509_md *dgst,
	u_char *sigblob, u_int len, const u_char *data, u_int datalen
) {
	int ret;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		error("ssh_xkalg_verify: out of memory");
		return -1;
	}

	ret = EVP_VerifyInit(ctx, dgst->evp);
	if (ret <= 0) {
		error("%s: verify-init fail", __func__);
		goto done;
	}

	ret = EVP_VerifyUpdate(ctx, data, datalen);
	if (ret <= 0) {
		error("%s: verify-update fail", __func__);
		goto done;
	}

	ret = dgst->VerifyFinal(ctx, sigblob, len, pubkey);
	if (ret <= 0) {
		error("%s: verify-final fail", __func__);
		goto done;
	}

done:
	EVP_MD_CTX_free(ctx);
	return ret;
}


static int
ssh_x509_verify(
	ssh_sign_ctx *ctx,
	const u_char *sig, size_t siglen,
	const u_char *data, size_t dlen
) {
	int r = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey *key;
	const SSHX509KeyAlgs *xkalg;
	int loc;
	EVP_PKEY* pubkey;
	u_char *sigblob = NULL;
	u_int len = 0;
	u_int datalen;

	key = ctx->key;
	debug3("ssh_x509_verify:  key alg/type/name: %s/%s/%s",
	    ctx->alg, sshkey_type(key), sshkey_ssh_name(key));
	debug3("ssh_x509_verify: compatibility: { 0x%08x, 0x%08x }",
	    ctx->compat->datafellows, ctx->compat->extra);

	loc = ssh_xkalg_nameind(ctx->alg, &xkalg, -1);
	if (loc < 0) {
		error("ssh_x509_verify: cannot handle algorithm"
		    " '%s' for key type %d[, curve %d]",
		    ctx->alg, key->type, key->ecdsa_nid);
		return SSH_ERR_INVALID_ARGUMENT;
	}

	pubkey = X509_get_pubkey(key->x509_data->cert);
	if (pubkey == NULL) {
		error("ssh_x509_verify: no 'X.509 public-key'");
		return SSH_ERR_INVALID_ARGUMENT;
	}

	if (dlen > INT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;
	datalen = dlen;

	/* process signature */
{	struct sshbuf *buf;

	buf = sshbuf_new();
	if (buf == NULL) {
		error("ssh_x509_verify: out of memory - sshbuf_new");
		return SSH_ERR_ALLOC_FAIL;
	}

	r = sshbuf_put(buf, sig, siglen);
	if (r != 0) goto end_sign_blob;

	/* check signature name */
{	u_char *sigformat;

	r = sshbuf_get_string(buf, &sigformat, NULL);
	if (r != 0) goto end_sign_blob;

	debug3("ssh_x509_verify: signature name = %.40s", sigformat);
	if (!ssh_is_x509signame(sigformat)) {
		error("ssh_x509_verify: cannot handle signature name %.40s", sigformat);
		r = SSH_ERR_INVALID_FORMAT;
	}
	free(sigformat);
}
	if (r != 0) goto end_sign_blob;

	/* extract signature blob */
{	size_t lenblob = 0;

	r = sshbuf_get_string(buf, &sigblob, &lenblob);
	if (r != 0) goto end_sign_blob;

	if (lenblob > INT_MAX) {
		r = SSH_ERR_SIGNATURE_INVALID;
		len = INT_MAX;
		goto end_sign_blob;
	}
	len = lenblob;
}

	/* check consistency */
{	size_t rlen = sshbuf_len(buf);
	if (rlen != 0) {
		error("ssh_x509_verify: remaining bytes in signature %zu", rlen);
		r = SSH_ERR_INVALID_FORMAT;
	}
}

end_sign_blob:
	sshbuf_free(buf);
}
	if (r != 0) goto done;

	 /* verify signed data */
{	int ret;
	for (; loc >= 0; loc = ssh_xkalg_nameind(ctx->alg, &xkalg, loc)) {
		const ssh_x509_md *dgst = &xkalg->dgst;
		debug3("ssh_x509_verify: md=%.30s, loc=%d", dgst->name, loc);

		ret = ssh_xkalg_verify(pubkey, dgst, sigblob, len, data, datalen);
		if (ret > 0) break;

		log_crypto_errors(SYSLOG_LEVEL_ERROR, __func__);
	}
	if (ret <= 0) {
		debug3("ssh_x509_verify: failed for all digests");
		r = SSH_ERR_SIGNATURE_INVALID;
	}
}

done:
	if (sigblob) {
		memset(sigblob, 's', len);
		free(sigblob);
		sigblob = NULL;
	}
	EVP_PKEY_free(pubkey);

	debug3("ssh_x509_verify: return %d", r);
	return r;
}


int
Xkey_sign(ssh_sign_ctx *ctx,
	  u_char **sigp, size_t *lenp,
	  const u_char *data, size_t datalen
) {
	struct sshkey *key = ctx->key;
	const SSHX509KeyAlgs *xkalg;

	if (ctx->alg == NULL)
		ctx->alg = sshkey_ssh_name(key);

	/* check if public algorithm is with X.509 certificates */
	if (ssh_xkalg_nameind(ctx->alg, &xkalg, -1) < 0) {
		int ret = sshkey_sign(key, sigp, lenp,
		    data, datalen, ctx->alg, ctx->compat->datafellows);
		if (ret == SSH_ERR_LIBCRYPTO_ERROR)
			log_crypto_errors(SYSLOG_LEVEL_ERROR, __func__);
		else
			debug3("%s: return %d", __func__, ret);
		return ret;
	}

{
	int is_shielded = sshkey_is_shielded(key);
	int ret;

	if ((ret = sshkey_unshield_private(key)) != 0)
		goto done;

	ret = ssh_x509_sign(xkalg, ctx, sigp, lenp, data, datalen);

	if (is_shielded) {
		int r = sshkey_shield_private(key);
		if (ret == 0) ret = r;
	}

done:
	debug3("%s: return %d", __func__, ret);
	return ret;
}
}


int
Xkey_check_sigalg(ssh_sign_ctx *ctx, const u_char *sig, size_t siglen) {
	int r;
	const SSHX509KeyAlgs *p;

	/* check if public algorithm is with X.509 certificates */
	if (ssh_xkalg_nameind(ctx->alg, &p, -1) < 0)
		return sshkey_check_sigtype(sig, siglen, ctx->alg);

{	char *sigalg = NULL;
	const char *expalg;

	r = sshkey_sigtype(sig, siglen, &sigalg);
	if (r < 0) goto out;

	expalg = X509PUBALG_SIGNAME(p);
	if (strcmp(expalg, sigalg) != 0) {
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		error("different signature algorithm - expected %s, got %s",
		    expalg, sigalg);
	}
	free(sigalg);
}

out:
	return r;
}


int
Xkey_verify(ssh_sign_ctx *ctx,
	    const u_char *sig, size_t siglen,
	    const u_char *data, size_t dlen
) {
	if (ctx->alg == NULL)
		ctx->alg = sshkey_ssh_name(ctx->key);

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(ctx->alg, &p, -1) < 0) {
		if (ctx->key->type == KEY_RSA_CERT &&
		    check_compat_fellows(ctx->compat, SSH_BUG_SIGTYPE)) {
			ctx->alg = NULL;
		}
		return sshkey_verify(ctx->key, sig, siglen,
		     data, dlen, ctx->alg, ctx->compat->datafellows);
	}
}

	return ssh_x509_verify(ctx, sig, siglen, data, dlen);
}


int
xkey_validate_cert(const struct sshkey *k) {
	if (!x509key_check("verify_cert", k))
		return SSH_ERR_INVALID_ARGUMENT;

	if (pssh_x509store_verify_cert == NULL) {
		error("%s: pssh_x509store_verify_cert is NULL", __func__);
		return SSH_ERR_INTERNAL_ERROR;
	}

{	SSH_X509 *xd = k->x509_data;
	return pssh_x509store_verify_cert(xd->cert, xd->chain) > 0
		? SSH_ERR_SUCCESS
		: SSH_ERR_KEY_CERT_INVALID;
}
}


u_int
ssh_x509_key_size(const struct sshkey *key) {
	EVP_PKEY *pkey;
	int k = 0;

	if (!x509key_check("key_size", key)) goto done;

	pkey = X509_get_pubkey(key->x509_data->cert);
	if (pkey == NULL) goto done;

	/* NOTE BN_num_bits returns int! */
	switch(EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA: {
		RSA *rsa;
		const BIGNUM *n;

		rsa = EVP_PKEY_get0_RSA(pkey);
		RSA_get0_key(rsa, &n, NULL, NULL);
		k = BN_num_bits(n);
		} break;
	case EVP_PKEY_DSA: {
		DSA *dsa;
		const BIGNUM *p;

		dsa = EVP_PKEY_get0_DSA(pkey);
		DSA_get0_pqg(dsa, &p, NULL, NULL);
		k = BN_num_bits(p);
		} break;
#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC: {
		int     ecdsa_nid;
		{
			EC_KEY *ecdsa = EVP_PKEY_get0_EC_KEY(pkey);
			ecdsa_nid = sshkey_ecdsa_key_to_nid(ecdsa);
		}
		k = sshkey_curve_nid_to_bits(ecdsa_nid);
		} break;
#endif
	default:
		fatal("ssh_x509_key_size: unknown EVP_PKEY type %d", EVP_PKEY_id(pkey));
		/*unreachable code*/
	}
	EVP_PKEY_free(pkey);
done:
	return (u_int) k;
}


int/*bool*/
ssh_x509_set_cert(struct sshkey *key, X509 *x509, STACK_OF(X509) *untrusted) {
	int ret = 0;
	SSH_X509 *xd;

	if (key == NULL) {
		fatal("%s: key is NULL", __func__);
		goto done; /*unreachable code*/
	}

{	int k_type = sshkey_type_plain(key->type);
	if (!ssh_x509_support_plain_type(k_type)) {
		fatal("%s: unsupported key type %d", __func__, key->type);
		goto done; /*unreachable code*/
	}
}

	xd = key->x509_data;
	if (xd != NULL) {
		if (xd->cert != NULL) {
			fatal("%s: X.509 certificate is already set", __func__);
			goto done; /*unreachable code*/
		}
	} else
		xd = key->x509_data = SSH_X509_new(); /*fatal on error*/

	xd->cert = x509;

	if (untrusted != NULL) {
		for (x509 = sk_X509_pop(untrusted); x509 != NULL; x509 = sk_X509_pop(untrusted)) {
			sk_X509_push(xd->chain, x509);
		}
		x509key_build_chain(key);
	}

	ret = 1;
done:
	return ret;
}


int
ssh_x509_cmp_cert(const struct sshkey *key1, const struct sshkey *key2) {
	/* only dns.c call this function so skip checks ...
	if (!x509key_check("cmp_cert", key1)) return -1;
	if (!x509key_check("cmp_cert", key2)) return 1;
	*/
	return X509_cmp(key1->x509_data->cert, key2->x509_data->cert);
}


int
Xkey_from_blob(const char *pkalg, const u_char *blob, size_t blen, struct sshkey **keyp) {
	int RFC6187_format;

	if (pkalg == NULL) {
		error("%s: pkalg is NULL", __func__);
		return SSH_ERR_INVALID_ARGUMENT;
	}

	debug3("%s() pkalg='%s', blen=%zu", __func__, pkalg, blen);

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return sshkey_from_blob(blob, blen, keyp);

	RFC6187_format = p->chain;
}
	return RFC6187_format
		? X509key_from_blob2(pkalg, blob, blen, keyp)
		: X509key_from_blob(blob, blen, keyp);
}


struct sshkey*
xkey_from_blob(const char *pkalg, const u_char *blob, u_int blen) {
	struct sshkey* key;
	int r;

	r = Xkey_from_blob(pkalg, blob, (size_t) blen, &key);

	return (r == SSH_ERR_SUCCESS) ? key : NULL;
}


int
Xkey_to_blob(const char *pkalg, const struct sshkey *key, u_char **blobp, size_t *lenp) {
	const SSHX509KeyAlgs *xkalg;

	if (pkalg == NULL) return SSH_ERR_INVALID_ARGUMENT;
	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	if (ssh_xkalg_nameind(pkalg, &xkalg, -1) < 0)
		return sshkey_to_blob(key, blobp, lenp);

{	struct sshbuf *b = sshbuf_new();
	if (b == NULL) return SSH_ERR_ALLOC_FAIL;

{	int ret = xkalg->chain /* RFC6187 format */
		? xkey_to_buf2(xkalg, key, b)
		: X509key_to_buf(key, b);
	if (ret != SSH_ERR_SUCCESS) return ret;
}

{	size_t len = sshbuf_len(b);
	if (lenp != NULL) *lenp = len;
	if (blobp != NULL) {
		*blobp = xmalloc(len);
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
}

	sshbuf_free(b);

	return SSH_ERR_SUCCESS;
}
}


int
xkey_to_blob(const char *pkalg, const struct sshkey *key, u_char **blobp, u_int *lenp) {
	size_t len;

{	int r = Xkey_to_blob(pkalg, key, blobp, &len);
	if (r != SSH_ERR_SUCCESS) return 0;
}

	/*cast from size_t to u_int is save*/
	if (lenp != NULL) *lenp = len;

	return len;
}


int
X509key_from_buf(struct sshbuf *b, struct sshkey **keyp) {
	int r;
	struct sshkey *key;

	if (b == NULL) return SSH_ERR_INVALID_ARGUMENT;

{	const u_char *blob = sshbuf_ptr(b);
	size_t blen = sshbuf_len(b);

	r = X509key_from_blob(blob, blen, &key);
	if (r != SSH_ERR_SUCCESS) goto done;
}
{	/* rewind buffer */
	size_t blen = i2d_X509(key->x509_data->cert, NULL);

	r = sshbuf_consume(b, blen);
	if (r != SSH_ERR_SUCCESS) goto done;
}

	if (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}

done:
	sshkey_free(key);
	return r;
}


int
Akey_puts_opts(
	const struct sshkey *key, struct sshbuf *b,
	enum sshkey_serialize_rep opts
) {
	if (!sshkey_is_x509(key))
		return sshkey_puts_opts(key, b, opts);

{	X509 *x;
	SSH_X509 *xd;

	xd = key->x509_data;
	if (xd == NULL) return SSH_ERR_INVALID_FORMAT;

	x = xd->cert;
	if (x == NULL) return SSH_ERR_INVALID_FORMAT;

	return sshbuf_put_x509(b, x);
}
}


int
Akey_gets(struct sshbuf *b, struct sshkey **keyp) {
	int r;

{	u_char *blob;
	size_t blen;

	r = sshbuf_get_string(b, &blob, &blen);
	if (r != 0) return r;

	r = X509key_from_blob(blob, blen, keyp);
	if (r != SSH_ERR_INVALID_FORMAT) return r;
}

	return sshkey_froms(b, keyp);
}


int
Akey_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp) {
	if (!sshkey_is_x509(key))
		return sshkey_to_blob(key, blobp, lenp);

{	struct sshbuf *b;
	int r;

	b = sshbuf_new();
	if (b == NULL) return SSH_ERR_ALLOC_FAIL;

	r = X509key_to_buf(key, b);
	if (r != 0) goto done;

{	size_t len = sshbuf_len(b);

	if (blobp != NULL) {
		u_char *blob = malloc(len);
		if (blob == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto done;
		}
		memmove(blob, sshbuf_ptr(b), len);
		*blobp = blob;
	}

	if (lenp != NULL) *lenp = len;
}
done:
	sshbuf_free(b);
	return r;
}
}


int
Akey_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp) {
	int r = 0;
	/* Note specific agent serialization for X.509 keys:
	 * process_request_identities()
	 * -> sshkey_puts() //=Akey_puts
	 *   -> to_blob_buf()
	 *     -> X509key_to_buf()
	 */
	/* for X.509 certificate encoded in DER: 0x30 - SEQUENCE */
	if ((blen > 1) && (blob[0] == 0x30)) {
		r = X509key_from_blob(blob, blen, keyp);
		if (r == 0)
			x509key_build_chain(*keyp);
		return r;
	}

	return sshkey_from_blob(blob, blen, keyp);
}


int
Xkey_puts(const char *pkalg, const struct sshkey *key, struct sshbuf *b) {
	const SSHX509KeyAlgs *xkalg;
	int r;

	if (pkalg == NULL) return SSH_ERR_INVALID_ARGUMENT;
	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	if (ssh_xkalg_nameind(pkalg, &xkalg, -1) < 0)
		return sshkey_puts(key, b);

	if (xkalg->chain) { /* RFC6187 format */
		struct sshbuf *d = sshbuf_new();
		if (d == NULL) return SSH_ERR_ALLOC_FAIL;

		r = xkey_to_buf2(xkalg, key, d);
		if (r != SSH_ERR_SUCCESS)
			debug3("%s: xkey_to_buf2 fail" , __func__);
		else
			r = sshbuf_put_stringb(b, d);

		sshbuf_free(d);
	} else
		r = sshbuf_put_x509(b, key->x509_data->cert);

	return r;
}


int
Xkey_putb(const char *pkalg, const struct sshkey *key, struct sshbuf *b) {
	const SSHX509KeyAlgs *xkalg;

	if (pkalg == NULL) return SSH_ERR_INVALID_ARGUMENT;
	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	if (ssh_xkalg_nameind(pkalg, &xkalg, -1) < 0)
		return sshkey_putb(key, b);

	return xkalg->chain /* RFC6187 format */
		? xkey_to_buf2(xkalg, key, b)
		: X509key_to_buf(key, b);
}


int
parse_key_from_blob(
	const u_char *blob, size_t blen,
	struct sshkey **keyp, char **pkalgp
) {
	int r;

if ((blen > 1) && (blob[0] == 0x30)) {
	/* try legacy X.509 keys - blob is an certificate
	   encoded in DER format: 0x30 - SEQUENCE */
	r = X509key_from_blob(blob, blen, keyp);
	if ((r == SSH_ERR_SUCCESS) && (pkalgp != NULL) && (keyp != NULL)) {
		struct sshkey *k = *keyp;
		const SSHX509KeyAlgs *p;

		if (ssh_xkalg_typeformind(k->type, k->ecdsa_nid, X509FORMAT_LEGACY, &p, -1) < 0)
			return SSH_ERR_KEY_TYPE_UNKNOWN;

		*pkalgp = xstrdup(p->name);
	}
	if (r != SSH_ERR_INVALID_FORMAT) return r;
}
{	/* try RFC 6187 formats */
	{	struct sshbuf *b = sshbuf_from(blob, blen);
		if (b == NULL) return SSH_ERR_ALLOC_FAIL;
		r = X509key_from_buf2_common(b, keyp, pkalgp);
		sshbuf_free(b);
	}

	if (r == SSH_ERR_SUCCESS) return r;
}

	/* try non X.509 key formats */
	r = sshkey_from_blob(blob, blen, keyp);
	if ((r == SSH_ERR_SUCCESS) && (pkalgp != NULL) && (keyp != NULL))
		*pkalgp = xstrdup(sshkey_ssh_name(*keyp));

	return r;
}
