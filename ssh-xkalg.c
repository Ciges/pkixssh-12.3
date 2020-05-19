/*
 * Copyright (c) 2005-2019 Roumen Petrov.  All rights reserved.
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

#include "ssh-xkalg.h"
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "match.h"
#include "myproposal.h"
#include "xmalloc.h"
#include "evp-compat.h"
#include "compat.h"

#define SHARAW_DIGEST_LENGTH (2*SHA_DIGEST_LENGTH)


#ifdef OPENSSL_NO_DSA
#  error "OPENSSL_NO_DSA"
#endif
#ifdef OPENSSL_NO_SHA
#  error "OPENSSL_NO_SHA"
#endif


static int
DSS1RAW_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey) {
	int ret;
	unsigned char buf[20+2*(SHA_DIGEST_LENGTH)];
	unsigned int  len;

	ret = EVP_SignFinal(ctx, buf, &len, pkey);
	if (ret <= 0) goto done;

	ret = -1;
{
	DSA_SIG *sig;

{	/* decode DSA signature */
	const unsigned char *psig = buf;
	sig = d2i_DSA_SIG(NULL, &psig, (long)len);
}

	*siglen = SHARAW_DIGEST_LENGTH;
	if (sig != NULL) {
		const BIGNUM *ps, *pr;
		u_int rlen, slen;

		DSA_SIG_get0(sig, &pr, &ps);

		rlen = BN_num_bytes(pr);
		slen = BN_num_bytes(ps);

		if (rlen > SHA_DIGEST_LENGTH || slen > SHA_DIGEST_LENGTH) {
			error("%s: bad sig size %u %u", __func__, rlen, slen);
			goto done;
		}

		explicit_bzero(sigret, SHARAW_DIGEST_LENGTH);
		BN_bn2bin(pr, sigret + SHARAW_DIGEST_LENGTH - SHA_DIGEST_LENGTH - rlen);
		BN_bn2bin(ps, sigret + SHARAW_DIGEST_LENGTH - slen);

		ret = 1;
	}
	DSA_SIG_free(sig);
}
done:
	return(ret);
}


static int
DSS1RAW_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey) {
	int ret = -1;
	unsigned char *buf = NULL;
	int len;

	if (siglen != SHARAW_DIGEST_LENGTH) return(ret);

{	BIGNUM *ps, *pr;
	DSA_SIG *sig;

	pr = BN_bin2bn(sigbuf                  , SHA_DIGEST_LENGTH, NULL);
	ps = BN_bin2bn(sigbuf+SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, NULL);
	if ((pr == NULL) || (ps == NULL)) goto parse_err;

	sig = DSA_SIG_new();
	if (sig == NULL) goto parse_err;

	if (DSA_SIG_set0(sig, pr, ps))
		goto encode;

	DSA_SIG_free(sig);
parse_err:
	BN_free(pr);
	BN_free(ps);
	return(ret);


encode:
	len = i2d_DSA_SIG(sig, NULL);
	if (len <= 0) goto done;

	buf = xmalloc(len);  /*fatal on error*/

{	/* encode DSA signature */
	unsigned char *pbuf = buf;
	len = i2d_DSA_SIG(sig, &pbuf);
}

	DSA_SIG_free(sig);

	if (len <= 0) goto done;
}

	ret = EVP_VerifyFinal(ctx, buf, len, pkey);

done:
	if (buf != NULL) {
		explicit_bzero(buf, len);
		free(buf);
	}
	return(ret);
}


#ifdef OPENSSL_HAS_ECC
static int
SSH_ECDSA_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey) {
	ECDSA_SIG *sig;
	unsigned int len;

{	int ret;
	unsigned char buf[20+2*(SHA512_DIGEST_LENGTH)];

	ret = EVP_SignFinal(ctx, buf, &len, pkey);
	if (ret <= 0) return(ret);

{	/* decode ECDSA signature */
	const unsigned char *psig = buf;
	sig = d2i_ECDSA_SIG(NULL, &psig, (long)len);
}

	if (sig == NULL) return(-1);
}

/* encode ECDSA r&s into SecSH signature blob */
{	int r;
	struct sshbuf *buf = NULL;
	const BIGNUM *pr, *ps;

	buf = sshbuf_new();
	if (buf == NULL) goto encode_err;

	ECDSA_SIG_get0(sig, &pr, &ps);

	r = sshbuf_put_bignum2(buf, pr);
	if (r != 0) goto encode_err;

	r = sshbuf_put_bignum2(buf, ps);
	if (r != 0) goto encode_err;

	len = sshbuf_len(buf);
	if ((size_t)len != sshbuf_len(buf)) goto encode_err;

	memcpy(sigret, sshbuf_ptr(buf), len);
	*siglen = len;
	return(1);

encode_err:
	sshbuf_free(buf);
	ECDSA_SIG_free(sig);
	return(-1);
}
}
#endif /*def OPENSSL_HAS_ECC*/


#ifdef OPENSSL_HAS_ECC
static int
SSH_ECDSA_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigblob, unsigned int siglen, EVP_PKEY *pkey) {
	ECDSA_SIG *sig;

	if ((SSHX_RFC6187_ASN1_OPAQUE_ECDSA_SIGNATURE & xcompat) != 0)
		return EVP_VerifyFinal(ctx, sigblob, siglen, pkey);

/* decode ECDSA r&s from SecSH signature blob */
{	int r;
	struct sshbuf *buf;
	const unsigned char *bnbuf;
	size_t bnlen;
	BIGNUM *pr = NULL, *ps = NULL;

	buf = sshbuf_from(sigblob, (size_t) siglen);
	if (buf == NULL) return(-1);

	/* extract mpint r */
	r = sshbuf_get_bignum2_bytes_direct(buf, &bnbuf, &bnlen);
	if (r != 0) goto parse_err;

	pr = BN_bin2bn(bnbuf, bnlen, NULL);
	if (pr == NULL) goto parse_err;

	/* extract mpint s */
	r = sshbuf_get_bignum2_bytes_direct(buf, &bnbuf, &bnlen);
	if (r != 0) goto parse_err;

	ps = BN_bin2bn(bnbuf, bnlen, NULL);
	if (ps == NULL) goto parse_err;

	sig = ECDSA_SIG_new();
	if (sig == NULL) goto parse_err;

	if (ECDSA_SIG_set0(sig, pr, ps))
		goto process;

	ECDSA_SIG_free(sig);

parse_err:
	BN_free(ps);
	BN_free(pr);
	sshbuf_free(buf);
	return(-1);
}

process:
{	int len;
	unsigned char *buf;
	int ret = -1;

	len = i2d_ECDSA_SIG(sig, NULL);
	if (len <= 0) {
		ECDSA_SIG_free(sig);
		return(-1);
	}

	buf = xmalloc(len);  /*fatal on error*/

{	/* encode ECDSA signature */
	unsigned char *pbuf = buf;
	len = i2d_ECDSA_SIG(sig, &pbuf);
}

	if (len > 0)
		ret = EVP_VerifyFinal(ctx, buf, len, pkey);

	if (buf != NULL) {
		explicit_bzero(buf, len);
		free(buf);
	}

	ECDSA_SIG_free(sig);

	return(ret);
}
}
#endif /*def OPENSSL_HAS_ECC*/


void
ssh_xkalg_dgst_compat(ssh_x509_md *dest, const ssh_x509_md *src, ssh_compat *compat) {
	dest->name = src->name;
	dest->evp = src->evp;

#ifdef OPENSSL_HAS_ECC
	if (check_compat_extra(compat, SSHX_RFC6187_ASN1_OPAQUE_ECDSA_SIGNATURE)) {
		if (src->SignFinal == SSH_ECDSA_SignFinal) {
			dest->SignFinal = EVP_SignFinal;
			dest->VerifyFinal = EVP_VerifyFinal;
			return;
		}
	}
#else
	(void)compat;
#endif /*ndef OPENSSL_HAS_ECC*/

	dest->SignFinal = src->SignFinal;
	dest->VerifyFinal = src->VerifyFinal;
}


/* SSH X509 public key algorithms*/
static int x509keyalgs_initialized = 0;
static SSHX509KeyAlgs x509keyalgs[20];


static void
initialize_xkalg(void) {
	SSHX509KeyAlgs *p = x509keyalgs;
	int k;

	if (x509keyalgs_initialized) return;

#ifdef TRACE_XKALG
logit("TRACE_XKALG initialize_xkalg:");
#endif
	k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	for (; k > 0; k--, p++) {
		p->name = NULL;
		p->dgst.name = NULL;
		p->dgst.evp = NULL;
		p->dgst.SignFinal = EVP_SignFinal;
		p->dgst.VerifyFinal = EVP_VerifyFinal;
		p->signame = NULL;
		p->basetype = KEY_UNSPEC;
		p->subtype = -1;
		p->chain = 0;
	}
	x509keyalgs_initialized = 1;
}


static void
add_default_xkalg(void) {
#ifdef TRACE_XKALG
logit("TRACE_XKALG add_default_xkalg:");
#endif

	/* EC public key algorithm: */
	/* - RFC6187: ssh opaque signature */
# ifdef OPENSSL_HAS_NISTP256
	if (ssh_add_x509key_alg("x509v3-ecdsa-sha2-nistp256,ssh-sha256,ecdsa-sha2-nistp256") < 0)
		fatal("ssh_init_xkalg: oops");
# endif
# ifdef OPENSSL_HAS_NISTP384
	if (ssh_add_x509key_alg("x509v3-ecdsa-sha2-nistp384,ssh-sha384,ecdsa-sha2-nistp384") < 0)
		fatal("ssh_init_xkalg: oops");
# endif
# ifdef OPENSSL_HAS_NISTP521
	if (ssh_add_x509key_alg("x509v3-ecdsa-sha2-nistp521,ssh-sha512,ecdsa-sha2-nistp521") < 0)
		fatal("ssh_init_xkalg: oops");
# endif

	/* RSA public key algorithm: */
	/* - draft-ietf-secsh-transport-NN.txt where NN <= 12
	 * does not define explicitly signature format.
	 * - starting from version 7.1 first is rsa-sha1
	 */
	if (ssh_add_x509key_alg("x509v3-sign-rsa,rsa-sha1") < 0)
		fatal("ssh_init_xkalg: oops");
#ifdef OPENSSL_FIPS
	if(!FIPS_mode())
#endif
	if (ssh_add_x509key_alg("x509v3-sign-rsa,rsa-md5") < 0)
		fatal("ssh_init_xkalg: oops");
	/* - RFC6187 */
	if (ssh_add_x509key_alg("x509v3-ssh-rsa,rsa-sha1,ssh-rsa") < 0)
		fatal("ssh_init_xkalg: oops");
#ifdef HAVE_EVP_SHA256
	if (ssh_add_x509key_alg("x509v3-rsa2048-sha256,rsa2048-sha256,rsa2048-sha256") < 0)
		fatal("ssh_init_xkalg: oops");
#endif

	/* DSA public key algorithm: */
	/* - default is compatible with draft-ietf-secsh-transport-NN.txt
	 * where NN <= 12
	 */
	if (ssh_add_x509key_alg("x509v3-sign-dss,dss-asn1") < 0)
		fatal("ssh_init_xkalg: oops");
	/* - some secsh implementations incompatible with
	 * draft-ietf-secsh-transport-NN.txt where NN <= 12
	 */
	if (ssh_add_x509key_alg("x509v3-sign-dss,dss-raw") < 0)
		fatal("ssh_init_xkalg: oops");
	/* - RFC6187 */
	if (ssh_add_x509key_alg("x509v3-ssh-dss,dss-raw,ssh-dss") < 0)
		fatal("ssh_init_xkalg: oops");
}


void
fill_default_xkalg(void) {
	SSHX509KeyAlgs *p = x509keyalgs;

#ifdef TRACE_XKALG
logit("TRACE_XKALG fill_default_xkalg:");
#endif
	initialize_xkalg();
	if (p[0].name == NULL) add_default_xkalg();
}


#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)
/* work-arounds for limited EVP digests in OpenSSL 0.9.8* ...
 * (missing ecdsa support)
 */

#if defined(OPENSSL_HAS_NISTP256) || defined(OPENSSL_HAS_NISTP384) || defined(OPENSSL_HAS_NISTP521)
static inline void
ssh_EVP_MD_ecdsa_init(EVP_MD *t, const EVP_MD *s) {
    memcpy(t, s, sizeof(*t));
    t->sign = (evp_sign_method*)ECDSA_sign;
    t->verify = (evp_verify_method*)ECDSA_verify;
    t->required_pkey_type[0] = EVP_PKEY_EC;
    t->required_pkey_type[1] = 0;
}
#endif


#ifdef OPENSSL_HAS_NISTP256
/* Test for NID_X9_62_prime256v1(nistp256) includes test for EVP_sha256 */
EVP_MD ecdsa_sha256_md = { NID_undef };

static const EVP_MD*
ssh_ecdsa_EVP_sha256(void) {
    if (ecdsa_sha256_md.type == NID_undef)
	ssh_EVP_MD_ecdsa_init(&ecdsa_sha256_md, EVP_sha256());
    return &ecdsa_sha256_md;
}
#endif

#ifdef OPENSSL_HAS_NISTP384
/* Test for NID_secp384r1(nistp384) includes test for EVP_sha384 */
EVP_MD ecdsa_sha384_md = { NID_undef };

static const EVP_MD*
ssh_ecdsa_EVP_sha384(void) {
    if (ecdsa_sha384_md.type == NID_undef)
	ssh_EVP_MD_ecdsa_init(&ecdsa_sha384_md, EVP_sha384());
    return &ecdsa_sha384_md;
}
#endif

#ifdef OPENSSL_HAS_NISTP521
/* Test for NID_secp521r1(nistp521) includes test for EVP_sha512 */
EVP_MD ecdsa_sha512_md = { NID_undef };

static const EVP_MD*
ssh_ecdsa_EVP_sha512(void) {
    if (ecdsa_sha512_md.type == NID_undef)
	ssh_EVP_MD_ecdsa_init(&ecdsa_sha512_md, EVP_sha512());
    return &ecdsa_sha512_md;
}
#endif

#else

#ifdef OPENSSL_HAS_NISTP256
static inline const EVP_MD* ssh_ecdsa_EVP_sha256(void) { return EVP_sha256(); }
#endif
#ifdef OPENSSL_HAS_NISTP384
static inline const EVP_MD* ssh_ecdsa_EVP_sha384(void) { return EVP_sha384(); }
#endif
#ifdef OPENSSL_HAS_NISTP521
static inline const EVP_MD* ssh_ecdsa_EVP_sha512(void) { return EVP_sha512(); }
#endif

#endif /*defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)*/


#ifdef OPENSSL_HAS_ECC
static inline void
wrap_digest_ecdsa(SSHX509KeyAlgs* p) {
	p->dgst.SignFinal = SSH_ECDSA_SignFinal;
	p->dgst.VerifyFinal = SSH_ECDSA_VerifyFinal;
}
#endif /*def OPENSSL_HAS_ECC*/


static int
ssh_x509key_alg_digest(SSHX509KeyAlgs* p, const char *dgstname) {
	const EVP_MD* md = NULL;

	if (dgstname == NULL) {
		fatal("ssh_get_md: dgstname is NULL");
		return(-1); /*unreachable code*/
	}

	if (strcasecmp("rsa-sha1", dgstname) == 0) { md = EVP_sha1(); goto done; }
	if (strcasecmp("rsa-md5" , dgstname) == 0) { md = EVP_md5(); goto done; }
#ifdef HAVE_EVP_SHA256
	if (strcasecmp("rsa2048-sha256", dgstname) == 0) { md = EVP_sha256(); goto done; }
#endif

#ifdef OPENSSL_HAS_NISTP256
	if (strcasecmp("ssh-sha256"  , dgstname) == 0) {
		md = ssh_ecdsa_EVP_sha256();
		wrap_digest_ecdsa(p);
		goto done;
	}
	if (strcasecmp("sha256"  , dgstname) == 0) { md = ssh_ecdsa_EVP_sha256(); goto done; }
#endif
#ifdef OPENSSL_HAS_NISTP384
	if (strcasecmp("ssh-sha384"  , dgstname) == 0) {
		md = ssh_ecdsa_EVP_sha384();
		wrap_digest_ecdsa(p);
		goto done;
	}
	if (strcasecmp("sha384"  , dgstname) == 0) { md = ssh_ecdsa_EVP_sha384(); goto done; }
#endif
#ifdef OPENSSL_HAS_NISTP521
	if (strcasecmp("ssh-sha512"  , dgstname) == 0) {
		md = ssh_ecdsa_EVP_sha512();
		wrap_digest_ecdsa(p);
		goto done;
	}
	if (strcasecmp("sha512"  , dgstname) == 0) { md = ssh_ecdsa_EVP_sha512(); goto done; }
#endif

	if (strcasecmp("dss-asn1", dgstname) == 0) { md = EVP_dss1(); goto done; }
	if (strcasecmp("dss-raw" , dgstname) == 0) {
		md = EVP_dss1();
		p->dgst.SignFinal = DSS1RAW_SignFinal;
		p->dgst.VerifyFinal = DSS1RAW_VerifyFinal;
		goto done;
	}

	return(-1);

done:
	p->dgst.name = dgstname;
	p->dgst.evp = md;

	return(0);
}


int
ssh_add_x509key_alg(const char *data) {
	char *name, *mdname, *signame;
	SSHX509KeyAlgs* p;
	int nid = -1;

	if (data == NULL) {
		error("ssh_add_x509pubkey_alg: data is NULL");
		return(-1);
	}

	name = xstrdup(data); /*fatal on error*/

	mdname = strchr(name, ',');
	if (mdname == NULL) {
		error("ssh_add_x509pubkey_alg: cannot parse digest");
		goto err;
	}
	*mdname++ = '\0';

	signame = strchr(mdname, ',');
	if (signame != NULL) *signame++ = '\0';

	initialize_xkalg();
	p = x509keyalgs;
	{
		int k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);

		for (; k > 0; k--, p++) {
			if (p->name == NULL) break;
		}
		if (k <= 0) {
			error("ssh_add_x509pubkey_alg: insufficient slots");
			goto err;
		}
	}

	if (strncmp(name, "x509v3-ecdsa-sha2-", 18) == 0) {
		const char *ec_name = name + 18;

		nid = sshkey_curve_name_to_nid(ec_name);
		if (nid < 0) {
			fatal("ssh_add_x509pubkey_alg: unsupported curve %s", ec_name);
		}

		p->basetype = KEY_ECDSA;
		p->chain = 1;
	} else
	if (strncmp(name, "x509v3-ssh-rsa", 14) == 0) {
		p->basetype = KEY_RSA;
		p->chain = 1;
	} else
#ifdef HAVE_EVP_SHA256
	if (strcmp(name, "x509v3-rsa2048-sha256") == 0) {
		p->basetype = KEY_RSA;
		p->chain = 1;
	} else
#endif
	if (strncmp(name, "x509v3-sign-rsa", 15) == 0) {
		p->basetype = KEY_RSA;
		p->chain = 0;
	} else
	if (strncmp(name, "x509v3-ssh-dss", 14) == 0) {
		p->basetype = KEY_DSA;
		p->chain = 1;
	} else
	if (strncmp(name, "x509v3-sign-dss", 15) == 0) {
		p->basetype = KEY_DSA;
		p->chain = 0;
	} else
	{
		error("ssh_add_x509pubkey_alg: "
			"unsupported public key algorithm '%s'", name);
		goto err;
	}

	if (ssh_x509key_alg_digest(p, mdname) < 0) {
		error("ssh_add_x509pubkey_alg: unsupported digest %.50s", mdname);
		goto err;
	}

#ifdef OPENSSL_FIPS
	if (FIPS_mode()) {
		if ((EVP_MD_flags(p->dgst.evp) & EVP_MD_FLAG_FIPS) == 0) {
			error("ssh_add_x509pubkey_alg: "
				"%s in not enabled in FIPS mode ", mdname);
			goto err;
		}
	}
#endif
	p->name = name;
	p->signame = signame;
	p->subtype = nid;

	return (1);

err:
	free((void*)name);
	return (-1);
}


int/*bool*/
ssh_is_x509signame(const char *signame) {
	SSHX509KeyAlgs *xkalg;
	int k;

	if (signame == NULL) {
		fatal("ssh_is_x509signame: signame is NULL");
		return(0); /*unreachable code*/
	}

	initialize_xkalg();
	xkalg = x509keyalgs;
	k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);

	for (; k > 0; k--, xkalg++) {
		if (xkalg->name == NULL) return(0);
		if (strcmp(signame, X509PUBALG_SIGNAME(xkalg)) == 0) return(1);
	}
	return(0);
}


int
ssh_xkalg_nameind(const char *name, const SSHX509KeyAlgs **q, int loc) {
	int k, n;
	const SSHX509KeyAlgs *p;

	if (name == NULL) return (-1);

	initialize_xkalg();
	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	if (k < n) p = &x509keyalgs[k];

	for (; k < n; k++, p++) {
		if (p->name == NULL) return(-1);
		if (strcmp(p->name, name) == 0) {
			if (q) *q = p;
			return(k);
		}
	}
	return(-1);
}


int
ssh_xkalg_typeind(int type, int subtype, const SSHX509KeyAlgs **q, int loc) {
	int k, n;
	const SSHX509KeyAlgs *p;

	initialize_xkalg();
	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	if (k < n) p = &x509keyalgs[k];

	type = sshkey_type_plain(type);
	for (; k < n; k++, p++) {
		if (p->name == NULL) break;
		if (type != p->basetype) continue;

		if ((subtype > 0) && (subtype != p->subtype))
			continue;

		if (q) *q = p;
		return(k);
	}
	return(-1);
}


int
ssh_xkalg_typeformind(int type, int subtype, int frm, const SSHX509KeyAlgs **q, int loc) {

	while ((loc = ssh_xkalg_typeind(type, subtype, q, loc)) >= 0) {
		int found = 0;

		switch (frm) {
		case X509FORMAT_FIRSTMATCH: found = 1;
			break;
		case X509FORMAT_LEGACY    : found = !(*q)->chain;
			break;
		case X509FORMAT_RFC6187   : found = (*q)->chain;
			break;
		}
		if (found) break;
	}
	return(loc);
}


int
ssh_xkalg_ind(const SSHX509KeyAlgs **q, int loc) {
	int k, n;

	initialize_xkalg();
	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);

	if (k < n) {
		const SSHX509KeyAlgs *p;

		p = &x509keyalgs[k];
		if (p->name != NULL) {
			if (q) *q = p;
			return(k);
		}
	}
	return(-1);
}


static void
ssh_xkalg_list(int type, struct sshbuf *b, const char *sep) {
	const SSHX509KeyAlgs *xkalg;
	int loc;
	int seplen;

	if (b == NULL) {
		error("ssh_xkalg_list: buffer is NULL");
		return;
	}

/*
IMPORTANT NOTE:
  For every unique "key name" we MUST define unique "key type"
otherwise cannot distinguish them !
As example structure Kex contain integer attribute "kex_type"
and kex use method "load_host_key" to find hostkey. When client
request hostkey algorithms (comma separated list with names)
server should be able to find first hostkey that match one of them.
Note to "load_host_key" is assigned method "get_hostkey_by_type"
defined in "sshd.c".
*/

	if (sep == NULL) sep = ",";
	seplen = strlen(sep);

	for (
	    loc = ssh_xkalg_typeind(type, -1, &xkalg, -1);
	    loc >= 0;
	    loc = ssh_xkalg_typeind(type, -1, &xkalg, loc)
	) {
		const char *p;
		int dupl, k, r;

		/* exclude duplicate names */
		p = xkalg->name;
		dupl = 0;
		for (
		    k = ssh_xkalg_typeind(type, -1, &xkalg, -1);
		    (k >= 0) && (k < loc);
		    k = ssh_xkalg_typeind(type, -1, &xkalg, k)
		) {
			if (strcmp(p, xkalg->name) == 0) {
				dupl = 1;
				break;
			}
		}
		if (dupl) continue;

		if (sshbuf_len(b) > 0) {
			if ((r = sshbuf_put(b, sep, seplen)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		if ((r = sshbuf_put(b, p, strlen(p))) != 0)
			fatal("%s: buffer error: %s",
			    __func__, ssh_err(r));
	}
}


void
ssh_xkalg_listall(struct sshbuf *b, const char *sep) {
	ssh_xkalg_list(KEY_ECDSA, b, sep);
	ssh_xkalg_list(KEY_RSA, b, sep);
	ssh_xkalg_list(KEY_DSA, b, sep);
}


char*
default_publickey_algorithms(void) {
	struct sshbuf *b;
	char *p;
	int r;

	b = sshbuf_new();
	if (b == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	ssh_xkalg_listall(b, ",");

	p = KEX_DEFAULT_PK_ALG;
	if ((r = sshbuf_put(b, ",", 1)) != 0 ||
	    (r = sshbuf_put(b, p, strlen(p))) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* Since PKIX-SSH 8.5 ssh-dss is not listed in KEX_DEFAULT_PK_ALG */
	p = "ssh-dss";
	if ((r = sshbuf_put(b, ",", 1)) != 0 ||
	    (r = sshbuf_put(b, p, strlen(p))) != 0 ||
	    (r = sshbuf_put(b, "\0", 1)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	p = xstrdup(sshbuf_ptr(b));

	sshbuf_free(b);

	return p;
}


char*
ssh_get_allnames(char sep, int sigflag, const char* pattern) {
	const char **list = NULL;;
	int loc;
	size_t k, n = 0, len = 0;

	if (pattern == NULL) pattern= "*";

{	const SSHX509KeyAlgs *xkalg;
	for (
	    loc = ssh_xkalg_ind(&xkalg, -1);
	    loc >= 0;
	    loc = ssh_xkalg_ind(&xkalg, loc)
	) {
		const char *p;

		if (match_pattern_list(xkalg->name, pattern, 0) != 1)
			continue;

		p = sigflag ? X509PUBALG_SIGNAME(xkalg) : xkalg->name;
		for (k = 0; k < n; k++) {
			if (strcmp(p, list[k]) == 0) {
				p = NULL;
				break;
			}
		}
		if (p == NULL) continue;

		k = n++;
		list = realloc(list, n * sizeof(char*));
		if (list == NULL)
			fatal("ssh_get_all_pkalg: realloc fail for xkalg");
		list[k] = p;
		len += 1 + strlen(p);
	}
}
{	const char *name;
	/*
	 * According RFC8308 protocol extension "server-sig-algs",
	 * despite of it name, list public key algorithms that the
	 * server is able to process.
	 * OpenBSD version is still broken and does not list algorithms
	 * that use custom certificates. Broken behaviour will be keep
	 * until is fixed in OpenBSD version. Note that brokenness is
	 * keep as well in check for allowed keys - see sshconnect2.c
	 * function try_identity().
	 */
	for (
	    loc = sshkey_algind(&name, SSHKEY_ALG_PLAINKEY, -1);
	    loc >= 0;
	    loc = sshkey_algind(&name, SSHKEY_ALG_PLAINKEY, loc)
	) {
		const char *p;

		if (match_pattern_list(name, pattern, 0) != 1)
			continue;

		p = name;
		for (k = 0; k < n; k++) {
			if (strcmp(p, list[k]) == 0) {
				p = NULL;
				break;
			}
		}
		if (p == NULL) continue;

		k = n++;
		list = realloc(list, n * sizeof(char*));
		if (list == NULL)
			fatal("ssh_get_all_pkalg: realloc fail for alg");
		list[k] = p;
		len += 1 + strlen(p);
	}
}
{	char *s = NULL, *p;

	if (n > 0) {
		s = p = malloc(len);
		if (s == NULL)
			fatal("ssh_get_all_pkalg: out of memory");
	}
	for (k = 0; k < n; k++) {
		size_t l = strlen(list[k]);
		memmove(p, list[k], l);
		p += l;
		*p++ = sep;
	}
	if (n > 0)
		*(--p) = '\0';

	free(list);
	return s;
}
}
