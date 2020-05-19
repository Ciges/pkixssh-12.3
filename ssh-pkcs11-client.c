/* $OpenBSD: ssh-pkcs11-client.c,v 1.15 2019/01/21 12:53:35 djm Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
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
#include <sys/socket.h>

#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/rsa.h>
#include "evp-compat.h"

#include "pathnames.h"
#include "xmalloc.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"
#include "sshxkey.h"
#include "authfd.h"
#include "atomicio.h"
#include "ssh-pkcs11.h"
#include "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

static int fd = -1;
static pid_t pid = -1;

static int
helper_msg_sign_request(
    struct sshbuf *buf, struct sshkey *key,
    const unsigned char *dgst, int dlen
) {
	int r = 0;
	const char *pkalg;;
	u_char *blob = NULL;
	size_t blen;

	/* Use method with algorithm nevertheless that sign request
	 * to helper is only with pure plain keys! Actually key-blob
	 * below is used by helper only to find key.
	 */
	pkalg = sshkey_ssh_name(key);
	r = Xkey_to_blob(pkalg, key, &blob, &blen);
	if (r != 0) goto done;

	if ((r = sshbuf_put_u8(buf, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshbuf_put_string(buf, blob, blen)) != 0 ||
	    (r = sshbuf_put_string(buf, dgst, (size_t) dlen)) != 0 ||
	    (r = sshbuf_put_u32(buf, 0)) != 0
	) goto done;

done:
	free(blob);

	return r;
}

static void
send_msg(struct sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	int r;

	POKE_U32(buf, mlen);
	if (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	if ((r = sshbuf_consume(m, mlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

static int
recv_msg(struct sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	int r;

	if ((len = atomicio(read, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		return (0); /* XXX */
	}
	len = PEEK_U32(buf);
	if (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	sshbuf_reset(m);
	while (len > 0) {
		l = len;
		if (l > sizeof(buf))
			l = sizeof(buf);
		if (atomicio(read, fd, buf, l) != l) {
			error("response from helper failed.");
			return (0); /* XXX */
		}
		if ((r = sshbuf_put(m, buf, l)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		len -= l;
	}
	if ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	return c;
}

int
pkcs11_init(int interactive)
{
	(void)interactive;
	return (0);
}

void
pkcs11_terminate(void)
{
	if (fd >= 0)
		close(fd);
}

static int
pkcs11_rsa_private_encrypt(int flen, const u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	struct sshkey *key;
	struct sshbuf *msg = NULL;
	u_char *signature = NULL;
	size_t slen = 0;
	int r;
	int ret = -1;

	if (padding != RSA_PKCS1_PADDING) return -1;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL) {
		error("%s: sshkey_new failed", __func__);
		goto done;
	}
	key->type = KEY_RSA;
	RSA_up_ref(rsa);
	key->rsa = rsa;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if (helper_msg_sign_request(msg, key, from, flen) != 0)
		goto done;
	send_msg(msg);
	sshbuf_reset(msg);

	if (recv_msg(msg) == SSH2_AGENT_SIGN_RESPONSE) {
		if ((r = sshbuf_get_string(msg, &signature, &slen)) != 0)
			goto done;
		if (slen <= (size_t)RSA_size(rsa)) {
			memcpy(to, signature, slen);
			ret = slen;
		}
	}

done:
	if (ret == -1)
		PKCS11err(PKCS11_RSA_PRIVATE_ENCRYPT, PKCS11_SIGNREQ_FAIL);

	free(signature);
	sshkey_free(key);
	sshbuf_free(msg);
	return ret;
}

#ifdef OPENSSL_HAS_ECC
static ECDSA_SIG*
pkcs11_ecdsa_do_sign(
	const unsigned char *dgst, int dlen,
	const BIGNUM *inv, const BIGNUM *rp,
	EC_KEY *ec
) {
	struct sshkey *key;
	struct sshbuf *msg = NULL;
	u_char *signature = NULL;
	size_t slen = 0;
	int r;
	ECDSA_SIG *ret = NULL;

	UNUSED(inv);
	UNUSED(rp);

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL) {
		error("%s: sshkey_new failed", __func__);
		goto done;
	}
	key->type = KEY_ECDSA;
	EC_KEY_up_ref(ec);
	key->ecdsa = ec;
	key->ecdsa_nid = sshkey_ecdsa_key_to_nid(ec);
	if (key->ecdsa_nid < 0) {
		error("%s: unsupported curve", __func__);
		goto done;
	}

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if (helper_msg_sign_request(msg, key, dgst, dlen) != 0)
		goto done;
	send_msg(msg);
	sshbuf_reset(msg);

	if (recv_msg(msg) == SSH2_AGENT_SIGN_RESPONSE) {
		if ((r = sshbuf_get_string(msg, &signature, &slen)) != 0)
			goto done;

		{	/* decode ECDSA signature */
			const unsigned char *p = signature;
			ret = d2i_ECDSA_SIG(NULL, &p, slen);
		}
	}

done:
	if (ret == NULL)
		PKCS11err(PKCS11_ECDSA_DO_SIGN, PKCS11_SIGNREQ_FAIL);

	free(signature);
	sshkey_free(key);
	sshbuf_free(msg);
	return ret;
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
#endif /*def OPENSSL_HAS_ECC*/

/* redirect the private key encrypt operation to the ssh-pkcs11-helper */
static int
wrap_rsa_key(RSA *rsa)
{
	static RSA_METHOD *helper_rsa = NULL;

	if (helper_rsa == NULL) {
		helper_rsa = RSA_meth_dup(RSA_PKCS1_OpenSSL());
		if (helper_rsa == NULL)
			return (-1);

		if (!RSA_meth_set1_name(helper_rsa, "ssh-pkcs11-helper")
		||  !RSA_meth_set_priv_enc(helper_rsa, pkcs11_rsa_private_encrypt)
		) {
			RSA_meth_free(helper_rsa);
			helper_rsa = NULL;
			return (-1);
		}
	}

	if (!RSA_set_method(rsa, helper_rsa))
		return (-1);
	return (0);
}

#ifdef OPENSSL_HAS_ECC
static int
wrap_ec_key(EC_KEY *ec)
{
	static EC_KEY_METHOD *helper_ec = NULL;

	if (helper_ec == NULL) {
#ifdef HAVE_EC_KEY_METHOD_NEW
		helper_ec = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
		if (helper_ec == NULL) return -1;

		EC_KEY_METHOD_set_sign(helper_ec,
		    pkcs11_ecdsa_sign,
		    NULL /* *sign_setup */,
		    pkcs11_ecdsa_do_sign);
#else
		helper_ec = ECDSA_METHOD_new(ECDSA_OpenSSL());
		if (helper_ec == NULL) return -1;

		ECDSA_METHOD_set_sign(helper_ec,
		    pkcs11_ecdsa_do_sign);
#endif
	}
	EC_KEY_set_method(ec, helper_ec);
	return 0;
}
#endif /*def OPENSSL_HAS_ECC*/

static int
wrap_key(struct sshkey *key) {
	switch(key->type) {
	case KEY_RSA: return (wrap_rsa_key(key->rsa));
#ifdef OPENSSL_HAS_ECC
	case KEY_ECDSA: return (wrap_ec_key(key->ecdsa));
#endif
	default:      return (-1);
	}
}

static int
pkcs11_start_helper(void)
{
	int pair[2];
	char *helper, *verbosity = NULL;

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG1)
		verbosity = "-vvv";

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		return (-1);
	}
	if ((pid = fork()) == -1) {
		error("fork: %s", strerror(errno));
		return (-1);
	} else if (pid == 0) {
		if ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		helper = getenv("SSH_PKCS11_HELPER");
		if (helper == NULL || strlen(helper) == 0)
			helper = _PATH_SSH_PKCS11_HELPER;
		debug("%s: starting %s %s", __func__, helper,
		    verbosity == NULL ? "" : verbosity);
		execlp(helper, helper, verbosity, (char *)NULL);
		fprintf(stderr, "exec: %s: %s\n", helper, strerror(errno));
		_exit(1);
	}
	close(pair[1]);
	fd = pair[0];
	return (0);
}

int
pkcs11_add_provider(char *name, char *pin, struct sshkey ***keysp)
{
	struct sshkey *k;
	int ret = -1, r, type;
	u_char *blob;
	size_t blen;
	u_int32_t nkeys, i;
	struct sshbuf *msg;

	if (fd < 0 && pkcs11_start_helper() < 0)
		return (-1);

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH_AGENTC_ADD_SMARTCARD_KEY)) != 0 ||
	    (r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, pin)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	send_msg(msg);
	sshbuf_reset(msg);

	type = recv_msg(msg);
	switch (type) {
	case SSH2_AGENT_IDENTITIES_ANSWER: {
		if ((r = sshbuf_get_u32(msg, &nkeys)) != 0) {
			error("%s: buffer error: %s", __func__, ssh_err(r));
			goto done;
		}
		*keysp = xcalloc(nkeys, sizeof(struct sshkey *));
		for (i = 0; i < nkeys; i++) {
			if ((r = sshbuf_get_string(msg, &blob, &blen)) != 0 ||
			    (r = sshbuf_skip_string(msg)) != 0) {
				error("%s: buffer error: %s",
				    __func__, ssh_err(r));
				k = NULL;
				goto set_key;
			}
			if ((r = Akey_from_blob(blob, blen, &k)) != 0) {
				error("%s: bad key: %s", __func__, ssh_err(r));
				k = NULL;
				goto set_key;
			}
			if (wrap_key(k) < 0) {
				sshkey_free(k);
				k = NULL;
			}
set_key:
			(*keysp)[i] = k;
			free(blob);
		}
		ret = nkeys;
	}	break;
	case SSH2_AGENT_FAILURE: {
		if ((r = sshbuf_get_u32(msg, &nkeys)) != 0) {
			error("%s: buffer error: %s", __func__, ssh_err(r));
		} else {
			ret = -nkeys;
			error("%s: helper fail to add provider: %d",
			    __func__, ret);
		}
	}	break;
	default:
		error("%s: unknown message: %d", __func__, type);
	}

done:
	sshbuf_free(msg);
	return ret;
}

int
pkcs11_del_provider(char *name)
{
	int r, ret = -1;
	struct sshbuf *msg;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH_AGENTC_REMOVE_SMARTCARD_KEY)) != 0 ||
	    (r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	send_msg(msg);
	sshbuf_reset(msg);

	if (recv_msg(msg) == SSH_AGENT_SUCCESS)
		ret = 0;
	sshbuf_free(msg);
	return (ret);
}

#endif /* ENABLE_PKCS11 */
