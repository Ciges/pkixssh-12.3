/* $OpenBSD: compat.c,v 1.113 2018/08/13 02:41:05 djm Exp $ */
/*
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 *
 * X.509 certificates support:
 * Copyright (c) 2017-2018 Roumen Petrov.  All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "packet.h"
#include "compat.h"
#include "log.h"
#include "match.h"
#include "kex.h"

int datafellows = 0;

/* datafellows bug compatibility */
static u_int
compat_datafellows(const char *version)
{
	int i;
	static struct {
		char	*pat;
		int	bugs;
	} check[] = {
		{ "OpenSSH_2.*,"
		  "OpenSSH_3.0*,"
		  "OpenSSH_3.1*",	SSH_BUG_EXTEOF|SSH_OLD_FORWARD_ADDR|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_3.*",	SSH_OLD_FORWARD_ADDR|SSH_BUG_SIGTYPE },
		{ "Sun_SSH_1.0*",	SSH_BUG_NOREKEY|SSH_BUG_EXTEOF},
		{ "OpenSSH_2*,"
		  "OpenSSH_3*,"
		  "OpenSSH_4*",		SSH_BUG_SIGTYPE },
		{ "OpenSSH_5*",		SSH_NEW_OPENSSH|SSH_BUG_DYNAMIC_RPORT|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_6.6.1*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE},
		{ "OpenSSH_6.5*,"
		  "OpenSSH_6.6*",	SSH_NEW_OPENSSH|SSH_BUG_CURVE25519PAD|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_7.0*,"
		  "OpenSSH_7.1*,"
		  "OpenSSH_7.2*,"
		  "OpenSSH_7.3*,"
		  "OpenSSH_7.4*,"
		  "OpenSSH_7.5*,"
		  "OpenSSH_7.6*,"
		  "OpenSSH_7.7*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE},
		{ "OpenSSH*",		SSH_NEW_OPENSSH },
		{ "*MindTerm*",		0 },
		{ "3.0.*",		SSH_BUG_DEBUG },
		{ "3.0 SecureCRT*",	SSH_OLD_SESSIONID },
		{ "1.7 SecureFX*",	SSH_OLD_SESSIONID },
		{ "1.2.18*,"
		  "1.2.19*,"
		  "1.2.20*,"
		  "1.2.21*,"
		  "1.2.22*",		SSH_BUG_IGNOREMSG },
		{ "1.3.2*",		/* F-Secure */
					SSH_BUG_IGNOREMSG },
		{ "Cisco-1.*",		SSH_BUG_DHGEX_LARGE|
					SSH_BUG_HOSTKEYS },
		{ "*SSH Compatible Server*",			/* Netscreen */
					SSH_BUG_PASSWORDPAD },
		{ "*OSU_0*,"
		  "OSU_1.0*,"
		  "OSU_1.1*,"
		  "OSU_1.2*,"
		  "OSU_1.3*,"
		  "OSU_1.4*,"
		  "OSU_1.5alpha1*,"
		  "OSU_1.5alpha2*,"
		  "OSU_1.5alpha3*",	SSH_BUG_PASSWORDPAD },
		{ "*SSH_Version_Mapper*",
					SSH_BUG_SCANNER },
		{ "PuTTY_Local:*,"	/* dev versions < Sep 2014 */
		  "PuTTY-Release-0.5*," /* 0.50-0.57, DH-GEX in >=0.52 */
		  "PuTTY_Release_0.5*,"	/* 0.58-0.59 */
		  "PuTTY_Release_0.60*,"
		  "PuTTY_Release_0.61*,"
		  "PuTTY_Release_0.62*,"
		  "PuTTY_Release_0.63*,"
		  "PuTTY_Release_0.64*",
					SSH_OLD_DHGEX },
		{ "FuTTY*",		SSH_OLD_DHGEX }, /* Putty Fork */
		{ "Probe-*",
					SSH_BUG_PROBE },
		{ "TeraTerm SSH*,"
		  "TTSSH/1.5.*,"
		  "TTSSH/2.1*,"
		  "TTSSH/2.2*,"
		  "TTSSH/2.3*,"
		  "TTSSH/2.4*,"
		  "TTSSH/2.5*,"
		  "TTSSH/2.6*,"
		  "TTSSH/2.70*,"
		  "TTSSH/2.71*,"
		  "TTSSH/2.72*",	SSH_BUG_HOSTKEYS },
		{ "WinSCP_release_4*,"
		  "WinSCP_release_5.0*,"
		  "WinSCP_release_5.1,"
		  "WinSCP_release_5.1.*,"
		  "WinSCP_release_5.5,"
		  "WinSCP_release_5.5.*,"
		  "WinSCP_release_5.6,"
		  "WinSCP_release_5.6.*,"
		  "WinSCP_release_5.7,"
		  "WinSCP_release_5.7.1,"
		  "WinSCP_release_5.7.2,"
		  "WinSCP_release_5.7.3,"
		  "WinSCP_release_5.7.4",
					SSH_OLD_DHGEX },
		{ "ConfD-*",
					SSH_BUG_UTF8TTYMODE },
		{ "Twisted_*",		0 },
		{ "Twisted*",		SSH_BUG_DEBUG },
		{ NULL,			0 }
	};

	/* process table, return first match */
	for (i = 0; check[i].pat; i++) {
		if (match_pattern_list(version, check[i].pat, 0) == 1) {
			debug("match: %s pat %s compat 0x%08x",
			    version, check[i].pat, check[i].bugs);
			datafellows = check[i].bugs;	/* XXX for now */
			return check[i].bugs;
		}
	}
	debug("no match: %s", version);
	return 0;
}

#define	SEP	","
int
proto_spec(const char *spec)
{
	char *s, *p, *q;
	int ret = SSH_PROTO_UNKNOWN;

	if (spec == NULL)
		return ret;
	q = s = strdup(spec);
	if (s == NULL)
		return ret;
	for ((p = strsep(&q, SEP)); p && *p != '\0'; (p = strsep(&q, SEP))) {
		switch (atoi(p)) {
		case 2:
			ret |= SSH_PROTO_2;
			break;
		default:
			logit("ignoring bad proto spec: '%s'.", p);
			break;
		}
	}
	free(s);
	return ret;
}

char *
compat_cipher_proposal(char *cipher_prop)
{
	if (!(datafellows & SSH_BUG_BIGENDIANAES))
		return cipher_prop;
	debug2("%s: original cipher proposal: %s", __func__, cipher_prop);
	if ((cipher_prop = match_filter_blacklist(cipher_prop, "aes*")) == NULL)
		fatal("match_filter_blacklist failed");
	debug2("%s: compat cipher proposal: %s", __func__, cipher_prop);
	if (*cipher_prop == '\0')
		fatal("No supported ciphers found");
	return cipher_prop;
}

char *
compat_pkalg_proposal(char *pkalg_prop)
{
	if (!(datafellows & SSH_BUG_RSASIGMD5))
		return pkalg_prop;
	debug2("%s: original public key proposal: %s", __func__, pkalg_prop);
	if ((pkalg_prop = match_filter_blacklist(pkalg_prop, "ssh-rsa")) == NULL)
		fatal("match_filter_blacklist failed");
	debug2("%s: compat public key proposal: %s", __func__, pkalg_prop);
	if (*pkalg_prop == '\0')
		fatal("No supported PK algorithms found");
	return pkalg_prop;
}

char *
compat_kex_proposal(char *p)
{
	if ((datafellows & (SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX)) == 0)
		return p;
	debug2("%s: original KEX proposal: %s", __func__, p);
	if ((datafellows & SSH_BUG_CURVE25519PAD) != 0)
		if ((p = match_filter_blacklist(p,
		    "curve25519-sha256@libssh.org")) == NULL)
			fatal("match_filter_blacklist failed");
	if ((datafellows & SSH_OLD_DHGEX) != 0) {
		if ((p = match_filter_blacklist(p,
		    "diffie-hellman-group-exchange-sha256,"
		    "diffie-hellman-group-exchange-sha1")) == NULL)
			fatal("match_filter_blacklist failed");
	}
	debug2("%s: compat KEX proposal: %s", __func__, p);
	if (*p == '\0')
		fatal("No supported key exchange algorithms found");
	return p;
}


struct sshx_compatibility_st {
	int/*boolean*/ flag;
	const char *pattern;
};
typedef struct sshx_compatibility_st sshx_compatibility;


static sshx_compatibility*
xkey_compatibility_find(
    const char *remote_version,
    sshx_compatibility *compatibility_info
) {
	sshx_compatibility *p;

	for (p = compatibility_info; p->pattern; p++) {
		if (match_pattern_list(remote_version, p->pattern, 0) == 1)
			break;
	}
	return p;
}


int xcompat = 0;

static u_int
xkey_compatibility(const char *remote_version) {
	u_int res = 0;
	sshx_compatibility *p;

/* Process each table and stop on first match.
   Order of compatibility info is important!
*/
{	static sshx_compatibility info[] = {
		{ 0, "OpenSSH*PKIX[??.*" /* 10.+ first correct */ },
		{ 0, "OpenSSH*PKIX[X.*" /* developlement */ },
		{ 1, "OpenSSH*" /* PKIX pre 10.0 */ },
		{ 1, "SecureNetTerm-3.1" /* same as PKIX pre 10.0 */},
		{ 0, NULL } };
	p = xkey_compatibility_find(remote_version, info);
}
	if (p->flag != 0) {
		res |= SSHX_RFC6187_MISSING_KEY_IDENTIFIER;
		res |= SSHX_RFC6187_ASN1_OPAQUE_ECDSA_SIGNATURE;
	}
	debug("x.509 compatibility rfc6187_missing_key_identifier=%s: pattern '%s' match '%s'",
	    (p->flag != 0 ? "yes": "no"),
	    (p->pattern != NULL ? p->pattern : "*"),
	    remote_version);
	debug("x.509 compatibility rfc6187_asn1_opaque_ecdsa_signature=%s: pattern '%s' match '%s'",
	    (p->flag != 0 ? "yes": "no"),
	    (p->pattern != NULL ? p->pattern : "*"),
	    remote_version);

{	static sshx_compatibility info[] = {
		{ 0, "OpenSSH*PKIX*" /* all correct */ },
		{ 1, "OpenSSH_7.3*" /* list only rsa-sha2-256 and rsa-sha2-512 */ },
		{ 1, "OpenSSH_7.4*" /* list without rsa-sha2-256 and rsa-sha2-512 */ },
		{ 0, NULL } };
	p = xkey_compatibility_find(remote_version, info);
}
	if (p->flag != 0) {
		res |= SSHX_OPENSSH_BROKEN_ALGO_INFO;
	}
	debug("x.509 compatibility broken list with accepted publickey algorithms=%s: pattern '%s' match '%s'",
	    (p->flag != 0 ? "yes": "no"),
	    (p->pattern != NULL ? p->pattern : "*"),
	    remote_version);

	xcompat = res; /* TODO */
	return res;
}


void
ssh_set_compatibility(struct ssh *ssh, const char *remote_version) {
	ssh_compat *flags = &ssh->compat;
	if (remote_version == NULL) {
		flags->datafellows = 0;
		flags->extra = 0;
		return;
	}
	flags->datafellows = compat_datafellows(remote_version);
	flags->extra = xkey_compatibility(remote_version);
}


int
sshbuf_get_compat(struct sshbuf *b, ssh_compat *v) {
	u_int32_t v1, v2;
	int r;

	r = sshbuf_get_u32(b, &v1);
	if (r != 0) return r;
	r = sshbuf_get_u32(b, &v2);
	if (r != 0) return r;

	v->datafellows = v1;
	v->extra = v2;
	return 0;
}


int
sshbuf_put_compat(struct sshbuf *b, const ssh_compat *v) {
	int r;

	r = sshbuf_put_u32(b, v->datafellows);
	if (r != 0) return r;
	r = sshbuf_put_u32(b, v->extra);
	if (r != 0) return r;

	return 0;
}
