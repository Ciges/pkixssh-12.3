#ifndef SSH_XKALG_H
#define SSH_XKALG_H
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

#include "includes.h"


typedef int	(*fEVP_SignFinal)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s, EVP_PKEY *pkey);
typedef int	(*fEVP_VerifyFinal)(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey);

struct ssh_x509_md_st {
	const char       *name;
	const EVP_MD     *evp;
	fEVP_SignFinal    SignFinal;
	fEVP_VerifyFinal  VerifyFinal;
};
typedef struct ssh_x509_md_st ssh_x509_md;

void	ssh_xkalg_dgst_compat(ssh_x509_md *dest, const ssh_x509_md *src, ssh_compat *compat);

typedef struct {
	const char   *name;
	ssh_x509_md   dgst;
	const char   *signame;
	int           basetype;
	int           chain;
	int           subtype; /* curve nid for EC keys */
}	SSHX509KeyAlgs;
#define X509PUBALG_SIGNAME(p)	(p->signame ? p->signame : p->name)


void	fill_default_xkalg(void);
	/* format "name,dgst_name[,sig_name]" */
int	ssh_add_x509key_alg(const char *data);


int/*bool*/	ssh_is_x509signame(const char *signame);

int	ssh_xkalg_nameind(const char *name, const SSHX509KeyAlgs **q, int loc);
int	ssh_xkalg_typeind(int type, int subtype, const SSHX509KeyAlgs **q, int loc);
#define X509FORMAT_FIRSTMATCH	1
#define X509FORMAT_LEGACY	2
#define X509FORMAT_RFC6187	3
int	ssh_xkalg_typeformind(int type, int subtype, int frm, const SSHX509KeyAlgs **q, int loc);
int	ssh_xkalg_ind(const SSHX509KeyAlgs **q, int loc);

void	ssh_xkalg_listall(struct sshbuf *b, const char *sep);

char*	default_publickey_algorithms(void);

char*	ssh_get_allnames(char sep, int sigflag, const char* pattern);

#endif /* SSH_XKALG_H */
