#ifndef X509STORE_H
#define X509STORE_H
/*
 * Copyright (c) 2002-2018 Roumen Petrov.  All rights reserved.
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
#include <openssl/x509.h>


int	ssh_X509_NAME_print(BIO* bio, X509_NAME *xn);
char*	ssh_X509_NAME_oneline(X509_NAME *xn);

#ifndef HAVE_ASN1_STRING_GET0_DATA		/* OpenSSL < 1.1 */
static inline const unsigned char *
ASN1_STRING_get0_data(const ASN1_STRING *x) {
	 return(x->data);
}
#endif /*ndef HAVE_ASN1_STRING_GET0_DATA	OpenSSL < 1.1 */

static inline void
ssh_ASN1_STRING_get0_data(const ASN1_STRING *a,
    const unsigned char **p, int *len
) {
	if (p != NULL)
		*p = ASN1_STRING_get0_data(a);
	if (len != NULL)
		*len = ASN1_STRING_length(
		    (ASN1_STRING_LENGTH_CONST ASN1_STRING*) a);
}


int ssh_x509store_verify_cert(X509 *_cert, STACK_OF(X509) *_chain);

STACK_OF(X509)* ssh_x509store_build_certchain(X509 *_cert, STACK_OF(X509) *_untrusted);


typedef struct {
	int is_server;
	/* allowed client/server certificate purpose */
	int allowedcertpurpose; /* note field contain purpose index */
	int key_allow_selfissued; /* make sense only when x509store is enabled */
	int mandatory_crl;

	/* boolean: if true first key is validated that authorized
	 * otherwise first is authorized then validated.
	 */
	int validate_first;
}       SSH_X509Flags;

extern SSH_X509Flags ssh_x509flags;

void ssh_x509flags_initialize(SSH_X509Flags *flags, int is_server);
void ssh_x509flags_defaults(SSH_X509Flags *flags);

/* return purpose index, not purpose id (!) */
int ssh_get_x509purpose_s(int _is_server, const char* _purpose_synonym);

char* format_x509_purpose(int purpose_index);


int	ssh_X509_NAME_cmp(X509_NAME *_a, X509_NAME *_b);
int/*bool*/	ssh_X509_is_selfsigned(X509 *_cert);

typedef struct {
	/* ssh PKI(X509) store */
	const char   *certificate_file;
	const char   *certificate_path;
	const char   *revocation_file;
	const char   *revocation_path;
#ifdef LDAP_ENABLED
	const char   *ldap_ver;
	const char   *ldap_url;
#endif
}       X509StoreOptions;

void X509StoreOptions_init(X509StoreOptions *options);
void X509StoreOptions_reset(X509StoreOptions *options);
void X509StoreOptions_system_defaults(X509StoreOptions *options);
void X509StoreOptions_user_defaults(X509StoreOptions *options, uid_t uid);

void ssh_x509store_cleanup(void);

int/*bool*/ ssh_x509store_addlocations(const X509StoreOptions *locations);

typedef char SSHXSTOREPATH;
#if !HAVE_DECL_DEFINE_STACK_OF
DECLARE_STACK_OF(SSHXSTOREPATH)
# define sk_SSHXSTOREPATH_new_null()	SKM_sk_new_null(SSHXSTOREPATH)
# define sk_SSHXSTOREPATH_num(st)	SKM_sk_num(SSHXSTOREPATH, (st))
# define sk_SSHXSTOREPATH_value(st, i)	SKM_sk_value(SSHXSTOREPATH, (st), (i))
# define sk_SSHXSTOREPATH_push(st, val)	SKM_sk_push(SSHXSTOREPATH, (st), (val))
#else
DEFINE_STACK_OF(SSHXSTOREPATH)
#endif

int/*bool*/ ssh_x509store_addpaths(const STACK_OF(SSHXSTOREPATH) *paths);

X509*
ssh_x509store_get_cert_by_subject(X509_STORE *store, X509_NAME *name);

X509_CRL*
ssh_x509store_get_crl_by_subject(X509_STORE *store, X509_NAME *name);


#ifdef SSH_OCSP_ENABLED

enum va_type {
	SSHVA_NONE,
	SSHVA_OCSP_CERT,
	SSHVA_OCSP_SPEC
};


typedef struct {
	int type; /*allowed values from enum va_type*/

	/* file with additional trusted certificates */
	const char *certificate_file;

	/* ssh OCSP Provider(Respoder) URL */
	const char *responder_url;
}       VAOptions;

int ssh_get_default_vatype(void);
int ssh_get_vatype_s(const char* type);
const char*
ssh_get_vatype_i(int id);

void ssh_set_validator(const VAOptions *_va); /*fatal on error*/

int ssh_ocsp_validate(X509 *cert, X509_STORE *x509store);

#endif /*def SSH_OCSP_ENABLED*/


#endif /* X509STORE_H */
