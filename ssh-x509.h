#ifndef SSH_X509_H
#define SSH_X509_H
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

#include "includes.h"

#include <openssl/x509.h>

#include "sshxkey.h"
#include "sshkey.h"
#include "sshbuf.h"


/*
 * Method return a key(x509) only with "Subject"("Distinguished Name") !
 */
struct sshkey*	X509key_from_subject(const char *pkalg, const char *cp, char **ep);


/* draft-ietf-secsh-transport-12.txt */
int	X509key_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp);

int	X509key_to_buf(const struct sshkey *key, struct sshbuf *b);
int	X509key_from_buf(struct sshbuf *b, struct sshkey **keyp);

int	X509key_encode_identity(const char *pkalg, const struct sshkey *key, struct sshbuf *b);
int	X509key_decode_identity(const char *pkalg, struct sshbuf *b, struct sshkey *k);

void	x509key_move_identity(struct sshkey *from, struct sshkey *to);
void	x509key_copy_identity(const struct sshkey *from, struct sshkey *to);
void	x509key_demote(const struct sshkey *k, struct sshkey *pk);

char*	x509key_subject(const struct sshkey *key);

/*
 * Method write base 64 encoded X.509 identity of key.
 */
int	x509key_write(const struct sshkey *key, struct sshbuf *b);
/*
 * Method write subject of key X.509 certificate.
 */
int	Xkey_write_subject(const char *pkalg, const struct sshkey *key, FILE *f);

void	x509key_parse_cert(struct sshkey *key, EVP_PKEY *pk, BIO *bio);
void	x509key_load_certs(const char *pkalg, struct sshkey *key, const char *filename);
void	x509key_build_chain(struct sshkey *key);

int/*bool*/	x509key_write_identity_bio_pem(BIO *bio, const struct sshkey *key);

int	ssh_x509_equal(const struct sshkey *a, const struct sshkey *b);

int		ssh_x509key_type(const char *name);
const char*	ssh_x509key_name(const struct sshkey *k);

u_int	ssh_x509_key_size(const struct sshkey *key);

/* NOTE caller is responsible to ensure that X.509 certificate match private key */
int/*bool*/	ssh_x509_set_cert(struct sshkey *key, X509 *x509, STACK_OF(X509) *untrusted);
int		ssh_x509_cmp_cert(const struct sshkey *key1, const struct sshkey *key2);


/* backward compatibility for extended key format support */
struct sshkey	*xkey_from_blob(const char *pkalg, const u_char *blob, u_int blen);

int	xkey_to_blob(const char *pkalg, const struct sshkey *key, u_char **blobp, u_int *lenp);

int	parse_key_from_blob(const u_char *blob, size_t blen,
	    struct sshkey **keyp, char **pkalgp);


int	xkey_validate_cert(const struct sshkey *k);


static inline int/*bool*/
sshkey_is_x509(const struct sshkey *key) {
	return (key != NULL) && (key->x509_data != NULL);
}


SSH_X509*	SSH_X509_new(void);
void		SSH_X509_free(SSH_X509* xd);
X509*		SSH_X509_get_cert(SSH_X509 *xd);

#endif /* SSH_X509_H */
