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

#include "x509store.h"
#include <openssl/x509v3.h>
#include "log.h"

#include <string.h>
#include <openssl/err.h>

#include "xmalloc.h"
#include "pathnames.h"
#include "misc.h"
#include <openssl/x509_vfy.h>
#ifdef LDAP_ENABLED
#  include "x509_by_ldap.h"
#endif

#if 0 /* enable if check below is not suitable for you build environment */
/* work-around if attribute X509_VERIFY_PARAM.check_time is not accessible */
# define USE_X509_STORE_CTX_INDEX	1
#endif
#ifndef USE_X509_STORE_CTX_INDEX
#  if defined(HAVE_X509_STORE_CTX_GET0_PARAM) && !defined(HAVE_X509_VERIFY_PARAM_GET_TIME)
/* Note structure X509_VERIFY_PARAM is defined in OpenSSL 0.9.8+ together
 * with function X509_STORE_CTX_get0_param()
 */
#    if defined(HAVE_OPENSSL_INIT_CRYPTO) && !defined(LIBRESSL_VERSION_NUMBER)
/* Temporary work-around for opaque structure X509_VERIFY_PARAM.
 * In OpenSSL 1.1.0* branch X509_VERIFY_PARAM_get_time() is available since 1.1.0d.
 * As result for versions from 1.1.0 to 1.1.0c we has to provide work-around.
 */
#      define USE_X509_STORE_CTX_INDEX	1
#    else
/* Use wrapper function X509_VERIFY_PARAM_get_time() */
#    endif
#  endif
#endif
#ifdef USE_X509_STORE_CTX_INDEX
/* do not define local get function if structure X509_VERIFY_PARAM is opaque */
#  define HAVE_X509_VERIFY_PARAM_GET_TIME
#endif
#ifndef HAVE_X509_STORE_CTX_GET0_PARAM
/* do not define local get function as X509_VERIFY_PARAM is not available */
#  define HAVE_X509_VERIFY_PARAM_GET_TIME
#endif


#ifndef HAVE_X509_STORE_SET_VERIFY_CB		/* OpenSSL < 1.0.0 */
static inline void
X509_STORE_set_verify_cb(X509_STORE *ctx, int (*verify_cb) (int, X509_STORE_CTX *)) {
	ctx->verify_cb = verify_cb;
}
#endif /*ndef HAVE_X509_STORE_SET_VERIFY_CB*/


SSH_X509Flags
ssh_x509flags = {
	0,	/* is_server */
	-1,	/* allowedcertpurpose */
	-1,	/* key_allow_selfissued */
	-1,	/* mandatory_crl */
	-1	/* validate_first */
};


static X509_STORE	*x509store = NULL;


#ifdef USE_X509_STORE_CTX_INDEX
static int	ssh_X509_STORE_CTX_index = -1;

struct ssh_X509_STORE_CTX_data_st {
	time_t	check_time;
};

typedef struct ssh_X509_STORE_CTX_data_st SSH_X509_STORE_CTX_DATA;


static inline SSH_X509_STORE_CTX_DATA*
SSH_X509_STORE_CTX_DATA_new(void) {
	SSH_X509_STORE_CTX_DATA *p;

	p = malloc(sizeof(SSH_X509_STORE_CTX_DATA));
	if (p != NULL) {
		p->check_time = 0;
	}
	return p;
}

static inline void
SSH_X509_STORE_CTX_DATA_free(SSH_X509_STORE_CTX_DATA* p) {
	free(p);
}
#endif /*def USE_X509_STORE_CTX_INDEX*/


#ifndef HAVE_X509_CRL_GET0_LASTUPDATE		/* OpenSSL < 1.1 */
static inline const ASN1_TIME*
X509_CRL_get0_lastUpdate(const X509_CRL *crl) {
	return X509_CRL_get_lastUpdate(crl);
}

static inline const ASN1_TIME*
X509_CRL_get0_nextUpdate(const X509_CRL *crl) {
	return X509_CRL_get_nextUpdate(crl);
}
#endif /* ndef HAVE_X509_CRL_GET0_LASTUPDATE	OpenSSL < 1.1 */


#ifndef HAVE_X509_OBJECT_NEW	/* OpenSSL < 1.1 */
/* backport specific OpenSSL X509_OBJECT functions */
static inline X509_OBJECT*
X509_OBJECT_new(void) {
	X509_OBJECT *xobj;

	xobj = OPENSSL_malloc(sizeof (X509_OBJECT));
	if (xobj != NULL) {
		memset(xobj, '\0', sizeof(*xobj));
		xobj->type = X509_LU_FAIL;
	}
	return xobj;
}

static inline void
X509_OBJECT_free(X509_OBJECT *xobj) {
	if (xobj == NULL) return;

	X509_OBJECT_free_contents(xobj);
	OPENSSL_free(xobj);
}
#endif /*ndef HAVE_X509_OBJECT_NEW*/

#ifndef HAVE_X509_STORE_CTX_GET_BY_SUBJECT	/* OpenSSL < 1.1 */
static inline int
X509_STORE_CTX_get_by_subject(
    X509_STORE_CTX *vs, /*X509_LOOKUP_TYPE*/int type,
    X509_NAME *name, X509_OBJECT *ret
) {
	return X509_STORE_get_by_subject(vs, type, name, ret);
}
#endif /*ndef HAVE_X509_STORE_CTX_GET_BY_SUBJECT*/

#ifndef HAVE_X509_OBJECT_GET0_X509	/* OpenSSL < 1.1 */
/* backport specific OpenSSL X509_OBJECT functions */
static inline X509*
X509_OBJECT_get0_X509(const X509_OBJECT *xobj) {
	if (xobj == NULL) return NULL;
	if (xobj->type != X509_LU_X509) return NULL;

	return xobj->data.x509;
}

static inline X509_CRL*
X509_OBJECT_get0_X509_CRL(const X509_OBJECT *xobj) {
	if (xobj == NULL) return NULL;
	if (xobj->type != X509_LU_CRL) return NULL;

	return xobj->data.crl;
}
#endif /*ndef HAVE_X509_OBJECT_GET0_X509*/

#ifndef HAVE_X509_VERIFY_PARAM_GET_TIME	/* OpenSSL < 1.1.0d, actually < 1.1.0 */
static inline time_t
X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM *param) {
    return param->check_time;
}
#endif /*ndef HAVE_X509_VERIFY_PARAM_GET_TIME*/


#if 1
#  define SSH_CHECK_REVOKED
#endif


#ifdef SSH_CHECK_REVOKED
static X509_STORE	*x509revoked = NULL;
static int ssh_x509revoked_cb(int ok, X509_STORE_CTX *ctx);


static char *
ssh_ASN1_INTEGER_2_string(ASN1_INTEGER *_asni) {
	BIO  *bio;
	int   k;
	char *p;

	if (_asni == NULL) {
		error("ssh_ASN1_INTEGER_2_string: _asni is NULL");
		return NULL;
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		fatal("ssh_ASN1_INTEGER_2_string: out of memory");
		return NULL; /* ;-) */
	}

	i2a_ASN1_INTEGER(bio, _asni);
	k = BIO_pending(bio);
	p = xmalloc(k + 1); /*fatal on error*/
	k = BIO_read(bio, p, k);
	p[k] = '\0';
	BIO_free_all(bio);

	return p;
}
#endif /*def SSH_CHECK_REVOKED*/


static int
ssh_x509store_lookup(X509_STORE *store, int type, X509_NAME *name, X509_OBJECT *xobj) {
	X509_STORE_CTX *csc;
	int ret = -1;

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: X509_STORE_CTX_new failed with '%s'"
		    , __func__, ebuf);
		return -1;
	}

	if (X509_STORE_CTX_init(csc, store, NULL, NULL) <= 0) {
		/*memory allocation error*/
		error("%s: cannot initialize x509store context"
		    , __func__);
		goto done;
	}
	ret = X509_STORE_CTX_get_by_subject(csc, type, name, xobj);
	X509_STORE_CTX_cleanup(csc);

done:
	X509_STORE_CTX_free(csc);

	return ret;
}


X509*
ssh_x509store_get_cert_by_subject(X509_STORE *store, X509_NAME *name) {
	X509 *ret = NULL;

{	/* opaque use of X509_OBJECT */
	X509_OBJECT *xobj;

	xobj = X509_OBJECT_new();
	if (xobj == NULL) {
		error("ssh_x509store_get_cert_by_subject: cannot allocate X509_OBJECT");
		return NULL;
	}

	if (ssh_x509store_lookup(store, X509_LU_X509, name, xobj) > 0)
		ret = X509_OBJECT_get0_X509(xobj);

	X509_OBJECT_free(xobj);
}

	return ret;
}


X509_CRL*
ssh_x509store_get_crl_by_subject(X509_STORE *store, X509_NAME *name) {
	X509_CRL *ret = NULL;

{	/* opaque use of X509_OBJECT */
	X509_OBJECT *xobj;

	xobj = X509_OBJECT_new();
	if (xobj == NULL) {
		error("ssh_X509_STORE_get_X509_CRL_by_subject: cannot allocate X509_OBJECT");
		return NULL;
	}

	if (ssh_x509store_lookup(store, X509_LU_CRL, name, xobj) > 0)
		ret = X509_OBJECT_get0_X509_CRL(xobj);

	X509_OBJECT_free(xobj);
}

	return ret;
}


static int
ssh_x509store_cb(int ok, X509_STORE_CTX *ctx) {
	int ctx_error = X509_STORE_CTX_get_error(ctx);
	X509 *ctx_cert = X509_STORE_CTX_get_current_cert(ctx);
	int self_signed = 0;

	if ((!ok) &&
	    (ctx_error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	) {
		if (ssh_x509flags.key_allow_selfissued) {
			ok = ssh_X509_is_selfsigned(ctx_cert);
			if (ok)
				self_signed = 1;
		}
	}
	if (!ok) {
		char *buf;
		buf = ssh_X509_NAME_oneline(X509_get_subject_name(ctx_cert)); /*fatal on error*/
		error("ssh_x509store_cb: subject='%s', error %d at %d depth lookup:%.200s",
			buf,
			ctx_error,
			X509_STORE_CTX_get_error_depth(ctx),
			X509_verify_cert_error_string(ctx_error));
		free(buf);
	}
#ifdef SSH_CHECK_REVOKED
	if (ok && !self_signed) {
		ok = ssh_x509revoked_cb(ok, ctx);
	}
#endif
	return ok;
}


typedef struct  {
	const char **synonyms;
}	CertPurposes;


static const char *__purpose_any[] = {
	"any", "any purpose", "any_purpose", "anypurpose", NULL
};


static const char *__purpose_sslclient[] = {
	"sslclient", "ssl client", "ssl_client", "client", NULL
};


static const char *__purpose_sslserver[] = {
	"sslserver", "ssl server", "ssl_server", "server", NULL
};


static CertPurposes
sslclient_purposes[] = {
	{ __purpose_sslclient },
	{ __purpose_any },
	{ NULL }
};


static CertPurposes
sslserver_purposes [] = {
	{ __purpose_sslserver },
	{ __purpose_any },
	{ NULL }
};


static const char*
get_cert_purpose(const char* _purpose_synonym, CertPurposes *_purposes) {
	int i;

	for (i = 0; _purposes[i].synonyms; i++) {
		const char *q = _purposes[i].synonyms[0];
		if (strcasecmp(_purpose_synonym, q) == 0) {
			return q;
		} else {
			const char **p;
			for (p = (_purposes[i].synonyms) + 1; *p; p++) {
				if (strcasecmp(_purpose_synonym, *p) == 0 ) {
					return q;
				}
			}
		}
	}
	return NULL;
}


void
ssh_x509flags_initialize(SSH_X509Flags *flags, int is_server) {
	flags->is_server = is_server;
	flags->allowedcertpurpose = -1;
	flags->key_allow_selfissued = -1;
	flags->mandatory_crl = -1;
	flags->validate_first = -1;
}


void
ssh_x509flags_defaults(SSH_X509Flags *flags) {
	if (flags->allowedcertpurpose == -1) {
		int is_server = flags->is_server;
		const char* purpose_synonym = is_server ? __purpose_sslclient[0] : __purpose_sslserver[0];

		flags->allowedcertpurpose = ssh_get_x509purpose_s(is_server, purpose_synonym);
	}
	if (flags->key_allow_selfissued == -1) {
		flags->key_allow_selfissued = 0;
	}
#ifdef SSH_CHECK_REVOKED
	if (flags->mandatory_crl == -1) {
		flags->mandatory_crl = 0;
	}
#else
	if (flags->mandatory_crl != -1) {
		logit("useless option: mandatory_crl");
	}
#endif
	if (flags->validate_first == -1) {
		flags->validate_first = 0;
	}
}


int
ssh_get_x509purpose_s(int _is_server, const char* _purpose_synonym) {
	const char * sslpurpose;

	sslpurpose = get_cert_purpose(_purpose_synonym,
		(_is_server ? sslclient_purposes : sslserver_purposes));
	if (sslpurpose != NULL) {
		int purpose_index = X509_PURPOSE_get_by_sname((char*)sslpurpose);
		if (purpose_index  < 0)
			fatal(	"ssh_get_x509purpose_s(%.10s): "
				"X509_PURPOSE_get_by_sname fail for argument '%.30s(%.40s)'",
				(_is_server ? "server" : "client"),
				sslpurpose, _purpose_synonym);
		return purpose_index;
	}
	return -1;
}


char*
format_x509_purpose(int purpose_index) {
	X509_PURPOSE *xp;

	xp = X509_PURPOSE_get0(purpose_index);
	if (xp == NULL) {
		fatal("format_x509_purpose: cannot get purpose from index");
		return "skip"; /* ;-) */
	}
	return X509_PURPOSE_get0_sname(xp);
}


int/*bool*/
ssh_X509_is_selfsigned(X509 *_cert) {
#ifdef EXFLAG_SS
  /* OpenSSL 0.9.7+ */
  #if 0
    #define USE_EXFLAG_SS
  #endif
#endif
#ifdef USE_EXFLAG_SS
	X509_check_purpose(_cert, -1, 0); /* set flags */
	return (_cert->ex_flags & EXFLAG_SS) != 0;
#else
	X509_NAME *issuer, *subject;

	issuer  = X509_get_issuer_name(_cert);
	subject = X509_get_subject_name(_cert);

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		char *buf;

		buf = ssh_X509_NAME_oneline(issuer);  /*fatal on error*/
		debug3("%s: issuer='%s'", __func__, buf);
		free(buf);

		buf = ssh_X509_NAME_oneline(subject); /*fatal on error*/
		debug3("%s: subject='%s'", __func__, buf);
		free(buf);
	}

	return ssh_X509_NAME_cmp(issuer, subject) == 0;
#endif
}


void
X509StoreOptions_init(X509StoreOptions *options) {
	options->certificate_file = NULL;
	options->certificate_path = NULL;
	options->revocation_file = NULL;
	options->revocation_path = NULL;
#ifdef LDAP_ENABLED
	options->ldap_ver = NULL;
	options->ldap_url = NULL;
#endif
}


void
X509StoreOptions_reset(X509StoreOptions *options) {
	free((char*)options->certificate_file);	options->certificate_file = NULL;
	free((char*)options->certificate_path);	options->certificate_path = NULL;
	free((char*)options->revocation_file);		options->revocation_file = NULL;
	free((char*)options->revocation_path);		options->revocation_path = NULL;
#ifdef LDAP_ENABLED
	free((char*)options->ldap_ver);		options->ldap_ver = NULL;
	free((char*)options->ldap_url);		options->ldap_url = NULL;
#endif
}


void
X509StoreOptions_system_defaults(X509StoreOptions *options) {
	if (options->certificate_file == NULL)
		options->certificate_file = xstrdup(_PATH_CA_CERTIFICATE_FILE);
	if (options->certificate_path == NULL)
		options->certificate_path = xstrdup(_PATH_CA_CERTIFICATE_PATH);
	if (options->revocation_file == NULL)
		options->revocation_file = xstrdup(_PATH_CA_REVOCATION_FILE);
	if (options->revocation_path == NULL)
		options->revocation_path = xstrdup(_PATH_CA_REVOCATION_PATH);
#ifdef LDAP_ENABLED
	/*nothing to do ;-)*/
#endif
}


static void
tilde_expand_filename2(const char **_fn, const char* _default, uid_t uid) {
	if (*_fn == NULL) {
		*_fn = tilde_expand_filename(_default, uid);
	} else {
		const char *p = *_fn;
		*_fn = tilde_expand_filename(p, uid);
		free((void*)p);
	}
}


void
X509StoreOptions_user_defaults(X509StoreOptions *options, uid_t uid) {
	tilde_expand_filename2(&options->certificate_file, _PATH_USERCA_CERTIFICATE_FILE, uid);
	tilde_expand_filename2(&options->certificate_path, _PATH_USERCA_CERTIFICATE_PATH, uid);
	tilde_expand_filename2(&options->revocation_file , _PATH_USERCA_REVOCATION_FILE , uid);
	tilde_expand_filename2(&options->revocation_path , _PATH_USERCA_REVOCATION_PATH , uid);
#ifdef LDAP_ENABLED
	/*nothing to do ;-)*/
#endif
}


static void
ssh_x509store_initcontext(void) {
#ifdef USE_X509_STORE_CTX_INDEX
	if (ssh_X509_STORE_CTX_index < 0)
		ssh_X509_STORE_CTX_index = X509_STORE_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
#endif
	if (x509store == NULL) {
		x509store = X509_STORE_new();
		if (x509store == NULL) {
			fatal("cannot create x509store context");
		}
		X509_STORE_set_verify_cb(x509store, ssh_x509store_cb);
	}
#ifdef SSH_CHECK_REVOKED
	if (x509revoked == NULL) {
		x509revoked = X509_STORE_new();
		if (x509revoked == NULL) {
			fatal("cannot create x509revoked context");
		}
	}
#endif
}


void
ssh_x509store_cleanup(void) {
	if (x509store != NULL) {
		X509_STORE_free(x509store);
		x509store = NULL;
	}
#ifdef SSH_CHECK_REVOKED
	if (x509revoked != NULL) {
		X509_STORE_free(x509revoked);
		x509revoked = NULL;
	}
#endif
}


int/*bool*/
ssh_x509store_addlocations(const X509StoreOptions *_locations) {
	int flag;

	if (_locations == NULL) {
		error("ssh_x509store_addlocations: _locations is NULL");
		return 0;
	}
	if ((_locations->certificate_path == NULL) &&
	    (_locations->certificate_file == NULL)) {
		error("ssh_x509store_addlocations: certificate path and file are NULLs");
		return 0;
	}
#ifdef SSH_CHECK_REVOKED
	if ((_locations->revocation_path == NULL) &&
	    (_locations->revocation_file == NULL)) {
		error("ssh_x509store_addlocations: revocation path and file are NULLs");
		return 0;
	}
#endif
	ssh_x509store_initcontext();

	flag = 0;
	/*
	 * Note:
	 * After X509_LOOKUP_{add_dir|load_file} calls we must call
	 * ERR_clear_error() otherwise when the first call to
	 * X509_LOOKUP_XXXX fail the second call fail too !
	 */
	if (_locations->certificate_path != NULL) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(x509store, X509_LOOKUP_hash_dir());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add hash dir lookup !");
			return 0; /* ;-) */
		}
		if (X509_LOOKUP_add_dir(lookup, _locations->certificate_path, X509_FILETYPE_PEM)) {
			debug2("hash dir '%.400s' added to x509 store", _locations->certificate_path);
			flag = 1;
		}
		ERR_clear_error();
	}
	if (_locations->certificate_file != NULL) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(x509store, X509_LOOKUP_file());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add file lookup !");
			return 0; /* ;-) */
		}
		if (X509_LOOKUP_load_file(lookup, _locations->certificate_file, X509_FILETYPE_PEM)) {
			debug2("file '%.400s' added to x509 store", _locations->certificate_file);
			flag = 1;
		}
		ERR_clear_error();
	}
	/*at least one lookup should succeed*/
	if (flag == 0) return 0;

	flag = 0;
#ifdef SSH_CHECK_REVOKED
	if (_locations->revocation_path != NULL
	/* NOTE configuration parser does not allow empty string but
	 * indirectly we use empty string in ssh-agent and ssh-add to
	 * avoid blocking exception above!
	 * (see ssh_x509store_addpaths)
	 */
	&& _locations->revocation_path[0] != '\0'
	) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(x509revoked, X509_LOOKUP_hash_dir());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add hash dir revocation lookup !");
			return 0; /* ;-) */
		}
		if (X509_LOOKUP_add_dir(lookup, _locations->revocation_path, X509_FILETYPE_PEM)) {
			debug2("hash dir '%.400s' added to x509 revocation store", _locations->revocation_path);
			flag = 1;
		}
		ERR_clear_error();
	}
	if (_locations->revocation_file != NULL) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(x509revoked, X509_LOOKUP_file());
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add file revocation lookup !");
			return 0; /* ;-) */
		}
		if (X509_LOOKUP_load_file(lookup, _locations->revocation_file, X509_FILETYPE_PEM)) {
			debug2("file '%.400s' added to x509 revocation store", _locations->revocation_file);
			flag = 1;
		}
		ERR_clear_error();
	}
#else /*ndef SSH_CHECK_REVOKED*/
	if (_locations->revocation_path != NULL) {
		logit("useless option: revocation_path");
	}
	if (_locations->revocation_file != NULL) {
		logit("useless option: revocation_file");
	}
	flag = 1;
#endif /*ndef SSH_CHECK_REVOKED*/
	/*at least one revocation lookup should succeed*/
	if (flag == 0) return 0;

#ifdef LDAP_ENABLED
	/* could be set only in client and daemon program */
	if (_locations->ldap_url != NULL) {
		X509_LOOKUP_METHOD* lookup_method;
		X509_LOOKUP *lookup;

		lookup_method = X509_LOOKUP_ldap();

#ifdef USE_LDAP_STORE
		/* NOTE: All LDAP-connections will use one and the same protocol version */
		if (!set_ldap_version(_locations->ldap_ver)) {
			fatal("ssh_x509store_addlocations: cannot set ldap version !");
			return 0; /* ;-) */
		}
#endif


		lookup = X509_STORE_add_lookup(x509store, lookup_method);
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add ldap lookup !");
			return 0; /* ;-) */
		}
		if (X509_LOOKUP_add_ldap(lookup, _locations->ldap_url)) {
			debug2("ldap url '%.400s' added to x509 store", _locations->ldap_url);
		}
#ifndef USE_LDAP_STORE
		if (_locations->ldap_ver != NULL) {
			if (!X509_LOOKUP_set_protocol(lookup, _locations->ldap_ver)) {
				fatal("ssh_x509store_addlocations: cannot set ldap version !");
				return 0; /* ;-) */
			}
		}
#endif /*ndef USE_LDAP_STORE*/
		/*ERR_clear_error();*/

#ifdef SSH_CHECK_REVOKED
		lookup = X509_STORE_add_lookup(x509revoked, lookup_method);
		if (lookup == NULL) {
			fatal("ssh_x509store_addlocations: cannot add ldap lookup(revoked) !");
			return 0; /* ;-) */
		}
		if (X509_LOOKUP_add_ldap(lookup, _locations->ldap_url)) {
			debug2("ldap url '%.400s' added to x509 store(revoked)", _locations->ldap_url);
		}
#ifndef USE_LDAP_STORE
		if (_locations->ldap_ver != NULL) {
			if (!X509_LOOKUP_set_protocol(lookup, _locations->ldap_ver)) {
				fatal("ssh_x509store_addlocations: cannot set ldap version(revoked) !");
				return 0; /* ;-) */
			}
		}
#endif /*ndef USE_LDAP_STORE*/
		/*ERR_clear_error();*/
#endif /*def SSH_CHECK_REVOKED*/
	}
#endif /*def LDAP_ENABLED*/

done:
	return 1;
}


int/*bool*/
ssh_x509store_addpaths(const STACK_OF(SSHXSTOREPATH) *paths) {
	int ret = 1;
	int k, N;
	X509StoreOptions extra;

	if (paths == NULL) return ret;

	N = sk_SSHXSTOREPATH_num(paths);
	for (k = 0; k < N; k++) {
		struct stat st;
		char *path = sk_SSHXSTOREPATH_value(paths, k);

		if (stat(path, &st) == -1) {
			error("%s: error %s for path='%s'", __func__, strerror(errno), path);
			return 0;
		}

		X509StoreOptions_init(&extra);
		if (S_ISDIR(st.st_mode))
			extra.certificate_path = path;
		else
			extra.certificate_file = path;
#ifdef SSH_CHECK_REVOKED
		extra.revocation_path = xstrdup(""); /*ignore*/
#endif
		ret = ssh_x509store_addlocations(&extra);
		X509StoreOptions_reset(&extra);

		if (!ret) break;
	}

	return ret;
}


static int
ssh_verify_cert(X509_STORE_CTX *_csc) {
	int flag;

	if (ssh_x509flags.allowedcertpurpose >= 0) {
		int def_purpose =  ( ssh_x509flags.is_server
			? X509_PURPOSE_SSL_CLIENT
			: X509_PURPOSE_SSL_SERVER
		);
		X509_PURPOSE *xptmp = X509_PURPOSE_get0(ssh_x509flags.allowedcertpurpose);
		int purpose;
		if (xptmp == NULL) {
			fatal("ssh_verify_cert: cannot get purpose from index");
			return -1; /* ;-) */
		}
		purpose = X509_PURPOSE_get_id(xptmp);
		flag = X509_STORE_CTX_purpose_inherit(_csc, def_purpose, purpose, 0);
		if (flag <= 0) {
			/*
			 * By default openssl applications don't check return code from
			 * X509_STORE_CTX_set_purpose or X509_STORE_CTX_purpose_inherit.
			 *
			 * Both methods return 0 (zero) and don't change purpose in context when:
			 * -X509_STORE_CTX_set_purpose(...)
			 *   purpose is X509_PURPOSE_ANY
			 * -X509_STORE_CTX_purpose_inherit(...)
			 *   purpose is X509_PURPOSE_ANY and default purpose is zero (!)
			 *
			 * Take note when purpose is "any" check method in current
			 * OpenSSL code just return 1. This openssl behavior is same
			 * as ssh option "AllowedCertPurpose=skip".
			 */
			int ecode;
			char ebuf[1024];

			ecode = X509_STORE_CTX_get_error(_csc);
			error("ssh_verify_cert: context purpose error, code=%d, msg='%.200s'"
				, ecode
				, X509_verify_cert_error_string(ecode));

			crypto_errormsg(ebuf, sizeof(ebuf));
			error("%s: X509_STORE_CTX_purpose_inherit failed with '%s'"
			    , __func__, ebuf);
			return -1;
		}
	}

{	/* lets use same time in all time checks */
	time_t check_time;

	time(&check_time);
	X509_STORE_CTX_set_time(_csc, 0, check_time);
#ifdef USE_X509_STORE_CTX_INDEX
{	SSH_X509_STORE_CTX_DATA* data = NULL;

	if (ssh_X509_STORE_CTX_index >= 0)
		data = SSH_X509_STORE_CTX_DATA_new();

	if (data != NULL) {
		data->check_time = check_time;
		X509_STORE_CTX_set_ex_data(_csc, ssh_X509_STORE_CTX_index, data);
	}
}
#endif /*def USE_X509_STORE_CTX_INDEX*/
}

	flag = X509_verify_cert(_csc);

#ifdef USE_X509_STORE_CTX_INDEX
{	SSH_X509_STORE_CTX_DATA* data = NULL;

	if (ssh_X509_STORE_CTX_index >= 0)
		data = X509_STORE_CTX_get_ex_data(_csc, ssh_X509_STORE_CTX_index);

	if (data != NULL) {
		X509_STORE_CTX_set_ex_data(_csc, ssh_X509_STORE_CTX_index, NULL);
		SSH_X509_STORE_CTX_DATA_free(data);
	}
}
#endif /*def USE_X509_STORE_CTX_INDEX*/

	if (flag < 0) {
		/* NOTE: negative result is returned only if certificate to check
		 * is not set in context. This function is called if _cert is non
		 * NULL, i.e. certificate has to be set in context!
		 * Lets log (possible in future) cases with negative value.
		 */
		logit("ssh_verify_cert: X509_verify_cert return unexpected negative value: '%d'", flag);
		return -1;
	}
	if (flag == 0) {
		int ecode = X509_STORE_CTX_get_error(_csc);
		error("ssh_verify_cert: verify error, code=%d, msg='%.200s'"
			, ecode
			, X509_verify_cert_error_string(ecode));
		return -1;
	}

	return 1;
}


int
ssh_x509store_verify_cert(X509 *_cert, STACK_OF(X509) *_chain) {
	int ret = 1;
	X509_STORE_CTX *csc;

	if (_cert == NULL) {
		/*already checked but ...*/
		error("%s: cert is NULL", __func__);
		ret = -1;
		goto done;
	}
	/* _chain could be NULL */
	if (x509store == NULL) {
		error("%s: context is NULL", __func__);
		ret = -1;
		goto done;
	}

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		char *buf;
		buf = ssh_X509_NAME_oneline(X509_get_subject_name(_cert)); /*fatal on error*/
		debug3("%s: for '%s'", __func__, buf);
		free(buf);
	}

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: X509_STORE_CTX_new failed with '%s'"
		    , __func__, ebuf);
		ret = -1;
		goto done;
	}

	if (X509_STORE_CTX_init(csc, x509store, _cert, _chain) <= 0) {
		/*memory allocation error*/
		error("%s: cannot initialize x509store context", __func__);
		ret = -1;
		goto donecsc;
	}
	ret = ssh_verify_cert(csc);
	X509_STORE_CTX_cleanup(csc);
donecsc:
	X509_STORE_CTX_free(csc);
#ifdef SSH_OCSP_ENABLED
	if (ret > 0) {
/*
 * PKIX-SSH implementation first verify and validate certificate by
 * "X.509 store" with certs and crls from file system. It is fast
 * check. After this when certificate chain is correct and
 * certificate is not revoked we send a status request to an OCSP
 * responder if configured.
 *
 * RFC2560(OCSP):
 * ...
 * 2.7 CA Key Compromise
 * If an OCSP responder knows that a particular CA's private key
 * has been compromised, it MAY return the revoked state for all
 * certificates issued by that CA.
 * ...
 * 5. Security Considerations
 * For this service to be effective, certificate using systems must
 * connect to the certificate status service provider. In the event
 * such a connection cannot be obtained, certificate-using systems
 * could implement CRL processing logic as a fall-back position.
 * ...
 * RFC2560(OCSP)^
 *
 * About PKIX-SSH implementation:
 * 1.) We prefer to delegate validation of issuer certificates to
 * 'OCSP Provider'. It is easy and simple to configure an OCSP
 * responder to return revoked state for all certificates issued
 * by a CA. Usually 'OCSP Provider' admins shall be first informed
 * for certificates with changed state. In each case this simplify
 * 'OCSP client'.
 * 2.) To conform to RFC2560 we should use OCSP to check status of
 * all certificates in the chain. Since this is network request it
 * is good to implement a cache and to save status with lifetime.
 * Might is good to have an OCSP cache server ;-).
 *
 * To minimize network latency and keeping in mind 1.) we send
 * 'OCSP request' only for the last certificate in the chain, i.e.
 * sended client or server certificate.
 *
 * Therefore instead to send OCSP request in ssh_x509revoked_cb()
 * we do this here.
 */
		ret = ssh_ocsp_validate(_cert, x509store);
	}
#endif /*def SSH_OCSP_ENABLED*/

done:
{
	const char *msg_ok = "trusted";
	const char *msg;
	msg = (ret > 0) ? msg_ok : (ret < 0 ? "error" : "rejected");
	debug3("%s: return %d(%s)", __func__, ret, msg);
}
	return ret;
}


static int
ssh_build_certchain_cb(int ok, X509_STORE_CTX *ctx) {

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		X509 *ctx_cert = X509_STORE_CTX_get_current_cert(ctx);
		char *buf;

		buf = ssh_X509_NAME_oneline(X509_get_subject_name(ctx_cert)); /*fatal on error*/
		debug3("ssh_build_certchain_cb: subject='%s'", buf);
		free(buf);
	}

	return ok;
}


STACK_OF(X509)*
ssh_x509store_build_certchain(X509 *cert, STACK_OF(X509) *untrusted) {
	STACK_OF(X509) *ret = NULL;
	X509_STORE_CTX *csc;

	if (cert == NULL) {
		/*already checked but ...*/
		error("%s: cert is NULL", __func__);
		return NULL;
	}
	/* _chain could be NULL */
	if (x509store == NULL) {
		error("%s: X.509 store in not initialized", __func__);
		return NULL;
	}

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: X509_STORE_CTX_new failed with '%s'"
		    , __func__, ebuf);
		return NULL;
	}

	if (X509_STORE_CTX_init(csc, x509store, cert, untrusted) <= 0) {
		/*memory allocation error*/
		error("%s: cannot initialize X.509 store context", __func__);
		goto donecsc;
	}

	X509_STORE_CTX_set_verify_cb(csc, ssh_build_certchain_cb);

	if (X509_verify_cert(csc) > 0) {
		X509 *x;
		ret = X509_STORE_CTX_get1_chain(csc);
		/*pop certificate - it must be first in chain*/
		x = sk_X509_delete(ret, 0);
		X509_free(x);
	} else {
		int ecode = X509_STORE_CTX_get_error(csc);
		verbose("cannot build certificate chain, code=%d, msg='%.200s'"
			, ecode
			, X509_verify_cert_error_string(ecode));
	}

donecsc:
	X509_STORE_CTX_free(csc);
	return ret;
}


#ifdef SSH_CHECK_REVOKED
static void
ssh_get_namestr_and_hash(
	X509_NAME *name,
	char **buf,
	u_long *hash
) {
	if (name == NULL) {
		debug("ssh_get_namestr_and_hash: name is NULL");
		if (buf ) *buf  = NULL;
		if (hash) *hash = 0; /* not correct but :-( */
		return;
	}

	if (buf ) *buf  = ssh_X509_NAME_oneline(name); /*fatal on error*/
	if (hash) *hash = X509_NAME_hash(name);
}


static inline uint32_t
ssh_X509_get_key_usage(X509 *x) {
#ifdef HAVE_X509_GET_KEY_USAGE
	/* defined in openssl 1.1+ */
	return X509_get_key_usage(x);
#else
	X509_check_purpose(x, -1, -1);
	return x->ex_flags & EXFLAG_KUSAGE ? x->ex_kusage : UINT32_MAX;
#endif
}


static inline unsigned long
ssh_X509_STORE_CTX_get_verify_flags(X509_STORE_CTX *ctx) {
#ifdef HAVE_X509_STORE_CTX_GET0_PARAM
	X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
	return X509_VERIFY_PARAM_get_flags(param);
#else
	return ctx->flags;
#endif
}


static inline time_t
X509_STORE_CTX_get_verify_check_time(X509_STORE_CTX *ctx) {
#ifndef USE_X509_STORE_CTX_INDEX
#ifdef HAVE_X509_STORE_CTX_GET0_PARAM
	X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
	return X509_VERIFY_PARAM_get_time(param);
#else
	return ctx->check_time;
#endif
#else /*def USE_X509_STORE_CTX_INDEX*/
	SSH_X509_STORE_CTX_DATA* data = NULL;

	if (ssh_X509_STORE_CTX_index >= 0)
		data = X509_STORE_CTX_get_ex_data(ctx, ssh_X509_STORE_CTX_index);

	if (data != NULL)
		return data->check_time;

{	/*failback to current time*/
	time_t check_time;
	time(&check_time);
	return check_time;
}
#endif
}


static int/*bool*/
ssh_check_crl(X509_STORE_CTX *_ctx, X509* _issuer, X509_CRL *_crl) {
	time_t  check_time;
	time_t *pcheck_time;
	int     k;
	u_long hash;

	if (_issuer == NULL) {
		error("ssh_check_crl: issuer is NULL");
		return 0;
	}
	if (_crl == NULL) {
		debug("ssh_check_crl: crl is NULL");
		return 1;
	}

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		BIO *bio;
		char *p;

		bio = BIO_new(BIO_s_mem());
		if (bio == NULL) {
			fatal("ssh_check_crl: out of memory");
			return 0; /* ;-) */
		}

		ssh_X509_NAME_print(bio, X509_CRL_get_issuer(_crl));

		BIO_printf(bio, "; Last Update: ");
		ASN1_UTCTIME_print(bio, X509_CRL_get0_lastUpdate(_crl));

		BIO_printf(bio, "; Next Update: ");
		ASN1_UTCTIME_print(bio, X509_CRL_get0_nextUpdate(_crl));

		k = BIO_pending(bio);
		p = xmalloc(k + 1); /*fatal on error*/
		k = BIO_read(bio, p, k);
		p[k] = '\0';

		debug3("ssh_check_crl: Issuer: %s", p);

		free(p);
		BIO_free(bio);
	}

/* RFC 3280:
 * The cRLSign bit is asserted when the subject public key is used
 * for verifying a signature on certificate revocation list (e.g., a
 * CRL, delta CRL, or an ARL).  This bit MUST be asserted in
 * certificates that are used to verify signatures on CRLs.
 */
	if (!(ssh_X509_get_key_usage(_issuer) & KU_CRL_SIGN)) {
		char *buf;
	#ifdef X509_V_ERR_KEYUSAGE_NO_CRL_SIGN
		/*first defined in OpenSSL 0.9.7d*/
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_KEYUSAGE_NO_CRL_SIGN);
	#endif
		ssh_get_namestr_and_hash(X509_get_subject_name(_issuer), &buf, &hash);
		error("ssh_check_crl:"
			" to verify crl signature key usage 'cRLSign'"
			" must present in issuer certificate '%s' with hash=0x%08lx"
			, buf, hash
		);
		free(buf);
		return 0;
	}

	{
		EVP_PKEY *pkey = X509_get_pubkey(_issuer);
		if (pkey == NULL) {
			error("ssh_check_crl: unable to decode issuer public key");
			X509_STORE_CTX_set_error(_ctx, X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY);
			return 0;
		}

		if (X509_CRL_verify(_crl, pkey) <= 0) {
			char *buf;

			ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
			error("ssh_check_crl: CRL has invalid signature"
				": issuer='%s', hash=0x%08lx"
				, buf, hash
			);
			X509_STORE_CTX_set_error(_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
			free(buf);
			EVP_PKEY_free(pkey);
			return 0;
		}
		EVP_PKEY_free(pkey);
	}


	if (ssh_X509_STORE_CTX_get_verify_flags(_ctx) & X509_V_FLAG_USE_CHECK_TIME) {
		check_time = X509_STORE_CTX_get_verify_check_time(_ctx);
		pcheck_time = &check_time;
	} else
		pcheck_time = NULL;

	k = X509_cmp_time(X509_CRL_get0_lastUpdate(_crl), pcheck_time);
	if (k == 0) {
		char *buf;

		ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
		error("ssh_check_crl: CRL has invalid lastUpdate field"
			": issuer='%s', hash=0x%08lx"
			, buf, hash
		);
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD);
		free(buf);
		return 0;
	}
	if (k > 0) {
		char *buf;

		ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
		error("ssh_check_crl: CRL is not yet valid"
			": issuer='%s', hash=0x%08lx"
			, buf, hash
		);
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_CRL_NOT_YET_VALID);
		free(buf);
		return 0;
	}

	k = X509_cmp_time(X509_CRL_get0_nextUpdate(_crl), pcheck_time);
	if (k == 0) {
		char *buf;

		ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
		error("ssh_check_crl: CRL has invalid nextUpdate field"
			": issuer='%s', hash=0x%08lx"
			, buf, hash
		);
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
		free(buf);
		return 0;
	}
#if 0
	/*test "extend time limit"*/
	if (k < 0) {
		time_t	tm;
		if (pcheck_time == NULL) {
			tm = time(NULL);
			pcheck_time = &tm;
		}
		*pcheck_time -= convtime("1w");
		k = X509_cmp_time(X509_CRL_get_nextUpdate(_crl), pcheck_time);
	}
#endif
	if (k < 0) {
		char *buf;

		ssh_get_namestr_and_hash(X509_CRL_get_issuer(_crl), &buf, &hash);
		error("ssh_check_crl: CRL is expired"
			": issuer='%s', hash=0x%08lx"
			, buf, hash
		);
		X509_STORE_CTX_set_error(_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
		free(buf);
		return 0;
	}

	return 1;
}


static int/*bool*/
ssh_is_cert_revoked(X509_STORE_CTX *_ctx, X509_CRL *_crl, X509 *_cert) {
	X509_REVOKED *revoked;
	ASN1_INTEGER *serial;
	int ret = 1;
	int k;

	if (_crl == NULL) return 1;

	revoked = X509_REVOKED_new();
	if (revoked == NULL) {
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: X509_REVOKED_new failed with '%s'"
		    , __func__, ebuf);
		return 1;
	}

	serial = X509_get_serialNumber(_cert);
	X509_REVOKED_set_serialNumber(revoked, serial);
	k = sk_X509_REVOKED_find(X509_CRL_get_REVOKED(_crl), revoked);
	if (k < 0) {
		ret = 0;
		goto done;
	}

	X509_STORE_CTX_set_error(_ctx, X509_V_ERR_CERT_REVOKED);
	/* yes, revoked. print log and ...*/
{
	char *dn, *ser, *in;

	dn  = ssh_X509_NAME_oneline(X509_get_subject_name(_cert)); /*fatal on error*/
	ser = ssh_ASN1_INTEGER_2_string(serial);
	in  = ssh_X509_NAME_oneline(X509_CRL_get_issuer  (_crl )); /*fatal on error*/

	error("certificate '%s' with serial '%.40s' revoked from issuer '%s'"
		, dn, ser, in);
	free(dn);
	free(ser);
	free(in);
}
done:
	if (revoked) X509_REVOKED_free(revoked);
	return ret;
}


static int
ssh_x509revoked_cb(int ok, X509_STORE_CTX *ctx) {
	X509     *cert;
	X509_CRL *crl;

	if (!ok) return 0;
	if (x509revoked == NULL)
		return ok; /* XXX:hmm */

	cert = X509_STORE_CTX_get_current_cert(ctx);
	if (cert == NULL) {
		error("ssh_x509revoked_cb: missing current certificate in x509store context");
		return 0;
	}

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG3) {
		char *buf;

		buf = ssh_X509_NAME_oneline(X509_get_issuer_name(cert)); /*fatal on error*/
		debug3("ssh_x509revoked_cb: Issuer: %s", buf);
		free(buf);

		buf = ssh_X509_NAME_oneline(X509_get_subject_name(cert)); /*fatal on error*/
		debug3("ssh_x509revoked_cb: Subject: %s", buf);
		free(buf);
	}

/* TODO:
 * NID_crl_distribution_points may contain one or more
 * CRLissuer != cert issuer
 */
	crl = ssh_x509store_get_crl_by_subject(
	    x509revoked,
	    X509_get_subject_name(cert)
	);
	if (crl != NULL) {
/*
 * In callback we cannot check CRL signature at this point when we use
 * X509_get_issuer_name(), because we don't know issuer public key!
 * Of course we can get the public key from X509_STORE defined by
 * static variable "x509store".
 * Of course we can check revocation outside callback, but we should
 * try to find public key in X509_STORE[s].
 *
 * At this point we can get easy public key of "current certificate"!
 *
 * Method: "look forward"
 * At this call we check CLR (signature and other) issued with "current
 * certificate" ("CertA"). If all is OK with "CertA" by next call of
 * callback method "current certificate" is signed from "CertA" and the
 * CRL issued from "CertA", if any is already verified - cool ;-).
 *
 * Note that when a certificate is revoked all signed from that
 * certificate are revoked automatically too. With method "look forward"
 * we already know that all issuers of "current certificate" aren't
 * revoked.
 */
		ok = ssh_check_crl(ctx, cert, crl);
	} else {
		if (ssh_x509flags.mandatory_crl == 1) {
			int loc;
			loc = X509_get_ext_by_NID(cert, NID_crl_distribution_points, -1);
			ok = (loc < 0);
			if (!ok) {
				error("ssh_x509revoked_cb: unable to get issued CRL");
				X509_STORE_CTX_set_error(ctx, X509_V_ERR_UNABLE_TO_GET_CRL);
			}
		}
	}
	if (!ok) return 0;

	crl = ssh_x509store_get_crl_by_subject(
	      x509revoked,
	      X509_get_issuer_name(cert)
	);
	if (crl != NULL) {
		ok = !ssh_is_cert_revoked(ctx, crl, cert);
	}
	if (!ok) return 0;

	return ok;
}
#endif
