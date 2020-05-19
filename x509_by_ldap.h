#ifndef X509_BY_LDAP_H
#define X509_BY_LDAP_H
/*
 * Copyright (c) 2004-2019 Roumen Petrov.  All rights reserved.
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
#ifndef LDAP_ENABLED
#  include "error: LDAP is disabled"
#endif

/* required includes */
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

#include "ssh_ldap.h" /*for build defines*/

#ifdef	__cplusplus
extern "C" {
#endif


X509_LOOKUP_METHOD* X509_LOOKUP_ldap(void);

#define X509_L_LDAP_HOST	1
#define X509_LOOKUP_add_ldap(x,value) \
		X509_LOOKUP_ctrl((x),X509_L_LDAP_HOST,(value),(long)(0),NULL)

#ifndef USE_LDAP_STORE
#define X509_L_LDAP_VERSION	2
#define X509_LOOKUP_set_protocol(x,value) \
		X509_LOOKUP_ctrl((x),X509_L_LDAP_VERSION,(value),(long)(0),NULL)
#endif


#ifdef	__cplusplus
}
#endif


#endif /*ndef X509_BY_LDAP_H*/
