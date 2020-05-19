/*
 * Copyright (c) 2018-2019 Roumen Petrov.  All rights reserved.
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

#include <openssl/err.h>

#include "ssh-pkcs11.h"


#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA PKCS11_str_functs[] = {
	{ ERR_PACK(0, PKCS11_LOGIN, 0)			, "login" },
	{ ERR_PACK(0, PKCS11_REAUTHENTICATE, 0)		, "reauthenticate" },
	{ ERR_PACK(0, PKCS11_GET_KEY, 0)		, "get_key" },
	{ ERR_PACK(0, PKCS11_RSA_PRIVATE_ENCRYPT, 0)	, "rsa_private_encrypt" },
	{ ERR_PACK(0, PKCS11_DSA_DO_SIGN, 0)		, "dsa_do_sign" },
	{ ERR_PACK(0, PKCS11_ECDSA_DO_SIGN, 0)		, "ecdsa_do_sign" },
	{ 0, NULL }
};

static ERR_STRING_DATA PKCS11_str_reasons[] = {
	{ ERR_PACK(0, 0, PKCS11_SIGNREQ_FAIL)		, "sign request fail" },
	{ ERR_PACK(0, 0, PKCS11_C_SIGNINIT_FAIL)	, "C_SignInit fail" },
	{ ERR_PACK(0, 0, PKCS11_C_SIGN_FAIL)		, "C_Sign fail" },
	{ ERR_PACK(0, 0, PKCS11_C_LOGIN_FAIL)		, "C_Login fail" },
	{ ERR_PACK(0, 0, PKCS11_FINDKEY_FAIL)		, "find key fail" },
	{ 0, NULL }
};

static ERR_STRING_DATA PKCS11_lib_name[] = {
   {0, "SSH PKCS#11"},
   {0, NULL}
};

#endif /*ndef OPENSSL_NO_ERR*/


static int ERR_LIB_PKCS11 = 0;

void
ERR_PKCS11_PUT_error(int function, int reason, char *file, int line, const char* funcname) {
	if (ERR_LIB_PKCS11 == 0)
		ERR_LIB_PKCS11 = ERR_get_next_error_library();

#ifdef OPENSSL_NO_FILENAMES /* OpenSSL 1.1+ */
	file = NULL;
	line = 0;
#endif
#ifdef ERR_raise_data
	UNUSED(function);
	ERR_new();
	ERR_set_debug(file, line, funcname);
	ERR_set_error(ERR_LIB_PKCS11, reason, NULL);
#else
	UNUSED(funcname);
	ERR_PUT_error(ERR_LIB_PKCS11, function, reason, file, line);
#endif /*ndef ERR_raise_data*/
}


void
ERR_load_PKCS11_strings(void) {
#ifndef OPENSSL_NO_ERR
{	static int loaded = 0;
	if (loaded) return;
	loaded = 1;
}
	if (ERR_LIB_PKCS11 == 0)
		ERR_LIB_PKCS11 = ERR_get_next_error_library();

	ERR_load_strings(ERR_LIB_PKCS11, PKCS11_str_functs);
	ERR_load_strings(ERR_LIB_PKCS11, PKCS11_str_reasons);

	PKCS11_lib_name[0].error = ERR_PACK(ERR_LIB_PKCS11, 0, 0);
	ERR_load_strings(0, PKCS11_lib_name);
#endif /*ndef OPENSSL_NO_ERR*/
}

#else /*def ENABLE_PKCS11*/

typedef int pkcs11_empty_translation_unit;

#endif
