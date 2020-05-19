#ifndef KEY_ENG_H
#define KEY_ENG_H
/*
 * Copyright (c) 2011-2017 Roumen Petrov.  All rights reserved.
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
#include "sshkey.h"

extern void ssh_engines_startup(void);
extern void ssh_engines_shutdown(void);

#ifdef	USE_OPENSSL_ENGINE

#include <openssl/engine.h>

extern int/*bool*/
process_engconfig_line(char *line, const char *filename, int linenum);

extern void ssh_load_engines(void);

extern int engine_load_private_type(int type, const char *filename, const char *passphrase, struct sshkey **keyp, char **commentp);
extern int engine_try_load_public(struct sshkey *k, const char *filename, char **commentp);
#endif /*ndef USE_OPENSSL_ENGINE*/

#ifdef USE_OPENSSL_STORE2
extern int store_load_private_type(int type, const char *filename, const char *passphrase, struct sshkey **keyp, char **commentp);
extern int store_try_load_public(struct sshkey *k, const char *filename, char **commentp);
#endif /*USE_OPENSSL_STORE2*/

#endif /*ndef KEY_ENG_H*/
