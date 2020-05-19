/* 	$OpenBSD: tests.c,v 1.1 2014/06/24 01:14:18 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#include "../test_helper/test_helper.h"
#include "ssh_api.h"

void sshkey_tests(void);
void sshkey_file_tests(void);
void sshkey_fuzz_tests(void);

void
tests(void)
{
	ssh_crypto_init();

	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();

	ssh_crypto_fini();
}
