/* 	$OpenBSD: tests.c,v 1.1 2015/01/15 23:41:29 markus Exp $ */
/*
 * Placed in the public domain
 */

#include "../test_helper/test_helper.h"
#include "ssh_api.h"

void kex_tests(void);

void
tests(void)
{
	ssh_crypto_init();

	kex_tests();

	ssh_crypto_fini();
}
