/* OPENBSD ORIGINAL: lib/libc/crypto/arc4random.c */

/*	$OpenBSD: arc4random.c,v 1.25 2013/10/01 18:34:57 markus Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014-2018, Roumen Petrov.  All rights reserved.
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

/*
 * ChaCha based random number generator for OpenBSD.
 */

#include "includes.h"

#include <sys/types.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef OPENSSL_FIPS
#include <log.h>
#include <openssl/err.h>
#endif


#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

#ifdef OPENSSL_FIPS
/* for FIPS build always use functions from "compat" library */
# undef HAVE_ARC4RANDOM
# undef HAVE_ARC4RANDOM_STIR
# undef HAVE_ARC4RANDOM_BUF
# undef HAVE_ARC4RANDOM_UNIFORM
#endif

#if !defined(HAVE_ARC4RANDOM) || !defined(HAVE_ARC4RANDOM_STIR)

#ifdef WITH_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

#ifdef OPENSSL_FIPS
/* define to avoid use of 'efficient' arc4random_buf() */
# define HAVE_ARC4RANDOM_BUF

/* Size of key to use */
#define SEED_SIZE 20
static int rc4_ready = 0;

void      fips_arc4random_stir(void);
u_int32_t fips_arc4random(void);
void      save_arc4random_stir(void);
u_int32_t save_arc4random(void);

/* FIXME: based on readhat/fedora fips patch */
void
fips_arc4random_stir(void) {
	unsigned char rand_buf[SEED_SIZE];

	if (RAND_bytes(rand_buf, sizeof(rand_buf)) <= 0)
		fatal("Couldn't obtain random bytes (error %ld)",
		    ERR_get_error());
	rc4_ready = 1;
}
u_int32_t
fips_arc4random(void) {
	unsigned int r = 0;
	void *rp = &r;

	if (!rc4_ready) {
		fips_arc4random_stir();
	}
	RAND_bytes(rp, sizeof(r));

	return(r);
}

void
arc4random_stir(void) {
	if (FIPS_mode())
		fips_arc4random_stir();
	else
		save_arc4random_stir();
}

u_int32_t
arc4random(void) {
	return FIPS_mode()
		? fips_arc4random()
		: save_arc4random();
}

# define arc4random_stir	save_arc4random_stir
# define arc4random		save_arc4random
#endif /*def OPENSSL_FIPS*/


#include "log.h"

#define KEYSTREAM_ONLY
#include "chacha_private.h"

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)
static int rs_initialized;
static pid_t rs_stir_pid;
static chacha_ctx rs;		/* chacha context for random keystream */
static u_char rs_buf[RSBUFSZ];	/* keystream blocks */
static size_t rs_have;		/* valid bytes at end of rs_buf */
static size_t rs_count;		/* bytes till reseed */

static inline void _rs_rekey(u_char *dat, size_t datlen);

static inline void
_rs_init(u_char *buf, size_t n)
{
	if (n < KEYSZ + IVSZ)
		return;
	chacha_keysetup(&rs, buf, KEYSZ * 8, 0);
	chacha_ivsetup(&rs, buf + KEYSZ);
}

#ifndef WITH_OPENSSL
# ifndef SSH_RANDOM_DEV
#  define SSH_RANDOM_DEV "/dev/urandom"
# endif /* SSH_RANDOM_DEV */
static void
getrnd(u_char *s, size_t len)
{
	int fd;
	ssize_t r;
	size_t o = 0;

#ifdef HAVE_GETRANDOM
	if ((r = getrandom(s, len, 0)) > 0 && (size_t)r == len)
		return;
#endif /* HAVE_GETRANDOM */

	if ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1)
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV, strerror(errno));
	while (o < len) {
		r = read(fd, s + o, len - o);
		if (r == -1) {
			if (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				continue;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
}
#endif /* WITH_OPENSSL */

static void
_rs_stir(void)
{
	u_char rnd[KEYSZ + IVSZ];

#ifdef WITH_OPENSSL
	if (RAND_bytes(rnd, sizeof(rnd)) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (unsigned long)ERR_get_error());
#else
	getrnd(rnd, sizeof(rnd));
#endif

	if (!rs_initialized) {
		rs_initialized = 1;
		_rs_init(rnd, sizeof(rnd));
	} else
		_rs_rekey(rnd, sizeof(rnd));
	explicit_bzero(rnd, sizeof(rnd));

	/* invalidate rs_buf */
	rs_have = 0;
	memset(rs_buf, 0, RSBUFSZ);

	rs_count = 1600000;
}

static inline void
_rs_stir_if_needed(size_t len)
{
	pid_t pid = getpid();

	if (rs_count <= len || !rs_initialized || rs_stir_pid != pid) {
		rs_stir_pid = pid;
		_rs_stir();
	} else
		rs_count -= len;
}

static inline void
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rs_buf, 0,RSBUFSZ);
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rs, rs_buf, rs_buf, RSBUFSZ);
	/* mix in optional user provided data */
	if (dat) {
		size_t i, m;

		m = MIN(datlen, KEYSZ + IVSZ);
		for (i = 0; i < m; i++)
			rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rs_buf, KEYSZ + IVSZ);
	memset(rs_buf, 0, KEYSZ + IVSZ);
	rs_have = RSBUFSZ - KEYSZ - IVSZ;
}

static inline void
_rs_random_buf(void *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	size_t m;

	_rs_stir_if_needed(n);
	while (n > 0) {
		if (rs_have > 0) {
			m = MIN(n, rs_have);
			memcpy(buf, rs_buf + RSBUFSZ - rs_have, m);
			memset(rs_buf + RSBUFSZ - rs_have, 0, m);
			buf += m;
			n -= m;
			rs_have -= m;
		}
		if (rs_have == 0)
			_rs_rekey(NULL, 0);
	}
}

# ifndef HAVE_ARC4RANDOM
static inline void
_rs_random_u32(u_int32_t *val)
{
	_rs_stir_if_needed(sizeof(*val));
	if (rs_have < sizeof(*val))
		_rs_rekey(NULL, 0);
	memcpy(val, rs_buf + RSBUFSZ - rs_have, sizeof(*val));
	memset(rs_buf + RSBUFSZ - rs_have, 0, sizeof(*val));
	rs_have -= sizeof(*val);
	return;
}
# endif /*ndef HAVE_ARC4RANDOM*/

# ifndef HAVE_ARC4RANDOM_STIR
void
arc4random_stir(void)
{
#  if (defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4RANDOM_UNIFORM)) \
      || defined(OPENSSL_FIPS)
   /* platforms that have arc4random_uniform() and not
    * arc4random_stir() should not need the latter.
    * also exclude in FIPS build as there is no need to call
    * arc4random_stir() before using arc4random_buf().
    */
#  else
	_ARC4_LOCK();
	_rs_stir();
	_ARC4_UNLOCK();
#  endif
}
# endif /*ndef HAVE_ARC4RANDOM_STIR*/

# if 0 /*UNUSED*/
void
arc4random_addrandom(u_char *dat, int datlen)
{
	int m;

	_ARC4_LOCK();
	if (!rs_initialized)
		_rs_stir();
	while (datlen > 0) {
		m = MIN(datlen, KEYSZ + IVSZ);
		_rs_rekey(dat, m);
		dat += m;
		datlen -= m;
	}
	_ARC4_UNLOCK();
}
# endif /*UNUSED*/

# ifndef HAVE_ARC4RANDOM
u_int32_t
arc4random(void)
{
	u_int32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	return val;
}
# endif /*ndef HAVE_ARC4RANDOM*/

/*
 * If we are providing arc4random, then we can provide a more efficient 
 * arc4random_buf().
 */
# if !defined(HAVE_ARC4RANDOM_BUF) && !defined(HAVE_ARC4RANDOM)
void
arc4random_buf(void *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
# endif /*!defined(HAVE_ARC4RANDOM_BUF) && !defined(HAVE_ARC4RANDOM)*/

#ifdef OPENSSL_FIPS
/* redefine to use arc4random_buf() based on arc4random() */
# define HAVE_ARC4RANDOM
# undef HAVE_ARC4RANDOM_BUF
#endif

#endif /*!defined(HAVE_ARC4RANDOM) || !defined(HAVE_ARC4RANDOM_STIR)*/

/* arc4random_buf() that uses platform arc4random() */
#if !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
void
arc4random_buf(void *_buf, size_t n)
{
	size_t i;
	u_int32_t r = 0;
	char *buf = (char *)_buf;

	for (i = 0; i < n; i++) {
		if (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, sizeof(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

#ifndef HAVE_ARC4RANDOM_UNIFORM
/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
u_int32_t
arc4random_uniform(u_int32_t upper_bound)
{
	u_int32_t r, min;

	if (upper_bound < 2)
		return 0;

	/* 2**32 % x == (2**32 - x) % x */
	min = -upper_bound % upper_bound;

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		r = arc4random();
		if (r >= min)
			break;
	}

	return r % upper_bound;
}
#endif /* !HAVE_ARC4RANDOM_UNIFORM */

#if 0
/*-------- Test code for i386 --------*/
#include <stdio.h>
#include <machine/pctr.h>
int
main(int argc, char **argv)
{
	const int iter = 1000000;
	int     i;
	pctrval v;

	v = rdtsc();
	for (i = 0; i < iter; i++)
		arc4random();
	v = rdtsc() - v;
	v /= iter;

	printf("%qd cycles\n", v);
	exit(0);
}
#endif
