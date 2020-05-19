#include "includes.h"

#ifdef HAVE_EVP_SHA256 /* OpenSSL 0.9.8+ */

/* $OpenBSD: hash.c,v 1.5 2018/01/13 00:24:09 naddy Exp $ */
/*
 * Public domain. Author: Christian Weisgerber <naddy@openbsd.org>
 * API compatible reimplementation of function from nacl
 */

#include "crypto_api.h"

#include <stdarg.h>

#include "digest.h"
#include "log.h"
#include "ssherr.h"

int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{
	int r;

	if ((r = ssh_digest_memory(SSH_DIGEST_SHA512, in, inlen, out,
	    crypto_hash_sha512_BYTES)) != 0)
		fatal("%s: %s", __func__, ssh_err(r));
	return 0;
}

#else /*ndef HAVE_EVP_SHA256*/

/* Copied from nacl-20110221/crypto_hash/sha512/ref/hash.c */

/*
20080913
D. J. Bernstein
Public domain.
*/

#include "crypto_api.h"

int	crypto_hashblocks_sha512(unsigned char *, const unsigned char *,
     unsigned long long);

#define blocks crypto_hashblocks_sha512

static const unsigned char iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

typedef unsigned long long uint64;

int crypto_hash_sha512(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  unsigned char h[64];
  unsigned char padded[256];
  unsigned int i;
  unsigned long long bytes = inlen;

  for (i = 0;i < 64;++i) h[i] = iv[i];

  blocks(h,in,inlen);
  in += inlen;
  inlen &= 127;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 112) {
    for (i = inlen + 1;i < 119;++i) padded[i] = 0;
    padded[119] = bytes >> 61;
    padded[120] = bytes >> 53;
    padded[121] = bytes >> 45;
    padded[122] = bytes >> 37;
    padded[123] = bytes >> 29;
    padded[124] = bytes >> 21;
    padded[125] = bytes >> 13;
    padded[126] = bytes >> 5;
    padded[127] = bytes << 3;
    blocks(h,padded,128);
  } else {
    for (i = inlen + 1;i < 247;++i) padded[i] = 0;
    padded[247] = bytes >> 61;
    padded[248] = bytes >> 53;
    padded[249] = bytes >> 45;
    padded[250] = bytes >> 37;
    padded[251] = bytes >> 29;
    padded[252] = bytes >> 21;
    padded[253] = bytes >> 13;
    padded[254] = bytes >> 5;
    padded[255] = bytes << 3;
    blocks(h,padded,256);
  }

  for (i = 0;i < 64;++i) out[i] = h[i];

  return 0;
}
#endif /*ndef HAVE_EVP_SHA256*/
