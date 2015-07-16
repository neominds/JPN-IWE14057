/* compatibility.h - Header file to convert OpenSSL constants to CCI constants  */

/* Copyright 2005 Wind River Systems, Inc.                                      */

/* 
modification history
--------------------
01a,03feb05,cdw  created
*/

/*
DESCRIPTION

This header file is used to convert some OpenSSL crypto based
constants to their CCI equivalents.  This is required for backwards
compatibility with source code that hasn't yet been converted to use
CCI.

*/

#ifndef _COMPATIBILITY_H_
#define _COMPATIBILITY_H_

#include <wrn/cci/cci.h>

#define MD2_BLOCK               CCI_MD2_BLOCKSIZE
#define MD2_DIGEST_LENGTH       CCI_MD2_DIGESTSIZE
#define MD2_INT                 unsigned int
#define MD4_CBLOCK              CCI_MD4_BLOCKSIZE
#define MD4_DIGEST_LENGTH       CCI_MD4_DIGESTSIZE
#define MD5_CBLOCK              CCI_MD5_BLOCKSIZE
#define MD5_DIGEST_LENGTH       CCI_MD5_DIGESTSIZE
#define RIPEMD160_CBLOCK        CCI_RMD160_BLOCKSIZE
#define RIPEMD160_DIGEST_LENGTH CCI_RMD160_DIGESTSIZE
#define SHA_CBLOCK              CCI_SHA1_BLOCKSIZE
#define SHA_DIGEST_LENGTH       CCI_SHA1_DIGESTSIZE
#define SHA256_CBLOCK		CCI_SHA256_BLOCKSIZE
#define SHA256_DIGEST_LENGTH	CCI_SHA256_DIGESTSIZE
#define SHA384_CBLOCK		CCI_SHA384_BLOCKSIZE
#define SHA384_DIGEST_LENGTH	CCI_SHA384_DIGESTSIZE
#define SHA512_CBLOCK		CCI_SHA512_BLOCKSIZE
#define SHA512_DIGEST_LENGTH	CCI_SHA512_DIGESTSIZE

#endif
