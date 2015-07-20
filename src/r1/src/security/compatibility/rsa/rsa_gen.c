/* crypto/rsa/rsa_gen.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <time.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <wrn/cci/cci.h>

RSA *cci_to_openssl( CCIPublicKey privateKey, RSA *opensslKey );
#define BN_STREAM( cciSize, cciStream, bn ) {cciStream = (cci_b *)cciAlloc( BN_num_bytes( bn ));cciSize = BN_bn2bin( bn, cciStream );}

int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{

{
	CCIContext		cciContext;
	cci_st			cciStatus = CCI_FAILURE;
	cci_b			*publicExponent=0;
	cci_t			exponentSize=0;
	CCIPublicKey 		privateKey, publicKey;


	/*
	** --- First create a request context
	*/
	cciStatus = cciCtxCreate( &cciContext, CCI_APP_PROVIDER_ID, CCI_CLASS_PUBLICKEY, CCI_PUBLICKEY_RSA );
	if( CCISUCCESS( cciStatus ) )
	{
		cciPKIKeyCreate( CCI_APP_PROVIDER_ID, CCI_RSA_PUBLIC_KEY, &publicKey  );
		cciPKIKeyCreate( CCI_APP_PROVIDER_ID, CCI_RSA_PRIVATE_KEY, &privateKey );


		/*
		** --- Set the Public Exponent 
		*/
		BN_STREAM (exponentSize, publicExponent, e);
		cciPKIKeyCompSet( publicKey, CCI_RSA_PUBLIC_EXPONENT, publicExponent, exponentSize );

		/*
		** --- Set the request attributes
		*/
		cciCtxAttrSet( cciContext, CCI_PUBLICKEY_OPERATION,		CCI_PUBLICKEY_OP_GEN_KEYPAIR );
		cciCtxAttrSet( cciContext, CCI_PUBLICKEY_PUBLIC,		publicKey );
		cciCtxAttrSet( cciContext, CCI_PUBLICKEY_PRIVATE,		privateKey );
		cciCtxAttrSet( cciContext, CCI_PUBLICKEY_LENGTH_BITS,	bits );

		/*
		** --- Generate the keys...
		*/
		cciStatus = cciCtxPKIKeyGen( cciContext );
		cciCtxDestroy( cciContext );

		cci_to_openssl(privateKey, rsa);

		cciPKIKeyDestroy( publicKey );
    		cciPKIKeyDestroy( privateKey );
    		if(publicExponent)
    		{
    			cciFree(publicExponent);
    		}
	}

	if(CCISUCCESS(cciStatus))
	{
		return 1;	
	}
	else
		return 0;
	}
}


RSA *RSA_generate_key(int bits, unsigned long e_value,
    void (*callback)(int,int,void *), void *cb_arg)
{
    CCIPublicKey	publicKey;
    CCIPublicKey	privateKey;
    RSA *rsa=NULL;

    cciPKIGenerateKeys(CCI_APP_PROVIDER_ID,CCI_PUBLICKEY_RSA, &privateKey, &publicKey, bits );

    rsa = cci_to_openssl(privateKey,NULL);

    cciPKIKeyDestroy( publicKey );
    cciPKIKeyDestroy( privateKey );
    return(rsa);
}
