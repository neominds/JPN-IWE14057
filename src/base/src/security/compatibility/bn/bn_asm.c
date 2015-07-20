/* crypto/bn/bn_lib.c */
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

#ifndef BN_DEBUG
# undef NDEBUG /* avoid conflicting definitions */
# define NDEBUG
#endif

#include "cryptlib.h"
#include <openssl/bn.h>


void BN_bn2cci( const BIGNUM *a, cci_m ret )
{
	cci_t	numBytes;
    cci_b 	*byteArray;

	if (a && ret) 
	{
		numBytes = BN_num_bytes( a );
		byteArray = (cci_b *)cciAlloc( numBytes );

		numBytes = BN_bn2bin(a, byteArray);
			
		cciImportBin( ret, byteArray, numBytes );

		if (a->neg) cciNeg( ret );
		cciFree( byteArray );
	}
}
			    	   
#define BN_CLEAR_ARRAY( bn ) {int idx; for( idx = 0; idx < bn->top; idx++ )bn->d[ idx ] = 0;}

void BN_cci2bn( cci_m op, BIGNUM *ret )
{
	cci_t	numBytes;
    cci_b 	*byteArray;

	if (op && ret) 
	{
		BN_CLEAR_ARRAY( ret );
		numBytes = cciExportBin(op, &byteArray);			
		BN_bin2bn( byteArray, numBytes, ret );
		ret->neg = cciIsNeg( op );
		cciFree( byteArray );
	}
}



void BN_compare( BIGNUM *bn, cci_m cm )
{
	cci_t cciNumbyes;
	cci_t bnNumbyes;
	cci_b *bnArray, *cciArray;

	bnNumbyes = BN_num_bytes( bn );
	bnArray = (cci_b *)cciAlloc( bnNumbyes );
	BN_bn2bin(bn, bnArray);

	cciNumbyes = cciExportBin(cm, &cciArray);

	if ((bnNumbyes != cciNumbyes) ||
		(memcmp(cciArray, bnArray, cciNumbyes)) ||
		(cci_bool)bn->neg != cciIsNeg(cm) ||
		(BN_is_zero(bn) != cciIsZero(cm))) 
	{
		if ((cci_bool)bn->neg != cciIsNeg(cm)) 
			printf("POLARITY mismatch!. BN=%u, CCI=%u\n", bn->neg, cciIsNeg(cm) );

		if (BN_is_zero(bn) != cciIsZero(cm)) 
			printf("ZERO mismatch!. BN=%u, CCI=%u\n", BN_is_zero(bn), cciIsZero(cm) );

		printf("cciNumbyes - %u, bnNumbyes = %u\n", cciNumbyes, bnNumbyes );
		printf("CCI-A:%s\n", cciDecStr( cm ));
		printf("CCI-B:%s\n", cciDecStr( cm ));
		printf("CCI-R:%s\n", cciDecStr( cm ));

		printf("BN -A:%s\n", BN_bn2dec( bn ));
		printf("BN -B:%s\n", BN_bn2dec( bn ));
		printf("BN -R:%s\n", BN_bn2dec( bn ));

		exit(0);
	}

	cciFree( bnArray );
	cciFree( cciArray );
}



/* r can == a or b */
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
	{
	int ccip_BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
	return ccip_BN_add(r,a,b);
	}


int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
	{
	int ccip_BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
	return ccip_BN_sub(r,a,b);
	}


BIGNUM *BN_dup(const BIGNUM *a)
	{
	BIGNUM *ccip_BN_dup(const BIGNUM *a);
	return ccip_BN_dup(a);
	}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
	{
	BIGNUM *ccip_BN_copy(BIGNUM *a, const BIGNUM *b);
	return ccip_BN_copy(a, b);
	}

int BN_set_word(BIGNUM *a, BN_ULONG w)
	{
	int ccip_BN_set_word(BIGNUM *a, BN_ULONG w);
	return ccip_BN_set_word(a, w);
	}

int BN_cmp(const BIGNUM *a, const BIGNUM *b)
	{
	int ccip_BN_cmp(const BIGNUM *a, const BIGNUM *b);
	return ccip_BN_cmp(a, b);
	}

int BN_set_bit(BIGNUM *a, int n)
	{
	int ccip_BN_set_bit(BIGNUM *a, int n);
	return ccip_BN_set_bit(a,n);
	}

int BN_clear_bit(BIGNUM *a, int n)
	{
	int ccip_BN_clear_bit(BIGNUM *a, int n);
	return ccip_BN_clear_bit(a,n);
	}

int BN_is_bit_set(const BIGNUM *a, int n)
	{
	int ccip_BN_is_bit_set(const BIGNUM *a, int n);
	return ccip_BN_is_bit_set(a, n);
	}

int BN_mask_bits(BIGNUM *a, int n)
	{
	int ccip_BN_mask_bits(BIGNUM *a, int n);
	return ccip_BN_mask_bits(a, n);
	}


int BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor,
	   BN_CTX *ctx)
	{
	int ccip_BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor,
	   BN_CTX *ctx);
	return ccip_BN_div(dv,rm,num,divisor,ctx);
	}

int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
	{
	int ccip_BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);	
	return ccip_BN_exp(r, a, p, ctx);	
	}

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
	       BN_CTX *ctx)
	{
	int ccip_BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx);
	return ccip_BN_mod_exp(r,a,p,m,ctx);

	}


int BN_gcd(BIGNUM *r, const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx)
	{
	int ccip_BN_gcd(BIGNUM *r, const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx);
	return ccip_BN_gcd(r, in_a, in_b,ctx);
	}


BIGNUM *BN_mod_inverse(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
	{
	BIGNUM *ccip_BN_mod_inverse(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
	return ccip_BN_mod_inverse(r, a,n, ctx);
	}

int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
	{
	int ccip_BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
	return ccip_BN_mod_add(r,a,b,m,ctx);
	}

int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
	{
	int ccip_BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
	return ccip_BN_mod_sub(r, a, b, m, ctx);
	}

int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
	BN_CTX *ctx)
	{
	int ccip_BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
	BN_CTX *ctx);
	return ccip_BN_mod_mul(r,a,b,m,ctx);

	}


int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
	{
	int ccip_BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
	return ccip_BN_mod_sqr(r,a,m, ctx);
	}


int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	int ccip_BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
	return ccip_BN_mul(r,a, b, ctx);
	}



int BN_is_prime(const BIGNUM *a, int checks, void (*callback)(int,int,void *),
	BN_CTX *ctx_passed, void *cb_arg)
	{
	int ccip_BN_is_prime(const BIGNUM *a, int checks, void (*callback)(int,int,void *),
	BN_CTX *ctx_passed, void *cb_arg);
	return ccip_BN_is_prime(a,checks, callback,ctx_passed,cb_arg);
	}

int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
	{
	int ccip_BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
	return ccip_BN_lshift(r,a,n);
	}

int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
	{
	int ccip_BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
	return ccip_BN_rshift(r, a,n);
	}


int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	int ccip_BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
	return ccip_BN_sqr(r,a,ctx);
	}

int BN_add_word(BIGNUM *a, BN_ULONG w)
	{
	int ccip_BN_add_word(BIGNUM *a, BN_ULONG w);
	return ccip_BN_add_word(a, w);
	}

int BN_sub_word(BIGNUM *a, BN_ULONG w)
	{
	int ccip_BN_sub_word(BIGNUM *a, BN_ULONG w);
	return (ccip_BN_sub_word(a,w));
	}

int BN_mul_word(BIGNUM *a, BN_ULONG w)
	{
	int ccip_BN_mul_word(BIGNUM *a, BN_ULONG w);
	return ccip_BN_mul_word(a,w);
	}

/* --- Convert */
BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w)
	{
        BN_ULONG ccip_BN_mod_word(const BIGNUM *a, BN_ULONG w);
		return(ccip_BN_mod_word(a, w));
	}

/* --- Convert */
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w)
	{
        BN_ULONG ccip_BN_div_word(BIGNUM *a, BN_ULONG w);
		return(ccip_BN_div_word(a, w));
	}

/* --- Convert */
int BN_num_bits(const BIGNUM *a)
	{
        int	ccip_BN_num_bits(const BIGNUM *a);
		return(ccip_BN_num_bits(a));
	}
/* --- Convert */
BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe,
	const BIGNUM *add, const BIGNUM *rem,
	void (*callback)(int,int,void *), void *cb_arg)
	{
        BIGNUM *ccip_BN_generate_prime(BIGNUM *ret,int bits,int safe,
			const BIGNUM *add, const BIGNUM *rem,
			void (*callback)(int,int,void *),void *cb_arg);
		return(ccip_BN_generate_prime(ret,bits,safe,add, rem,callback,cb_arg));
	}

