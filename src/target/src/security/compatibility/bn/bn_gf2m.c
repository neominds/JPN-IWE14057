/* crypto/bn/bn_gf2m.c */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * In addition, Sun covenants to all licensees who provide a reciprocal
 * covenant with respect to their own patents if any, not to sue under
 * current and future patent claims necessarily infringed by the making,
 * using, practicing, selling, offering for sale and/or otherwise
 * disposing of the ECC Code as delivered hereunder (or portions thereof),
 * provided that such covenant shall not apply:
 *  1) for code that a licensee deletes from the ECC Code;
 *  2) separates from the ECC Code; or
 *  3) for infringements caused by:
 *       i) the modification of the ECC Code or
 *      ii) the combination of the ECC Code with other software or
 *          devices where such combination causes the infringement.
 *
 * The software is originally written by Sheueling Chang Shantz and
 * Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

/*
 * NOTE: This file is licensed pursuant to the OpenSSL license below and may
 * be modified; but after modifications, the above covenant may no longer
 * apply! In such cases, the corresponding paragraph ["In addition, Sun
 * covenants ... causes the infringement."] and this note can be edited out;
 * but please keep the Sun copyright notice and attribution.
 */

/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include "cryptlib.h"
#include "bn_lcl.h"

/* Add polynomials a and b and store result in r; r could be a or b, a and b 
 * could be equal; r is the bitwise XOR of a and b.
 */
int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int ccip_BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
	return ccip_BN_GF2m_add(r,a,b);
    }


/* Some functions allow for representation of the irreducible polynomials
 * as an int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */


/* Performs modular reduction of a and store result in r.  r could be a. */
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[])
{
	int ccip_BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[]);
	return ccip_BN_GF2m_mod_arr(r,a,p);
    }

/* Performs modular reduction of a by p and store result in r.  r could be a.
 *
 * This function calls down to the BN_GF2m_mod_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the
 * BN_GF2m_mod_arr function.
 */
int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p)
{
	int ccip_BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
	return ccip_BN_GF2m_mod(r,a,p);
}


/* Compute the product of two polynomials a and b, reduce modulo p, and store
 * the result in r.  r could be a or b; a could be b.
 */
int	BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const unsigned int p[], BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const unsigned int p[], BN_CTX *ctx);
	return ccip_BN_GF2m_mod_mul_arr(r,a,b,p, ctx);
    }

/* Compute the product of two polynomials a and b, reduce modulo p, and store
 * the result in r.  r could be a or b; a could equal b.
 *
 * This function calls down to the BN_GF2m_mod_mul_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the 
 * BN_GF2m_mod_mul_arr function.
 */
int	BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
	return ccip_BN_GF2m_mod_mul(r,a,b, p, ctx);
}

/* Square a, reduce the result mod p, and store it in a.  r could be a. */
int	BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[], BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[], BN_CTX *ctx);
	return ccip_BN_GF2m_mod_sqr_arr(r,a,p,ctx);
    }

/* Square a, reduce the result mod p, and store it in a.  r could be a.
 *
 * This function calls down to the BN_GF2m_mod_sqr_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the 
 * BN_GF2m_mod_sqr_arr function.
 */
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
	return ccip_BN_GF2m_mod_sqr(r, a, p,ctx);
	}


/* Invert a, reduce modulo p, and store the result in r. r could be a. 
 * Uses Modified Almost Inverse Algorithm (Algorithm 10) from
 *     Hankerson, D., Hernandez, J.L., and Menezes, A.  "Software Implementation
 *     of Elliptic Curve Cryptography Over Binary Fields".
 */
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
	return ccip_BN_GF2m_mod_inv(r, a, p, ctx);
        }

/* Invert xx, reduce modulo p, and store the result in r. r could be xx. 
 *
 * This function calls down to the BN_GF2m_mod_inv implementation; this wrapper
 * function is only provided for convenience; for best performance, use the 
 * BN_GF2m_mod_inv function.
 */
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *xx, const unsigned int p[], BN_CTX *ctx)
    {
	int ccip_BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *xx, const unsigned int p[], BN_CTX *ctx);
	return ccip_BN_GF2m_mod_inv_arr(r,xx,p,ctx);
            }



/* Divide y by x, reduce modulo p, and store the result in r. r could be x 
 * or y, x could equal y.
 */
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *y, const BIGNUM *x, const BIGNUM *p, BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *y, const BIGNUM *x, const BIGNUM *p, BN_CTX *ctx);
	return ccip_BN_GF2m_mod_div(r, y, x, p, ctx);
}

/* Divide yy by xx, reduce modulo p, and store the result in r. r could be xx 
 * or yy, xx could equal yy.
 *
 * This function calls down to the BN_GF2m_mod_div implementation; this wrapper
 * function is only provided for convenience; for best performance, use the 
 * BN_GF2m_mod_div function.
 */
int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *yy, const BIGNUM *xx, const unsigned int p[], BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *yy, const BIGNUM *xx, const unsigned int p[], BN_CTX *ctx);
	return ccip_BN_GF2m_mod_div_arr(r, yy,xx, p,ctx);
        }


/* Compute the bth power of a, reduce modulo p, and store
 * the result in r.  r could be a.
 * Uses simple square-and-multiply algorithm A.5.1 from IEEE P1363.
 */
int	BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const unsigned int p[], BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const unsigned int p[], BN_CTX *ctx);
	return ccip_BN_GF2m_mod_exp_arr(r,a,b,p, ctx);
}

/* Compute the bth power of a, reduce modulo p, and store
 * the result in r.  r could be a.
 *
 * This function calls down to the BN_GF2m_mod_exp_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the 
 * BN_GF2m_mod_exp_arr function.
 */
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
	return ccip_BN_GF2m_mod_exp(r, a, b, p, ctx);
}

/* Compute the square root of a, reduce modulo p, and store
 * the result in r.  r could be a.
 * Uses exponentiation as in algorithm A.4.1 from IEEE P1363.
 */
int	BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[], BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[], BN_CTX *ctx);
	return ccip_BN_GF2m_mod_sqrt_arr(r,a,p, ctx);
}

/* Compute the square root of a, reduce modulo p, and store
 * the result in r.  r could be a.
 *
 * This function calls down to the BN_GF2m_mod_sqrt_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the 
 * BN_GF2m_mod_sqrt_arr function.
 */
int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
	return ccip_BN_GF2m_mod_sqrt(r,a, p, ctx);	
}

/* Find r such that r^2 + r = a mod p.  r could be a. If no r exists returns 0.
 * Uses algorithms A.4.7 and A.4.6 from IEEE P1363.
 */
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a_, const unsigned int p[], BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a_, const unsigned int p[], BN_CTX *ctx);
	return ccip_BN_GF2m_mod_solve_quad_arr(r,a_,p,ctx);
    }

/* Find r such that r^2 + r = a mod p.  r could be a. If no r exists returns 0.
 *
 * This function calls down to the BN_GF2m_mod_solve_quad_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the 
 * BN_GF2m_mod_solve_quad_arr function.
 */
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
	int ccip_BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
	return ccip_BN_GF2m_mod_solve_quad(r, a, p, ctx);
}

/* Convert the bit-string representation of a polynomial
 * ( \sum_{i=0}^n a_i * x^i , where a_0 is *not* zero) into an array
 * of integers corresponding to the bits with non-zero coefficient.
 * Up to max elements of the array will be filled.  Return value is total
 * number of coefficients that would be extracted if array was large enough.
 */
int BN_GF2m_poly2arr(const BIGNUM *a, unsigned int p[], int max)
{
	int ccip_BN_GF2m_poly2arr(const BIGNUM *a, unsigned int p[], int max);
	return ccip_BN_GF2m_poly2arr(a,p,max);
    }

/* Convert the coefficient array representation of a polynomial to a 
 * bit-string.  The array must be terminated by 0.
 */
int BN_GF2m_arr2poly(const unsigned int p[], BIGNUM *a)
{

	int ccip_BN_GF2m_arr2poly(const unsigned int p[], BIGNUM *a);
	return ccip_BN_GF2m_arr2poly(p,a);
}

