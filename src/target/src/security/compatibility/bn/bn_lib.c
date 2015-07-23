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
# undef NDEBUG                  /* avoid conflicting definitions */
# define NDEBUG
#endif

#include "cryptlib.h"
#include <openssl/bn.h>

int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
	{
	int ccip_BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
	return(ccip_BN_usub(r, a, b));
	}

BN_BLINDING *BN_BLINDING_new(const BIGNUM *A,const BIGNUM *Ai, BIGNUM *mod)
	{
        BN_BLINDING *ccip_BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
		return(ccip_BN_BLINDING_new(A, Ai, mod));
	}

void BN_BLINDING_free(BN_BLINDING *r)
{
        void ccip_BN_BLINDING_free(BN_BLINDING *r);
        ccip_BN_BLINDING_free(r);
    }

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
	{
        int ccip_BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
		return(ccip_BN_BLINDING_update(b, ctx));
    }

int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)
	{
        int ccip_BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
		return(ccip_BN_BLINDING_convert(n, b, ctx));
    }

int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)
	{
        int ccip_BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
        return(ccip_BN_BLINDING_invert(n, b, ctx));
    }

					 
BN_CTX *BN_CTX_new(void)
	{
    BN_CTX *ccip_BN_CTX_new(void);
	cciLibInit();
	return( ccip_BN_CTX_new() );
}

void BN_CTX_init(BN_CTX *ctx)
{
    void	ccip_BN_CTX_init(BN_CTX *c);
    ccip_BN_CTX_init(ctx);
}

void BN_CTX_free(BN_CTX *ctx)
{
	void	ccip_BN_CTX_free(BN_CTX *c);
    ccip_BN_CTX_free(ctx);
	}

void BN_CTX_start(BN_CTX *ctx)
	{
    void	ccip_BN_CTX_start(BN_CTX *ctx);
    ccip_BN_CTX_start(ctx);
}

BIGNUM *BN_CTX_get(BN_CTX *ctx)
{
    BIGNUM *ccip_BN_CTX_get(BN_CTX *ctx);
    return(ccip_BN_CTX_get(ctx));
	}

void BN_CTX_end(BN_CTX *ctx)
	{
    void	ccip_BN_CTX_end(BN_CTX *ctx);
	ccip_BN_CTX_end(ctx);
        }
					   
void BN_set_params(int mult, int high, int low, int mont)
	{
        void ccip_BN_set_params(int mul,int high,int low,int mont);
	    ccip_BN_set_params(mult, high,low,mont);

        }

int BN_get_params(int which)
    {
        int ccip_BN_get_params(int which);
		return(ccip_BN_get_params(which));
	}

BIGNUM *bn_dup_expand(const BIGNUM *b, int words)
        {
        BIGNUM *ccip_bn_dup_expand(const BIGNUM *b, int words);
        return( ccip_bn_dup_expand(b, words));
        }


const BIGNUM *BN_value_one(void)
	{
		const BIGNUM *ccip_BN_value_one(void);
		return(ccip_BN_value_one());
    }

char *BN_options(void)
	{
		char *ccip_BN_options(void);
		return(ccip_BN_options());
}

int BN_num_bits_word(BN_ULONG l)
{
        int	ccip_BN_num_bits_word(BN_ULONG);
	return(ccip_BN_num_bits_word(l));
	}


void BN_clear_free(BIGNUM *a)
{
        void	ccip_BN_clear_free(BIGNUM *a);
		ccip_BN_clear_free(a);
}

void BN_free(BIGNUM *a)
{
        void	ccip_BN_free(BIGNUM *a);
        ccip_BN_free(a);
}

void BN_init(BIGNUM *a)
{
	cciLibInit();
    memset(a, 0, sizeof(BIGNUM));
    bn_check_top(a);
}

BIGNUM *BN_new(void)
{
		BIGNUM *ccip_BN_new(void);
		cciLibInit();
		return(ccip_BN_new());
	}



/* This is an internal function that should not be used in applications.
 * It ensures that 'b' has enough room for a 'words' word number
 * and initialises any unused part of b->d with leading zeros.
 * It is mostly used by the various BIGNUM routines. If there is an error,
 * NULL is returned. If not, 'b' is returned. */

BIGNUM *bn_expand2(BIGNUM *b, int words)
	{
        BIGNUM *ccip_bn_expand2(BIGNUM *a, int words);
		return(ccip_bn_expand2(b, words));
    }

void BN_swap(BIGNUM *a, BIGNUM *b)
	{
        void	ccip_BN_swap(BIGNUM *a, BIGNUM *b);
        ccip_BN_swap(a, b);
    }

void BN_clear(BIGNUM *a)
	{
        void	ccip_BN_clear(BIGNUM *a);
		ccip_BN_clear(a);
    }

BN_ULONG BN_get_word(const BIGNUM *a)
	{
        BN_ULONG ccip_BN_get_word(const BIGNUM *a);
		return( ccip_BN_get_word(a));
        }


BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
	{
        BIGNUM *ccip_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
		return(ccip_BN_bin2bn(s,len,ret));
        }

/* ignore negative */
int BN_bn2bin(const BIGNUM *a, unsigned char *to)
	{
        int	ccip_BN_bn2bin(const BIGNUM *a, unsigned char *to);
		return(ccip_BN_bn2bin(a, to));
    }

int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
	{
        int	ccip_BN_ucmp(const BIGNUM *a, const BIGNUM *b);
		return(ccip_BN_ucmp(a, b));
}



void ERR_load_BN_strings(void)
{
        void ccip_ERR_load_BN_strings(void);
		ccip_ERR_load_BN_strings();
	}

int BN_mod_exp2_mont(BIGNUM *rr, const BIGNUM *a1, const BIGNUM *p1,
	const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
	BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	int	ccip_BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
			const BIGNUM *a2, const BIGNUM *p2,const BIGNUM *m,
			BN_CTX *ctx,BN_MONT_CTX *m_ctx);
	return(ccip_BN_mod_exp2_mont(rr, a1, p1, a2, p2, m, ctx, in_mont));


	}

int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		    const BIGNUM *m, BN_CTX *ctx)
	{
	int	ccip_BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
					const BIGNUM *m, BN_CTX *ctx);
	return(ccip_BN_mod_exp_recp(r, a, p,m, ctx));
            }


int BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
		    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	int	ccip_BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
	return(ccip_BN_mod_exp_mont(rr, a, p,m, ctx, in_mont));
        }

int BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	int	ccip_BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
			const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
	return(ccip_BN_mod_exp_mont_word(rr, a, p, m, ctx, in_mont));
    }


int BN_mod_exp_simple(BIGNUM *r,
	const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
	BN_CTX *ctx)
	{
	int	ccip_BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m,BN_CTX *ctx);
	return(ccip_BN_mod_exp_simple(r, a, p, m,ctx));
}


int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
	int	ccip_BN_kronecker(const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx);
	return(ccip_BN_kronecker(a,b,ctx));
	}



int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
	{
        int	ccip_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
		return(ccip_BN_nnmod(r, m, d, ctx));
    }


/* BN_mod_add variant that may be used if both  a  and  b  are non-negative
 * and less than  m */
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m)
	{
        int	ccip_BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
		return(ccip_BN_mod_add_quick(r, a, b, m));
}



/* BN_mod_sub variant that may be used if both  a  and  b  are non-negative
 * and less than  m */
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m)
	{
        int	ccip_BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
        return(ccip_BN_mod_sub_quick(r, a, b, m));
}




int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
	{
        int	ccip_BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
		return(ccip_BN_mod_lshift1(r, a, m, ctx));
    }


/* BN_mod_lshift1 variant that may be used if  a  is non-negative
 * and less than  m */
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m)
	{
        int	ccip_BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
		return(ccip_BN_mod_lshift1_quick(r, a, m));
    }


int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m, BN_CTX *ctx)
{
        int	ccip_BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m, BN_CTX *ctx);
		return(ccip_BN_mod_lshift(r, a, n, m, ctx));
	}


/* BN_mod_lshift variant that may be used if  a  is non-negative
 * and less than  m */
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m)
	{
        int	ccip_BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);
		return(ccip_BN_mod_lshift_quick( r, a, n, m));
	}


#define MONT_WORD /* use the faster word-based algorithm */

int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
			  BN_MONT_CTX *mont, BN_CTX *ctx)
	{
        int ccip_BN_mod_mul_montgomery(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,
			BN_MONT_CTX *mont, BN_CTX *ctx);
		return(ccip_BN_mod_mul_montgomery(r,a,b,mont, ctx));
	}

int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
	     BN_CTX *ctx)
	{
        int ccip_BN_from_montgomery(BIGNUM *r,const BIGNUM *a,
			BN_MONT_CTX *mont, BN_CTX *ctx);
		return(ccip_BN_from_montgomery(ret,a, mont, ctx));
}

BN_MONT_CTX *BN_MONT_CTX_new(void)
{
        BN_MONT_CTX *ccip_BN_MONT_CTX_new(void );
		return(ccip_BN_MONT_CTX_new());
}

void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
{
        void ccip_BN_MONT_CTX_init(BN_MONT_CTX *ctx);
        ccip_BN_MONT_CTX_init(ctx);
}

void BN_MONT_CTX_free(BN_MONT_CTX *mont)
{
        void ccip_BN_MONT_CTX_free(BN_MONT_CTX *mont);
        ccip_BN_MONT_CTX_free(mont);
}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
{
        int ccip_BN_MONT_CTX_set(BN_MONT_CTX *mont,const BIGNUM *mod,BN_CTX *ctx);
		return(ccip_BN_MONT_CTX_set(mont,mod,ctx));
	}

BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)
	{
        BN_MONT_CTX *ccip_BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from);
		return(ccip_BN_MONT_CTX_copy(to,from));
    }


int BN_bn2mpi(const BIGNUM *a, unsigned char *d)
	{
        int	ccip_BN_bn2mpi(const BIGNUM *a, unsigned char *to);
		return(ccip_BN_bn2mpi(a, d));
    }

BIGNUM *BN_mpi2bn(const unsigned char *d, int n, BIGNUM *a)
	{
        BIGNUM *ccip_BN_mpi2bn(const unsigned char *s,int len,BIGNUM *ret);
		return(ccip_BN_mpi2bn(d,n,a));
        }
					 
int BN_is_prime_fasttest(const BIGNUM *a, int checks,
		void (*callback)(int,int,void *),
		BN_CTX *ctx_passed, void *cb_arg,
		int do_trial_division)
	{
        int	ccip_BN_is_prime_fasttest(const BIGNUM *p,int nchecks,
			void (*callback)(int,int,void *),BN_CTX *ctx,void *cb_arg,
			int do_trial_division);
		return(ccip_BN_is_prime_fasttest(a,checks,callback,ctx_passed,cb_arg,do_trial_division));
    }



int BN_rand(BIGNUM *rnd, int bits, int top, int bottom)
	{
        int     ccip_BN_rand(BIGNUM *rnd, int bits, int top,int bottom);
		return( ccip_BN_rand(rnd, bits, top,bottom));
}

int     BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
        int     ccip_BN_pseudo_rand(BIGNUM *rnd, int bits, int top,int bottom);
		return(ccip_BN_pseudo_rand(rnd, bits, top,bottom));
	}

int     BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom)
	{
        int ccip_BN_bntest_rand(BIGNUM *rnd, int bits, int top,int bottom);
		return(ccip_BN_bntest_rand(rnd, bits, top,bottom));
    }



int	BN_rand_range(BIGNUM *r, const BIGNUM *range)
	{
        int	ccip_BN_rand_range(BIGNUM *rnd, BIGNUM *range);
		return(ccip_BN_rand_range(r, (void *)range));
}

int	BN_pseudo_rand_range(BIGNUM *r,const BIGNUM *range)
{
        int	ccip_BN_pseudo_rand_range(BIGNUM *rnd, BIGNUM *range);
		return(ccip_BN_pseudo_rand_range(r, (void *)range));
	}



void BN_RECP_CTX_init(BN_RECP_CTX *recp)
	{
        void	ccip_BN_RECP_CTX_init(BN_RECP_CTX *recp);
		ccip_BN_RECP_CTX_init(recp);
    }

BN_RECP_CTX *BN_RECP_CTX_new(void)
	{
        BN_RECP_CTX *ccip_BN_RECP_CTX_new(void);
		return(ccip_BN_RECP_CTX_new());
}

void BN_RECP_CTX_free(BN_RECP_CTX *recp)
{
        void	ccip_BN_RECP_CTX_free(BN_RECP_CTX *recp);
        ccip_BN_RECP_CTX_free(recp);
	}

int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *d, BN_CTX *ctx)
	{
	    int	ccip_BN_RECP_CTX_set(BN_RECP_CTX *recp,const BIGNUM *rdiv,BN_CTX *ctx);
		return(ccip_BN_RECP_CTX_set(recp,d,ctx));
    }

int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
	BN_RECP_CTX *recp, BN_CTX *ctx)
	{
        int	ccip_BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
			BN_RECP_CTX *recp,BN_CTX *ctx);
		return(ccip_BN_mod_mul_reciprocal(r, x, y,recp,ctx));
    }

int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
	BN_RECP_CTX *recp, BN_CTX *ctx)
	{
        int	ccip_BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
			BN_RECP_CTX *recp, BN_CTX *ctx);
		return(ccip_BN_div_recp(dv, rem, m, recp, ctx));
}

int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx)
{
        int	ccip_BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
		return(ccip_BN_reciprocal(r, m, len, ctx));
	}


int BN_lshift1(BIGNUM *r, const BIGNUM *a)
	{
        int	ccip_BN_lshift1(BIGNUM *r, const BIGNUM *a);
		return(ccip_BN_lshift1(r, a));
    }

int BN_rshift1(BIGNUM *r, const BIGNUM *a)
	{
        int	ccip_BN_rshift1(BIGNUM *r, const BIGNUM *a);
		return(ccip_BN_rshift1(r, a));
}


BIGNUM *BN_mod_sqrt(BIGNUM *in, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx) 
{
        BIGNUM *ccip_BN_mod_sqrt(BIGNUM *ret,
			const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
		return(ccip_BN_mod_sqrt(in,a, p,ctx));
	}

static const char *Hex="0123456789ABCDEF";


/* Must 'OPENSSL_free' the returned data */
char *BN_bn2hex(const BIGNUM *a)
	{
        char *	ccip_BN_bn2hex(const BIGNUM *a);
		return(ccip_BN_bn2hex(a));
}

/* Must 'OPENSSL_free' the returned data */
char *BN_bn2dec(const BIGNUM *a)
{
        char *	ccip_BN_bn2dec(const BIGNUM *a);
		return(ccip_BN_bn2dec(a));
}

int BN_hex2bn(BIGNUM **bn, const char *a)
{
        int 	ccip_BN_hex2bn(BIGNUM **a, const char *str);
		return(ccip_BN_hex2bn(bn, a));
}

int BN_dec2bn(BIGNUM **bn, const char *a)
{
        int 	ccip_BN_dec2bn(BIGNUM **a, const char *str);
		return(ccip_BN_dec2bn(bn, a));
}

#ifndef OPENSSL_NO_BIO
#ifndef OPENSSL_NO_FP_API
int BN_print_fp(FILE *fp, const BIGNUM *a)
{
	BIO *b;
	int ret;

	if ((b=BIO_new(BIO_s_file())) == NULL)
    return (0);
	BIO_set_fp(b,fp,BIO_NOCLOSE);
	ret=BN_print(b,a);
	BIO_free(b);
	return(ret);
}

int BN_print(BIO *bp, const BIGNUM *a)
	{
	int i,j,v,z=0;
	int ret=0;

	if ((a->neg) && (BIO_write(bp,"-",1) != 1)) goto end;
	if ((a->top == 0) && (BIO_write(bp,"0",1) != 1)) goto end;
	for (i=a->top-1; i >=0; i--)
{
		for (j=BN_BITS2-4; j >= 0; j-=4)
			{
			/* strip leading zeros */
			v=((int)(a->d[i]>>(long)j))&0x0f;
			if (z || (v != 0))
				{
				if (BIO_write(bp,&(Hex[v]),1) != 1)
					goto end;
				z=1;
        }
    }
        }
	ret=1;
end:
	return(ret);
    }
#endif
#endif


