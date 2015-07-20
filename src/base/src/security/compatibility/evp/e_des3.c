/* crypto/evp/e_des3.c */
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
#include "cryptlib.h"
#ifndef OPENSSL_NO_DES
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "evp_locl.h"
#include <openssl/des.h>
#include "evp_cci.h"

#define DESKEYSIZE 24
#define DES3KEY_OFFSET 16
#define DESBLOCKSIZE 8



static int des_ede_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
    unsigned char deskey[DESKEYSIZE];

    memcpy(deskey,key,DESKEYSIZE);
    memcpy(&deskey[DES3KEY_OFFSET],deskey,DESBLOCKSIZE);  /* set up key for 2 key 3DES */

    cciEVPCipherInit(ctx,deskey,iv,enc);
    return 1;
}

static const EVP_CIPHER des_ede_cbc = { 
        43,    
        8,
        24, 
        8, 
        0 | 0x2,
        des_ede_init_key, 
        cciEVPCipher,
        cciEVPCipherCleanup,
        0, /* ctx_size */
        EVP_CIPHER_set_asn1_iv,   
        EVP_CIPHER_get_asn1_iv,	  
        ((void *)0),
        ((void *)0)
 };

const EVP_CIPHER *EVP_des_ede_cbc(void)
{
    return &des_ede_cbc;
}

static const EVP_CIPHER des_ede_cfb = {
        60,  
        1,  
        24,    
        8, 
        0 | 0x3,
        des_ede_init_key, 
        cciEVPCipher, 
        cciEVPCipherCleanup, 
        0, /* ctx_size */
        EVP_CIPHER_set_asn1_iv,  		   
        EVP_CIPHER_get_asn1_iv,	  
        ((void *)0), 
        ((void *)0) 
};

const EVP_CIPHER *EVP_des_ede_cfb(void)
{
    return &des_ede_cfb;
}


static const EVP_CIPHER des_ede_ofb = {
        62,
        1,  
        24,   
        8, 
        0 | 0x4, 
        des_ede_init_key, 
        cciEVPCipher, 
        cciEVPCipherCleanup, 
        0, /* ctx_size */
        EVP_CIPHER_set_asn1_iv,  		   
        EVP_CIPHER_get_asn1_iv,	  
        ((void *)0), 
        ((void *)0) 
};

const EVP_CIPHER *EVP_des_ede_ofb(void)
{
    return &des_ede_ofb;
}

static const EVP_CIPHER des_ede_ecb = {
        32,
        8,    
        24,  
        8, 	  
        0 | 0x1, 
        des_ede_init_key, 
        cciEVPCipher, 
        cciEVPCipherCleanup, 
        0, /* ctx_size */
        EVP_CIPHER_set_asn1_iv,   
        EVP_CIPHER_get_asn1_iv,	  
        ((void *)0), 
        ((void *)0) 
};

const EVP_CIPHER *EVP_des_ede_ecb(void)
{
    return &des_ede_ecb;
}

static const EVP_CIPHER des_ede3_cbc = { 
        44,
        8,
        24, 
        8, 
        0 | 0x2, 
        cciEVPCipherInit, 
        cciEVPCipher, 
        cciEVPCipherCleanup, 
        0, /* ctx_size */
        EVP_CIPHER_set_asn1_iv,   
        EVP_CIPHER_get_asn1_iv,	  
        ((void *)0), 
        ((void *)0) 
};

const EVP_CIPHER *EVP_des_ede3_cbc(void)
{
    return &des_ede3_cbc;
}

static const EVP_CIPHER des_ede3_cfb = { 
        61,  
        1,
        24,
        8,
        0 | 0x3, 
        cciEVPCipherInit, 
        cciEVPCipher, 
        cciEVPCipherCleanup, 
        0, /* ctx_size */
        EVP_CIPHER_set_asn1_iv,  		   
        EVP_CIPHER_get_asn1_iv,	  
        ((void *)0), 
        ((void *)0) 
};

const EVP_CIPHER *EVP_des_ede3_cfb(void)
{
    return &des_ede3_cfb;
}

static const EVP_CIPHER des_ede3_ofb = { 
        63,
        1,
        24,    
        8, 	  		     
        0 | 0x4, 
        cciEVPCipherInit, 
        cciEVPCipher, 
        cciEVPCipherCleanup, 
        0, /* ctx_size */
        EVP_CIPHER_set_asn1_iv,  		   
        EVP_CIPHER_get_asn1_iv,	  
        ((void *)0), 	
        ((void *)0)
};

const EVP_CIPHER *EVP_des_ede3_ofb(void)
{
    return &des_ede3_ofb;
}

static const EVP_CIPHER des_ede3_ecb = { 
        33,
        8,
        24,
        8, 	  
        0 | 0x1, 
        cciEVPCipherInit, 
        cciEVPCipher, 
        cciEVPCipherCleanup, 
        0, /* ctx_size */
        EVP_CIPHER_set_asn1_iv,   
        EVP_CIPHER_get_asn1_iv,	  
        ((void *)0), 
        ((void *)0) 
};

const EVP_CIPHER *EVP_des_ede3_ecb(void)
{
    return &des_ede3_ecb;
}


const EVP_CIPHER *EVP_des_ede(void)
{
    return &des_ede_ecb;
}

const EVP_CIPHER *EVP_des_ede3(void)
{
    return &des_ede3_ecb;
}



#endif
