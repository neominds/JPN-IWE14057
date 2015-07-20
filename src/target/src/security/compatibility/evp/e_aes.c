 /* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_AES
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include "evp_locl.h"


#include "evp_cci.h"


static const EVP_CIPHER aes_128_cbc = { 	   
               419,
               16,
               16,
               16, 	   
               0 | 0x2,
               cciEVPCipherInit, 
               cciEVPCipher,
               cciEVPCipherCleanup,
               0, 	    
               EVP_CIPHER_set_asn1_iv,    			  
               EVP_CIPHER_get_asn1_iv,	   
               ((void *)0),
               ((void *)0) 
};

const EVP_CIPHER *EVP_aes_128_cbc(void)
{
    return &aes_128_cbc;
}

static const EVP_CIPHER aes_128_ofb = { 	   
               420,
               1,  
               16,
               16,      
               0 | 0x4,
               cciEVPCipherInit, 
               cciEVPCipher, 
               cciEVPCipherCleanup, 
               0, 	    
               EVP_CIPHER_set_asn1_iv,  		    			  
               EVP_CIPHER_get_asn1_iv,	   
               ((void *)0),
	            ((void *)0) 
};

const EVP_CIPHER *EVP_aes_128_ofb(void)
{
    return &aes_128_ofb;
}

static const EVP_CIPHER aes_128_ecb = { 	   
               418,
               16,
               16, 
               16,   
               0 | 0x1,
               cciEVPCipherInit, 
               cciEVPCipher, 
               cciEVPCipherCleanup,
               0, 	    
               EVP_CIPHER_set_asn1_iv,    			  
               EVP_CIPHER_get_asn1_iv,	   
               ((void *)0), 
               ((void *)0) 
};

const EVP_CIPHER *EVP_aes_128_ecb(void)
{
    return &aes_128_ecb;
}


static const EVP_CIPHER aes_192_cbc = { 	   
               423,
               16,
               24,
               16, 	   
               0 | 0x2,
               cciEVPCipherInit, 
               cciEVPCipher, 	    
               cciEVPCipherCleanup,
               0, 	    
               EVP_CIPHER_set_asn1_iv,    			  
               EVP_CIPHER_get_asn1_iv,	   
               ((void *)0), 
               ((void *)0) }
;

const EVP_CIPHER *EVP_aes_192_cbc(void)
{
    return &aes_192_cbc;
}

static const EVP_CIPHER aes_192_ofb = { 	   
               424,
               1,
               24,
               16, 	  		      
               0 | 0x4, 
               cciEVPCipherInit, 
               cciEVPCipher, 
               cciEVPCipherCleanup, 
               0, 	    
               EVP_CIPHER_set_asn1_iv,  		    			  
               EVP_CIPHER_get_asn1_iv,	   
               ((void *)0), 
               ((void *)0) };

const EVP_CIPHER *EVP_aes_192_ofb(void) {
    return &aes_192_ofb;
}

static const EVP_CIPHER aes_192_ecb = { 	   
                422,
                16,
                24,
                16, 	   
                0 | 0x1,
                cciEVPCipherInit, 
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 	    
                EVP_CIPHER_set_asn1_iv,    			  
                EVP_CIPHER_get_asn1_iv,	   
                ((void *)0), 
                ((void *)0) };


const EVP_CIPHER *EVP_aes_192_ecb(void)  {
    return &aes_192_ecb;
}


static const EVP_CIPHER aes_256_cbc = { 	   
               427,
               16,
               32, 
               16, 	   
               0 | 0x2, 
               cciEVPCipherInit, 
               cciEVPCipher, 
               cciEVPCipherCleanup,
               0, 	    
               EVP_CIPHER_set_asn1_iv,    			  
               EVP_CIPHER_get_asn1_iv,	   
               ((void *)0),
               ((void *)0) 
};

const EVP_CIPHER *EVP_aes_256_cbc(void) {
    return &aes_256_cbc;
}

static const EVP_CIPHER aes_256_ofb = { 	   
               428,
               1,
               32,
               16, 	  		      
               0 | 0x4,
               cciEVPCipherInit,
               cciEVPCipher, 	    
               cciEVPCipherCleanup, 	
               0, 	    
               EVP_CIPHER_set_asn1_iv, 
               EVP_CIPHER_get_asn1_iv,	   
               ((void *)0), 	
               ((void *)0) };

const EVP_CIPHER *EVP_aes_256_ofb(void) {
    return &aes_256_ofb;
}

static const EVP_CIPHER aes_256_ecb = { 	   
               426,     
               16,     
               32,  		     
               16, 	   
               0 | 0x1, 	  		       
               cciEVPCipherInit, 	
               cciEVPCipher, 	    
               cciEVPCipherCleanup, 	
               0, 	    
               EVP_CIPHER_set_asn1_iv,    			  
               EVP_CIPHER_get_asn1_iv,	   
               ((void *)0),
               ((void *)0) };

const EVP_CIPHER *EVP_aes_256_ecb(void) {
    return &aes_256_ecb;
}

static const EVP_CIPHER    aes_256_cfb8     = {
                655,
                1,
                256/8,
                16,
                0   | 0x3,
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv  ,     
                EVP_CIPHER_get_asn1_iv  ,	    
                ((void *)0),
                ((void *)0)  };

const EVP_CIPHER *EVP_aes_256_cfb8    (void) {
    return &   aes_256_cfb8    ;
}

static const EVP_CIPHER    aes_192_cfb8     = {    
                654,   
                1 ,       
                192  /8,
                16,
                0   | 0x3 ,      
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv  ,     
                EVP_CIPHER_get_asn1_iv  ,	    
                ((void *)0)   , 
                ((void *)0)  };

const EVP_CIPHER *EVP_aes_192_cfb8    (void) {
    return &   aes_192_cfb8    ;
}

static const EVP_CIPHER    aes_128_cfb8     = {     
                653     ,   
                1 ,       
                128  /8  ,      
                16   ,     
                0   | 0x3 ,      
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv  ,     
                EVP_CIPHER_get_asn1_iv  ,	    
                ((void *)0)   , 
                ((void *)0)  };

const EVP_CIPHER *EVP_aes_128_cfb8    (void) {
    return &   aes_128_cfb8    ;
}

static const EVP_CIPHER    aes_256_cfb1     = {     
                652     ,   
                1 ,       
                256  /8  ,      
                16   ,     
                0   | 0x3 ,      
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv  ,     
                EVP_CIPHER_get_asn1_iv  ,	    
                ((void *)0)   , 
                ((void *)0)  };

const EVP_CIPHER *EVP_aes_256_cfb1    (void) {
    return &   aes_256_cfb1    ;
}

static const EVP_CIPHER    aes_192_cfb1     = {
                651     ,   
                1 ,       
                192  /8  ,
                16   ,     
                0   | 0x3 ,      
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv  ,     
                EVP_CIPHER_get_asn1_iv  ,	    
                ((void *)0)   , 
                ((void *)0)  };

const EVP_CIPHER *EVP_aes_192_cfb1    (void) {
    return &   aes_192_cfb1    ;
}

static const EVP_CIPHER    aes_128_cfb1     = {     
                650,
                1,
                128  /8,
                16,
                0   | 0x3,
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv  ,     
                EVP_CIPHER_get_asn1_iv  ,	    
                ((void *)0)   , 
                ((void *)0)  };

const EVP_CIPHER *EVP_aes_128_cfb1    (void) {
    return &   aes_128_cfb1    ;
}

static const EVP_CIPHER     aes_256_cfb128     = {     
                429     ,   
                1 ,         
                32    ,         
                16    ,         		       
                0     | 0x3 ,         
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv    ,         		       
                EVP_CIPHER_get_asn1_iv    ,	        		       
                ((void *)0)     , 
                ((void *)0)  };

const EVP_CIPHER *EVP_aes_256_cfb128    (void) {
    return &    aes_256_cfb128    ;
}


static const EVP_CIPHER     aes_192_cfb128     = {         		       
                425     ,   
                1 ,         
                24    ,         
                16    ,         		       
                0     | 0x3 ,         
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv    ,         		       
                EVP_CIPHER_get_asn1_iv    ,	        		       
                ((void *)0)     , ((void *)0)  };


const EVP_CIPHER *EVP_aes_192_cfb128    (void) {
    return &    aes_192_cfb128    ;
}

static const EVP_CIPHER     aes_128_cfb128     = {         		       
                421     ,   
                1 ,         
                16    ,         
                16    ,         		       
                0     | 0x3 ,         
                cciEVPCipherInit  ,    
                cciEVPCipher, 
                cciEVPCipherCleanup,
                0, 
                EVP_CIPHER_set_asn1_iv    ,         		       
                EVP_CIPHER_get_asn1_iv    ,	        		       
                ((void *)0)     , ((void *)0)  };

const EVP_CIPHER *EVP_aes_128_cfb128    (void) {
    return &    aes_128_cfb128    ;
}
#endif



