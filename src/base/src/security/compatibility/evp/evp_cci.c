/* evp_cci.c - CCI adapter for the EVP interface */
/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,04jan05,tat  created
*/

/*
DESCRIPTION

This library contains routines that implement the CCI Adapter for the EVP interface.  These functions
are called by the EVP API, and should not be called directly by the application.

INCLUDES 
openssl/evp.h evp_cci.h

NOMANUAL

*/
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/wr_err.h>
#include "evp_cci.h"

/******************************************************************************
*
* cciEVPDigestInit - initialize a CCI Digest Context
*
* This routine calls cciEVPDigestInit_exe using the user configured CCI Provider:
* CCI_APP_PROVIDER_ID.
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the EVP_MD_CTX structure used by the EVP layer

*
* \i <algorithmId>
* CCI_ALGORITHM_ID that indicates what hashing algorithm to use
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int cciEVPDigestInit
    (
    EVP_MD_CTX *ctx,
    CCI_ALGORITHM_ID algorithmId
    )
    {
    return cciEVPDigestInit_ex (ctx, algorithmId, CCI_APP_PROVIDER_ID);
    }

/******************************************************************************
*
* cciEVPDigestInit_ex - initialize a CCI Digest Context
*
* This routine initializes the CCI layer for a digest operation.  It stores the CCIContext
* in the ctx->md_data buffer (allocated by the calling function in the EVP Layer).  It calls
* cciCtxInit, which in turn allocates the low level session context.  The CCIContext must be cleaned
* by cciEVPDigestFinal or cciEVPDigestCleanup, before calling cciEVPDigestInit with this EVP_MD_CTX again.
* Failure to call cciEVPDigestFinal or cciEVPDigestCleanup will cause a memory leak.
*
* cciEVPDigestInit_ex should be used usually instead of cciEVPDigestInit_exe, except in the case where
* the caller wants to specify the CCI provider to be used.
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the EVP_MD_CTX structure used by the EVP layer. 
*
* \i <algorithmId>
* CCI_ALGORITHM_ID that indicates what hashing algorithm to use
*
* \i <providerId>
* CCI_PROVIDER_ID that indicates what CCI Provider to use
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int cciEVPDigestInit_ex
    (
    EVP_MD_CTX *ctx,
    CCI_ALGORITHM_ID algorithmId,
    CCI_PROVIDER_ID providerId
    )
    {
    cci_st cciStatus;
    
      


    ctx->md_data = cciAlloc(sizeof(CCIContextRec));
    cciStatus = cciCtxInit ((CCIContext) (ctx->md_data), providerId, CCI_CLASS_HASH,
                            algorithmId); /* this call allocates the low level session context */	

    if (!CCISUCCESS (cciStatus))
        {
        SECLIBerr(WRSECLIB_F_cciEVPDigestInit_ex,WRSECLIB_R_CCI_FAILED);
        return EVP_CCI_FAILURE;
        }
    return EVP_CCI_SUCCESS;
    }

/******************************************************************************
*
* cciEVPDigestUpdate - update a CCI Digest 
*
* This routine calls cciHashUpdate with the data to be digested, using the 
* CCIContext stored at ctx->md_data
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the EVP_MD_CTX structure used by the EVP layer
*
* \i <data>
* Data to be hashed
*
* \i <count>
* Number of bytes to be hashed
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int cciEVPDigestUpdate
    (
    EVP_MD_CTX *ctx,
    const void *data,
    unsigned int count
    )
    {
    cci_st cciStatus;

    cciStatus = cciHashUpdate ((CCIContext)ctx->md_data, data, count);

    if (!CCISUCCESS (cciStatus))
        {
        SECLIBerr(WRSECLIB_F_cciEVPDigestUpdate,WRSECLIB_R_CCI_FAILED);
        return EVP_CCI_FAILURE;
        }
    return EVP_CCI_SUCCESS;
    }

/******************************************************************************
*
* cciEVPDigestFinal - finalize a digest calculation
*
* This routine calls cciHashFinal, using the 
* CCIContext stored at ctx->md_data.  It also calls cciEVPDigestCleanup() to ensure
* that the CCIContext is cleared.
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the EVP_MD_CTX structure used by the EVP layer
*
* \i <md>
* Pointer to buffer that the resulting message digest is copied to. It must be at least 
* ctx->digest->md_size bytes.
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int cciEVPDigestFinal
    (
    EVP_MD_CTX *ctx,
    unsigned char *md
    )
    {
    cci_st cciStatus;
    cci_t len = ctx->digest->md_size;
    CCIContext cciCtx = (CCIContext)ctx->md_data;

    cciStatus = cciHashFinal (cciCtx, md, &len);

    cciEVPDigestCleanup (ctx); /* call cleanup to ensure that cciCtxClear is called */

    if (!CCISUCCESS (cciStatus))
        {
        SECLIBerr(WRSECLIB_F_cciEVPDigestFinal,WRSECLIB_R_CCI_FAILED);
        return EVP_CCI_FAILURE;
        }
    return EVP_CCI_SUCCESS;
    }

/******************************************************************************
*
* cciEVPDigestCleanup - cleanup a context
*
* This routine calls cciCtxClear, using the CCIContext stored at ctx->md_data.  
* This frees the low level session context.  This function is called via cciEVPDigestFinal, 
* and via EVP_MD_CTX_cleanup().
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the EVP_MD_CTX structure used by the EVP layer
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int cciEVPDigestCleanup
    (
    EVP_MD_CTX *ctx
    )
    {
    cci_st cciStatus=CCI_SUCCESS;
    CCIContext cciCtx = (CCIContext)ctx->md_data;

    if(cciCtx)
    {
        cciStatus = cciCtxClear(cciCtx);
        cciFree(cciCtx);
    }
    
    ctx->md_data=NULL;

    if (!CCISUCCESS (cciStatus))
        {
        SECLIBerr(WRSECLIB_F_cciEVPDigestCleanup,WRSECLIB_R_CCI_FAILED);
        return EVP_CCI_FAILURE;
        }
    return EVP_CCI_SUCCESS;
    }

/******************************************************************************
*
* cciEVPDigestCopy - copy an EVP_MD_CTX context
*
* This routine copies the CCIContext in EVP_MD_CTX from into EVP_MD_CTX to.  This
* requires that the provider being used on the from context is the default CCI software
* provider.
*
* Parameters:
* \is 
* \i <to> 
* Pointer to the EVP_MD_CTX structure used by the EVP layer.  This is the context copied to
*
* \i <from>
* Pointer to the EVP_MD_CTX structure used by the EVP layer.  This is the context copied from
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int cciEVPDigestCopy
    (
    EVP_MD_CTX *to,
    const EVP_MD_CTX *from
    )
    {
    CCIContext cciTo;
    CCIContext cciFrom;
    cci_st cciStatus=CCI_SUCCESS;


    
    cciFrom = (CCIContext)from->md_data;

    if (CCI_DEF_PROVIDER_ID != cciCtxProviderId (cciFrom))
        {
        SECLIBerr(WRSECLIB_F_cciEVPDigestCopy,WRSECLIB_R_NON_COPY_SAFE_CONTEXT);
        return EVP_CCI_FAILURE;
        }

     to->md_data = cciAlloc(sizeof(CCIContextRec));
     cciTo = (CCIContext)to->md_data;
      
     if(!to->md_data)
        {          
        SECLIBerr(WRSECLIB_F_cciEVPDigestCopy,ERR_R_MALLOC_FAILURE);
        return EVP_CCI_FAILURE;
        }         
     
         
     memcpy(to->md_data,from->md_data,sizeof(CCIContextRec));


    /* at this point cciTo is an exact copy of cciFrom.  cciTo does not yet
    have its own CCI Session context, it is pointing to cciFrom's session ctx 
    By setting cciCtxSession to NULL, cciCtxHashCopy will create a new cciCtxSession */

    cciCtxSessionCtxSet (cciTo, NULL);

    cciStatus = cciCtxHashCopy (cciTo, cciFrom);

    if (!CCISUCCESS (cciStatus))
        {
        SECLIBerr(WRSECLIB_F_cciEVPDigestCopy,WRSECLIB_R_CCI_FAILED);
        return EVP_CCI_FAILURE;
        }
    return EVP_CCI_SUCCESS;
    }

/******************************************************************************
*
* cciEVPCipher - update the Cipher
*
* This routine performs the actual encryption/decryption by calling cciCtxCipher. 
* It can be called multiple times.
*
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the EVP_CIPHER_CTX structure used by the EVP layer
*
* \i <out>
* Pointer to output buffer.  Must be at least inl bytes
*
* \i <in>
* Pointer to data to be encryted/decrypted
*
* \i <inl>
* Length of data to be encrypted/decrypted
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/

int cciEVPCipher
    (
    EVP_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    unsigned int inl
    )
    { 
    EVP_CCI_CTX *evpCCICtx;
    CCIContext cciContext;
    cci_st cciStatus;
    cci_t outl = inl;

    evpCCICtx = (EVP_CCI_CTX *)(ctx->cipher_data);
    cciContext = (evpCCICtx->cciContext);
 
    cciStatus = cciCtxCipher (cciContext, (cci_b *)in, (cci_t)inl, (cci_b *)out, (cci_t *)&outl);

    if (!CCISUCCESS (cciStatus))
        {
        SECLIBerr(WRSECLIB_F_cciEVPCipher,WRSECLIB_R_CCI_FAILED);
        return EVP_CCI_FAILURE;
        }
    return EVP_CCI_SUCCESS;
    }

/******************************************************************************
*
* cciEVPCipherCleanup - cleanup the EVP_CIPHER_CTX 
*
* This routine first clears the low level CCIContext by calling cciCtxClear.  It then
* frees the EVP_CCI_CTX pointed to by ctx->cipher_data.
*
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the EVP_CIPHER_CTX structure used by the EVP layer
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/

int cciEVPCipherCleanup
    (
    EVP_CIPHER_CTX *ctx
    )
    {
    EVP_CCI_CTX *evpCCICtx;
    cci_st cciStatus;
    evpCCICtx = (EVP_CCI_CTX *)(ctx->cipher_data);

    if (ctx->cipher_data)
        {
        cciStatus = cciCtxClear(evpCCICtx->cciContext);
        cciFree(evpCCICtx->cciContext);

        if (!CCISUCCESS (cciStatus))
            {
            SECLIBerr(WRSECLIB_F_cciEVPCipherCleanup,WRSECLIB_R_CCI_FAILED);
            return EVP_CCI_FAILURE;
            }

        memset (ctx->cipher_data, 0, evpCCICtx->ctxSize);
        OPENSSL_free (ctx->cipher_data);
        ctx->cipher_data = NULL;
        }
    return EVP_CCI_SUCCESS;
    }

/******************************************************************************
*
* cciEVPCipherInit - initialize a CCI Cipher Context
*
* This routine initializes the CCI layer for a cipher operation.  It allocates an EVP_CCI_CTX structure 
* which includes a variable length buffer at the end of the structure to store the key.
* The key/IV may be changed by calling cciEVPDigestInit again.  In the case where the key has gotten larger
* a new EVP_CCI_CTX is created with the new key buffer size, and the original EVP_CCI_CTX is freed.
*
* Note that Ciphers are different from Digests, as the shim layer allocates the low level cipher
* context for ciphers, but does not for message digests.
*
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the EVP_CIPHER_CTX structure used by the EVP layer
*
* \i <key>
* Pointer to the key to be copied
*
* \i <iv>
* Pointer to the IV. The IV is stored by the caller, only the pointer is copied
*
* \i <enc>
* Indicates whether the cipher is to encrypt or decrypt.  1 for encrypt, decrypt otherwise
* \ie
*
* RETURNS: EVP_CCI_SUCCESS if successful, EVP_CCI_FAILURE otherwise
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int cciEVPCipherInit
    (
    EVP_CIPHER_CTX *ctx,
    const unsigned char *key,
    const unsigned char *iv,
    int enc
    )
    {
    EVP_CCI_CTX *evpCCICtx;
    CCIContext cciContext=NULL;
    unsigned int ctxSize;
    CCI_CIPHER cciCipher;
    CCI_MODE_CONSTANTS cciMode;
    cci_st cciStatus;



    evpCCICtx = (EVP_CCI_CTX *)(ctx->cipher_data);
    #define DEBUG_PRINT 0

    switch (ctx->cipher->nid) /* map EVP cipher to CCI_CIPHER and CCI_MODE_CONSTANTS */
        {
        case NID_des_cbc:

            #if DEBUG_PRINT
            printf ("NID_des_cbc\n");
            #endif

            cciCipher = CCI_CIPHER_DES;
            cciMode = CCI_MODE_CBC;
            break;

        case NID_des_ecb:

            #if DEBUG_PRINT
            printf ("NID_des_ecb\n");
            #endif

            cciCipher = CCI_CIPHER_DES;
            cciMode = CCI_MODE_ECB;
            break;

        case NID_des_ofb64:

    #if DEBUG_PRINT
    printf ("NID_des_ofb64\n");
    #endif

    cciCipher = CCI_CIPHER_DES;
    cciMode = CCI_MODE_OFB;
    break;

        case NID_des_cfb64:

    #if DEBUG_PRINT
    printf ("NID_des_cfb64\n");
    #endif

    cciCipher = CCI_CIPHER_DES;
    cciMode = CCI_MODE_CFB;
    break;

        case 43:

    #if DEBUG_PRINT
    printf ("2 key - ");
    #endif

        case 44:

    #if DEBUG_PRINT
    printf ("3DES CBC\n");
    #endif

    cciCipher = CCI_CIPHER_3DES;
    cciMode = CCI_MODE_CBC;
    break;

        case 60:

    #if DEBUG_PRINT
    printf ("2 key - ");
    #endif

        case 61:

    #if DEBUG_PRINT
    printf ("3DES CFB\n");
    #endif

    cciCipher = CCI_CIPHER_3DES;
    cciMode = CCI_MODE_CFB;
    break;

        case 62:

    #if DEBUG_PRINT
    printf ("2 key -");
    #endif

        case 63:

    #if DEBUG_PRINT
    printf ("3DES OFB\n");
    #endif

    cciCipher = CCI_CIPHER_3DES;
    cciMode = CCI_MODE_OFB;
    break;

        case 32:

    #if DEBUG_PRINT
    printf ("2 key - ");
    #endif

        case 33:

    #if DEBUG_PRINT
    printf ("3DES ECB\n");
    #endif

    cciCipher = CCI_CIPHER_3DES;
    cciMode = CCI_MODE_ECB;
    break;

        case NID_rc4:
        case NID_rc4_40:

    #if DEBUG_PRINT
    printf ("rc4\n");
    #endif

    cciCipher = CCI_CIPHER_RC4;
    cciMode = CCI_MODE_NONE;
    break;

        case 419:

    #if DEBUG_PRINT
    printf ("aes_128_cbc\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_CBC;
    break;

        case 421:

    #if DEBUG_PRINT
    printf ("aes_128_cfb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_CFB;
    break;

        case 420:

    #if DEBUG_PRINT
    printf ("aes_128_ofb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_OFB;
    break;

        case 418:

    #if DEBUG_PRINT
    printf ("aes_128_ecb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_ECB;
    break;

        case 423:

    #if DEBUG_PRINT
    printf ("aes_192_cbc\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_CBC;
    break;

        case 425:

    #if DEBUG_PRINT
    printf ("aes_192_cfb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_CFB;
    break;

        case 424:

    #if DEBUG_PRINT
    printf ("aes_192_ofb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_OFB;
    break;

        case 422:

    #if DEBUG_PRINT
    printf ("aes_192_ecb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_ECB;
    break;

        case 427:

    #if DEBUG_PRINT
    printf ("aes_256_cbc\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_CBC;
    break;

        case 429:

    #if DEBUG_PRINT
    printf ("aes_256_cfb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_CFB;
    break;

        case 428:

    #if DEBUG_PRINT
    printf ("aes_256_ofb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_OFB;
    break;

        case 426:

    #if DEBUG_PRINT
    printf ("aes_256_ecb\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_ECB;
    break;

        case 655: /* aes_256_cfb8 */
        case 654: /* aes_192_cfb8 */
        case 653: /* aes_128_cfb8 */

    #if DEBUG_PRINT
    printf ("aes cfb8\n");
    #endif

    cciCipher = CCI_CIPHER_AES;
    cciMode = CCI_MODE_CFB8;
    break;

        case 652: /* aes_256_cfb1 */
        case 651: /* aes_192_cfb1 */
        case 650: /* aes_128_cfb1 */
            cciCipher = CCI_CIPHER_AES;
            cciMode = CCI_MODE_CFB1;
            break;

        case 656: /* des_cfb1 */
            cciCipher = CCI_CIPHER_DES;
            cciMode = CCI_MODE_CFB1;
            break;

        case 657: /* des_cfb8 */

            #if DEBUG_PRINT
            printf ("des_cfb8\n");
            #endif

            cciCipher = CCI_CIPHER_DES;
            cciMode = CCI_MODE_CFB8;
            break;

        default:
            SECLIBerr(WRSECLIB_F_cciEVPCipherInit,WRSECLIB_R_UNKNOWN_ALGORITHM_TYPE);
            return EVP_CCI_FAILURE;
        }

    /* this next bit of code figures out if its a reinit, and if so does a new EVP_CCI_CTX need to be
    created with a longer key buffer */

    if (!evpCCICtx)                           /* first time init is called */
        {
        goto alloc_evpCCICtx;                 /* the EVP_CCI_CTX has not been created yet, so go do it */
        }

    if (ctx->key_len <= evpCCICtx->keyLength) /* something changed, maybe smaller key length */
        {                                     /* smaller keylength can still use same context */
        goto init_evpCCICtx;
        }
    else                          /* new key length is larger then this evpCCICtx has allocated */
        {
        cciContext = evpCCICtx->cciContext;
        OPENSSL_free (evpCCICtx); /* free the current context, we need a bigger one */
        }

    alloc_evpCCICtx:
    ctxSize = sizeof (EVP_CCI_CTX) + sizeof (unsigned char) * ctx->key_len;

    ctx->cipher_data = OPENSSL_malloc (ctxSize);
    evpCCICtx = (EVP_CCI_CTX *)(ctx->cipher_data);

    if (!evpCCICtx)
        {          
        SECLIBerr(WRSECLIB_F_cciEVPCipherInit,ERR_R_MALLOC_FAILURE);
        return EVP_CCI_FAILURE;
        }
        
    if(!cciContext)      
    	cciContext = evpCCICtx->cciContext = cciAlloc(sizeof(CCIContextRec));

    if (!evpCCICtx->cciContext)
        {          
        SECLIBerr(WRSECLIB_F_cciEVPCipherInit,ERR_R_MALLOC_FAILURE);
        return EVP_CCI_FAILURE;
        }            

    evpCCICtx->keyLength = ctx->key_len;
    evpCCICtx->ctxSize = ctxSize;

    init_evpCCICtx:
    cciContext = evpCCICtx->cciContext;

    memcpy (evpCCICtx->key, key,
            ctx->key_len);                              /* copy the key to local storage, as it is not stored in EVP_CIPHER_CTX */

    cciStatus = cciCtxInit (cciContext, CCI_APP_PROVIDER_ID, CCI_CLASS_CIPHER, cciCipher);
 
    if (!CCISUCCESS (cciStatus))
        {
        SECLIBerr(WRSECLIB_F_cciEVPCipherInit,WRSECLIB_R_CCI_FAILED);
        return EVP_CCI_FAILURE;
        }

    cciCtxAttrSet (cciContext, CCI_CIPHER_IV, ctx->iv); /* IV is stored in EVP_CIPHER_CTX */
    cciCtxAttrSet (cciContext, CCI_CIPHER_MODE, cciMode);
    cciCtxAttrSet (cciContext, CCI_CIPHER_KEY_LENGTH, ctx->key_len);
    cciCtxAttrSet (cciContext, CCI_CIPHER_IV_LENGTH, ctx->cipher->iv_len);
    cciCtxAttrSet (cciContext, CCI_CIPHER_KEY, evpCCICtx->key);
    

    if (enc)
        {
        cciCtxAttrSet (cciContext, CCI_CIPHER_OPERATION, CCI_ENCRYPT);
        }
    else
        {
        cciCtxAttrSet (cciContext, CCI_CIPHER_OPERATION, CCI_DECRYPT);
        }
    return EVP_CCI_SUCCESS;
    }
