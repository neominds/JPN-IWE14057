/* hmac.c - EVP <-> CCI shim for HMAC */
/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01b,24mar05,tat fix compiler warning
01a,01jan05,tat  created
*/

/*
DESCRIPTION

This library contains routines that implement the CCI Adapter for the HMAC interface.  The HMAC_CTX 
structure has been modified.  Any applications that access the contents of HMAC_CTX will need to be 
ported to not use the contents of HMAC_CTX directly. 


INCLUDES 
openssl/hmac.h 
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include "cryptlib.h"
#include <openssl/wr_err.h>

#define HMAC_DEBUG_SUSPEND_ON_ERROR
/******************************************************************************
*
* hmacGetCCIAlgorithmId - get HMAC CCI_ALGORITHM_ID for a given NID  
*
* This routine converts the OpenSSL supplied message digest type and returns
* the corresponding CCI_ALGORITHM_ID for the HMAC.
*
* Parameters:
* \is 
* \i <type> 
* Message Digest NID Type
* \ie
*
* RETURNS: CCI_ALGORITHM_ID for the HMAC
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static CCI_ALGORITHM_ID hmacGetCCIAlgorithmId(int type)
{
    CCI_ALGORITHM_ID algorithmID=CCI_HMAC_SHA1;

    switch(type)
    {
    case NID_sha1:
        algorithmID = CCI_HMAC_SHA1;
        break;
    case NID_md5:
        algorithmID = CCI_HMAC_MD5;
        break;
    case NID_md4:
        algorithmID = CCI_HMAC_MD4;
        break;
    case NID_ripemd160:
        algorithmID = CCI_HMAC_RIPEMD160;
        break;
    case NID_sha256:
        algorithmID = CCI_HMAC_SHA256;
        break;
    case NID_sha384:
        algorithmID = CCI_HMAC_SHA384;
        break;
    case NID_sha512:
        algorithmID = CCI_HMAC_SHA512;
        break;
    /* 	Not supported yet.  Enabled when SHA224 is available in CCI 
    case NID_sha224:
    algortihmID = CCI_HMAC_SHA224;
    break;
    */
    default:
        /* this case should never happen.  For debugging, the task is suspended.  For
        release code, it defaults to SHA1 because there is no way to return error to the caller.
        In most cases this will produce a bad HMAC, but the application code will detect it 
        and handle the error case.            
        */
        SECLIBerr(WRSECLIB_F_HMAC_Init_ex,WRSECLIB_R_UNKNOWN_ALGORITHM_TYPE);
#ifdef HMAC_DEBUG_SUSPEND_ON_ERROR    

        SECLIBerr(WRSECLIB_F_HMAC_Init_ex,WRSECLIB_R_TASK_SUSPEND);
        taskSuspend(0);
#else
        algorithmID = CCI_HMAC_SHA1;
#endif
        break;
    }
    return algorithmID;
}
/******************************************************************************
*
* HMAC_Init_ex - initialize an HMAC context
*
* This routine initializes the HMAC operation using CCI.  The CCI_APP_PROVIDER_ID
* CCI provider is used.  If md == NULL, then the HMAC_CTX is reused.
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the HMAC_CTX structure used by the caller
*
* \i <key>
* Key to be used
*
* \i <len>
* Length of the key
*
* \i <md>
* Pointer to the EVP_MD (message digest type) to be used
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
                  const EVP_MD *md, ENGINE *impl)
    {

    /* can't call cciHmacInit because it mallocs a CCIContextRec, for HMAC CCIContextRec is a member of HMAC_CTX */
    cci_st cciStatus;
    int j;
    CCI_ALGORITHM_ID algorithmID=0;
    const EVP_MD *localMd = md;
    EVP_MD_CTX mdCtx;

    if(md == NULL)  /* reinit */
        {
        localMd = ctx->md;    /* use same message digest as last time */
        }
    else                     /* this is the first use of the ctx */
        {
        ctx->md = localMd;   /* save EVP_MD being used for this HMAC */
        }


    /* first determine what type of message digest to use */
    algorithmID = hmacGetCCIAlgorithmId(localMd->type);


    if (key != NULL)
        {
        j=EVP_MD_block_size(localMd);
        OPENSSL_assert(j <= sizeof ctx->key);
        if (j < len)  /* key is too long, hash the key to get key the same as digest length */
            {
            EVP_MD_CTX_init(&mdCtx);
            EVP_DigestInit(&mdCtx,localMd);            /* optimize this later with call to digest() */
            EVP_DigestUpdate(&mdCtx,key,len);
            EVP_DigestFinal(&mdCtx,ctx->key,
                            &(ctx->key_length));
            }
        else
            {
            OPENSSL_assert(len <= sizeof ctx->key);
            memcpy(ctx->key,key,len);
            ctx->key_length=len;
            }
        if(ctx->key_length != HMAC_MAX_MD_CBLOCK)           /* key is too small, pad the key */
            {
            memset(&(ctx->key[ctx->key_length]), 0,
                   HMAC_MAX_MD_CBLOCK - (ctx->key_length));
            ctx->key_length = HMAC_MAX_MD_CBLOCK;
            }

        }

    /*
    ** ---init request context that is in HMAC_CTX 
    */
    if(ctx->ctxInit)
        {
        cciCtxClear(ctx->cciCtx);
        }
    cciStatus = cciCtxInit((ctx->cciCtx),CCI_APP_PROVIDER_ID,CCI_CLASS_HMAC, algorithmID);
    ctx->ctxInit=1;
    if( CCISUCCESS( cciStatus ) )
        {
        /*
        ** --- Set the request attributes...
        */
        cciCtxAttrSet( (ctx->cciCtx), CCI_HMAC_KEY, &(ctx->key[0]) );
        cciCtxAttrSet( (ctx->cciCtx), CCI_HMAC_KEY_LENGTH, ctx->key_length );
        }
    else
        {
        SECLIBerr(WRSECLIB_F_HMAC_Init_ex,WRSECLIB_R_CCI_FAILED);
#ifdef HMAC_DEBUG_SUSPEND_ON_ERROR
        SECLIBerr(WRSECLIB_F_HMAC_Init_ex,WRSECLIB_R_TASK_SUSPEND);
        taskSuspend(0);
#endif
		
	
		}
	return cciStatus;

    }
/******************************************************************************
*
* HMAC_Init - initialize an HMAC context
*
* This routine initializes the HMAC operation using CCI.  
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the HMAC_CTX structure used by the caller
*
* \i <key>
* Key to be used
*
* \i <len>
* Length of the key
*
* \i <md>
* Pointer to the EVP_MD (message digest type) to be used
*
* \i <impl>
* Engine pointer.  This is not used in this implementation.  
* \ie
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* NOMANUAL
*/
void HMAC_Init(HMAC_CTX *ctx, const void *key, int len,
               const EVP_MD *md)
    {
    HMAC_Init_ex(ctx,key,len,md, NULL);
    }
/******************************************************************************
*
* HMAC_Update - update the HMAC operation with data
*
* This routine updates the HMAC operation with data by calling cciHmacUpdate
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the HMAC_CTX structure used by the caller
*
* \i <data>
* Input data
*
* \i <len>
* Length of the data
* \ie
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len)
    {
    cci_st cciStatus;
    cciStatus = cciHmacUpdate((ctx->cciCtx),data,len);
    if( !CCISUCCESS( cciStatus ) )
        {
        SECLIBerr(WRSECLIB_F_HMAC_Update,WRSECLIB_R_CCI_FAILED);
        }
	return cciStatus;
    }
/******************************************************************************
*
* HMAC_Final - finalize the HMAC operation
*
* This routine finalize the HMAC operation and copies the output to md
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the HMAC_CTX structure used by the caller
*
* \i <md>
* Output buffer.   Must be at least EVP_MD_block_size(ctx->md) in size
*
* \i <len>
* Length of the data
* \ie
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* NOMANUAL
*/
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
    {
    cci_st cciStatus;
    unsigned int tempLen;

    if(!len)            /* cci requires a length pointer */
    {                   /* indicates how large md buffer is */
      len = &tempLen;   /* if len != NULL, length of output is returned in len */
    }

    *len = EVP_MD_block_size(ctx->md);
    cciStatus = cciHmacFinal((ctx->cciCtx),md,len);
    if( !CCISUCCESS( cciStatus ) )
        {
        SECLIBerr(WRSECLIB_F_HMAC_Final,WRSECLIB_R_CCI_FAILED);
#ifdef HMAC_DEBUG_SUSPEND_ON_ERROR
        SECLIBerr(WRSECLIB_F_HMAC_Init_ex,WRSECLIB_R_TASK_SUSPEND);
        taskSuspend(0);
#endif
        }
	return cciStatus;

}
/******************************************************************************
*
* HMAC_CTX_init - init a HMAC_CTX structure
*
* This function allocates the low level CCIContext.  The HMAC_CTX structure
* must be cleaned by calling HMAC_CTX_cleanup.  
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the HMAC_CTX structure used by the caller
* \ie
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* NOMANUAL
*/

void HMAC_CTX_init(HMAC_CTX *ctx)
    {
    memset(ctx,0,sizeof(HMAC_CTX));

    ctx->cciCtx = cciAlloc(sizeof(CCIContextRec));
    if(!ctx->cciCtx)
        {
        SECLIBerr(WRSECLIB_F_HMAC_Init_ex,WRSECLIB_R_CCI_FAILED);
#ifdef HMAC_DEBUG_SUSPEND_ON_ERROR                         
        SECLIBerr(WRSECLIB_F_HMAC_Init_ex,WRSECLIB_R_TASK_SUSPEND);
        taskSuspend(0);
#endif            
        }
    }
/******************************************************************************
*
* HMAC_CTX_cleanup - cleanup a HMAC_CTX structure
*
* This routine cleans up the low level CCIContext by calling cciCtxClear.
* This function must be called if HMAC_Init or HMAC_Init_ex has been called with this
* HMAC_CTX.  This function does NOT free ctx.
*
* Parameters:
* \is 
* \i <ctx> 
* Pointer to the HMAC_CTX structure used by the caller
* \ie
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* NOMANUAL
*/
void HMAC_CTX_cleanup(HMAC_CTX *ctx)
    {
    cci_t digestLength;

    if(ctx->cciCtx)
    {
        digestLength=0;
        cciCtxAttrSet( ctx->cciCtx, CCI_OUTPUT_LENGTH, &digestLength );
        if(ctx->ctxInit)
            {
            cciCtxClear(ctx->cciCtx);
            }
        cciFree(ctx->cciCtx);
    }
    memset(ctx,0,sizeof(HMAC_CTX));
    }
/******************************************************************************
*
* HMAC - one shot HMAC operation
*
* This routine calculates the HMAC of the data in d, and returns the result in md.
*
* Parameters:
* \is 
* \i <evp_md> 
* Pointer to the EVP_MD structure used to define the Message digest to use.
* \i <key> 
* Pointer to key to use.
* \i <key_len> 
* Key length.
* \i <d>
* Pointer to input data. 
* \i <n> 
* Length of input data.
* \i <md>
* Pointer to output buffer.  Must be large enough to hold evp_md->md_size bytes
* \i <md_len>
* Pointer to output buffer Length.  The if !NULL length of the output message digest is stored here.
* \ie
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* NOMANUAL
*/

unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, int n, unsigned char *md,
                    unsigned int *md_len)
{
    static unsigned char m[EVP_MAX_MD_SIZE];
    CCI_ALGORITHM_ID algorithmID;
    unsigned int length;

    if (md == NULL) md=m;

    if(!md_len)
        md_len = &length;

    *md_len = EVP_MD_block_size(evp_md);

    algorithmID = hmacGetCCIAlgorithmId(evp_md->type);
    cciHmacBlock(CCI_APP_PROVIDER_ID,algorithmID,key, key_len,d,n,md,md_len );

#if 0
    HMAC_CTX c;
    static unsigned char m[EVP_MAX_MD_SIZE];
    if (md == NULL) md=m;


    HMAC_CTX_init(&c);
    HMAC_Init(&c,key,key_len,evp_md);
    HMAC_Update(&c,d,n);
    HMAC_Final(&c,md,md_len);
    HMAC_CTX_cleanup(&c);
#endif     
    return(md);
}
