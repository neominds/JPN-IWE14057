/* rsa_cci.c - CCI RSA implementation */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01c,11apr05,tat  code review rework
01b,26jan05,cdw  changed path to cci.h
01a,08dec04,tat  created
*/

/*
DESCRIPTION
This file implements the RSA CCI method

NOMANUAL
*/

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <wrn/cci/cci.h>
#include <openssl/wr_err.h>


#ifndef RSA_NULL


typedef enum rsa_cci_op_type
    {
    RSA_CCI_ENCRYPT,
    RSA_CCI_DECRYPT,
    RSA_CCI_SIGN,
    RSA_CCI_VERIFY
    } RSA_CCI_OPERATION_TYPE;

typedef enum rsa_cci_key_type
    {
    RSA_CCI_PUBLIC_KEY,
    RSA_CCI_PRIVATE_KEY
    } RSA_CCI_KEY_TYPE;

/* local functions */
static int RSA_cci_cipher(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding, RSA_CCI_OPERATION_TYPE encrypt, RSA_CCI_KEY_TYPE keyType);
static int RSA_cci_sign_verify(int type, const unsigned char *m, unsigned int m_len,
   const unsigned char *sigbuf, unsigned int *siglen, const RSA *rsa, RSA_CCI_OPERATION_TYPE sign);
static int RSA_cci_public_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa,int padding);
static int RSA_cci_private_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa,int padding);
static int RSA_cci_public_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa,int padding);
static int RSA_cci_private_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa,int padding);
static int RSA_cci_init(RSA *rsa);
static int RSA_cci_sign(int type, const unsigned char *m, unsigned int m_len,
     unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
static int RSA_cci_verify(int type, const unsigned char *m, unsigned int m_len,
   const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);
BOOL openssl_to_cci( const RSA *opensslKey, CCIPublicKey *privateKey, CCIPublicKey *publicKey );



/* local variables */

static RSA_METHOD rsa_pkcs1_cci_meth={
    "CCI PKCS#1 RSA",
    RSA_cci_public_encrypt,
    RSA_cci_public_decrypt, 
    RSA_cci_private_encrypt, 
    RSA_cci_private_decrypt,
    NULL,  
    BN_mod_exp_mont,
    RSA_cci_init,
    NULL, 
    RSA_FLAG_SIGN_VER, /* flags */
    NULL,
    RSA_cci_sign, 
    RSA_cci_verify, 
    };

/*******************************************************************************
*
* RSA_PKCS1_SSLcci - returns pointer to RSA_METHOD
*
* This routine returns a pointer to the RSA_METHOD that uses CCI.
*
* RETURNS: RSA_METHOD *
*
* ERRNO: N/A
* NOMANUAL
*/
const RSA_METHOD *RSA_PKCS1_SSLcci(void)
    {
    return (&rsa_pkcs1_cci_meth);
    }

/*******************************************************************************
*
* RSA_PKCS1_SSLeay - returns pointer to RSA_METHOD
*
* This routine originally existed in the OpenSSL rsa_eay.c file.  The Wind River
* implementation has removed this file, but includes this function here.  It returns
* a pointer to the RSA_METHOD that is implemented using CCI.
*
* RETURNS: RSA_METHOD *
*
* ERRNO: N/A
* NOMANUAL
*/
const RSA_METHOD *RSA_PKCS1_SSLeay(void)
    {
    return (RSA_PKCS1_SSLcci ()); /* rsa_eay.c is no longer linked, so return pointer
                                       to the rsa_pkcs1_cci_meth here */

    }

/******************************************************************************
*
* RSA_cci_public_encrypt - encrypt using the RSA public key
*
* This routine performs RSA encryption using the public key. 
*
* Parameters:
* \is 
* \i <flen> 
* Length of data to be encrypted
*
* \i <from> 
* Pointer to data to be encrypted (usually the session key)
*
* \i <to>
* Pointer to output buffer (must be at least RSA_size(rsa) bytes of memory)
*
* \i <rsa>
* Public key structure.
*
* \i <padding>
* Type of padding to be used.  Can be: RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, 
* RSA_SSLV23_PADDING, or RSA_NO_PADDING
* \ie
*
*
* RETURNS: -1 if Error, otherwise returns the length of the ciphertext
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static int RSA_cci_public_encrypt
    (
    int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa,
    int padding
    )
    {
    return RSA_cci_cipher (flen, from, to, rsa, padding, RSA_CCI_ENCRYPT, RSA_CCI_PUBLIC_KEY);
    }

/******************************************************************************
*
* RSA_cci_private_encrypt - encrypt using the RSA private key
*
* This routine performs RSA encryption using the private key. 
*
* Parameters:
* \is 
* \i <flen> 
* Length of data to be encrypted
*
* \i <from> 
* Pointer to data to be encrypted (usually the session key)
*
* \i <to>
* Pointer to output buffer (must be at least RSA_size(rsa) bytes of memory)
*
* \i <rsa>
* Private key structure
*
* \i <padding>
* Type of padding to be used.  Can be: RSA_PKCS1_PADDING, RSA_SSLV23_PADDING, 
* or RSA_NO_PADDING
* \ie
*
*
* RETURNS: -1 if Error, otherwise returns the length of the ciphertext
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static int RSA_cci_private_encrypt
    (
    int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa,
    int padding
    )
    {
    return RSA_cci_cipher (flen, from, to, rsa, padding, RSA_CCI_ENCRYPT, RSA_CCI_PRIVATE_KEY);
    }

/******************************************************************************
*
* RSA_cci_private_decrypt - decrypt using the RSA private key
*
* This routine performs RSA decryption using the private key. 
*
* Parameters:
* \is 
* \i <flen> 
* Length of data to be decrypted
*
* \i <from> 
* Pointer to data to be decrypted
*
* \i <to>
* Pointer to output buffer (must be at least RSA_size(rsa) bytes of memory)
*
* \i <rsa>
* Private key structure.
*
* \i <padding>
* Type of padding to be used.  Can be: RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, 
* RSA_SSLV23_PADDING, or RSA_NO_PADDING
* \ie
*
*
* RETURNS: -1 if Error, otherwise returns the length of the plaintext 
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static int RSA_cci_private_decrypt
    (
    int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa,
    int padding
    )
    {
    return RSA_cci_cipher (flen, from, to, rsa, padding, RSA_CCI_DECRYPT, RSA_CCI_PRIVATE_KEY);
    }

/******************************************************************************
*
* RSA_cci_public_decrypt - decrypt using the RSA public key
*
* This routine performs RSA decryption using the public key. 
*
* Parameters:
* \is 
* \i <flen> 
* Length of data to be decrypted
*
* \i <from> 
* Pointer to data to be decrypted
*
* \i <to>
* Pointer to output buffer (must be at least RSA_size(rsa) bytes of memory)
*
* \i <rsa>
* Public key structure.
*
* \i <padding>
* Type of padding to be used.  Can be: RSA_PKCS1_PADDING, RSA_SSLV23_PADDING, 
* or RSA_NO_PADDING
* \ie
*
*
* RETURNS: -1 if Error, otherwise returns the length of the plaintext 
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static int RSA_cci_public_decrypt
    (
    int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa,
    int padding
    )
    {
    return RSA_cci_cipher (flen, from, to, rsa, padding, RSA_CCI_DECRYPT, RSA_CCI_PUBLIC_KEY);
    }

/******************************************************************************
*
* RSA_cci_init - initialize an RSA structure
*
* This routine initializes the RSA flags.
*
* Parameters:
* \is 
* \i <rsa> 
* RSA public key structure
* \ie
*
* RETURNS: 1 
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static int RSA_cci_init
    (
    RSA *rsa
    )
    {
    rsa->flags |= RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE;
    return (1);
    }

/******************************************************************************
*
* RSA_cci_sign - sign a message digest 
*
* This routine signs a message digest using the private key.
*
* Parameters:
* \is 
* \i <type> 
* Type of message digest to be signed. Valid values are:
* NID_md2, NID_md4, NID_md5, NID_ripemd160, NID_sha1, NID_md5_sha1
*
* \i <m> 
* Message digest to be signed
*
* \i <m_len>
* Length of message digest
*
* \i <sigret>
* Output buffer to hold the signature.  It must be  RSA_size(rsa) bytes in length.
*
* \i <siglen>
* Location to store the length of the signature.
*
* \i <rsa>
* Private key structure
* \ie
*
*
* RETURNS: 1 if Success, 0 if Error
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static int RSA_cci_sign
    (
    int type,
    const unsigned char *m,
    unsigned int m_len,
    unsigned char *sigret,
    unsigned int *siglen,
    const RSA *rsa
    )
    {
    return RSA_cci_sign_verify (type, m, m_len, sigret, siglen, rsa, RSA_CCI_SIGN);
    }

/******************************************************************************
*
* RSA_cci_verify - verify a signature 
*
* This routine verifies the signature of a message digest.
*
* Parameters:
* \is 
* \i <type> 
* Type of message digest to be signed. Valid values are:
* NID_md2, NID_md4, NID_md5, NID_ripemd160, NID_sha1, NID_md5_sha1
*
* \i <m> 
* Message digest to be signed
*
* \i <m_len>
* Length of message digest
*
* \i <sigbuf>
* Signature to be verified
*
* \i <siglen>
* Length of the signature
*
* \i <rsa>
* Public key structure
* \ie
*
*
* RETURNS: 1 if Success, 0 if Error
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static int RSA_cci_verify
    (
    int type,
    const unsigned char *m,
    unsigned int m_len,
   const unsigned char *sigbuf,
    unsigned int siglen,
    const RSA *rsa
    )
    {
    return RSA_cci_sign_verify (type, m, m_len, sigbuf, &siglen, rsa, RSA_CCI_VERIFY);
    }
/******************************************************************************
*
* openssl_to_cci - convert an RSA structure to CCIPublicKey structures
*
* This routine converts an RSA structure to CCIPublicKey structures. 
* publicKey and privateKey both point to new CCIPublicKey structures
* when this function returns. 
*
* Parameters:
* \is 
* \i <opensslKey> 
* RSA structure to be converted
*
* \i <privateKey> 
* CCIPublicKey * that will point to the private key when the function returns.  
* If privateKey is NULL, the private key will not be created.
*
* \i <publicKey>
* CCIPublicKey * that will point to the public key when the function returns.
* If publicKey is NULL, the private key will not be created.
* \ie
*
* RETURNS: TRUE always
*
* ERRNO: N/A
* 
* NOMANUAL
*/
#define BN_STREAM( cciSize, cciStream, bn ) {cciStream = (cci_b *)cciAlloc( BN_num_bytes( bn ));cciSize = BN_bn2bin( bn, cciStream );}

BOOL openssl_to_cci
    (
    const RSA *opensslKey,
    CCIPublicKey *privateKey,
    CCIPublicKey *publicKey
    )
    {
    cci_b *N, *P, *Q, *E, *D, *dP, *dQ, *qINV;
    cci_t sN, sP, sQ, sE, sD, sdP, sdQ, sqINV;

    /*
    ** --- Generate private and public key objects...
    */
    if (NULL != publicKey)
        {
        cciPKIKeyCreate (CCI_DEF_PROVIDER_ID, CCI_RSA_PUBLIC_KEY, publicKey);
        }

    if (NULL != privateKey)
        {
        cciPKIKeyCreate (CCI_DEF_PROVIDER_ID, CCI_RSA_PRIVATE_KEY, privateKey);
        if(opensslKey->flags & RSA_FLAG_NO_BLINDING)  /* Blinding is on by default since 0.9.7b */
            {
            cciPKIBlindingSet (*privateKey, FALSE); 
            }
        else
            {
            cciPKIBlindingSet (*privateKey, TRUE); 
            }
        }

    /*
    ** --- Extract byte-streams from RSA key
    */
    qINV = dP = dQ = E = D = N = P = Q = NULL;
    sqINV = sdP = sdQ = sD = sE = sN = sP = sQ = 0;

    if (opensslKey->n)
        BN_STREAM (sN, N, opensslKey->n);

    if (opensslKey->e)
        BN_STREAM (sE, E, opensslKey->e);

    if (opensslKey->d)
        BN_STREAM (sD, D, opensslKey->d);

    if (opensslKey->p)
        BN_STREAM (sP, P, opensslKey->p);

    if (opensslKey->q)
        BN_STREAM (sQ, Q, opensslKey->q);

    if (opensslKey->dmp1)
        BN_STREAM (sdP, dP, opensslKey->dmp1);

    if (opensslKey->dmq1)
        BN_STREAM (sdQ, dQ, opensslKey->dmq1);

    if (opensslKey->iqmp)
        BN_STREAM (sqINV, qINV, opensslKey->iqmp);

    /* --- Set CCI private key components */

    if (NULL != privateKey)
        {
        cciPKIKeyCompSet (*privateKey, CCI_RSA_MODULAS, N, sN);
        cciPKIKeyCompSet (*privateKey, CCI_RSA_PUBLIC_EXPONENT, E, sE);
        cciPKIKeyCompSet (*privateKey, CCI_RSA_PRIVATE_EXPONENT, D, sD);
        cciPKIKeyCompSet (*privateKey, CCI_RSA_PRIME_FACTOR_P, P, sP);
        cciPKIKeyCompSet (*privateKey, CCI_RSA_PRIME_FACTOR_Q, Q, sQ);
        cciPKIKeyCompSet (*privateKey, CCI_RSA_EXPONENT_dP, dP, sdP);
        cciPKIKeyCompSet (*privateKey, CCI_RSA_EXPONENT_dQ, dQ, sdQ);
        cciPKIKeyCompSet (*privateKey, CCI_RSA_CRT_QINV, qINV, sqINV);
        }

    /* --- Set CCI public key components */

    if (NULL != publicKey)
        {
        cciPKIKeyCompSet (*publicKey, CCI_RSA_MODULAS, N, sN);
        cciPKIKeyCompSet (*publicKey, CCI_RSA_PUBLIC_EXPONENT, E, sE);
        }

    /*
    ** ---Free memory resources
    */

    cciFree (N);
    cciFree (E);
    cciFree (D);
    cciFree (P);
    cciFree (Q);
    cciFree (dP);
    cciFree (dQ);
    cciFree (qINV);

    return (TRUE);
    }

/******************************************************************************
*
* cci_to_openssl - convert a CCI private key to an RSA structure
*
* This routine converts a CCI private key to an RSA struct.
*
* Parameters:
* \is 
* \i <privateKey> 
* CCIPublicKey key to be converted (contains both public and private key)
*
* \i <opensslKey>
* Pointer to RSA structure to be used.  If opensslKey is NULL, a new RSA
* structure is created.
* \ie
*
* RETURNS: RSA *, pointer to a new RSA structure created by this function.
*
* ERRNO: N/A
* 
* NOMANUAL
*/
RSA *cci_to_openssl
    (
    CCIPublicKey key,
    RSA *opensslKey
    )
    {
    

    cci_b *N, *P, *Q, *E, *D, *dP, *dQ, *qINV;
    cci_t sN, sP, sQ, sE, sD, sdP, sdQ, sqINV;

    /*
    ** --- Extract byte-streams from CCI keys
    */
    qINV = dP = dQ = E = D = N = P = Q = NULL;
    sqINV = sdP = sdQ = sD = sE = sN = sP = sQ = 0;
    cciPKIKeyCompGet (key, CCI_RSA_MODULAS, &N, &sN);
    cciPKIKeyCompGet (key, CCI_RSA_PUBLIC_EXPONENT, &E, &sE);
    cciPKIKeyCompGet (key, CCI_RSA_PRIVATE_EXPONENT, &D, &sD);
    cciPKIKeyCompGet (key, CCI_RSA_PRIME_FACTOR_P, &P, &sP);
    cciPKIKeyCompGet (key, CCI_RSA_PRIME_FACTOR_Q, &Q, &sQ);
    cciPKIKeyCompGet (key, CCI_RSA_EXPONENT_dP, &dP, &sdP);
    cciPKIKeyCompGet (key, CCI_RSA_EXPONENT_dQ, &dQ, &sdQ);
    cciPKIKeyCompGet (key, CCI_RSA_CRT_QINV, &qINV, &sqINV);

    /*
    ** --- Set key components into RSA key
    */
    if(NULL==opensslKey)
         opensslKey = RSA_new ();

    opensslKey->n = BN_bin2bn (N, sN, opensslKey->n);
    opensslKey->e = BN_bin2bn (E, sE, opensslKey->e);
    opensslKey->d = BN_bin2bn (D, sD, opensslKey->d);
    opensslKey->p = BN_bin2bn (P, sP, opensslKey->p);
    opensslKey->q = BN_bin2bn (Q, sQ, opensslKey->q);
    opensslKey->dmp1 = BN_bin2bn (dP, sdP, opensslKey->dmp1);
    opensslKey->dmq1 = BN_bin2bn (dQ, sdQ, opensslKey->dmq1);
    opensslKey->iqmp = BN_bin2bn (qINV, sqINV, opensslKey->iqmp);

    /*
     Blinding is on by default with a new CCIPublicKey.  Currently there is no API to get the current
     state of blinding from a CCIPublicKey, so we assume it is on.  When the API becomes available 
     we will test to see if we should call RSA_blinding_on() or RSA_blinding_off

     Blinding is on by default in later releases (0.9.7b) and above of openssl 

    */


    RSA_blinding_on (opensslKey, NULL); 
    /*
    ** ---Free memory resources
    */
    cciFree (N);
    cciFree (E);
    cciFree (D);
    cciFree (P);
    cciFree (Q);
    cciFree (dP);
    cciFree (dQ);
    cciFree (qINV);

    return (opensslKey);
    }
/******************************************************************************
*
* RSA_cci_cipher - invoke a RSA cipher operation
*
* This routine performs RSA cipher operation.
*
* Parameters:
* \is 
* \i <flen> 
* Length of input data
*
* \i <from> 
* Pointer to input data (either ciphertext or plaintext)
*
* \i <to>
* Pointer to output buffer (must be at least RSA_size(rsa) bytes of memory)
*
* \i <rsa>
* RSA key structure.
*
* \i <padding>
* Type of padding to be used.  Can be: RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, 
* RSA_SSLV23_PADDING, or RSA_NO_PADDING
*
* \i <encrypt>
* Either RSA_CCI_ENCRYPT or RSA_CCI_DECRYPT
* 
* \i <keyType>
* Either RSA_CCI_PUBLIC_KEY or RSA_CCI_PRIVATE_KEY
* \ie
*
*
* RETURNS: -1 if Error, otherwise returns the length of the plaintext 
*
* ERRNO: N/A
* 
* NOMANUAL
*/

static int RSA_cci_cipher
    (
    int flen,
    const unsigned char *from,
    unsigned char *to,
    RSA *rsa,
    int padding,
    RSA_CCI_OPERATION_TYPE encrypt,
    RSA_CCI_KEY_TYPE keyType
    )
    {
    int r = -1;
    cci_t paddingFormat;
    cci_t hashingFormat = 0;
    cci_t outputTextLength;
    cci_st cciStatus;
    CCIPublicKey key;

    /* first convert RSA key to CCI keys */

    if (RSA_CCI_PUBLIC_KEY == keyType)
        {
        openssl_to_cci (rsa, NULL, &key); /* only need public key */
        }
    else
        {
        openssl_to_cci (rsa, &key, NULL); /* only need private key */
        }

    switch (padding)
        {
    
        #ifndef OPENSSL_NO_SHA
        case RSA_PKCS1_OAEP_PADDING:
            if(((RSA_CCI_ENCRYPT == encrypt) && (RSA_CCI_PUBLIC_KEY == keyType)) 
                || ((RSA_CCI_DECRYPT == encrypt) && (RSA_CCI_PRIVATE_KEY == keyType)))
            {
                paddingFormat = CCI_PUBLICKEY_OAEP;
                hashingFormat = CCI_PUBLICKEY_HASH_SHA1;
                break;
            }
            else
            {
                SECLIBerr(WRSECLIB_F_RSA_cci_cipher,WRSECLIB_R_OAEP_NOT_SUPPORTED);
                goto err;
            }
            break;
        #endif

        case RSA_SSLV23_PADDING: /* private encrypt, public encrypt RSA_SSLV23_PADDING means CCI_PUBLIC_KEY_SSLV23 */
            if (RSA_CCI_ENCRYPT == encrypt)
                {
                paddingFormat = CCI_PUBLICKEY_SSLV23;
                break;
                }

        /* private decrypt, public decrypt RSA_SSLV23_PADDING CCI_PUBLICKEY_PKCS1_V1_5 */
        case RSA_PKCS1_PADDING:
            paddingFormat = CCI_PUBLICKEY_PKCS1_V1_5;
            break;

        case RSA_NO_PADDING:
            paddingFormat = CCI_PUBLICKEY_NO_PADDING;
            break;

        default:
            SECLIBerr(WRSECLIB_F_RSA_cci_cipher,WRSECLIB_R_UNKNOWN_PADDING_TYPE);            
            goto err;
        }

    outputTextLength = RSA_size (rsa);

    if (RSA_CCI_ENCRYPT == encrypt)
        {
        cciStatus = cciPKIEncrypt (key, paddingFormat, hashingFormat, (cci_b *)from, flen, &to, &outputTextLength);
        }
    else
        {
        cciStatus = cciPKIDecrypt (key, paddingFormat, hashingFormat, (cci_b *)from, flen, &to, &outputTextLength);
        }

    if (!CCISUCCESS (cciStatus))
        {
        SECLIBerr(WRSECLIB_F_RSA_cci_cipher,WRSECLIB_R_CCI_FAILED);            
        }
    else
        {
        r = outputTextLength;
        }

    err:
        cciPKIKeyDestroy (key);
        return (r);
    }
/******************************************************************************
*
* RSA_cci_sign_verify - sign or verify a message digest 
*
* This routine signs or verifies a message digest.
*
* Parameters:
* \is 
* \i <type> 
* Type of message digest to be signed. Valid values are:
* NID_md2, NID_md4, NID_md5, NID_ripemd160, NID_sha1, NID_md5_sha1
*
* \i <m> 
* Message digest to be signed
*
* \i <m_len>
* Length of message digest
*
* \i <sigbuf>
* Buffer to hold the signature.  It must be  RSA_size(rsa) bytes in length.  For
* sign=RSA_CCI_SIGN the signature is copied to this buffer.  For sign=RSA_CCI_VERIFY
* this buffer must contain the signature and is compared against the internally calculated signature.
*
* \i <siglen>
* For sign=RSA_CCI_SIGN, this parameter must point to the location that the signature length is copied too.
* For sign=RSA_CCI_VERIFY, this parameter must point to the location that the signature length is stored.
*
* \i <rsa>
* Private key structure
*
* \i <sign>
* Either RSA_CCI_SIGN or RSA_CCI_VERIFY        
* \ie
*
*
* RETURNS: 1 if Success, 0 if Error
*
* ERRNO: N/A
* 
* NOMANUAL
*/
static int RSA_cci_sign_verify
    (
    int type,
    const unsigned char *m,
    unsigned int m_len,
   const unsigned char *sigbuf,
    unsigned int *siglen,
    const RSA *rsa,
    RSA_CCI_OPERATION_TYPE sign
    )
    {
    int ret = -1;
    cci_st cciStatus;
    CCIPublicKey key;
    cci_t signType;

    /* first convert RSA key to CCI keys */
    if (RSA_CCI_SIGN == sign)
        {
        openssl_to_cci (rsa, &key, NULL); /* when signing only need private key */
        }
    else
        {
        openssl_to_cci (rsa, NULL, &key); /* when verifying only need public key */
        }

    switch (type)
        {
        case NID_md2:
            signType = CCI_PUBLICKEY_HASH_MD2;
            break;

        case NID_md4:
            signType = CCI_PUBLICKEY_HASH_MD4;
            break;

        case NID_ripemd160:
            signType = CCI_PUBLICKEY_HASH_RIP160;
            break;

        case NID_md5:
            signType = CCI_PUBLICKEY_HASH_MD5;
            break;

        case NID_sha1:
            signType = CCI_PUBLICKEY_HASH_SHA1;
            break;

        case NID_md5_sha1:
            signType = CCI_PUBLICKEY_HASH_OPENSSL;
            break;

        default:
            SECLIBerr(WRSECLIB_F_RSA_cci_sign_verify,WRSECLIB_R_UNKNOWN_ALGORITHM_TYPE);
            goto err;
            break;
        }

    if (RSA_CCI_SIGN == sign) /* CCI requires *siglen be set */
        {
        *siglen = RSA_size (rsa);
        cciStatus = cciPKISignDigest (key, signType, (unsigned char *)m, &sigbuf, siglen);
        }
    else
        {
        cciStatus = cciPKIVerifyDigest (key, signType, (cci_b *)m, sigbuf, *siglen);
        }

    if (!CCISUCCESS (cciStatus))
        {
        printf("CCI returned %d\n",cciStatus);
        SECLIBerr(WRSECLIB_F_RSA_cci_sign_verify,WRSECLIB_R_CCI_FAILED);
        }
    else
        {
        ret = 1;
        }

    err:
        cciPKIKeyDestroy (key);
        return (ret);
    }
#endif
