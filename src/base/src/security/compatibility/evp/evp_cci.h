/* evp_cci.h - CCI adapter for the EVP interface */
/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,04jan05,tat  created
*/

#include <wrn/cci/cci.h>

typedef enum evp_cci_status
    {
    EVP_CCI_FAILURE = 0,
    EVP_CCI_SUCCESS = 1
    }

EVP_CCI_STATUS;

int cciEVPDigestCleanup
    (
    EVP_MD_CTX *ctx
    );

int cciEVPDigestFinal
    (
    EVP_MD_CTX *ctx,
    unsigned char *md
    );

int cciEVPDigestUpdate
    (
    EVP_MD_CTX *ctx,
    const void *data,
    unsigned int count
    );

int cciEVPDigestInit
    (
    EVP_MD_CTX *ctx,
    CCI_ALGORITHM_ID algorithmId
    );

int cciEVPDigestInit_ex
    (
    EVP_MD_CTX *ctx,
    CCI_ALGORITHM_ID algorithmId,
    CCI_PROVIDER_ID providerId
    );

int cciEVPCipherInit
    (
    EVP_CIPHER_CTX *ctx,
    const unsigned char *key,
    const unsigned char *iv,
    int enc
    );

int cciEVPCipherCleanup
    (
    EVP_CIPHER_CTX *ctx
    );

int cciEVPCipher
    (
    EVP_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    unsigned int inl
    );

int cciEVPDigestCopy
    (
    EVP_MD_CTX *to,
    const EVP_MD_CTX *from
    );

typedef struct evp_cci_ctx
    {
    CCIContext cciContext;  /* pointer to a CCI context */
    unsigned int keyLength; /* length of key buffer that is right after this structure (starting at key[0]) */
    unsigned int ctxSize;   /* sizeof(EVP_CCI_CTX) + sizeof(unsigned char) * keyLength */
    unsigned char key[0];   /* first byte of the variable key length buffer */
    } EVP_CCI_CTX;
