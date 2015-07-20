/* rand_cci.c - CCI random number interface */
/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,22Feb05,tat  created
*/


#include <openssl/rand.h>
#include "rand_lcl.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <wrn/cci/cci.h>



const char *RAND_version="CCI RAND" OPENSSL_VERSION_PTEXT;

static void local_cci_rand_seed(const void *buf, int num);
static int local_cci_rand_bytes(unsigned char *buf, int num);
static int local_cci_rand_status(void);

RAND_METHOD rand_cci_meth={
    local_cci_rand_seed,
    local_cci_rand_bytes,
    NULL,
    NULL,
    local_cci_rand_bytes,
    local_cci_rand_status
    };


RAND_METHOD *RAND_CCI(void)
{
    return(&rand_cci_meth);
}
static void local_cci_rand_seed(const void *buf, int num)
{
    cci_st status;

    status = cciRandSeed(CCI_APP_PROVIDER_ID,(cci_b *) buf, num );

    if(!CCISUCCESS(status))
    {
        printf("cciRandSeed failed with error %d\n",status);
    }
}
static int local_cci_rand_bytes(unsigned char *buf, int num)
{
    cci_st status;
    
    status = cciRand(CCI_APP_PROVIDER_ID, buf,num);

    if(!CCISUCCESS(status))
    {
        printf("cciRand failed with error %d\n",status);
        return -1;
    }

    return 1;
}

static int local_cci_rand_status(void)
{
    return 1;
}
