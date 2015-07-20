/* wr_err.c Wind River error logging */
/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,18apr05,tat  created
*/

/*
DESCRIPTION

This file defines the error messages used by the Wind River Security Library


INCLUDES 
openssl/wr_err.h 
*/


/* 
    To add a new error, add the function and reason code to the wrseclib_funcs 
    enum in wr_err.h.  Then add the strings for the function and reason code below.
*/

#include <openssl/wr_err.h>
#include <vxWorks.h>


static ERR_STRING_DATA WRSECLIB_evp_str_functs[] = {
    { ERR_PACK(ERR_LIB_WRSECLIB, 0, 0),        "Wind River Security Library"},
    { ERR_PACK(0, WRSECLIB_F_cciEVPDigestInit_ex, 0),    "cciEVPDigestInit_ex" },
    { ERR_PACK(0, WRSECLIB_F_cciEVPDigestUpdate, 0),     "cciEVPDigestUpdate" },
    { ERR_PACK(0, WRSECLIB_F_cciEVPDigestFinal, 0),      "cciEVPDigestFinal" },   
    { ERR_PACK(0, WRSECLIB_F_cciEVPDigestCleanup, 0),    "cciEVPDigestCleanup" },   
    { ERR_PACK(0, WRSECLIB_F_cciEVPDigestCopy, 0),    "cciEVPDigestCopy" },   
    { ERR_PACK(0, WRSECLIB_F_cciEVPCipher, 0),    "cciEVPCipher" },   
    { ERR_PACK(0, WRSECLIB_F_cciEVPCipherCleanup, 0),    "cciEVPCipherCleanup" },   
    { ERR_PACK(0, WRSECLIB_F_cciEVPCipherInit, 0),    "cciEVPCipherInit" },   
    { ERR_PACK(0, WRSECLIB_F_RSA_cci_cipher, 0),    "RSA_cci_cipher" },
    { ERR_PACK(0, WRSECLIB_F_RSA_cci_sign_verify, 0),"RSA_cci_sign_verify" },
    { ERR_PACK(0, WRSECLIB_F_HMAC_Init_ex, 0),    "HMAC_Init_ex" },
    { ERR_PACK(0, WRSECLIB_F_HMAC_Update, 0),"HMAC_Update" },
    { ERR_PACK(0, WRSECLIB_F_HMAC_Final, 0),"HMAC_Final" },
    { 0, NULL }
};


static ERR_STRING_DATA WRSECLIB_str_reasons[]=
{
    {WRSECLIB_R_CCI_FAILED              ,"CCI call fails, check return code"},
    {WRSECLIB_R_NON_COPY_SAFE_CONTEXT   ,"non-copyable context"},
    {WRSECLIB_R_UNKNOWN_ALGORITHM_TYPE   ,"unknown algorithm"},
    {WRSECLIB_R_OAEP_NOT_SUPPORTED,"RSA_PKCS1_OAEP_PADDING not supported in this mode"},
    {WRSECLIB_R_UNKNOWN_PADDING_TYPE,"Unknown padding type"},
    {WRSECLIB_R_OAEP_NOT_SUPPORTED,"RSA_PKCS1_OAEP_PADDING not supported in this mode"},
    {WRSECLIB_R_UNKNOWN_PADDING_TYPE,"Unknown padding type"},
    {WRSECLIB_R_TASK_SUSPEND,"Fatal Error: suspending task"},
    {0,NULL}
};

/*******************************************************************************
*
* ERR_load_WRSECLIB_strings - load error strings
*
* This routine loads error strings used in the Wind River adapter
*
* RETURNS: N/A
*
* ERRNO: N/A
* NOMANUAL
*/
void ERR_load_WRSECLIB_strings(void)
{
    static BOOL initialized=FALSE;


    if (FALSE==initialized)
    {
        initialized =TRUE;
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(ERR_LIB_WRSECLIB,WRSECLIB_str_reasons);
#endif
    }
}


