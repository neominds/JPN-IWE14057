/* wr_err.h Wind River error logging */
/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,18apr05,tat  created
*/

/*

   This file declares the functions and reason codes that are used by Wind River
   software to report errors to the Openssl ERR module.
   
   The actual error strings are declared in target/src/security/compatibility/vxworks/wr_err.c.

   Refer to the ERR module documentation for details on how to use the ERR module.

*/


#include <openssl/err.h>

void ERR_load_WRSECLIB_strings(void);

#define SECLIBerr(f,r) ERR_PUT_error(ERR_LIB_WRSECLIB,(f),(r),__FILE__,__LINE__)
                                  
enum wrseclib_funcs {
   WRSECLIB_F_cciEVPDigestInit_ex=100,
   WRSECLIB_F_cciEVPDigestUpdate,
   WRSECLIB_F_cciEVPDigestFinal,
   WRSECLIB_F_cciEVPDigestCleanup,
   WRSECLIB_F_cciEVPDigestCopy,
   WRSECLIB_F_cciEVPCipherInit,
   WRSECLIB_F_cciEVPCipher,
   WRSECLIB_F_cciEVPCipherCleanup,
   WRSECLIB_F_RSA_cci_cipher,
   WRSECLIB_F_RSA_cci_sign_verify,
   WRSECLIB_F_HMAC_Init_ex,
   WRSECLIB_F_HMAC_Update,
   WRSECLIB_F_HMAC_Final
   };

enum wrseclib_reasons {
   WRSECLIB_R_CCI_FAILED=100,
   WRSECLIB_R_NON_COPY_SAFE_CONTEXT,
   WRSECLIB_R_UNKNOWN_ALGORITHM_TYPE,
   WRSECLIB_R_OAEP_NOT_SUPPORTED,
   WRSECLIB_R_UNKNOWN_PADDING_TYPE,
   WRSECLIB_R_TASK_SUSPEND
   };

