/*---------------------

Copyright (C) Wind River Systems, Inc. All rights are reserved.

Redistribution and use of the software in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions in source code form must retain all copyright notices
     and a copy of this license.
  2. No right is granted herein to use the Wind River name, trademarks, trade dress or
     other company identifiers (except in connection with required copyright notices).
  3. THIS SOFTWARE IS PROVIDED BY WIND RIVER SYSTEMS "AS IS" AND ANY EXPRESS OR
     IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF
     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT,
     ARE DISCLAIMED. IN NO EVENT SHALL WIND RIVER SYSTEMS BE LIABLE FOR ANY
     DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
     INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
     LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
     ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
     (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
     THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

End of License.

---------------------*/
/*
modification history
--------------------
01a,mar05,tat  created file

*/


/****************************************************************
description:
-----------

This file may be used to include the Security Libraries component via a command-line build.

The following steps describe how to configure Wind River Security Libraries into the VxWorks image using the 
command-line from the BSP directory.  

Command-line Build Instructions
-------------------------------

Step 1: Add this source file to the BSP folder.
------  (e.g. C:\Tornados\Tornado2_2_1_X86\target\config\pcPentium2 )

Step 2: Adjust the BSP Makefile so that this object is linked to the vxWorks image
------
    MACH_EXTRA = secLibInit.o

Step 3: Configure the Security Library command-line build by specifying the #define INCLUDES in this file
------

Step 4: Add calls to configure the Security Library component in usrConfig.c
-------
        In the function usrRoot(), in the INCLUDE_USER_APPL section add a call
        to secLibInit().  Make sure INCLUDE_USER_APPL is defined.

        Generally secLibInit() should be called before any other initialization is 
        done.

        For other providers you must link in provider modules and call 
        usrCciLoadProvider( Mpc190ExportCCIProvider, USE_SOFTWARE_DEFAULT ) within
        secLibInit().  See CPI documentation for futher details.
        
    
Step 3: Rebuild the vxWorks image:
------

E:\windriver\vxworks-6.2\target\config\pcPentium make CPU=PENTIUM TOOL=diab clean
E:\windriver\vxworks-6.2\target\config\pcPentium make CPU=PENTIUM TOOL=diab vxWorks

*/
/********************************************************* 
Define Security Library Features Features we want included 
*********************************************************/
#define INCLUDE_CCI_DEFAULT_PROVIDER
#define INCLUDE_CCI_IMPORT_AES
#define INCLUDE_CCI_IMPORT_AESKW
#define INCLUDE_CCI_IMPORT_DES
#define INCLUDE_CCI_IMPORT_RC4
#define INCLUDE_CCI_IMPORT_RC4TKIP
#define INCLUDE_CCI_IMPORT_NULL
#define INCLUDE_CCI_IMPORT_PRNG
#define INCLUDE_CCI_IMPORT_HASH_CRC32
#define INCLUDE_CCI_IMPORT_HASH_MD2
#define INCLUDE_CCI_IMPORT_HASH_MD4
#define INCLUDE_CCI_IMPORT_HASH_MD5
#define INCLUDE_CCI_IMPORT_HASH_SHA1
#define INCLUDE_CCI_IMPORT_HASH_SHA256
#define INCLUDE_CCI_IMPORT_HASH_SHA384
#define INCLUDE_CCI_IMPORT_HASH_SHA512
#define INCLUDE_CCI_IMPORT_HASH_RIP160
#define INCLUDE_CCI_IMPORT_HASH_RIP128
#define INCLUDE_CCI_IMPORT_HMAC_MD4
#define INCLUDE_CCI_IMPORT_HMAC_MD5
#define INCLUDE_CCI_IMPORT_HMAC_SHA1
#define INCLUDE_CCI_IMPORT_HMAC_SHA256
#define INCLUDE_CCI_IMPORT_HMAC_SHA384
#define INCLUDE_CCI_IMPORT_HMAC_SHA512
#define INCLUDE_CCI_IMPORT_HMAC_RIP160
#define INCLUDE_CCI_IMPORT_HMAC_RIP128
#define INCLUDE_CCI_IMPORT_HMAC_AESXCBC
#define INCLUDE_CCI_IMPORT_PUBLICKEY_RSA
                         
#define CCI_TASK_PRIORITY 75
#define SHARED_REGION_SIZE 4096

/* include the configlettes */
#include "../comps/src/net/usrNetCciInit.c"  /* CCI */
#include "../comps/src/usrCertsInit.c"       /* X509 Certificates and utilities */

/***************************************************************
* secLibInit() - initializes the Security Libraries
*         
* Initializes CCI using the parameters defined in this file.  
* The Security Libraries configlette is then called to initialize the
* component.
* 
***************************************************************/
void secLibInit()
{
    usrCciInit();
    usrCciLoadProvider( CCI_DEFAULT_PROVIDER, 0 );

    /* if another provider is to be used, load it here as well */
    /* ie usrCciLoadProvider( Mpc190ExportCCIProvider, USE_SOFTWARE_DEFAULT );
    See CPI documentation. */

    usrCertSupportConfigure(); /* inits the security libraries */
}





