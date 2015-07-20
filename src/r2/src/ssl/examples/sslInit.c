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
01a,15nov04,tat  created file

*/


/****************************************************************
description:
-----------

This file may be used to include the SSL component via a command-line build.

The following steps describe how to configure Wind River SSL/TLS into the VxWorks image using the 
command-line from the BSP directory. The Wind River SSL/TLS component requires
that the Security Libraries are also included in the command-line build, before the SSL/TLS
component is.

Command-line Build Instructions
-------------------------------

Step 0: Configure the Security Libraries
------  
    The SSL/TLS component depends on the Security Libraries.  Configure the Security Libraries
    first.  (see secLibInit.c)


Step 1: Add this source file to the BSP folder.
------  (e.g. C:\Tornados\Tornado2_2_1_X86\target\config\pcPentium2 )

Step 2: Adjust the BSP Makefile so that this object is linked to the vxWorks image
------
    MACH_EXTRA = sslInit.o

Step 3: Configure the SSL/TLS command-line build by specifying the #define INCLUDES in this file
------

Step x: Adjust config.h to include at least the network components
 
#define STANDALONE_NET
#define INCLUDE_NETWORK
#define INCLUDE_NET_INIT

      
Step 4: Add calls to configure the SSL/TLS component in usrConfig.c
-------
        In the function usrRoot(), in the INCLUDE_USER_APPL section add a call
        to sslLibInit().  Make sure INCLUDE_USER_APPL is defined.

        sslLibInit() should be called right after secLibInit() is called.

    
Step 3: Rebuild the vxWorks image:
------

C:\Tornados\Tornado2_2_1_X86\target\config\pcPentium2 make CPU=PPC603 TOOL=gnu clean
C:\Tornados\Tornado2_2_1_X86\target\config\pcPentium2 make CPU=PPC603 TOOL=gnu vxWorks

*/          
/********************************************************* 
Define SSL Features we want included 
*********************************************************/

#define INCLUDE_SSL             /* The SSL/TLS API */
#define INCLUDE_SSL_APPS   /* The SSL applications (including OpenSSL) */
#define INCLUDE_SSL_TESTS  /* The SSL selftests */
                         

/* include the configlette */

#include "../comps/src/net/usrNetSSL.c"

/***************************************************************
* sslLibInit() - initializes the SSL/TLS component
*         
* Calls the SSL/TLS configlette.  The SSL INCLUDES from this file
* are used by usrNetSSLConfigure().
* 
* Notes: The Security Libraries must be initialized before this 
* is called.  See secLibInit().
***************************************************************/
void sslLibInit()
{
    usrNetSSLConfigure();
}






