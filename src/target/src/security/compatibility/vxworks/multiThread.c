/* multiThread.c - multithread locking routines for OpenSSL*/

/* Copyright 1984-2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,18nov04,tat   written
*/

/*
DESCRIPTION
These routines implement the platform specific multithread locking routines
used by OpenSSL
*/ 

#include "semLib.h"
#include "taskLib.h"

#include "openssl/crypto.h"

static SEM_ID *semArray; 
void sslLockingCallback(int mode, int type, char *file, int line);

/************************************************************************
* sslMultiThreadInit - initialize the locking functions
*
* This routine sets up the OpenSSL thread safe functionality.
* It creates an array of mutex semaphores to be used by the OpenSSL library
* for locking access to global data.  This function is called by the Security
* Libraries configlette.
* 
* OpenSSL thread safe functionality is implemented using two callbacks:
* The task id callback which returns the taskId of the calling function,
* and the locking callback.  Both are implemented using platform specific
* functions. 
* 
* RETURNS: OK if success, otherwise ERROR if semMCreate fails.
* ERRNO: N/A
* NOMANUAL
*/
STATUS sslMultiThreadInit(void)
{
    int i;
    semArray = (SEM_ID *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(SEM_ID));  
    
    if(NULL==semArray){
        printf("OpenSSL Malloc Error in sslMultiThreadInit\n");
        return ERROR;
    }

    for(i=0; i<CRYPTO_num_locks();i++)
        {
        semArray[i] = semMCreate(SEM_Q_PRIORITY);
        if(NULL == semArray[i])
            {
            printf("Error creating locking semaphore\n");
            return ERROR;
            }
         }
    CRYPTO_set_id_callback((unsigned long (*)()) taskIdSelf);
    CRYPTO_set_locking_callback((void (*)())sslLockingCallback);
    return OK;
}
/******************************************************************************
*
* sslLockingCallback - lock or unlock a specific OpenSSL crypto lock
*
* This routine performs the actual locking/unlocking of the mutex semaphores
* that were created in sslMultiThreadInit.
*
* Parameters:
* \is 
* \i <mode> 
* CRYPTO_LOCK or CRYPTO_UNLOCK
*
* \i <type> 
* Crypto lock index number.
*
* \i <file>
* Filename of calling function
*
* \i <line>
* Line number of calling function
* \ie
*
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* NOMANUAL
*/
void sslLockingCallback(int mode, int type, char *file, int line)
    {
    #ifdef undef
    fprintf(stderr,"thread=%4d mode=%s lock=%s %s:%d\n",
    CRYPTO_thread_id(),
    (mode&CRYPTO_LOCK)?"l":"u",
    (type&CRYPTO_READ)?"r":"w",file,line);
    #endif

    if (mode & CRYPTO_LOCK)
        {
        semTake(semArray[type],WAIT_FOREVER);
        }
    else
        {
        semGive(semArray[type]);
        }
    }
/************************************************************************
* sslMultiThreadCleanup - undo initialization
*
* This routine sets the locking callback to NULL, deletes the mutex semaphores
* as well as frees the memory allocated for the semaphore IDs.
* 
* RETURNS: OK always
* ERRNO: N/A
* NOMANUAL
*/
STATUS sslMultiThreadCleanup(void)
    {
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i=0; i<CRYPTO_num_locks(); i++)
    {
        semDelete(semArray[i]);
    }
    OPENSSL_free(semArray);
    return OK;
    }





