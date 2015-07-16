/* sslMemoryRoutines.c - memory routines for SSL */
/* Copyright 2004 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,22nov04,tat  created
*/

#include <vxWorks.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>   
#include <taskLib.h>
#include <string.h>
#include "sslMemoryRoutines.h" 
#include <limits.h>

#ifdef SSL_MEMORY_USE_MEMORY_POOL
#include <netBufLib.h>
#include <net/mbuf.h>
#endif


LOCAL BOOL tNetTaskAllocationDebugging = FALSE;

#ifdef SSL_MEMORY_USE_MEMORY_POOL
#define SSL_MEMORY_MAX_NETMALLOC_SIZE (SSL_MEMORY_MAX_CLUSTER_SIZE \
                                         - sizeof(long))
#define SSL_MEMORY_NETMALLOC_MAGIC ((USHORT)0xfeed)
LOCAL STATUS sslMemoryPoolInit();
LOCAL void* sslMemoryPoolMalloc(UINT bufSize);
LOCAL void sslMemoryPoolFree(void * pBuf);
LOCAL NET_POOL    sslMemoryNetPool;     
LOCAL NET_POOL_ID pSSLMemoryNetPoolID = NULL;
LOCAL M_CL_CONFIG sslMclBlkConfig = {0, 0, NULL, 0}; /* All fields calculated in sslMemoryPoolInit() */
LOCAL CL_DESC sslClDescTbl [] =   /* cluster descriptor table */
    {
      /*
       * clusterSize num             memArea    memSize
       * ----------  ----            -------    -------
       */
        {64,         SSL_NUM_64,    NULL,      1},      /* memArea and memSize   */
        {128,        SSL_NUM_128,   NULL,      2},      /* are calculated in     */
        {256,        SSL_NUM_256,   NULL,      3},      /* sslMemoryPoolInit() */
        {512,        SSL_NUM_512,   NULL,      4},
        {1024,       SSL_NUM_1024,  NULL,      5},
        {2048,       SSL_NUM_2048,  NULL,      6},
        {4096,       SSL_NUM_4096,  NULL,      7},
        {8192,       SSL_NUM_8192,  NULL,      8},
        {16384,      SSL_NUM_16384, NULL,      9},
        {32768,      SSL_NUM_32768, NULL,     10},
        {65536,      SSL_NUM_65536, NULL,     11}
    };
#ifdef SSL_MEMORY_STATISTICS
LOCAL void adjustPoolStatistics(UINT bufSize, int adjustAmount);
LOCAL void memoryStatsSemTake();
LOCAL void memoryStatsSemGive();
#define INCREMENT (1)
#define DECREMENT (-1)
LOCAL UINT memPoolAllocations[][3] =
    {
        /* cluster size, current allocations, high water mark of
         *                                    cluster allocations of
         *                                    that size */
        {0,  0, 0}, /* the first element in this array must be {0, 0, 0} */
        {64, 0, 0},
        {128, 0, 0},
        {256, 0, 0},
        {512, 0, 0},
        {1024, 0, 0},
        {2048, 0, 0},
        {4096, 0, 0},
        {8192, 0, 0},
        {16384, 0, 0},
        {32768, 0, 0},
        {65536, 0, 0},
        {UINT_MAX, 0, 0} /* The last element in this array must be {UINT_MAX, 0, 0} */
    };
#endif /* #ifdef SSL_MEMORY_STATISTICS */
#endif /* #ifdef SSL_MEMORY_USE_MEMORY_POOL */

#ifdef SSL_MEMORY_STATISTICS
LOCAL SEM_ID sslMemoryStatsSem = NULL;
LOCAL UINT bytesAllocated = 0;
LOCAL UINT bytesFreed = 0;
LOCAL UINT allocations = 0;
LOCAL UINT frees = 0;
LOCAL UINT currentBytesAllocated = 0;
LOCAL UINT maxBytesAllocated = 0;

/**************************************************************************/
STATUS sslMemoryStats()
    {
    printf ("bytesAllocated = %u\n", bytesAllocated);
    printf ("bytesFreed = %u\n", bytesFreed);
    printf ("allocations = %u\n", allocations);
    printf ("frees = %u\n", frees);
    printf ("maxBytesAllocated = %u\n", maxBytesAllocated);
    printf ("currentBytesAllocated = %u\n", currentBytesAllocated);
    return (OK);
    }
#else 
STATUS sslMemoryStats()
    {
    printf ("SSL Memory Stats functionality was not compiled in.\n");
    return(OK);
    }
#endif

/**************************************************************************/
void* sslMemoryAllocate (UINT elemSize)
    {
    SSL_MEMORY_NODE *pNode;
    void* p_object;
    UINT allocatedSize;

    pNode = NULL;
    p_object = NULL;

    allocatedSize = elemSize + sizeof(SSL_MEMORY_NODE);

#ifdef SSL_MEMORY_NETTASK_ALLOC_DEBUGGING
    if (tNetTaskAllocationDebugging 
        && (strcmp(taskName(taskIdSelf()),"tNetTask") == 0))
        {
        printf ("Alloc in tNetTask!!!!!!!!!\n");
        taskSuspend(0);
        }
#endif

#ifdef SSL_MEMORY_USE_MEMORY_POOL
    pNode = (SSL_MEMORY_NODE*)sslMemoryPoolMalloc(allocatedSize);
    if (pNode != NULL)
        {
        pNode->bufferType = SSL_MEMORY_MBLK_ALLOCATED;
#ifdef SSL_MEMORY_STATISTICS
        adjustPoolStatistics(allocatedSize, INCREMENT);
#endif                                                  
        }
    else
#endif /* SSL_MEMORY_USE_MEMORY_POOL */
        {
        pNode = (SSL_MEMORY_NODE*)malloc (allocatedSize);
        if (pNode != NULL)
            {
            pNode->bufferType = 0;
            }
        }

    if (pNode != NULL)
        {
        pNode->reserved = SSL_MEMORY_ALLOCATED_MAGIC;
        pNode->bufferLength = elemSize;
        p_object = ((unsigned char*)pNode) + sizeof(SSL_MEMORY_NODE);
#ifdef SSL_MEMORY_STATISTICS
        memoryStatsSemTake();
        allocations++;
        bytesAllocated += elemSize;
        currentBytesAllocated += elemSize;
        if (maxBytesAllocated < currentBytesAllocated)
            {
            maxBytesAllocated = currentBytesAllocated;
            }
        memoryStatsSemGive();
#endif
#ifdef SSL_MEMORY_INITIALIZE
        memset(p_object, SSL_MEMORY_INITIALIZATION_FIELD, elemSize);
#endif
        }
#ifdef SSL_MEMORY_SUSPEND_ON_FAILURE
    else
        {
        printf("sslMemoryAllocate() %u bytes failed!\r\n",  allocatedSize );
        taskSuspend(0);
        }
#endif

    return (p_object);
    }
/**************************************************************************/
void* sslMemoryRealloc(
    void * pBlock,            /* block to reallocate */
    size_t newSize            /* new block size */
    )
    {
    void *pNewBlock;
    SSL_MEMORY_NODE *pNode;
    UINT elemSize;

    if(NULL == pBlock)
        {                                        
        return sslMemoryAllocate(newSize);
        }
    else if(0 == newSize)
        {
         sslMemoryFree(pBlock);
         return NULL;
        }
    
    /* for debug, just do a copy on a realloc, optimize this later */
    pNode = (SSL_MEMORY_NODE*)(((unsigned char*)pBlock) - sizeof(SSL_MEMORY_NODE));
    elemSize = pNode->bufferLength;


    pNewBlock = sslMemoryAllocate(newSize);

    if(NULL == pNewBlock)
        {
        return NULL;
        }
    memcpy(pNewBlock,pBlock,elemSize);
    sslMemoryFree(pBlock);
    return pNewBlock;
}
/**************************************************************************/
void* sslMemoryCalloc (UINT elemNum, UINT elemSize)
    {
    void* p_object;
    UINT allocSize = 0;

    p_object = NULL;
    allocSize = elemSize * elemNum;
    p_object = (void*)sslMemoryAllocate(allocSize);
    if (p_object != NULL)
        {
        bzero((char*)p_object,allocSize);
        }
#ifdef SSL_MEMORY_SUSPEND_ON_FAILURE
    else
        {
        printf("sslMemoryCalloc() %u bytes failed!\r\n",  allocSize);
        taskSuspend(0);
        }
#endif

    return (p_object);
    }


/**************************************************************************/
void sslMemoryFree (void* p_object)
    {
    SSL_MEMORY_NODE *pNode;
    UINT elemSize;
#ifdef SSL_MEMORY_USE_MEMORY_POOL
    BOOL mBlkAllocated;
#endif

    if (p_object == NULL)
        {
        return;
        }

    pNode = (SSL_MEMORY_NODE*)(((unsigned char*)p_object) - sizeof(SSL_MEMORY_NODE));
    elemSize = pNode->bufferLength;

                                                           
#ifdef SSL_MEMORY_SUSPEND_ON_FAILURE
    if (pNode->reserved != SSL_MEMORY_ALLOCATED_MAGIC)
        {
        printf("Attempt to free %p using sslMemoryFree()\n", p_object);
        taskSuspend(0);
        }
#endif

#ifdef SSL_MEMORY_STATISTICS
    memoryStatsSemTake();
    frees++;
    bytesFreed += elemSize;
    currentBytesAllocated -= elemSize;
    memoryStatsSemGive();
#endif

#ifdef SSL_MEMORY_USE_MEMORY_POOL
    if ((pNode->bufferType & SSL_MEMORY_MBLK_ALLOCATED)
        == SSL_MEMORY_MBLK_ALLOCATED)
        {
        mBlkAllocated = TRUE;
        }
    else
        {
        mBlkAllocated = FALSE;
        }
#endif

#ifdef SSL_MEMORY_INITIALIZE
    memset(pNode, SSL_MEMORY_INITIALIZATION_FIELD, elemSize + sizeof(SSL_MEMORY_NODE));
#endif

#ifdef SSL_MEMORY_USE_MEMORY_POOL
    if (mBlkAllocated)
        {
        struct mBlk* pMblk;
        
        pMblk = *((struct mBlk **)(((unsigned char*)pNode) - sizeof(struct mBlk **)));
        if (pMblk->mBlkHdr.reserved == SSL_MEMORY_NETMALLOC_MAGIC)
            {
            sslMemoryPoolFree((void*)pNode);
#ifdef SSL_MEMORY_STATISTICS
            adjustPoolStatistics(elemSize + sizeof(SSL_MEMORY_NODE), DECREMENT);
#endif
            return;
            }
#ifdef SSL_MEMORY_SUSPEND_ON_FAILURE
        else
            {
            /* Should never happen */
            printf("mBlk reserved and SSL_MEMORY_NODE type field mismatch: %p\n",
                   p_object);
            taskSuspend(0);
            }
#endif
        }
#endif /* #ifdef SSL_MEMORY_USE_MEMORY_POOL */
    
    free ((void*)pNode);
    
    return;
    }

/**************************************************************************/
#ifdef SSL_MEMORY_USE_MEMORY_POOL
LOCAL STATUS sslMemoryPoolInit()
    {
    STATUS result;    
    int sslClDescTblNumEnt; /* number of cluster desc entries */
    int n;

    /* Use pSSLMemoryNetPoolID as a semaphore to prevent multiple
     * initializations. */
    taskLock();
    if (pSSLMemoryNetPoolID)
        {
        taskUnlock();
        return (OK);
        }

    netBufLibInit();

    sslMclBlkConfig.clBlkNum = 0;
    sslClDescTblNumEnt = (NELEMENTS(sslClDescTbl));
    for (n = 0; n < sslClDescTblNumEnt; n++)
        {
        sslClDescTbl[n].memSize = (sslClDescTbl[n].clNum 
                                     * (sslClDescTbl[n].clSize + sizeof(long)));
        sslClDescTbl[n].memArea = malloc(sslClDescTbl[n].memSize); 
        if (sslClDescTbl[n].memArea == NULL)
            {
            result = ERROR;
            goto error;
            }
        sslMclBlkConfig.clBlkNum += sslClDescTbl[n].clNum;
        }

    sslMclBlkConfig.mBlkNum = sslMclBlkConfig.clBlkNum * 4 / 3;
    sslMclBlkConfig.memSize = (sslMclBlkConfig.mBlkNum * (M_BLK_SZ + sizeof(long))) 
        + (sslMclBlkConfig.clBlkNum * CL_BLK_SZ);
    sslMclBlkConfig.memArea = malloc(sslMclBlkConfig.memSize);
    if (sslMclBlkConfig.memArea == NULL)
        {
        result = ERROR;
        goto error;
        }

    result = netPoolInit(&sslMemoryNetPool, &sslMclBlkConfig, &sslClDescTbl[0], 
                         sslClDescTblNumEnt, NULL);
    if (result == OK)
        {
        pSSLMemoryNetPoolID = &sslMemoryNetPool;
        taskUnlock();
        return (OK);
        }

error:
    /* Memory allocation error, or netPoolInit() failed -- Cleanup
     * memory and try again later. */
    for (n = 0; n < sslClDescTblNumEnt; n++)
        {
        if (sslClDescTbl[n].memArea != NULL)
            {
            free (sslClDescTbl[n].memArea);
            }
        }
    if (sslMclBlkConfig.memArea != NULL)
        {
        free (sslMclBlkConfig.memArea);
        }
    pSSLMemoryNetPoolID = NULL;    
    taskUnlock();
    return (result);
    }

/**************************************************************************/
LOCAL void * sslMemoryPoolMalloc
    (
    UINT   bufSize        /* size of the buffer to get */
    )
    { 
    FAST struct mbuf *     pMblk; 
    FAST struct mbuf ** pPtrMblk; 

    if (bufSize > SSL_MEMORY_MAX_NETMALLOC_SIZE)
        {
#ifdef SSL_MEMORY_STATISTICS
        /* Buffer too large to allocate an mblk from the pool */
        memoryStatsSemTake();
        memPoolAllocations[NELEMENTS(memPoolAllocations)- 1][1] += INCREMENT;
        memoryStatsSemGive();
#endif
        return NULL;
        }

    if (sslMemoryPoolInit() != OK)
        {
        return (NULL);
        }
    pMblk = netTupleGet (pSSLMemoryNetPoolID, 
                         (bufSize + sizeof(struct mbuf *)),
                         M_DONTWAIT, MT_DATA, TRUE);
    if (pMblk != NULL) 
        { 
        pPtrMblk = mtod(pMblk, struct mbuf **); 
        *pPtrMblk = pMblk; 
        pMblk->m_data += sizeof(struct mbuf **); 
        pMblk->mBlkHdr.reserved = SSL_MEMORY_NETMALLOC_MAGIC;
        return (mtod(pMblk, char *));
        } 
    else 
        {
#ifdef SSL_MEMORY_STATISTICS
        /* Couldn't allocate an mblk from the pool */
        memoryStatsSemTake();
        memPoolAllocations[0][1] += INCREMENT;
        memoryStatsSemGive();
#endif
        return (NULL); 
        }
    }

/**************************************************************************/
LOCAL void sslMemoryPoolFree
    (
    void * pBuf        /* pointer to buffer to free */     
    ) 
    {
    if (pBuf != NULL)
        {
        (void)m_free (*((struct mbuf **)(((char*)pBuf) - sizeof(struct mbuf **))));
        }
    }

/**************************************************************************/
void sslMemoryPoolShow (void)
    {
    UCHAR clType; 
    CL_POOL_ID pClPool;

    printf ("________________________\n"); 
    printf ("SSL CLUSTER POOL TABLE\n"); 
    printf ("_______________________________________________________________________________\n");
    printf ("size     clusters  free");
#ifdef SSL_MEMORY_STATISTICS
    printf ("      max alloc att"); 
#endif
    printf ("  usage\n"); 
    printf ("-------------------------------------------------------------------------------\n");
    for (clType = pSSLMemoryNetPoolID->clLg2Min; 
         clType <= pSSLMemoryNetPoolID->clLg2Max; clType++)
        {
        if ((pClPool = netClPoolIdGet (pSSLMemoryNetPoolID,
                                       CL_LOG2_TO_CL_SIZE(clType),
                                       TRUE)) != NULL)
            {
            printf ("%-9d", pClPool->clSize); 
            printf ("%-10d", pClPool->clNum); 
            printf ("%-10d", pClPool->clNumFree);
#ifdef SSL_MEMORY_STATISTICS
            {
            UINT currentCluster;
            for (currentCluster = NELEMENTS(memPoolAllocations) - 2;
                 currentCluster > 0;
                 currentCluster--)
                {
                if (pClPool->clSize == memPoolAllocations[currentCluster][0])
                    {
                    break;
                    }
                }
            printf ("%-15d", memPoolAllocations[currentCluster][2]);
            }
#endif
            printf ("%-14d\n", pClPool->clUsage); 
            }
        }
#ifdef SSL_MEMORY_STATISTICS
    printf ("-------------------------------------------------------------------------------\n");
    printf ("Number of allocations larger than the largest cluster: %d\n", 
            memPoolAllocations[NELEMENTS(memPoolAllocations) - 1][1]);
    printf ("Number of failed attempts to allocate a buffer from the memory pool: %d\n", 
            memPoolAllocations[0][1]);
#endif
    printf ("-------------------------------------------------------------------------------\n");
    }

#ifdef SSL_MEMORY_STATISTICS
/**************************************************************************/
LOCAL void adjustPoolStatistics
    (
    UINT bufSize,
    int adjustAmount
    )
    {
    UINT currentCluster;
    UINT *pCurrentCount;
    UINT *pCurrentMax;

    bufSize += sizeof(long); /* account for the cluster header */

    memoryStatsSemTake();
    for (currentCluster = NELEMENTS(memPoolAllocations) - 2;
         currentCluster > 0;
         currentCluster--)
        {
        if (bufSize > memPoolAllocations[currentCluster - 1][0])
            {
            pCurrentCount = &memPoolAllocations[currentCluster][1];
            *pCurrentCount += adjustAmount;
            if (adjustAmount == INCREMENT) 
                {
                pCurrentMax = &memPoolAllocations[currentCluster][2];
                if (*pCurrentMax < *pCurrentCount)
                    {
                    *pCurrentMax = *pCurrentCount;
                    }
                }
            break;
            }
        }
    memoryStatsSemGive();
    return;
    }
#endif /* #ifdef SSL_MEMORY_STATISTICS */
#else /* #ifdef SSL_MEMORY_USE_MEMORY_POOL */
/**************************************************************************/
void sslMemoryPoolShow (void)
    {
    printf ("SSL_MEMORY_USE_MEMORY_POOL not configured\n"); 
    }
#endif /* #ifdef SSL_MEMORY_USE_MEMORY_POOL */

#ifdef SSL_MEMORY_STATISTICS
/**************************************************************************/
LOCAL void memoryStatsSemTake()
    {
    taskLock();
    if (sslMemoryStatsSem == NULL)
        {
        sslMemoryStatsSem = semMCreate(SEM_Q_PRIORITY 
                                         | SEM_INVERSION_SAFE
                                         | SEM_DELETE_SAFE);
        }
    taskUnlock();
    semTake(sslMemoryStatsSem, WAIT_FOREVER);
    return;
    }

LOCAL void memoryStatsSemGive()
    {
    semGive(sslMemoryStatsSem);
    return;
    }
#endif

void sslNetTaskAllocationDebuggingSet(BOOL enable)
    {
#ifdef SSL_MEMORY_NETTASK_ALLOC_DEBUGGING
    tNetTaskAllocationDebugging = enable;
#endif
    return;
    }

BOOL sslNetTaskAllocationDebuggingGet(void)
    {
    return tNetTaskAllocationDebugging;
    }


/**************************************************************************/


