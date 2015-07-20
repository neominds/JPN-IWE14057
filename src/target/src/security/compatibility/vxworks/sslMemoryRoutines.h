/* sslMemoryRoutines.h - memory routines for SSL */
/* Copyright 2004 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,22nov04,tat  created based on SSL_memory_routines.h
*/

#ifndef __SSL_MEMORY_ROUTINES_H__
#define __SSL_MEMORY_ROUTINES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <vxWorks.h>

/* Use a netbufLib cluster pool to allocate small buffers.
 *
 * Memory will be allocated using the smallest available cluster large
 * enough to contain that memory, or the system heap if no appropriate
 * clusters are available.  This can greatly improve performance and
 * reduce memory fragmentation, at the cost of increased memory usage.
 * For optimal performance, and minimal memory usage for your
 * application, this feature requires tuning of the data clusters used
 * by the memory pool.  The following is recommended as a starting
 * point:
 *
 *    64 byte clusters - SSL_NUM_64    1500
 *   128 byte clusters - SSL_NUM_128   500
 *   256 byte clusters - SSL_NUM_256   100
 *   512 byte clusters - SSL_NUM_512   50
 *  1024 byte clusters - SSL_NUM_1024  25
 *  2048 byte clusters - SSL_NUM_2048  10
 *  4096 byte clusters - SSL_NUM_4096  5
 *  8192 byte clusters - SSL_NUM_8192  0
 * 16384 byte clusters - SSL_NUM_16384 0
 * 32768 byte clusters - SSL_NUM_32768 0
 * 65536 byte clusters - SSL_NUM_65536 0
 *
 * Use sslMemoryPoolShow() and #define SSL_MEMORY_STATISTICS to
 * observe remaining free clusters.  "max alloc att" indicates the
 * high water mark for allocations of a given cluster size.  i.e. The
 * maximum number of clusters of a given size that were in use at one
 * time.
 *
 * "Number of failed attempts to allocate a buffer from the memory
 * pool" indicates the number of times the SSL memory pool code
 * couldn't find a suitable cluster, and instead had to use the system
 * heap to satisfy the memory allocation.
 * 
 * If clusters larger than 4096 bytes are to be used, also increase
 * SSL_MEMORY_MAX_CLUSTER_SIZE accordingly.
 */
#ifdef _WRS_KERNEL
#define SSL_MEMORY_USE_MEMORY_POOL 
#else
#undef SSL_MEMORY_USE_MEMORY_POOL
#endif

#ifdef SSL_MEMORY_USE_MEMORY_POOL
#define SSL_NUM_64    1500
#define SSL_NUM_128   500
#define SSL_NUM_256   100 
#define SSL_NUM_512   50  
#define SSL_NUM_1024  25  
#define SSL_NUM_2048  10 
#define SSL_NUM_4096  5
#define SSL_NUM_8192  0
#define SSL_NUM_16384 0
#define SSL_NUM_32768 0
#define SSL_NUM_65536 0
#define SSL_MEMORY_MAX_CLUSTER_SIZE   4096
#endif

/* Enable SSL memory usage statistics - Observe results with
 * sslMemoryStats() */
#undef SSL_MEMORY_STATISTICS 

/* taskSuspend() on memory allocation in tNetTask context.  Controlled
 * at runtime by setting/clearing the global BOOL tNetTaskAllocationDebugging */
#undef SSL_MEMORY_NETTASK_ALLOC_DEBUGGING

/* taskSuspend() the calling task on memory allocation failure */
#undef SSL_MEMORY_SUSPEND_ON_FAILURE

/* Initialize all buffers to SSL_MEMORY_INITIALIZATION_FIELD after
 * allocation and prior to freeing. This is meant as a debugging aid,
 * it should normally be undefined for performance reasons. */
#undef SSL_MEMORY_INITIALIZE
#define SSL_MEMORY_INITIALIZATION_FIELD ((unsigned char)0xfd)

STATUS sslMemoryStats(void);
void* sslMemoryAllocate (UINT elemSize);
void* sslMemoryCalloc (UINT elemNum, UINT elemSize);
void sslMemoryFree (void* p_object);
void sslMemoryPoolShow (void);
void sslNetTaskAllocationDebuggingSet(BOOL enable);
BOOL sslNetTaskAllocationDebuggingGet(void);

/* SSL_MEMORY_ALLOCATED_MAGIC indicates that the buffer was
 * allocated using the SSLMemory allocation routines */
#define SSL_MEMORY_ALLOCATED_MAGIC 0xadfacade
typedef struct
    {
    UINT reserved;     /* Set to SSL_MEMORY_ALLOCATED_MAGIC */
    UINT bufferType;   /* May indicate type of buffer (use is optional) */
    UINT bufferLength; /* The allocated length of *buffer */
    } SSL_MEMORY_NODE;

/* buffer types */
#define SSL_MEMORY_MBLK_ALLOCATED 0x80000000

#ifdef __cplusplus
}
#endif

#endif /* __SSL_MEMORY_ROUTINES_H__ */
