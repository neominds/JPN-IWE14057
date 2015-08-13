/* strings.h - POSIX string library header file */

/* Copyright 2003-2004 Wind River Systems, Inc. */

/*
modification history
--------------------
01e,30aug05,mcm  Fix for SPR#110897 - strings.h should not include string.h
01d,16dec04,aeg  added various function prototypes (SPR #105335).
01c,26feb03,mcm  Including string.h
01b,06dec03,mcm  Fixed prototypes for bzero etc.
01a,04nov03,pad  created
*/

#ifndef __INCstringsh
#define __INCstringsh

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _SIZE_T
#define _SIZE_T
/*typedef int size_t;*/
#endif /* _SIZE_T */

extern int 	bcmp	    (char *, char *, int);
extern void	binvert     (char *, int);
extern void	bswap	    (char *, char *, int);
extern void	swab	    (char *, char *, int);
extern void	uswab	    (char *, char *, int);
extern void 	bzero	    (char *, int); 
extern void 	bcopy	    (const char *, char *, int);
extern void	bcopyBytes  (char *, char *, int);
extern void	bcopyWords  (char *, char *, int);
extern void	bcopyLongs  (char *, char *, int);
extern void 	bfill	    (char *, int, int);
extern void	bfillBytes  (char *, int, int);
extern char *	index       (const char *, int);
extern char *	rindex      (const char *, int);

#if FALSE /* XXX PAD - not supported yet */
extern int	ffs (int);
extern int	strcasecmp (const char *, const char *);
extern int	strncasecmp (const char *, const char *, size_t);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __INCstringah */
