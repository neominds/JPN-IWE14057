/*  wrkk_sting.c */ 

#include <vxWorks.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errnoLib.h>

int strncasecmp
    (
    const char *s1,
    const char *s2,
    size_t n
    )
    {
    int c = 0;

    for (;
         n > 0 && (c = tolower((unsigned char)*s1) - tolower((unsigned char)*s2)) == 0 && *s1;
         ++s1, ++s2, --n);
    return (c);
    }

int strcasecmp(const char *str1, const char *str2)
	{
	while (*str1 && *str2)
		{
		int res = toupper(*str1) - toupper(*str2);
		if (res) return res < 0 ? -1 : 1;
		}
	if (*str1)
		return 1;
	if (*str2)
		return -1;
	return 0;
	}

/* getpctype  */

/* _Ctype code bits */
#define _XB		0x400 /* extra blank */
#define _XA		0x200 /* extra alphabetic */
#define _XS		0x100 /* extra space */
#define _BB		0x80 /* BEL, BS, etc. */
#define _CN		0x40 /* CR, FF, HT, NL, VT */
#define _DI		0x20 /* '0'-'9' */
#define _LO		0x10 /* 'a'-'z' */
#define _PU		0x08 /* punctuation */
#define _SP		0x04 /* space */
#define _UP		0x02 /* 'A'-'Z' */
#define _XD		0x01 /* '0'-'9', 'A'-'F', 'a'-'f' */



/* macros */
#define XBB (_BB | _CN)
#define XBL (XBB | _XB)
#define XDI (_DI | _XD)
#define XLO (_LO | _XD)
#define XUP (_UP | _XD)
		
/* static data */
static const short ctyp_tab[257] = {0, /* EOF */
		   0, _BB, _BB, _BB, _BB, _BB, _BB, _BB,
		 _BB, XBL, XBB, XBB, XBB, XBB, _BB, _BB,
		 _BB, _BB, _BB, _BB, _BB, _BB, _BB, _BB,
		 _BB, _BB, _BB, _BB, _BB, _BB, _BB, _BB,
		 _SP, _PU, _PU, _PU, _PU, _PU, _PU, _PU,
		 _PU, _PU, _PU, _PU, _PU, _PU, _PU, _PU,
		 XDI, XDI, XDI, XDI, XDI, XDI, XDI, XDI,
		 XDI, XDI, _PU, _PU, _PU, _PU, _PU, _PU,
		 _PU, XUP, XUP, XUP, XUP, XUP, XUP, _UP,
		 _UP, _UP, _UP, _UP, _UP, _UP, _UP, _UP,
		 _UP, _UP, _UP, _UP, _UP, _UP, _UP, _UP,
		 _UP, _UP, _UP, _PU, _PU, _PU, _PU, _PU,
		 _PU, XLO, XLO, XLO, XLO, XLO, XLO, _LO,
		 _LO, _LO, _LO, _LO, _LO, _LO, _LO, _LO,
		 _LO, _LO, _LO, _LO, _LO, _LO, _LO, _LO,
		 _LO, _LO, _LO, _PU, _PU, _PU, _PU, _BB,
 }; /* rest all match nothing */

const short *(_Getpctype)(void)
{ 
/*get table pointer */
 return (&ctyp_tab[1]);
}

/*
static 
gettimeofday(tp, zp)
    struct timeval *tp;
    struct timezone *zp;
{
    tp->tv_sec = time(0);
    tp->tv_usec = 0;
}
*/

