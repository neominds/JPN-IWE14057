/* ssl_test_link_syms.c - Link symbols for component inclusion */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,25feb05,cdw   generated
*/

#include <vxWorks.h>

extern int bntest_main ();
extern int dhtest_main ();
extern int dsatest_main ();
extern int evp_test_main ();
extern int exptest_main ();
extern int hmactest_main ();
extern int cat ();
extern int randtest_main ();
extern int rsa_test_main ();
extern int doit ();

FUNCPTR * ssl_test_link_syms()
    {
    static FUNCPTR linksyms[] = 
        {
        (FUNCPTR) bntest_main,
        (FUNCPTR) dhtest_main,
        (FUNCPTR) dsatest_main,
        (FUNCPTR) evp_test_main,
        (FUNCPTR) exptest_main,
        (FUNCPTR) hmactest_main,
        (FUNCPTR) cat,
        (FUNCPTR) randtest_main,
        (FUNCPTR) rsa_test_main,
        (FUNCPTR) doit,
        0
        };
    return (linksyms);
    }

