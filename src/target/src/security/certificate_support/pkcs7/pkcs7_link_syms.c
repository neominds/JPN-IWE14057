/* pkcs7_link_syms.c - Link symbols for component inclusion */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,25feb05,cdw   generated
*/

#include <vxWorks.h>

extern int PKCS7_ATTR_SIGN_it ();
extern int PKCS7_add_attrib_smimecap ();
extern int PKCS7_add_attribute ();
extern int PKCS7_RECIP_INFO_set ();
extern int SMIME_crlf_copy ();
extern int PKCS7_decrypt ();
extern int ERR_load_PKCS7_strings ();

FUNCPTR * pkcs7_link_syms()
    {
    static FUNCPTR linksyms[] = 
        {
        (FUNCPTR) PKCS7_ATTR_SIGN_it,
        (FUNCPTR) PKCS7_add_attrib_smimecap,
        (FUNCPTR) PKCS7_add_attribute,
        (FUNCPTR) PKCS7_RECIP_INFO_set,
        (FUNCPTR) SMIME_crlf_copy,
        (FUNCPTR) PKCS7_decrypt,
        (FUNCPTR) ERR_load_PKCS7_strings,
        0
        };
    return (linksyms);
    }

