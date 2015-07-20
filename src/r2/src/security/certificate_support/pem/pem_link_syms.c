/* pem_link_syms.c - Link symbols for component inclusion */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,25feb05,cdw   generated
*/

#include <vxWorks.h>

extern int PEM_read_DHparams ();
extern int ERR_load_PEM_strings ();
extern int PEM_X509_INFO_read ();
extern int PEM_ASN1_read ();
extern int PEM_ASN1_read_bio ();
extern int PEM_read_PKCS8 ();
extern int PEM_read_PrivateKey ();
extern int PEM_SealFinal ();
extern int PEM_SignFinal ();
extern int PEM_read_X509 ();
extern int PEM_read_X509_AUX ();

FUNCPTR * pem_link_syms()
    {
    static FUNCPTR linksyms[] = 
        {
        (FUNCPTR) PEM_read_DHparams,
        (FUNCPTR) ERR_load_PEM_strings,
        (FUNCPTR) PEM_X509_INFO_read,
        (FUNCPTR) PEM_ASN1_read,
        (FUNCPTR) PEM_ASN1_read_bio,
        (FUNCPTR) PEM_read_PKCS8,
        (FUNCPTR) PEM_read_PrivateKey,
        (FUNCPTR) PEM_SealFinal,
        (FUNCPTR) PEM_SignFinal,
        (FUNCPTR) PEM_read_X509,
        (FUNCPTR) PEM_read_X509_AUX,
        0
        };
    return (linksyms);
    }

