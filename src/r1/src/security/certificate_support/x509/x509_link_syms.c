/* x509_link_syms.c - Link symbols for component inclusion */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,25feb05,cdw   generated
*/

#include <vxWorks.h>

extern int X509_LOOKUP_hash_dir ();
extern int X509_LOOKUP_file ();
extern int X509_ATTRIBUTE_count ();
extern int X509_CRL_cmp ();
extern int X509_STORE_load_locations ();
extern int X509_get_default_cert_area ();
extern int ERR_load_X509_strings ();
extern int X509_CRL_add1_ext_i2d ();
extern int X509_LOOKUP_by_alias ();
extern int X509_NAME_oneline ();
extern int X509_REQ_to_X509 ();
extern int X509_REQ_add1_attr ();
extern int X509_set_issuer_name ();
extern int X509_TRUST_add ();
extern int X509_verify_cert_error_string ();
extern int X509_EXTENSION_create_by_NID ();
extern int X509_STORE_CTX_cleanup ();
extern int X509_CRL_set_issuer_name ();
extern int X509_NAME_ENTRY_create_by_NID ();
extern int X509_REQ_set_pubkey ();
extern int NETSCAPE_SPKI_b64_decode ();
extern int X509_certificate_type ();
extern int NETSCAPE_SPKI_sign ();

FUNCPTR * x509_link_syms()
    {
    static FUNCPTR linksyms[] = 
        {
        (FUNCPTR) X509_LOOKUP_hash_dir,
        (FUNCPTR) X509_LOOKUP_file,
        (FUNCPTR) X509_ATTRIBUTE_count,
        (FUNCPTR) X509_CRL_cmp,
        (FUNCPTR) X509_STORE_load_locations,
        (FUNCPTR) X509_get_default_cert_area,
        (FUNCPTR) ERR_load_X509_strings,
        (FUNCPTR) X509_CRL_add1_ext_i2d,
        (FUNCPTR) X509_LOOKUP_by_alias,
        (FUNCPTR) X509_NAME_oneline,
        (FUNCPTR) X509_REQ_to_X509,
        (FUNCPTR) X509_REQ_add1_attr,
        (FUNCPTR) X509_set_issuer_name,
        (FUNCPTR) X509_TRUST_add,
        (FUNCPTR) X509_verify_cert_error_string,
        (FUNCPTR) X509_EXTENSION_create_by_NID,
        (FUNCPTR) X509_STORE_CTX_cleanup,
        (FUNCPTR) X509_CRL_set_issuer_name,
        (FUNCPTR) X509_NAME_ENTRY_create_by_NID,
        (FUNCPTR) X509_REQ_set_pubkey,
        (FUNCPTR) NETSCAPE_SPKI_b64_decode,
        (FUNCPTR) X509_certificate_type,
        (FUNCPTR) NETSCAPE_SPKI_sign,
        0
        };
    return (linksyms);
    }

