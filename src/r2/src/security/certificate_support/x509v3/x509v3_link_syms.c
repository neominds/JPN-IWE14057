/* x509v3_link_syms.c - Link symbols for component inclusion */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,25feb05,cdw   generated
*/

#include <vxWorks.h>

extern int v3_akey_id ();
extern int AUTHORITY_KEYID_free ();
extern int GENERAL_NAME_print ();
extern int BASIC_CONSTRAINTS_free ();
extern int v3_key_usage ();
extern int X509V3_EXT_CRL_add_conf ();
extern int CERTIFICATEPOLICIES_free ();
extern int CRL_DIST_POINTS_free ();
extern int i2s_ASN1_ENUMERATED_TABLE ();
extern int EXTENDED_KEY_USAGE_free ();
extern int EDIPARTYNAME_free ();
extern int v3_ns_ia5_list ();
extern int ACCESS_DESCRIPTION_free ();
extern int v3_crl_num ();
extern int X509V3_EXT_add ();
extern int v3_crl_hold ();
extern int PKEY_USAGE_PERIOD_free ();
extern int X509V3_EXT_print ();
extern int X509_PURPOSE_add ();
extern int i2s_ASN1_OCTET_STRING ();
extern int SXNETID_free ();
extern int X509V3_add_value ();
extern int ERR_load_X509V3_strings ();

FUNCPTR * x509v3_link_syms()
    {
    static FUNCPTR linksyms[] = 
        {
        (FUNCPTR) v3_akey_id,
        (FUNCPTR) AUTHORITY_KEYID_free,
        (FUNCPTR) GENERAL_NAME_print,
        (FUNCPTR) BASIC_CONSTRAINTS_free,
        (FUNCPTR) v3_key_usage,
        (FUNCPTR) X509V3_EXT_CRL_add_conf,
        (FUNCPTR) CERTIFICATEPOLICIES_free,
        (FUNCPTR) CRL_DIST_POINTS_free,
        (FUNCPTR) i2s_ASN1_ENUMERATED_TABLE,
        (FUNCPTR) EXTENDED_KEY_USAGE_free,
        (FUNCPTR) EDIPARTYNAME_free,
        (FUNCPTR) v3_ns_ia5_list,
        (FUNCPTR) ACCESS_DESCRIPTION_free,
        (FUNCPTR) v3_crl_num,
        (FUNCPTR) X509V3_EXT_add,
        (FUNCPTR) v3_crl_hold,
        (FUNCPTR) PKEY_USAGE_PERIOD_free,
        (FUNCPTR) X509V3_EXT_print,
        (FUNCPTR) X509_PURPOSE_add,
        (FUNCPTR) i2s_ASN1_OCTET_STRING,
        (FUNCPTR) SXNETID_free,
        (FUNCPTR) X509V3_add_value,
        (FUNCPTR) ERR_load_X509V3_strings,
        0
        };
    return (linksyms);
    }

