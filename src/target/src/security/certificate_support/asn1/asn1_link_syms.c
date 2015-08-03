/* asn1_link_syms.c - Link symbols for component inclusion */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,25feb05,cdw   generated
*/

#include <vxWorks.h>

extern int ASN1_BIT_STRING_get_bit ();
extern int d2i_ASN1_BOOLEAN ();
extern int d2i_ASN1_bytes ();
extern int ASN1_d2i_bio ();
extern int ASN1_digest ();
extern int ASN1_dup ();
extern int ASN1_ENUMERATED_get ();
extern int ASN1_GENERALIZEDTIME_check ();
//extern int ASN1_HEADER_free ();
extern int ASN1_i2d_bio ();
extern int ASN1_INTEGER_cmp ();
extern int ASN1_mbstring_copy ();
//extern int ASN1_BIT_STRING_asn1_meth ();
extern int ASN1_OBJECT_create ();
extern int ASN1_OCTET_STRING_cmp ();
extern int ASN1_PRINTABLE_type ();
extern int d2i_ASN1_SET ();
extern int ASN1_item_sign ();
extern int ASN1_STRING_print_ex ();
extern int ASN1_STRING_TABLE_add ();
extern int ASN1_TIME_check ();
extern int ASN1_TYPE_get ();
extern int ASN1_UTCTIME_check ();
extern int UTF8_getc ();
extern int ASN1_item_verify ();
extern int ERR_load_ASN1_strings ();
extern int ASN1_STRING_cmp ();
extern int ASN1_parse ();
extern int ASN1_add_oid_module ();
extern int ASN1_item_pack ();
extern int d2i_AutoPrivateKey ();
extern int d2i_PublicKey ();
extern int ASN1_TYPE_get_int_octetstring ();
extern int a2i_ASN1_ENUMERATED ();
extern int a2i_ASN1_INTEGER ();
extern int a2i_ASN1_STRING ();
extern int i2d_PrivateKey ();
extern int i2d_PublicKey ();
extern int NETSCAPE_ENCRYPTED_PKEY_free ();
extern int NETSCAPE_CERT_SEQUENCE_free ();
extern int PBEPARAM_free ();
extern int PBE2PARAM_free ();
extern int PKCS8_PRIV_KEY_INFO_free ();
extern int ASN1_BIT_STRING_name_print ();
extern int X509_CRL_print ();
extern int DHparams_print ();
extern int X509_REQ_print ();
extern int NETSCAPE_SPKI_print ();
extern int ASN1_GENERALIZEDTIME_print ();
extern int X509_CERT_AUX_print ();
extern int ASN1_item_d2i ();
extern int ASN1_item_ex_i2d ();
extern int ASN1_item_ex_free ();
extern int ASN1_item_ex_new ();
extern int ASN1_ANY_it ();
extern int asn1_do_adb ();
extern int X509_ALGOR_dup ();
extern int X509_ATTRIBUTE_SET_it ();
extern int BIGNUM_it ();
extern int X509_CRL_INFO_free ();
extern int X509_EXTENSION_dup ();
extern int X509_INFO_free ();
extern int LONG_it ();
extern int X509_NAME_ENTRIES_it ();
extern int X509_PKEY_free ();
extern int X509_PUBKEY_free ();
extern int X509_REQ_INFO_free ();
extern int X509_SIG_free ();
extern int NETSCAPE_SPKAC_free ();
extern int X509_VAL_free ();
extern int X509_CINF_free ();
extern int X509_CERT_AUX_free ();

FUNCPTR * asn1_link_syms()
    {
    static FUNCPTR linksyms[] = 
        {
        (FUNCPTR) ASN1_BIT_STRING_get_bit,
        (FUNCPTR) d2i_ASN1_BOOLEAN,
        (FUNCPTR) d2i_ASN1_bytes,
        (FUNCPTR) ASN1_d2i_bio,
        (FUNCPTR) ASN1_digest,
        (FUNCPTR) ASN1_dup,
        (FUNCPTR) ASN1_ENUMERATED_get,
        (FUNCPTR) ASN1_GENERALIZEDTIME_check,
       // (FUNCPTR) ASN1_HEADER_free,
        (FUNCPTR) ASN1_i2d_bio,
        (FUNCPTR) ASN1_INTEGER_cmp,
        (FUNCPTR) ASN1_mbstring_copy,
        //(FUNCPTR) ASN1_BIT_STRING_asn1_meth,
        (FUNCPTR) ASN1_OBJECT_create,
        (FUNCPTR) ASN1_OCTET_STRING_cmp,
        (FUNCPTR) ASN1_PRINTABLE_type,
        (FUNCPTR) d2i_ASN1_SET,
        (FUNCPTR) ASN1_item_sign,
        (FUNCPTR) ASN1_STRING_print_ex,
        (FUNCPTR) ASN1_STRING_TABLE_add,
        (FUNCPTR) ASN1_TIME_check,
        (FUNCPTR) ASN1_TYPE_get,
        (FUNCPTR) ASN1_UTCTIME_check,
        (FUNCPTR) UTF8_getc,
        (FUNCPTR) ASN1_item_verify,
        (FUNCPTR) ERR_load_ASN1_strings,
        (FUNCPTR) ASN1_STRING_cmp,
        (FUNCPTR) ASN1_parse,
        (FUNCPTR) ASN1_add_oid_module,
        (FUNCPTR) ASN1_item_pack,
        (FUNCPTR) d2i_AutoPrivateKey,
        (FUNCPTR) d2i_PublicKey,
        (FUNCPTR) ASN1_TYPE_get_int_octetstring,
        (FUNCPTR) a2i_ASN1_ENUMERATED,
        (FUNCPTR) a2i_ASN1_INTEGER,
        (FUNCPTR) a2i_ASN1_STRING,
        (FUNCPTR) i2d_PrivateKey,
        (FUNCPTR) i2d_PublicKey,
        (FUNCPTR) NETSCAPE_ENCRYPTED_PKEY_free,
        (FUNCPTR) NETSCAPE_CERT_SEQUENCE_free,
        (FUNCPTR) PBEPARAM_free,
        (FUNCPTR) PBE2PARAM_free,
        (FUNCPTR) PKCS8_PRIV_KEY_INFO_free,
        (FUNCPTR) ASN1_BIT_STRING_name_print,
        (FUNCPTR) X509_CRL_print,
        (FUNCPTR) DHparams_print,
        (FUNCPTR) X509_REQ_print,
        (FUNCPTR) NETSCAPE_SPKI_print,
        (FUNCPTR) ASN1_GENERALIZEDTIME_print,
        (FUNCPTR) X509_CERT_AUX_print,
        (FUNCPTR) ASN1_item_d2i,
        (FUNCPTR) ASN1_item_ex_i2d,
        (FUNCPTR) ASN1_item_ex_free,
        (FUNCPTR) ASN1_item_ex_new,
        (FUNCPTR) ASN1_ANY_it,
        (FUNCPTR) asn1_do_adb,
        (FUNCPTR) X509_ALGOR_dup,
        (FUNCPTR) X509_ATTRIBUTE_SET_it,
        (FUNCPTR) BIGNUM_it,
        (FUNCPTR) X509_CRL_INFO_free,
        (FUNCPTR) X509_EXTENSION_dup,
        (FUNCPTR) X509_INFO_free,
        (FUNCPTR) LONG_it,
        (FUNCPTR) X509_NAME_ENTRIES_it,
        (FUNCPTR) X509_PKEY_free,
        (FUNCPTR) X509_PUBKEY_free,
        (FUNCPTR) X509_REQ_INFO_free,
        (FUNCPTR) X509_SIG_free,
        (FUNCPTR) NETSCAPE_SPKAC_free,
        (FUNCPTR) X509_VAL_free,
        (FUNCPTR) X509_CINF_free,
        (FUNCPTR) X509_CERT_AUX_free,
        0
        };
    return (linksyms);
    }

