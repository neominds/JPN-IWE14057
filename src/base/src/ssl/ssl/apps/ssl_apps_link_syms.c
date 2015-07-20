/* ssl_apps_link_syms.c - Link symbols for component inclusion */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,25feb05,cdw   generated
*/

#include <vxWorks.h>

extern int app_RAND_allow_write_file ();
extern int VXW_strcasecmp ();
extern int asn1parse_main ();
extern int ca_main ();
extern int ciphers_main ();
extern int crl_main ();
extern int crl2pkcs7_main ();
extern int dgst_main ();
extern int dh_main ();
extern int dhparam_main ();
extern int dsa_main ();
extern int dsaparam_main ();
extern int enc_main ();
extern int errstr_main ();
extern int gendh_main ();
extern int gendsa_main ();
extern int genrsa_main ();
extern int nseq_main ();
extern int ocsp_main ();
extern int bio_err ();
extern int passwd_main ();
extern int alg_print ();
extern int pkcs7_main ();
extern int pkcs8_main ();
extern int prime_main ();
extern int rand_main ();
extern int req_main ();
extern int rsa_main ();
extern int rsautl_main ();
extern int apps_ssl_info_callback ();
extern int s_client_main ();
extern int s_crlf ();
extern int do_server ();
extern int s_time_main ();
extern int sess_id_main ();
extern int smime_main ();
extern int spkac_main ();
extern int verify_main ();
extern int version_main ();
extern int x509_main ();

FUNCPTR * ssl_apps_link_syms()
    {
    static FUNCPTR linksyms[] = 
        {
        (FUNCPTR) app_RAND_allow_write_file,
        (FUNCPTR) VXW_strcasecmp,
        (FUNCPTR) asn1parse_main,
        (FUNCPTR) ca_main,
        (FUNCPTR) ciphers_main,
        (FUNCPTR) crl_main,
        (FUNCPTR) crl2pkcs7_main,
        (FUNCPTR) dgst_main,
        (FUNCPTR) dh_main,
        (FUNCPTR) dhparam_main,
        (FUNCPTR) dsa_main,
        (FUNCPTR) dsaparam_main,
        (FUNCPTR) enc_main,
        (FUNCPTR) errstr_main,
        (FUNCPTR) gendh_main,
        (FUNCPTR) gendsa_main,
        (FUNCPTR) genrsa_main,
        (FUNCPTR) nseq_main,
        (FUNCPTR) ocsp_main,
        (FUNCPTR) bio_err,
        (FUNCPTR) passwd_main,
        (FUNCPTR) alg_print,
        (FUNCPTR) pkcs7_main,
        (FUNCPTR) pkcs8_main,
        (FUNCPTR) prime_main,
        (FUNCPTR) rand_main,
        (FUNCPTR) req_main,
        (FUNCPTR) rsa_main,
        (FUNCPTR) rsautl_main,
        (FUNCPTR) apps_ssl_info_callback,
        (FUNCPTR) s_client_main,
        (FUNCPTR) s_crlf,
        (FUNCPTR) do_server,
        (FUNCPTR) s_time_main,
        (FUNCPTR) sess_id_main,
        (FUNCPTR) smime_main,
        (FUNCPTR) spkac_main,
        (FUNCPTR) verify_main,
        (FUNCPTR) version_main,
        (FUNCPTR) x509_main,
        0
        };
    return (linksyms);
    }

