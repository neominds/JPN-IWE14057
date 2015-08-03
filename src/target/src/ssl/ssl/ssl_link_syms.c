/* ssl_link_syms.c - Link symbols for component inclusion */

/* Copyright 2005 Wind River Systems, Inc. */

/*
modification history
--------------------
01a,25feb05,cdw   generated
*/

#include <vxWorks.h>

extern int BIO_f_ssl ();
extern int SSLv23_client_method ();
//extern int SSL23_version_str ();
extern int SSLv23_method ();
extern int ssl23_read_bytes ();
extern int SSLv23_server_method ();
extern int SSLv2_client_method ();
extern int ssl2_enc ();
extern int ssl2_callback_ctrl ();
extern int SSLv2_method ();
extern int ssl2_do_write ();
extern int SSLv2_server_method ();
extern int ssl3_do_write ();
extern int SSLv3_client_method ();
extern int ssl3_alert_code ();
extern int ssl3_callback_ctrl ();
extern int SSLv3_method ();
extern int ssl3_dispatch_alert ();
extern int SSLv3_server_method ();
extern int SSL_library_init ();
extern int d2i_SSL_SESSION ();
extern int SSL_CTX_add_client_CA ();
extern int SSL_CIPHER_description ();
extern int ERR_load_SSL_strings ();
extern int SSL_load_error_strings ();
extern int SSL_CTX_callback_ctrl ();
extern int SSL_CTX_use_PrivateKey ();
extern int SSL_CTX_add_session ();
extern int SSL_alert_desc_string ();
extern int SSL_SESSION_print ();
extern int TLSv1_client_method ();
extern int tls1_alert_code ();
extern int tls1_clear ();
extern int TLSv1_method ();
extern int TLSv1_server_method ();

FUNCPTR * ssl_link_syms()
    {
    static FUNCPTR linksyms[] = 
        {
        (FUNCPTR) BIO_f_ssl,
        (FUNCPTR) SSLv23_client_method,
//        (FUNCPTR) SSL23_version_str,
        (FUNCPTR) SSLv23_method,
        (FUNCPTR) ssl23_read_bytes,
        (FUNCPTR) SSLv23_server_method,
        (FUNCPTR) SSLv2_client_method,
        (FUNCPTR) ssl2_enc,
        (FUNCPTR) ssl2_callback_ctrl,
        (FUNCPTR) SSLv2_method,
        (FUNCPTR) ssl2_do_write,
        (FUNCPTR) SSLv2_server_method,
        (FUNCPTR) ssl3_do_write,
        (FUNCPTR) SSLv3_client_method,
        (FUNCPTR) ssl3_alert_code,
        (FUNCPTR) ssl3_callback_ctrl,
        (FUNCPTR) SSLv3_method,
        (FUNCPTR) ssl3_dispatch_alert,
        (FUNCPTR) SSLv3_server_method,
        (FUNCPTR) SSL_library_init,
        (FUNCPTR) d2i_SSL_SESSION,
        (FUNCPTR) SSL_CTX_add_client_CA,
        (FUNCPTR) SSL_CIPHER_description,
        (FUNCPTR) ERR_load_SSL_strings,
        (FUNCPTR) SSL_load_error_strings,
        (FUNCPTR) SSL_CTX_callback_ctrl,
        (FUNCPTR) SSL_CTX_use_PrivateKey,
        (FUNCPTR) SSL_CTX_add_session,
        (FUNCPTR) SSL_alert_desc_string,
        (FUNCPTR) SSL_SESSION_print,
        (FUNCPTR) TLSv1_client_method,
        (FUNCPTR) tls1_alert_code,
        (FUNCPTR) tls1_clear,
        (FUNCPTR) TLSv1_method,
        (FUNCPTR) TLSv1_server_method,
        0
        };
    return (linksyms);
    }

