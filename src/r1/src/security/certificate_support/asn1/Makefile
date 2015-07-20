# Makefile - makefile for asn1
#
# modification history
# --------------------
# 01b, 05nov04,tat     added -DOPENSSL_NO_CAST
# 01a, 18mar04,cdw     written
#
# DESCRIPTION
# This file contains the makefile rules for building OpenSSL in the
# Tornado framework 
#*/

TGT_DIR=$(WIND_BASE)/target
USR_BUILD=no


ifeq ($(SPACE),user)
    USR_BUILD=yes
endif

ifeq ($(SPACE),USER)
    USR_BUILD=yes
endif


ifeq ($(USR_BUILD),yes)
    TGT_DIR =$(WIND_USR)
    MAKE_INCLUDE_PATH=$(WIND_USR)
else     
    TGT_DIR =$(WIND_BASE)/target
    MAKE_INCLUDE_PATH=$(TGT_DIR)/h
endif 




BF_ENC =	bf_enc.o
BN_ASM =	bn_asm.o
CAST_ENC =	c_enc.o
COMPATOBJ =	ui_compat.o
DES_ENC =	des_enc.o fcrypt_b.o
MD5_ASM_OBJ =
RC4_ENC =	rc4_enc.o
RC5_ENC =	rc5_enc.o
RMD160_ASM_OBJ =
SHA1_ASM_OBJ =

BNTEST =	bntest
ECTEST =	ectest
EXPTEST =	exptest
IDEATEST =	ideatest
SHATEST =	shatest
SHA1TEST =	sha1test
MDC2TEST =	mdc2test
RMDTEST =	rmdtest
MD2TEST =	md2test
MD4TEST =	md4test
MD5TEST =	md5test
HMACTEST =	hmactest
RC2TEST =	rc2test
RC4TEST =	rc4test
RC5TEST =	rc5test
BFTEST =	bftest
CASTTEST =	casttest
DESTEST =	destest
RANDTEST =	randtest
DHTEST =	dhtest
DSATEST =	dsatest
METHTEST =	methtest
SSLTEST =	ssltest
RSATEST =	rsa_test
ENGINETEST =	enginetest
EVPTEST =	evp_test

LIB_BASE_NAME=seclibs

override EXTRA_DEFINE+=-DOPENSSLDIR="\"./\"" -DOPENSSL_SYSNAME_VXWORKS \
	-DOPENSSL_NO_KRB5 -DOPENSSL_NO_HW -DOPENSSL_NO_CAST -DOPENSSL_NO_CAST5\
	-DOPENSSL_NO_ASM -DOPENSSL_NO_MDC2 -DOPENSSL_NO_IDEA \
	-DOPENSSL_NO_ENGINE -DOPENSSL_NO_RC5 -DOPENSSL_NO_RC2 \
        -DOPENSSL_NO_BF -DOPENSSL_NO_SPEED -DNO_STRINGS_H \
        -DOPENSSL_NO_DESX -DOPENSSL_NO_EC \
	 $(DEBUG_FLAG) -I$(TGT_DIR)/h/openssl \
	-I. -I.. -I../.. -I$(TGT_DIR)/src/security/utilities/misc \
	-I$(TGT_DIR)/h/openssl/private 

SUBDIRS = 

OBJS = 	a_object.o a_bitstr.o a_utctm.o a_gentm.o a_time.o a_int.o a_octet.o \
	a_print.o a_type.o a_set.o a_dup.o a_d2i_fp.o a_i2d_fp.o \
	a_enum.o a_utf8.o a_sign.o a_digest.o a_verify.o a_mbstr.o a_strex.o \
	x_algor.o x_val.o x_pubkey.o x_sig.o x_req.o x_attrib.o x_bignum.o \
	x_long.o x_name.o x_x509.o x_x509a.o x_crl.o x_info.o x_spki.o nsseq.o \
	d2i_pu.o d2i_pr.o i2d_pu.o i2d_pr.o \
	t_req.o t_x509.o t_x509a.o t_crl.o t_pkey.o t_spki.o t_bitst.o \
	tasn_new.o tasn_fre.o tasn_enc.o tasn_dec.o tasn_utl.o tasn_typ.o \
	f_int.o f_string.o n_pkey.o \
	f_enum.o a_hdr.o x_pkey.o a_bool.o x_exten.o \
	asn1_gen.o asn1_par.o asn1_lib.o asn1_err.o a_meth.o a_bytes.o a_strnid.o \
	evp_asn1.o asn_pack.o p5_pbe.o p5_pbev2.o p8_pkey.o asn_moid.o

OBJS+= asn1_link_syms.o

#include $(TGT_DIR)/h/make/rules.library
include $(MAKE_INCLUDE_PATH)/make/rules.library

