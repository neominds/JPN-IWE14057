# Makefile - makefile for x509v3
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
        -DOPENSSL_NO_DESX \
	 $(DEBUG_FLAG) -I$(TGT_DIR)/h/openssl \
	-I. -I.. -I../.. -I$(TGT_DIR)/src/security/utilities/misc \
	-I$(TGT_DIR)/h/openssl/private 

SUBDIRS = 

OBJS = 	v3_bcons.o v3_bitst.o v3_conf.o v3_extku.o v3_ia5.o v3_lib.o \
	v3_prn.o v3_utl.o v3err.o v3_genn.o v3_alt.o v3_skey.o v3_akey.o v3_pku.o \
	v3_int.o v3_enum.o v3_sxnet.o v3_cpols.o v3_crld.o v3_purp.o v3_info.o \
	v3_ocsp.o v3_akeya.o v3_pmaps.o v3_pcons.o v3_ncons.o v3_pcia.o v3_pci.o \
pcy_cache.o pcy_node.o pcy_data.o pcy_map.o pcy_tree.o pcy_lib.o \
v3_asid.o v3_addr.o

OBJS+= x509v3_link_syms.o

#include $(TGT_DIR)/h/make/rules.library
include $(MAKE_INCLUDE_PATH)/make/rules.library

