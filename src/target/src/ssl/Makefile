# Makefile - makefile for .
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


SUBDIRS = ssl openssl

include $(MAKE_INCLUDE_PATH)/make/rules.library

