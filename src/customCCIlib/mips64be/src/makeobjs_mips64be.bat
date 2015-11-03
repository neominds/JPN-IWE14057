@echo off

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o md5.o md5.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o md5_dgst.o md5_dgst.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o md5_one.o md5_one.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o sha1.o sha1.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o sha1dgst.o sha1dgst.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o sha1_one.o sha1_one.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o sha.o sha.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o sha_dgst.o sha_dgst.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o sha_one.o sha_one.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o sha256.o sha256.c

ccmips -Ic:\WindRiver\vxworks-6.2\target\h\ -Ic:\WindRiver\vxworks-6.2\target\h\types -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -mrtp -EB -mips64 -mabi=o64 -O -G 0 -B/host//lib/gcc-lib/ -D_VSB_CONFIG_FILE=\"/target/lib/h/config/vsbConfig.h\" -DCPU=MIPS64 -msoft-float -mno-branch-likely -DTOOL_FAMILY=gnu -DTOOL=gnu -fno-builtin -fno-defer-pop -DNO_STRINGS_H -I/target/usr/h -I/target/h/wrn/coreip -DAES_ASM  -c -o sha512.o sha512.c

echo object files created

ls -l *.o

mkdir staging 
cd staging
mkdir orig merged
cd orig
copy ..\..\..\libs\libcci_mips64be_orig.a . 2>nul 1>&2
armips -x libcci_mips64be_orig.a 2>nul 1>&2
copy *.o ..\merged\ 2>nul 1>&2
copy ..\..\*.o ..\merged\ 2>nul 1>&2
cd ..\merged
armips -cr libcci_mips64be.a *.o 2>nul 1>&2
echo Library created. Copying..
copy libcci_mips64be.a ..\..\..\newlib\

rem cleanup
cd ..
echo y|del merged\* 2>nul 1>&2
echo y|del orig\* 2>nul 1>&2
rmdir merged orig
cd ..
echo y|del *.o
rmdir staging

echo Done.



