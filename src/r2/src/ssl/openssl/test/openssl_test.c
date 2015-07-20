/* openssl_test.c - SSL Test code          
 * Copyright 2004 Wind River Systems, Inc.             
 * 
 *
 *
 * This file implements a subset of the tests run on a Unix host when you run make install.
 * The system tests require the files in openssl_test_files.zip to be present in the root directory 
 * 
 * When running the crypto tests, openssl reports memory leaks, this is because proper cleanup is
 * not done by the tasks spawned because they are normally standalone programs.
 *
 * 
 */

#include <stdio.h>
#include <taskLib.h>
#include <sysLib.h>
#include <string.h>
#include <ioLib.h>
#include <timers.h>
#include <time.h>

#ifdef _WRS_KERNEL
#include <envLib.h>
#else
#include <stdlib.h>
#endif


#define TEST_PRIORITY 100
#define TEST_STACKSIZE 100*1024
#define sleep(a) taskDelay((a) * sysClkRateGet())

extern int bntest_main(int argc, char *argv[]);
BOOL handleBntest(void);


extern int dsatest_main(int argc, char *argv[]);
BOOL handleDsatest(void);

extern int dhtest_main(int argc, char *argv[]);
BOOL handleDhtest(void);

extern int dummytest_main(int argc, char *argv[]);

extern int evp_test_main(int argc, char *argv[]);
BOOL handleEvptest(void);

extern int exptest_main(int argc, char *argv[]);
BOOL handleExptest(void);

extern int hmactest_main(int argc, char *argv[]);
BOOL handleHmactest(void);

extern int ideatest_main(int argc, char *argv[]);

extern int methtest_main(int argc, char *argv[]);
extern int randtest_main(int argc, char *argv[]);

extern int rsa_test_main(int argc, char *argv[]);
BOOL handleRsatest(void);

extern int openssl_main(int argc, char *argv[]);
extern int ssltest_main(int argc, char *argv[]);

void opensslWrapper(const char *args, int inFd, int outFd);

BOOL handleAll(void);
BOOL handleRandtest(void);
BOOL handleTx509(void);
BOOL handleTverify(void);
BOOL handleTestSs(void);
BOOL handleTestSsl(void);
BOOL handleSystemTest(void);
BOOL handleMakeCerts(void);

BOOL handleExit(void);
BOOL handleHelp(void);

BOOL fCompare(const char *f1, const char *f2);
void tx509(const char *cert);
struct cmds{
    const char *cmdStr;
    FUNCPTR cmdFunc;
};
typedef struct cmds CMDS;

CMDS testCmds[] = 
{{ "all", handleAll},
 { "bntest",handleBntest},
 { "dhtest",handleDhtest},
 { "dsatest",handleDsatest},
 { "evptest",handleEvptest},
 { "exptest",handleExptest},
 { "hmactest",handleHmactest},
 { "randtest",handleRandtest},
 { "rsatest",handleRsatest},
 { "tx509",handleTx509},
 { "tverify",handleTverify},
 { "makecerts",handleMakeCerts},
 { "testss",handleTestSs},
 { "testssl",handleTestSsl},
 { "systemtest",handleSystemTest},
 { "exit",handleExit},
 { "?",handleHelp},
 { NULL,NULL}};

void waitForTaskToEnd(int taskId, int interval)
    {
    while(taskIdVerify(taskId) == OK)
        {
        sleep(interval);
        }
    }
void deleteCerts()
    {
    printf("deleting temporary files...\n");
    remove("keyCA.ss");
    remove("reqCA.ss");
    remove("certCA.ss");
    remove("req2CA.ss");
    remove("keyU.ss");
    remove("reqU.ss");
    remove("certCA.srl");
    remove("certU.ss");
    remove("pca-key.pem");
    remove("pca-req.pem");
    remove("pca-cert.pem");
    remove("ca-key.pem");
    remove("ca-req.pem");
    remove("pca-cert.srl");
    remove("ca-cert.pem");
    remove("s512-key.pem");
    remove("s512-req.pem");
    remove("server.pem");
    remove("s1024key.pem");
    remove("s1024req.pem");
    remove("makeCerts_temp");
    remove("c512-key.pem");
    remove("c512-req.pem");
    remove("ca-cert.srl");
    remove("server2.pem");
    remove("client.pem");
}

void opensslSetTime(void)
    {
    struct tm  timeStruct;
    struct timespec currTimeSpec;
    int status;
    if( 1000 > time(NULL))    /* if clock is not set, set it */
        {
        timeStruct.tm_hour =0;
        timeStruct.tm_min = 0;
        timeStruct.tm_sec =0;
        timeStruct.tm_mday =21;
        timeStruct.tm_mon = 7;
        timeStruct.tm_year = 104;

        currTimeSpec.tv_sec = mktime(&timeStruct);
        currTimeSpec.tv_nsec =0;
        printf("Setting time to %s \n",asctime(&timeStruct));
        status = clock_settime(CLOCK_REALTIME,&currTimeSpec);
        }
    }

void openssl_test(void)
    {
    char cmdBuff[256];
    BOOL quit=FALSE;
    CMDS *cmdIter;
    int oldPriority;

    opensslSetTime();
    taskPriorityGet(0, &oldPriority);
    taskPrioritySet(0, TEST_PRIORITY + 1);

/*     putenv("OPENSSL_DEBUG_MEMORY=off"); */

    while(1){
    printf("\nopenssl_test>");

    
    while(!gets(cmdBuff))
        {
        sleep(1);
        }
    cmdIter= &testCmds[0];
    while(cmdIter->cmdStr)
        {
        if(strcmp(cmdBuff,cmdIter->cmdStr) == 0)
            {
            quit = cmdIter->cmdFunc();
            if(quit)
                {
                taskPrioritySet(0, oldPriority);
                return;
                }
            break;
            }
        cmdIter++;
        }
    if(cmdIter->cmdStr == NULL){
    printf("\nUnknown Command");
    }
    }
    taskPrioritySet(0, oldPriority);
    }
BOOL handleAll(void)
    {
    printf("Executing all crypto tests\n");
    handleBntest();
    handleDhtest();
    handleDsatest();
    handleEvptest();
    handleExptest();
    handleHmactest();
    handleRandtest();
    handleRsatest();
    handleSystemTest();
    printf("Finished Tests");
    return FALSE; 
    }

BOOL handleBntest(void)
    {
    int taskId;
    char *args[5];

    args[0] = "bntest";
    args[1] = "-out";
    args[2] = "test_output_bn.txt";
    args[3] = "-results";
    args[4] = NULL;

    printf("bntest_main\n");
    taskId = taskSpawn ("bntest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)bntest_main, 4, (int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    return FALSE;
    }
BOOL handleDhtest(void)
    {
    int taskId;
    printf("dhtest_main\n");
    taskId = taskSpawn ("dhtest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)dhtest_main, 0,0,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    return FALSE;
    }
BOOL handleDsatest(void)
    {
    int taskId;
    printf("dsatest_main\n");
    taskId = taskSpawn ("dsatest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)dsatest_main, 0,0,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    return FALSE;
    }
BOOL handleEvptest(void)
    {
    int taskId;
    char *args[3];
    args[0] = "evp_test";
    args[1] = "evptests.txt";
    args[2] = NULL;

    taskId = taskSpawn ("evp_test", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)evp_test_main, 2,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    return FALSE;
    }
BOOL handleExptest(void)
    {
    int taskId;
    printf("exptest_main\n");
    taskId = taskSpawn ("exp_test", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)exptest_main, 0,0,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    return FALSE;
    }
BOOL handleHmactest(void)
    {
    int taskId;
    printf("hmactest_main\n");
    taskId = taskSpawn ("hmactest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)hmactest_main, 0,0,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    return FALSE;
    }
BOOL handleRandtest(void)
    {
    int taskId;
    printf("randtest_main\n");
    taskId = taskSpawn ("rand_test", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)randtest_main, 0,0,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    return FALSE;
    }
BOOL handleRsatest(void)
    {
    int taskId;
    printf("rsa_main\n");
    taskId = taskSpawn ("rsa_test", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)rsa_test_main, 0,0,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    return FALSE;
    }
           
BOOL handleExit(void)
    {
    deleteCerts();
    printf("exiting\n");
    return TRUE;
    }
BOOL handleHelp(void)
    {
    CMDS *cmdIter=&testCmds[0];
    printf("Supported commands:\n");
    while(cmdIter->cmdStr){
    printf("%s\n",cmdIter->cmdStr);
    cmdIter++;
    }
    return FALSE;
    }
BOOL handleTx509(void)
    {
    /* implements tx509.com */
    printf("Testing Normal x509v1 Certificate\n");
    tx509("testx509.pem"); 
    printf("Testing First x509v3 Certificate\n");
    tx509("v3-cert1.pem");
    printf("Testing Second x509v3 Certificate\n");
    tx509("v3-cert2.pem");    
    return FALSE;
    }    
void tx509(const char *cert)
    {
    int taskId;
    BOOL result=FALSE;
    char *args[11];
    args[0] = "openssl";
    args[1] = "x509";

    
#define TX509_CLEANUP                                                   \
    remove("f.d"); remove("f.n");                                       \
    remove("f.p"); remove("ff.d1");  remove("ff.d2");                   \
    remove("ff.d3"); remove("ff.n1"); remove("ff.n2");                  \
    remove("ff.n3"); remove("ff.p1"); remove("ff.p2"); remove("ff.p3"); \
    sleep(1); /* wait one second for the filesystem to "catch up" */

    TX509_CLEANUP;

    printf("Testing X509 Certificate Conversions\n");

    sleep(1);
    printf("p -> d\n");

    args[2] = "-in";
    args[3] = (char *) cert;
    args[4] = "-inform";
    args[5] = "p";
    args[6] = "-outform";
    args[7] = "d";
    args[8] = "-out";
    args[9] = "f.d";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("p -> n\n");

    args[2] = "-in";
    args[3] = (char *) cert;
    args[4] = "-inform";
    args[5] = "p";
    args[6] = "-outform";
    args[7] = "n";
    args[8] = "-out";
    args[9] = "f.n";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
        
    sleep(1);
    printf("p -> p\n");

    args[2] = "-in";
    args[3] = (char *) cert;
    args[4] = "-inform";
    args[5] = "p";
    args[6] = "-outform";
    args[7] = "p";
    args[8] = "-out";
    args[9] = "f.p";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("d -> d\n");

    args[2] = "-in";
    args[3] = "f.d";
    args[4] = "-inform";
    args[5] = "d";
    args[6] = "-outform";
    args[7] = "d";
    args[8] = "-out";
    args[9] = "ff.d1";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("n -> d\n");

    args[2] = "-in";
    args[3] = "f.n";
    args[4] = "-inform";
    args[5] = "n";
    args[6] = "-outform";
    args[7] = "d";
    args[8] = "-out";
    args[9] = "ff.d2";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("p -> d\n");

    args[2] = "-in";
    args[3] = "f.p";
    args[4] = "-inform";
    args[5] = "p";
    args[6] = "-outform";
    args[7] = "d";
    args[8] = "-out";
    args[9] = "ff.d3";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("d -> n\n");

    args[2] = "-in";
    args[3] = "f.d";
    args[4] = "-inform";
    args[5] = "d";
    args[6] = "-outform";
    args[7] = "n";
    args[8] = "-out";
    args[9] = "ff.n1";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("n -> n\n");

    args[2] = "-in";
    args[3] = "f.n";
    args[4] = "-inform";
    args[5] = "n";
    args[6] = "-outform";
    args[7] = "n";
    args[8] = "-out";
    args[9] = "ff.n2";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("p -> n\n");

    args[2] = "-in";
    args[3] = "f.p";
    args[4] = "-inform";
    args[5] = "p";
    args[6] = "-outform";
    args[7] = "n";
    args[8] = "-out";
    args[9] = "ff.n3";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("d -> p\n");

    args[2] = "-in";
    args[3] = "f.d";
    args[4] = "-inform";
    args[5] = "d";
    args[6] = "-outform";
    args[7] = "p";
    args[8] = "-out";
    args[9] = "ff.p1";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("n -> p\n");

    args[2] = "-in";
    args[3] = "f.n";
    args[4] = "-inform";
    args[5] = "n";
    args[6] = "-outform";
    args[7] = "p";
    args[8] = "-out";
    args[9] = "ff.p2";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    sleep(1);
    printf("p -> p\n");

    args[2] = "-in";
    args[3] = "f.p";
    args[4] = "-inform";
    args[5] = "p";
    args[6] = "-outform";
    args[7] = "p";
    args[8] = "-out";
    args[9] = "ff.p3";
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);


    sleep(1);
    printf("Checking Results...\n");
    result = TRUE;
    result &= fCompare(cert,"f.p");
    result &= fCompare(cert,"ff.p1");
    result &= fCompare(cert,"ff.p2");
    result &= fCompare(cert,"ff.p3");

    result &= fCompare("f.n","ff.n1");
    result &= fCompare("f.n","ff.n2");
    result &= fCompare("f.n","ff.n3");

    result &= fCompare("f.p","ff.p1");
    result &= fCompare("f.p","ff.p2");
    result &= fCompare("f.p","ff.p3");
    if(result != TRUE)
        {
        printf("Certificate Conversions Failed\n");
        }
    else
        {
        printf("Certificate Conversions Passed\n");
        }
    TX509_CLEANUP;
    }


static FILE * file_open(const char *filename, const char *mode)
    {
    FILE *fPtr = NULL;
    int count = 0;

    while ((fPtr == NULL) && (count < 10))
        {
        fPtr = fopen(filename, mode);
        count++;
        if ((fPtr == NULL) && (count < 10))
            {
            /* Wait and try again */
            sleep((count + 1) / 2);
            }
        else
            {
            break;
            }
        }
    return (fPtr);
    }


void cat(char *source, char *dest)
    {
    FILE *fSrc, *fDest;
    int ch;

    fSrc =  file_open(source,"r");
    fDest = file_open(dest,"a");

    fseek(fDest,0,SEEK_END);

    if(!fSrc || !fDest)
        {
        if (fSrc)
            fclose (fSrc);
        if (fDest)
            fclose (fDest);
        
        return;
        }
 
    ch =fgetc(fSrc);
    while(EOF != ch)
        {

        fputc(ch, fDest);
        ch = fgetc(fSrc);
        }
    fclose(fSrc);
    fclose(fDest);
    }


BOOL fCompare(const char *f1, const char *f2)
    {
    FILE *fPtr1, *fPtr2;
    int ch1, ch2;

    fPtr1 = file_open(f1,"r");
    if(fPtr1 == NULL)
        {
        printf("Error:  Could not open %s\n",f1);
        return FALSE;
        }
    fPtr2 = file_open(f2,"r");
    if(fPtr2 == NULL)
        {
        printf("Error:  Could not open %s\n",f2);
        fclose(fPtr1);
        sleep(1);
        return FALSE;
        }
    ch1 = ch2 = 0;

    while(ch1 != EOF)
        {
        ch1 = fgetc(fPtr1);
        ch2 = fgetc(fPtr2);
        if(ch1 != ch2)
            {
            fclose(fPtr1);
            fclose(fPtr2);
            sleep(1);
            return FALSE;
            }
        }
    fclose(fPtr1);
    fclose(fPtr2);
    sleep(1);
    return TRUE;
    }
BOOL handleTverify(void)
    {
    char *args[27]= {"openssl","verify","-CAfile","certs.tmp","ca-cert.pem","dsa-ca.pem","dsa-pca.pem","factory.pem",
                     "ICE-CA.pem","ICE-root.pem","ICE-user.pem","nortelCA.pem",
                     "pca-cert.pem","RegTP-4R.pem","RegTP-5R.pem","RegTP-6R.pem","rsa-cca.pem","thawteCb.pem",
                     "thawteCp.pem","timCA.pem","tjhCA.pem","vsign1.pem","vsign2.pem","vsign3.pem","vsignss.pem",
                     "vsigntca.pem", NULL};       
    int taskId;


    printf("\nVerifying Certificates.  There should be some OK's and some failure\n");
    printf("There are definitely a few expired certificates\n");
    
    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 26,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    printf("Finished Verify\n");
    return FALSE;
    }
BOOL handleTestSs(void)
    {
    int taskId;
    char *CAkey = "keyCA.ss";
    char *CAcert = "certCA.ss";
    char *CAreq = "reqCA.ss";
    char *CAconf = "CAss.cnf";
    char *CAreq2 = "req2CA.ss";
    
    char *Uconf = "Uss.cnf";
    char *Ukey = "keyU.ss";
    char *Ureq = "reqU.ss";
    char *Ucert = "certU.ss";
    char *req_new = "-new";

    char *args[20];

    printf("Running TestSS\n");
    printf("Making a certificate request using 'req'\n");

    args[0] = "openssl" ;
    args[1] = "req";
    args[2] = "-config";
    args[3] = CAconf;
    args[4] = "-out";
    args[5] = CAreq;
    args[6] = "-keyout";
    args[7] = CAkey;
    args[8] = req_new;  /* TestSS.com has a test to see if we should use RSA or DSA, going to use RSA for now */
    args[9] = NULL; 

#ifdef _WRS_KERNEL
    putenv("RANDFILE=rnd");    
#else
    setenv("RANDFILE","rnd",1);
#endif
    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 9,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("Convert the certificate request into a self signed certificate\n");
    args[0] = "openssl" ;
    args[1] = "x509";
    args[2] = "-md5";
    args[3] = "-CAcreateserial";
    args[4] = "-in";
    args[5] = CAreq;
    args[6] = "-days";
    args[7] = "30";
    args[8] = "-req"; 
    args[9] = "-out"; 
    args[10] = CAcert;
    args[11] = "-signkey";
    args[12] = CAkey;
    args[13] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 13,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);


    printf("convert a certificate into a certificate request using x509\n");

    args[0] = "openssl" ;
    args[1] = "x509";
    args[2] = "-md5";
    args[3] = "-in";
    args[4] = CAcert;
    args[5] = "-x509toreq";
    args[6] = "-signkey";
    args[7] = CAkey;
    args[8] = "-out"; 
    args[9] = CAreq2;
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("results...\n");

    args[0] = "openssl";
    args[1] = "req";
    args[2] = "-config";
    args[3] = "openssl-vms.cnf";
    args[4] = "-verify";
    args[5] = "-in";
    args[6] = CAreq;
    args[7] = "-noout";
    args[8] = NULL; 

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 8,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    args[0] = "openssl";
    args[1] = "req";
    args[2] = "-config";
    args[3] = "openssl-vms.cnf";
    args[4] = "-verify";
    args[5] = "-in";
    args[6] = CAreq2;
    args[7] = "-noout";
    args[8] = NULL; 

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 8,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    args[0] = "openssl";
    args[1] = "verify";
    args[2] = "-CAfile";
    args[3] = CAcert;
    args[4] = CAcert;
    args[5] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 5,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("Make another certificate request using 'req'\n");

    args[0] = "openssl";
    args[1] = "req";
    args[2] = "-config";
    args[3] = Uconf;
    args[4] = "-out";
    args[5] = Ureq;
    args[6] = "-keyout";
    args[7] = Ukey;
    args[8] = req_new;
    args[9] = NULL; 

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 9,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("sign certificate request with the just created CA via x509\n");

    args[0] = "openssl" ;
    args[1] = "x509";
    args[2] = "-md5";
    args[3] = "-CAcreateserial";
    args[4] = "-in";
    args[5] = Ureq;
    args[6] = "-days";
    args[7] = "30";
    args[8] = "-req"; 
    args[9] = "-out";
    args[10] = Ucert;
    args[11] = "-CA";
    args[12] = CAcert;
    args[13] = "-CAkey";
    args[14] = CAkey;
    args[15] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 15,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);


    args[0] = "openssl";
    args[1] = "verify";
    args[2] = "-CAfile";
    args[3] = CAcert;
    args[4] = Ucert;
    args[5] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 5,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);


    printf("Certificate Details\n");

    args[0] = "openssl" ;
    args[1] = "x509";
    args[2] = "-md5";
    args[3] = "-subject";
    args[4] = "-issuer";
    args[5] = "-startdate";
    args[6] = "-enddate";
    args[7] = "-noout";
    args[8] = "-in"; 
    args[9] = Ucert;
    args[10] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    
    printf("The generated CA certificate is %s\n", CAcert);
    printf("The generated CA private key is %s\n",CAkey);
    printf("The generated user certificate is %s\n",Ucert);
    printf("The generated user private key is %s\n",Ukey);

    printf("End testss results\n");
    return FALSE;
    }
BOOL handleTestSsl(void)
    {
    int taskId;
    char *args[20];
    char *key="keyU.ss";
    char *cert="certU.ss";
    char *CA="certCA.ss";
/*     char *textout="testssl-x509-out.txt"; */
/*     FILE *fptr=NULL; */
/*     char *filebuff; */
/*     int fsize; */
/*     char *temp;   */
    BOOL dsa_cert;
                
    printf("Test SSL Protocol\n");

#if 0
    args[0] = "openssl";
    args[1] = "x509";
    args[2] = "-in";
    args[3] = cert;
    args[4] = "-text";
    args[5] = "-out";
    args[6] = textout;
    args[7] = NULL;

    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, 7,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    /* Determine if the cert is DSA */

    fptr=file_open(textout,"r");

    if(!fptr)
        {
        printf("Could not open %s\n",textout);
        return FALSE;
        }
    fsize=0;
    while(fgetc(fptr)!=EOF)
        {
        fsize++;
        }
    /* at this point fsize is the number of chars in the file */
    filebuff = malloc(sizeof(char) * (fsize+1));
    if(!filebuff)
        {
        printf("malloc failed\n");
        fclose (fptr);
        return FALSE;
        }    
    rewind(fptr);
    fread(filebuff,sizeof(char),fsize,fptr);
    printf("file:\n%s",filebuff);

    temp =strstr(filebuff,"DSA Public Key");

    if(temp)
        {
        printf("DSA KEY\n");
        dsa_cert = TRUE;
        }
    else
        {
        printf("Non DSA KEY\n");
        dsa_cert =FALSE;
        }
    fclose(fptr);
    remove(textout); 
#else
    dsa_cert = FALSE;
#endif
    /****************************************************************/
    printf("test sslv2\n");
    args[0] = "ssltest";
    args[1] = "-key";
    args[2] = key;
    args[3] = "-cert";
    args[4] = cert;
    args[5] = "-c_key";
    args[6] = key;
    args[7] = "-c_cert";
    args[8] = cert;
    args[9] = "-ssl2";
    args[10] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    
    printf("test sslv2 with server authentication\n");
    args[10] = "-server_auth";
    args[11] = "-CAfile";
    args[12] = CA;
    args[13] = NULL;
    
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 13,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2 with client auth\n");
    args[10] = "-client_auth";
    args[11] = "-CAfile";
    args[12] = CA;
    args[13] = NULL;
    
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 13,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2 with both client and server authentication\n");
    args[10] = "-server_auth";
    args[11] = "-client_auth";
    args[12] = "-CAfile";
    args[13] = CA;
    args[14] = NULL;
    
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 14,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv3\n");

    args[0] = "ssltest";
    args[1] = "-key";
    args[2] = key;
    args[3] = "-cert";
    args[4] = cert;
    args[5] = "-c_key";
    args[6] = key;
    args[7] = "-c_cert";
    args[8] = cert;
    args[9] = "-ssl3";
    args[10] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 10,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv3 with server authentication\n");
    args[10] = "-server_auth";
    args[11] = "-CAfile";
    args[12] = CA;
    args[13] = NULL;
     
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 13,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv3 with client auth\n");
    args[10] = "-client_auth";
    args[11] = "-CAfile";
    args[12] = CA;
    args[13] = NULL;
     
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 13,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv3 with both client and server authentication\n");
    args[10] = "-server_auth";
    args[11] = "-client_auth";
    args[12] = "-CAfile";
    args[13] = CA;
    args[14] = NULL;
    
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 14,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

#if 1

    printf("test sslv2/sslv3\n");

    args[0] = "ssltest";
    args[1] = "-key";
    args[2] = key;
    args[3] = "-cert";
    args[4] = cert;
    args[5] = "-c_key";
    args[6] = key;
    args[7] = "-c_cert";
    args[8] = cert;
    args[9] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 9,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2/sslv3 with server authentication\n");
    args[9] = "-server_auth";
    args[10] = "-CAfile";
    args[11] = CA;
    args[12] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 12,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2/sslv3 with client authentication\n");
    args[9] = "-client_auth";
    args[10] = "-CAfile";
    args[11] = CA;
    args[12] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 12,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2/sslv3 with both server and client authentication\n");
    args[9] = "-server_auth";
    args[10] = "-client_auth";
    args[11] = "-CAfile";
    args[12] = CA;
    args[13] = NULL;
         
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 13,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2 via BIO pair\n");
    args[9] = "-bio_pair";
    args[10] = "-ssl2";
    args[11] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 11,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2 with server authentication via BIO pair\n");
    args[11] = "-server_auth";
    args[12] = "-CAfile";
    args[13] = CA;
    args[14]  = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 14,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    if(!dsa_cert)
        {
        printf("test sslv2 with client authentication via BIO pair\n");
        args[11] = "-server_auth";
        args[12] = "-CAfile";
        args[13] = CA;
        args[14]  = NULL;
        taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 14,(int) args,0,0,0,0,0,0,0,0);
        waitForTaskToEnd(taskId,1);

    
        printf("test sslv2 with both server and client authentication via BIO pair\n");
        args[11] = "-server_auth";
        args[12] = "-client_auth";
        args[13] = "-CAfile";
        args[14] = CA;
        args[15]  = NULL;
        taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 15,(int) args,0,0,0,0,0,0,0,0);
        waitForTaskToEnd(taskId,1);
        }

    printf("test sslv3 via BIO pair\n");

    args[0] = "ssltest";
    args[1] = "-key";
    args[2] = key;
    args[3] = "-cert";
    args[4] = cert;
    args[5] = "-c_key";
    args[6] = key;
    args[7] = "-c_cert";
    args[8] = cert;
    args[9] = "-bio_pair";
    args[10] = "-ssl3";
    args[11] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 11,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv3 with server authentication via BIO pair\n");

    args[11] = "-server_auth";
    args[12] = "-CAfile";
    args[13] = CA;
    args[14] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 14,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv3 with client authentication via BIO pair\n");

    args[11] = "-client_auth";
    args[12] = "-CAfile";
    args[13] = CA;
    args[14] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 14,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv3 with both server and client authentication via BIO pair\n");

    args[11] = "-server_auth";
    args[12] = "-client_auth";
    args[13] = "-CAfile";
    args[14] = CA;
    args[15] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 15,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("tests sslv2/sslv3 via BIO pair\n");

    args[9] = NULL;
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 9,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

#endif
    printf("test sslv2/sslv3 w/o DHE via BIO pair\n");

    if(!dsa_cert)
        {
        args[9] = "-bio_pair";
        args[10] = "-no_dhe";
        args[11] = NULL;

        taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 11,(int) args,0,0,0,0,0,0,0,0);
        waitForTaskToEnd(taskId,1);
        }

    printf("test sslv2/sslv3 with 1024 bit DHE via BIO pair\n");
    args[10] = "-dhe1024dsa";
    args[11] = "-v";
    args[12] = NULL;
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 12,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2/sslv3 with server authentication\n");
    args[10] = "-server_auth";
    args[11] = "-CAfile";
    args[12] = CA;
    args[13] = NULL;
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 13,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2/sslv3 with client authentication via BIO pair\n");
    args[10] = "-client_auth";
    args[11] = "-CAfile";
    args[12] = CA;
    args[13] = NULL;
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 13,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test sslv2/sslv3 with both server and client authentication via BIO pair\n");
    args[10] = "-server_auth";
    args[11] = "-client_auth";
    args[12] = "-CAfile";
    args[13] = CA;
    args[14] = NULL;
    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 14,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);
    

    /*******************************************************************/
    
    printf("test tls1 with 1024 bit anonymous DH multiple handshakes\n");
    args[0] = "ssltest";
    args[1] = "-key";
    args[2] = key;
    args[3] = "-cert";
    args[4] = cert;
    args[5] = "-c_key";
    args[6] = key;
    args[7] = "-c_cert";
    args[8] = cert;
    args[9] = "-v";
    args[10] = "-bio_pair";
    args[11] = "-tls1";
    args[12] = "-cipher";
    args[13] = "\"ADH\"";
    args[14] = "-dhe1024dsa";
    args[15] = "-num";
    args[16] = "10";
    args[17] = "-f";
    args[18] = "-time";
    args[19] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 19,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test tls1 with 1024bit RSA, no DHE, multiple handshakes\n");
  
    args[0] = "ssltest";
    args[1] = "-v";
    args[2] = "-bio_pair";
    args[3] = "-tls1";
    args[4] = "-cert";
    args[5] = "server2.pem";
    args[6] = "-no_dhe";
    args[7] = "-num";
    args[8] = "10";
    args[9] = "-f";
    args[10] = "-time";
    args[11] = NULL;

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 11,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("test tls1 with 1024bit RSA, 1024bit DHE, multiple handshakes\n");
    args[6] = "-dhe1024";

    taskId = taskSpawn ("ssltest", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)ssltest_main, 11,(int) args,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    printf("Finished TestSSL\n");
    return FALSE;
    }
BOOL handleSystemTest(void)
    {
    handleMakeCerts();
    handleTx509();
    handleTverify();
    handleTestSs();
    handleTestSsl();
    return FALSE;
    }
void openssl(const char *args)
    {
    opensslWrapper(args,0,0);
    }
void opensslWrapper(const char *args, int inFd, int outFd)
    {
#define MAX_ARGS 40
    int taskId;
    int argc;
    char *argPtr[MAX_ARGS];
    char *userArgs=NULL;
    int oldStdin=-1;
    int oldStdout=-1;



    if(args)
        {
        userArgs = malloc(sizeof(char) *(strlen(args)+1));
        if(!userArgs)
            {
            printf("malloc failed, exiting\n");
            if (inFd) close(inFd);
            if (outFd) close(outFd);
            return;
            }
        strcpy(userArgs,args);
        }
    /* now break userArgs into individual strings */
    argPtr[0] = "openssl";
    for(argc=1;argc<MAX_ARGS;argc++)
        {
        if(argc==1)
            {
            argPtr[argc] = strtok(userArgs," ");
            }
        else
            {
            argPtr[argc] = strtok(NULL," ");
            }
        if(!argPtr[argc])
            {
            break;
            }
        /*     printf("arg is: %s\n",argPtr[argc]); */
        }
    /* at this point make sure the last value in argPtr array is NULL */
    if (MAX_ARGS == argc) 
        {
        argPtr[MAX_ARGS - 1] = NULL;
        }
    else
        {
        argPtr[argc] = NULL;
        }
#ifndef _WRS_KERNEL
    if(inFd)
    {
        oldStdin = dup(0);
        dup2(inFd,0);
    }
    if(outFd)
    {
        oldStdout = dup(1);
        dup2(outFd,1);
    }
    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, argc,(int) argPtr,0,0,0,0,0,0,0,0);
    waitForTaskToEnd(taskId,1);

    if(inFd)
    {

        dup2(oldStdin,0);
        close(oldStdin);
        close(inFd);
    }
    if(outFd)
    {
        dup2(oldStdout,1);
        close(oldStdout);
        close(outFd);
    }

#else	
    taskId = taskSpawn ("openssl", TEST_PRIORITY, 0, TEST_STACKSIZE, (FUNCPTR)openssl_main, argc,(int) argPtr,0,0,0,0,0,0,0,0);
    if(inFd)
    {

        ioTaskStdSet (taskId, 0, inFd); /* reset stdin for spawned task */
    }
    if(outFd)
    {
        printf("Setting task stdout to %d\n",outFd);

        ioTaskStdSet (taskId, 1, outFd); /* reset stdout for spawned task */
        ioGlobalStdSet(1,outFd);
    }
    waitForTaskToEnd(taskId,1);
    if(inFd)
    {

        close(inFd);
    }
    if(outFd)
    {
        ioGlobalStdSet(1,1); /* reset to std out*/
        close(outFd);
    }
#endif      
    }
BOOL handleMakeCerts(void)
    {
    /* Makes all the certs required for the tests */
    FILE *tmpFptr;
    int temp;

    opensslSetTime();

    deleteCerts();

    tmpFptr = file_open("makeCerts_temp","w");
    if(!tmpFptr)
        {
        printf("makeCerts Failed!\n");
        return FALSE;
        }
    fputs("AU\nQueensland\n.\nCryptSoft Pty Ltd\n.\nTest CA (1024 bit)\n\n\n\n",tmpFptr);
    fclose(tmpFptr);

    printf("Creating 1024 bit PCA cert request\n");
    temp = open("makeCerts_temp",0x0200,0644);
    if(!temp)
        {
        printf("makeCerts Failed!\n");
        return FALSE;
        }
    opensslWrapper("req -config openssl.cnf -new -md5 -newkey 1024 -keyout pca-key.pem -out pca-req.pem -nodes",temp,0);

    printf("Self Signing PCA\n");
    opensslWrapper("x509 -md5 -days 1461 -req -signkey pca-key.pem -CAcreateserial -CAserial pca-cert.srl -in pca-req.pem -out pca-cert.pem",0,0);


/******************************************************************/
    printf("Creating 1024 bit CA cert request\n");
       
    tmpFptr = file_open("makeCerts_temp","w");
    if(!tmpFptr)
        {
        printf("makeCerts Failed!\n");
        return FALSE;
        }
    fputs("AU\nQueensland\n.\nCryptSoft Pty Ltd\n.\nTest CA (1024 bit)\n\n\n\n",tmpFptr);
    fclose(tmpFptr);
    temp = open("makeCerts_temp",0x0200,0644);

    opensslWrapper("req -config openssl.cnf -new -md5 -newkey 1024 -keyout ca-key.pem -out ca-req.pem -nodes",temp,0);

    printf("Signing CA\n");
    opensslWrapper("x509 -md5 -days 1461 -req -CAcreateserial -CAserial pca-cert.srl -CA pca-cert.pem -CAkey pca-key.pem -in ca-req.pem -out ca-cert.pem",0,0);
/**************************************************/

    printf("Generating Server Certificate Request\n");

    tmpFptr = file_open("makeCerts_temp","w");
    if(!tmpFptr)
        {
        printf("makeCerts Failed!\n");
        return FALSE;
        }
    fputs("AU\nQueensland\n.\nCryptSoft Pty Ltd\n.\nServer test cert (512 bit)\n\n\n\n",tmpFptr);
    fclose(tmpFptr);
    temp = open("makeCerts_temp",0x0200,0644);
    opensslWrapper("req -config openssl.cnf -new -md5 -newkey 512 -keyout s512-key.pem -out s512-req.pem -nodes",temp,0);

    printf("Signing 512 bit server cert\n");
    opensslWrapper("x509 -md5 -days 365 -req -CAcreateserial -CAserial ca-cert.srl -CA ca-cert.pem -CAkey ca-key.pem -in s512-req.pem -out server.pem",0,0);


/***********************************************************/

    printf("Generating 1024 bit server request\n");

    tmpFptr = file_open("makeCerts_temp","w");
    if(!tmpFptr)
        {
        printf("makeCerts Failed!\n");
        return FALSE;
        }
    fputs("AU\nQueensland\n.\nCryptSoft Pty Ltd\n.\nServer test cert (1024 bit)\n\n\n\n",tmpFptr);
    fclose(tmpFptr);
    temp = open("makeCerts_temp",0x0200,0644);
    opensslWrapper("req -config openssl.cnf -new -md5 -newkey 1024 -keyout s1024key.pem -out s1024req.pem -nodes",temp,0);

    printf("Signing 1024 bit server cert\n");
    opensslWrapper("x509 -md5 -days 365 -req -CAcreateserial -CAserial ca-cert.srl -CA ca-cert.pem -CAkey ca-key.pem -in s1024req.pem -out server2.pem",0,0);

    /***********************************************/

    printf("Creating 512 bit client request\n");
    tmpFptr = file_open("makeCerts_temp","w");
    if(!tmpFptr)
        {
        printf("makeCerts Failed!\n");
        return FALSE;
        }
    fputs("AU\nQueensland\n.\nCryptSoft Pty Ltd\n.\nClient test cert (512 bit)\n\n\n\n",tmpFptr);
    fclose(tmpFptr);
    temp = open("makeCerts_temp",0x0200,0644);
    opensslWrapper("req -config openssl.cnf -new -md5 -newkey 512 -keyout c512-key.pem -out c512-req.pem -nodes",temp,0);
    
    printf("Signing 512 bit server cert\n");
    opensslWrapper("x509 -md5 -days 365 -req -CAcreateserial -CAserial ca-cert.srl -CA ca-cert.pem -CAkey ca-key.pem -in c512-req.pem -out client.pem",0,0);

/************************************************/
    remove("makeCerts_temp");
    cat("s512-key.pem","server.pem");
    cat("s1024key.pem","server2.pem");
    cat("c512-key.pem","client.pem");

    printf("cleanup...\n");

    printf("end makeCerts\n");

    return FALSE;
    }

void openssl_test_include()
    {
    /* Do Nothing */
    }
