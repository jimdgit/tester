//
//  main.cpp
//  Command Line Tester
//
//  Created by james donelson on 5/26/14.
//  Copyright (c) 2014 james donelson. All rights reserved.
//

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <map>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
using namespace std;
map <int,int> map1;

int mainrun(int argc, const char *argv[]);
int mainreq(void);
int TestRSAKeyGen(void);
int sign_document(unsigned char* data, // data to be signed
                  int length,          // Length of data
                  uint8_t* sig_buf,    // Buffer to hold sig
                   unsigned int* sig_len,    // length of sig buff
                  EVP_PKEY *pkey       // Private key to sign with.
//EVP_PKEY *pkey2       // Private key to sign with.
);
int VerifySignature(X509* cert,             // A cert
                    const void * data,      // Data that has been signed
                    unsigned int datalen,
                    uint8_t* sig_buf,       // Signature to be verified.
                    uint32_t sig_len );

unsigned char dataToSign[]="Sign This Data.";

int main(int argc, const char * argv[])
{
//    BIO *bio_err;
    printf("%s\n",OPENSSL_VERSION_TEXT);
    TestRSAKeyGen();
    mainrun( argc, argv);
    mainreq();
    // insert code here...
    std::cout << "Hello, World!\n";
    std::pair<int,int> p;
    p.first = 0;
    p.second = 1;
    map1.insert(p);
    for( int i = 0 ; i < 10 ; ++i)
    {
        p.first = i;
        p.second = i*10;
        map1.insert(p);
    }

    map<int,int>::iterator it = map1.begin();
    for( ; it != map1.end(); ++it )
    {
        cout << " f=" << it->first << " s=" << it->second << endl ;
    }
    return 0;
}

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
int mainrun(int argc,const char *argv[])
{
	BIO *bio_err;
	X509 *x509=NULL;
	EVP_PKEY *pkey=NULL;
    FILE* fp;
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    OpenSSL_add_all_algorithms();
     OpenSSL_add_all_ciphers();
     OpenSSL_add_all_digests();
    
	bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
    
	mkcert(&x509,&pkey,2048,0,365);
    
	RSA_print_fp(stdout,pkey->pkey.rsa,0);
    fp = fopen("/Users/jimdonelson/Documents/Certs/cert.pem","w+");
    PEM_write_X509(fp, x509);
    fclose(fp);
    
    fp = fopen("/Users/jimdonelson/Documents/Certs/cert.txt","w+");
	X509_print_fp(stdout,x509);
	X509_print_fp(fp,x509);
    fclose(fp);
    fp = fopen("/Users/jimdonelson/Documents/Certs/privk.pem","w+");
	PEM_write_PrivateKey(stdout,pkey,NULL,NULL,0,NULL, NULL);
	PEM_write_PrivateKey(fp,pkey,NULL,NULL,0,NULL, NULL);
    fclose(fp);
	PEM_write_X509(stdout,x509);
    
	X509_free(x509);
	EVP_PKEY_free(pkey);
    
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
    
	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);
	return(0);
}

int add_ext(X509 *cert, int nid, char *value);

static void callback(int p, int n, void *arg)
{
	char c='B';
    
	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	fputc(c,stderr);
}

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;
    uint8_t sig_buf[4096];
     unsigned int sig_len;
	
	if ((pkeyp == NULL) || (*pkeyp == NULL))
    {
		if ((pk=EVP_PKEY_new()) == NULL)
        {
			abort();
			return(0);
        }
    }
	else
		pk= *pkeyp;
    
	if ((x509p == NULL) || (*x509p == NULL))
    {
		if ((x=X509_new()) == NULL)
			goto err;
    }
	else
		x= *x509p;
    
	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
    {
		abort();
		goto err;
    }
    X509_set_pubkey(x,pk);
#if 1
    sign_document(    dataToSign, // data to be signed
                      (int)strlen((char*)dataToSign),          // Length of data
                      sig_buf,    // Buffer to hold sig
                      &sig_len,    // length of sig buff
                      pk       // Private key to sign with.
                      );
#endif
    if( VerifySignature(x,             // A cert
                    dataToSign,      // Data that has been signed
                     (int)strlen((char*)dataToSign),
                    sig_buf,       // Signature to be verified.
                     sig_len ) )
    {
        printf("Signature verified correctly \n");
    }
    else
    {
        printf("Signature verify failed!\n");
    }
	rsa=NULL;
    
	X509_set_version(x,2);
	ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	
    
	name=X509_get_subject_name(x);
    
	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
 
	X509_NAME_add_entry_by_txt(name,"C",
                              (int) MBSTRING_ASC, (unsigned char *)"UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC,(unsigned char *) "OpenSSL Group", -1, -1, 0);
 
    
    
	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	X509_set_issuer_name(x,name);
    
	/* Add various extensions: standard extensions */
	add_ext(x, NID_basic_constraints, (char*)"critical,CA:TRUE");
	add_ext(x, NID_key_usage, (char*)"critical,keyCertSign,cRLSign");
    
	add_ext(x, NID_subject_key_identifier, (char*)"hash");
    
	/* Some Netscape specific extensions */
	add_ext(x, NID_netscape_cert_type, (char*)"sslCA");
    
	add_ext(x, NID_netscape_comment, (char*)"example comment extension");
    
    
#ifdef CUSTOM_EXT
	/* Maybe even add our own extension based on existing */
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		add_ext(x, nid, "example comment alias");
	}
#endif
	
	if (!X509_sign(x,pk,EVP_sha256()))
		goto err;
    
	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;
    
	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}
int TestRSAKeyGen(void)
{
    char plain_text[]="Am I having fun yet?";
    RSA *rsa;
    int i32Result;
    unsigned char buf[1024];
    unsigned char buf2[1024];
    int len;
    unsigned int i;
    
    BIGNUM *bn =BN_new();
    if( !bn )
        return 0;
    BN_set_word(bn, RSA_F4);
    rsa = RSA_new();
    if( !rsa )
        goto error_exit;
    i32Result = RSA_generate_key_ex(rsa,2048,bn,NULL);
    for( i = 0 ; i < sizeof(buf2) ; ++i )
    {
        buf2[i] =0;
        buf[i] = 0;
    }
    len = RSA_public_encrypt((int)strlen(plain_text)+1,(unsigned char*) plain_text,(unsigned char*) buf, rsa,RSA_PKCS1_PADDING);
    i32Result = RSA_private_decrypt(len,(unsigned char*)buf,(unsigned char*) buf2, rsa,RSA_PKCS1_PADDING);
    i32Result = strcmp((char *)plain_text,(char *)buf2);
    
    for( i = 0 ; i < sizeof(buf2) ; ++i )
    {
        buf2[i] =0;
        buf[i] = 0;
    }
    
    len =  RSA_private_encrypt((int)strlen(plain_text)+1,(unsigned char*) plain_text,(unsigned char*) buf, rsa,RSA_PKCS1_PADDING);
    // Returns the size of the plain text.
    i32Result = RSA_public_decrypt(len,(unsigned char*)buf,(unsigned char*) buf2, rsa,RSA_PKCS1_PADDING);
    i32Result = strcmp((char *)plain_text,(char *)buf2);
    if( i32Result != 0)
        printf("RSA KEY GEN ERROR \n");
    
error_exit:
    if(rsa) RSA_free(rsa);
    if(bn) BN_free(bn);
    return 1;
    
}

int sign_document(unsigned char* data, // data to be signed
                  int length,          // Length of data
                  uint8_t* sig_buf,    // Buffer to hold sig
                  unsigned int* sig_len,    // length of sig buff
                  EVP_PKEY *pkey       // Private key to sign with.
)
{
    int err;
    EVP_MD_CTX     md_ctx;
    
    EVP_MD_CTX_init(&md_ctx);
    err =  EVP_SignInit_ex   (&md_ctx, EVP_sha256(),NULL);  // All Signatures use sha256
    err = EVP_SignUpdate (&md_ctx, data, length);
   
    err = EVP_SignFinal (&md_ctx, sig_buf, sig_len, pkey);
    return err;
}

#include <openssl/evp.h>

int VerifySignature(X509* cert,             // A cert
                    const void * data,      // Data that has been signed
                    unsigned int datalen,
                    uint8_t* sig_buf,       // Signature to be verified.
                   uint32_t sig_len )
{
    EVP_PKEY * pkey;
    EVP_MD_CTX md_ctx;
    int err;
    
    
    pkey=X509_get_pubkey(cert);
    
    
    if (pkey == NULL) {
        printf("VerifySignature: failed to get public key\n");
        return 0;
    }
    
    
    EVP_VerifyInit   (&md_ctx, EVP_sha256());
    EVP_VerifyUpdate (&md_ctx ,data,(unsigned int) datalen);
    err = EVP_VerifyFinal (&md_ctx, (unsigned char *)sig_buf, sig_len, pkey);
    EVP_PKEY_free (pkey);
    if (err != 1) {
        //log error
        return 0;
    }
    return 1;
}


int mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
int add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value);

int mainreq(void)
{
	BIO *bio_err;
	X509_REQ *req=NULL;
	EVP_PKEY *pkey=NULL;
    
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    
	bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
    
	mkreq(&req,&pkey,2048,0,365);
    
	RSA_print_fp(stdout,pkey->pkey.rsa,0);
	X509_REQ_print_fp(stdout,req);
    
	PEM_write_X509_REQ(stdout,req);
    
	X509_REQ_free(req);
	EVP_PKEY_free(pkey);
    
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
    
	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);
	return(0);
}
/*
static void callback(int p, int n, void *arg)
{
	char c='B';
    
	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	fputc(c,stderr);
}
*/
int mkreq(X509_REQ **req, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
	X509_REQ *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	
	if ((pk=EVP_PKEY_new()) == NULL)
		goto err;
    
	if ((x=X509_REQ_new()) == NULL)
		goto err;
    
	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		goto err;
    
	rsa=NULL;
    
	X509_REQ_set_pubkey(x,pk);
    
	name=X509_REQ_get_subject_name(x);
    
	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
	X509_NAME_add_entry_by_txt(name,"C",
                               MBSTRING_ASC, (const unsigned char *)"UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC, (const unsigned char *)"OpenSSL Group", -1, -1, 0);
    
#ifdef REQUEST_EXTENSIONS
	/* Certificate requests can contain extensions, which can be used
	 * to indicate the extensions the requestor would like added to
	 * their certificate. CAs might ignore them however or even choke
	 * if they are present.
	 */
    
	/* For request extensions they are all packed in a single attribute.
	 * We save them in a STACK and add them all at once later...
	 */
    
	exts = sk_X509_EXTENSION_new_null();
	/* Standard extenions */
    
	add_ext(exts, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    
	/* This is a typical use for request extensions: requesting a value for
	 * subject alternative name.
	 */
    
	add_ext(exts, NID_subject_alt_name, "email:steve@openssl.org");
    
	/* Some Netscape specific extensions */
	add_ext(exts, NID_netscape_cert_type, "client,email");
    
    
    
#ifdef CUSTOM_EXT
	/* Maybe even add our own extension based on existing */
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		add_ext(x, nid, "example comment alias");
	}
#endif
    
	/* Now we've created the extensions we add them to the request */
    
	X509_REQ_add_extensions(x, exts);
    
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    
#endif
	
	if (!X509_REQ_sign(x,pk,EVP_md5()))
		goto err;
    
	*req=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

int add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value)
{
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return 0;
	sk_X509_EXTENSION_push((struct stack_st_X509_EXTENSION *)sk,(void*) ex);
    
	return 1;
}










