//
//  ViewController.m
//  MuPDF-example
//
//  Created by Joseph Heenan on 05/07/2015.
//  Copyright (c) 2015 Artifex. All rights reserved.
//

#import "ViewController.h"
#import "mupdf/MuDocRef.h"
#import "mupdf/MuDocumentController.h"
#include "mupdf/fitz.h"
#include "mupdf/common.h"
#import "UIView+BBBPlaceWithConstraint.h"
#import "ossl_typ.h"
#import "evp.h"
#import "rsa.h"
#import "x509.h"
#import "pem.h"

enum
{
    ResourceCacheMaxSize = 128<<20	/**< use at most 128M for resource cache */
};

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UIView *pdfContainerView;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
}

- (IBAction)signPDFPressed {
    [self createCertificate];
}

- (void)setPdfContainerView:(UIView *)pdfContainerView {
    _pdfContainerView = pdfContainerView;
    queue = dispatch_queue_create("com.artifex.mupdf.queue", NULL);
    
    screenScale = [[UIScreen mainScreen] scale];
    
    ctx = fz_new_context(NULL, NULL, ResourceCacheMaxSize);
    fz_register_document_handlers(ctx);
    
    NSString *file = [[NSBundle mainBundle] pathForResource:@"hello-world" ofType:@"pdf"];
    MuDocRef *doc;
    
    doc = [[MuDocRef alloc] initWithFilename:file];
    if (doc) {
         MuDocumentController *document = [[MuDocumentController alloc] initWithFilename:file path:file document: doc];
        [_pdfContainerView addSubview:document.view];
        [_pdfContainerView addConstraints:[UIView placeView:document.view onOtherView:_pdfContainerView]];
        [document didMoveToParentViewController:self];
        [self addChildViewController:document];
    }
}

- (void)createCertificate {
    EVP_PKEY * pkey;
    pkey = EVP_PKEY_new();
    
    RSA * rsa;
    rsa = RSA_generate_key(
                           2048,   /* number of bits for the key - 2048 is a sensible value */
                           RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
                           NULL,   /* callback - can be NULL if we aren't displaying progress */
                           NULL    /* callback argument - not needed in this case */
                           );
    
    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        NSLog(@"fail");
    }
    
    X509 * x509;
    x509 = X509_new();
    
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);
    X509_NAME * name;
    name = X509_get_subject_name(x509);
    
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                               (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                               (unsigned char *)"MyCompany Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    
    if(!X509_sign(x509, pkey, EVP_sha1()))
    {
        NSLog(@"fail");
        X509_free(x509);
    }
    
    FILE * f;
    f = fopen("key.pem", "wb");
    PEM_write_PrivateKey(
                         f,                  /* write the key to the file we've opened */
                         pkey,               /* our key from earlier */
                         EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
                         "replace_me",       /* passphrase required for decrypting the key on disk */
                         10,                 /* length of the passphrase string */
                         NULL,               /* callback for requesting a password */
                         NULL                /* data to pass to the callback */
                         );
    FILE * p;
    f = fopen("cert.pem", "wb");
    PEM_write_X509(
                   p,   /* write the certificate to the file we've opened */
                   x509 /* our certificate */
                   );
}

@end
