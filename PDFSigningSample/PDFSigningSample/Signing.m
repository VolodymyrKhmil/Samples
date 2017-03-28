//
//  Signing.m
//  PDFSigningSample
//
//  Created by Volodymyr Khmil on 2/9/17.
//  Copyright © 2017 Bindeks. All rights reserved.
//
#import "openssl/err.h"
#import "openssl/bio.h"
#import "openssl/asn1.h"
#import "openssl/x509.h"
#import "openssl/err.h"
#import "openssl/objects.h"
#import "openssl/pem.h"
#import "openssl/pkcs7.h"
#import "Signing.h"
#import "document.h"

enum
{
    SEG_START = 0,
    SEG_SIZE = 1
};

typedef struct bsegs_struct
{
    int (*seg)[2];
    int nsegs;
    int current_seg;
    int seg_pos;
} BIO_SEGS_CTX;

static int bsegs_read(BIO *b, char *buf, int size)
{
    BIO_SEGS_CTX *ctx = (BIO_SEGS_CTX *)b->ptr;
    int read = 0;
    
    while (size > 0 && ctx->current_seg < ctx->nsegs)
    {
        int nb = ctx->seg[ctx->current_seg][SEG_SIZE] - ctx->seg_pos;
        
        if (nb > size)
            nb = size;
        
        if (nb > 0)
        {
            if (ctx->seg_pos == 0)
                (void)BIO_seek(b->next_bio, ctx->seg[ctx->current_seg][SEG_START]);
            
            (void)BIO_read(b->next_bio, buf, nb);
            ctx->seg_pos += nb;
            read += nb;
            buf += nb;
            size -= nb;
        }
        else
        {
            ctx->current_seg++;
            
            if (ctx->current_seg < ctx->nsegs)
                ctx->seg_pos = 0;
        }
    }
    
    return read;
}

static long bsegs_ctrl(BIO *b, int cmd, long arg1, void *arg2)
{
    return BIO_ctrl(b->next_bio, cmd, arg1, arg2);
}

static int bsegs_new(BIO *b)
{
    BIO_SEGS_CTX *ctx;
    
    ctx = (BIO_SEGS_CTX *)malloc(sizeof(BIO_SEGS_CTX));
    if (ctx == NULL)
        return 0;
    
    ctx->current_seg = 0;
    ctx->seg_pos = 0;
    ctx->seg = NULL;
    ctx->nsegs = 0;
    
    b->init = 1;
    b->ptr = (char *)ctx;
    b->flags = 0;
    b->num = 0;
    
    return 1;
}

static int bsegs_free(BIO *b)
{
    if (b == NULL)
        return 0;
    
    free(b->ptr);
    b->ptr = NULL;
    b->init = 0;
    b->flags = 0;
    
    return 1;
}

static long bsegs_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    return BIO_callback_ctrl(b->next_bio, cmd, fp);
}

static BIO_METHOD methods_bsegs =
{
    0,"segment reader",
    NULL,
    bsegs_read,
    NULL,
    NULL,
    bsegs_ctrl,
    bsegs_new,
    bsegs_free,
    bsegs_callback_ctrl,
};

static BIO_METHOD *BIO_f_segments(void)
{
    return &methods_bsegs;
}

static void BIO_set_segments(BIO *b, int (*seg)[2], int nsegs)
{
    BIO_SEGS_CTX *ctx = (BIO_SEGS_CTX *)b->ptr;
    
    ctx->seg = seg;
    ctx->nsegs = nsegs;
}

typedef struct verify_context_s
{
    X509_STORE_CTX x509_ctx;
    char certdesc[256];
    int err;
} verify_context;

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    verify_context *vctx;
    X509 *err_cert;
    int err, depth;
    
    vctx = (verify_context *)ctx;
    
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    
    X509_NAME_oneline(X509_get_subject_name(err_cert), vctx->certdesc, sizeof(vctx->certdesc));
    
    if (!ok && depth >= 6)
    {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
    }
    
    switch (ctx->error)
    {
        case X509_V_ERR_INVALID_PURPOSE:
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
            err = X509_V_OK;
            X509_STORE_CTX_set_error(ctx, X509_V_OK);
            ok = 1;
            break;
            
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            /*
             In this case, don't reset err to X509_V_OK, so that it can be reported,
             although we do return 1, so that the digest will still be checked
             */
            ok = 1;
            break;
            
        default:
            break;
    }
    
    if (ok && vctx->err == X509_V_OK)
        vctx->err = err;
    return ok;
}

static int pk7_verify(X509_STORE *cert_store, PKCS7 *p7, BIO *detached, char *ebuf, int ebufsize)
{
    PKCS7_SIGNER_INFO *si;
    verify_context vctx;
    BIO *p7bio=NULL;
    char readbuf[1024*4];
    int res = 1;
    int i;
    STACK_OF(PKCS7_SIGNER_INFO) *sk;
    
    vctx.err = X509_V_OK;
    ebuf[0] = 0;
    
    OpenSSL_add_all_algorithms();
    
    EVP_add_digest(EVP_md5());
    EVP_add_digest(EVP_sha1());
    
    ERR_load_crypto_strings();
    
    ERR_clear_error();
    
    X509_VERIFY_PARAM_set_flags(cert_store->param, X509_V_FLAG_CB_ISSUER_CHECK);
    X509_STORE_set_verify_cb_func(cert_store, verify_callback);
    
    p7bio = PKCS7_dataInit(p7, detached);
    
    /* We now have to 'read' from p7bio to calculate digests etc. */
    while (BIO_read(p7bio, readbuf, sizeof(readbuf)) > 0)
        ;
    
    /* We can now verify signatures */
    sk = PKCS7_get_signer_info(p7);
    if (sk == NULL)
    {
        /* there are no signatures on this data */
        res = 0;
        fz_strlcpy(ebuf, "No signatures", ebufsize);
        goto exit;
    }
    
    for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++)
    {
        int rc;
        si = sk_PKCS7_SIGNER_INFO_value(sk, i);
        rc = PKCS7_dataVerify(cert_store, &vctx.x509_ctx, p7bio,p7, si);
        if (rc <= 0 || vctx.err != X509_V_OK)
        {
            char tbuf[120];
            
            if (rc <= 0)
            {
                fz_strlcpy(ebuf, ERR_error_string(ERR_get_error(), tbuf), ebufsize);
            }
            else
            {
                /* Error while checking the certificate chain */
                snprintf(ebuf, ebufsize, "%s(%d): %s", X509_verify_cert_error_string(vctx.err), vctx.err, vctx.certdesc);
            }
            
            res = 0;
            goto exit;
        }
    }
    
exit:
    X509_STORE_CTX_cleanup(&vctx.x509_ctx);
    ERR_free_strings();
    
    return res;
}

static unsigned char adobe_ca[] =
{
};

static int verify_sig(char *sig, int sig_len, char *file, int (*byte_range)[2], int byte_range_len, char *ebuf, int ebufsize)
{
    PKCS7 *pk7sig = NULL;
    PKCS7 *pk7cert = NULL;
    X509_STORE *st = NULL;
    BIO *bsig = NULL;
    BIO *bcert = NULL;
    BIO *bdata = NULL;
    BIO *bsegs = NULL;
    STACK_OF(X509) *certs = NULL;
    int t;
    int res = 0;
    
    bsig = BIO_new_mem_buf(sig, sig_len);
    pk7sig = d2i_PKCS7_bio(bsig, NULL);
    if (pk7sig == NULL)
        goto exit;
    
    bdata = BIO_new(BIO_s_file());
    if (bdata == NULL)
        goto exit;
    BIO_read_filename(bdata, file);
    
    bsegs = BIO_new(BIO_f_segments());
    if (bsegs == NULL)
        goto exit;
    
    bsegs->next_bio = bdata;
    BIO_set_segments(bsegs, byte_range, byte_range_len);
    
    /* Find the certificates in the pk7 file */
    bcert = BIO_new_mem_buf(adobe_ca, sizeof(adobe_ca));
    pk7cert = d2i_PKCS7_bio(bcert, NULL);
    if (pk7cert == NULL)
        goto exit;
    
    t = OBJ_obj2nid(pk7cert->type);
    switch (t)
    {
        case NID_pkcs7_signed:
            certs = pk7cert->d.sign->cert;
            break;
            
        case NID_pkcs7_signedAndEnveloped:
            certs = pk7cert->d.sign->cert;
            break;
            
        default:
            break;
    }
    
    st = X509_STORE_new();
    if (st == NULL)
        goto exit;
    
    /* Add the certificates to the store */
    if (certs != NULL)
    {
        int i, n = sk_X509_num(certs);
        
        for (i = 0; i < n; i++)
        {
            X509 *c = sk_X509_value(certs, i);
            X509_STORE_add_cert(st, c);
        }
    }
    
    res = pk7_verify(st, pk7sig, bsegs, ebuf, ebufsize);
    
exit:
    BIO_free(bsig);
    BIO_free(bdata);
    BIO_free(bsegs);
    BIO_free(bcert);
    PKCS7_free(pk7sig);
    PKCS7_free(pk7cert);
    X509_STORE_free(st);
    
    return res;
}

typedef struct pdf_designated_name_openssl_s
{
    pdf_designated_name base;
    char buf[8192];
} pdf_designated_name_openssl;

struct pdf_signer_s
{
    int refs;
    X509 *x509;
    EVP_PKEY *pkey;
};

void pdf_drop_designated_name(fz_context *ctx, pdf_designated_name *dn)
{
    fz_free(ctx, dn);
}

static void add_from_bags(X509 **pX509, EVP_PKEY **pPkey, STACK_OF(PKCS12_SAFEBAG) *bags, const char *pw);

static void add_from_bag(X509 **pX509, EVP_PKEY **pPkey, PKCS12_SAFEBAG *bag, const char *pw)
{
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    switch (M_PKCS12_bag_type(bag))
    {
        case NID_keyBag:
            p8 = bag->value.keybag;
            pkey = EVP_PKCS82PKEY(p8);
            break;
            
        case NID_pkcs8ShroudedKeyBag:
            p8 = PKCS12_decrypt_skey(bag, pw, (int)strlen(pw));
            if (p8)
            {
                pkey = EVP_PKCS82PKEY(p8);
                PKCS8_PRIV_KEY_INFO_free(p8);
            }
            break;
            
        case NID_certBag:
            if (M_PKCS12_cert_bag_type(bag) == NID_x509Certificate)
                x509 = PKCS12_certbag2x509(bag);
            break;
            
        case NID_safeContentsBag:
            add_from_bags(pX509, pPkey, bag->value.safes, pw);
            break;
    }
    
    if (pkey)
    {
        if (!*pPkey)
            *pPkey = pkey;
        else
            EVP_PKEY_free(pkey);
    }
    
    if (x509)
    {
        if (!*pX509)
            *pX509 = x509;
        else
            X509_free(x509);
    }
}

static void add_from_bags(X509 **pX509, EVP_PKEY **pPkey, STACK_OF(PKCS12_SAFEBAG) *bags, const char *pw)
{
    int i;
    
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++)
        add_from_bag(pX509, pPkey, sk_PKCS12_SAFEBAG_value(bags, i), pw);
}

pdf_signer *pdf_read_pfx_s(fz_context *ctx, X509 *pX509, EVP_PKEY *pPkey)
{
    pdf_signer *signer = NULL;
    
    fz_var(signer);
    fz_try(ctx)
    {
        signer = fz_malloc_struct(ctx, pdf_signer);
        signer->refs = 1;
        
        OpenSSL_add_all_algorithms();
        
        EVP_add_digest(EVP_md5());
        EVP_add_digest(EVP_sha1());
        
        ERR_load_crypto_strings();
        
        ERR_clear_error();
        

        signer->x509 = pX509;
        signer->pkey = pPkey;
    }
    fz_catch(ctx)
    {
        pdf_drop_signer(ctx, signer);
        fz_rethrow(ctx);
    }
    
    return signer;
}

void pdf_drop_signer(fz_context *ctx, pdf_signer *signer)
{
    
        X509_free(signer->x509);
        EVP_PKEY_free(signer->pkey);
        fz_free(ctx, signer);
    
}

pdf_designated_name *pdf_signer_designated_name(fz_context *ctx, pdf_signer *signer)
{
    pdf_designated_name_openssl *dn = fz_malloc_struct(ctx, pdf_designated_name_openssl);
    char *p;
    
    X509_NAME_oneline(X509_get_subject_name(signer->x509), dn->buf, sizeof(dn->buf));
    p = strstr(dn->buf, "/CN=");
    if (p) dn->base.cn = p+4;
    p = strstr(dn->buf, "/O=");
    if (p) dn->base.o = p+3;
    p = strstr(dn->buf, "/OU=");
    if (p) dn->base.ou = p+4;
    p = strstr(dn->buf, "/emailAddress=");
    if (p) dn->base.email = p+14;
    p = strstr(dn->buf, "/C=");
    if (p) dn->base.c = p+3;
    
    for (p = dn->buf; *p; p++)
        if (*p == '/')
            *p = 0;
    
    return (pdf_designated_name *)dn;
}

void pdf_write_digest(fz_context *ctx, pdf_document *doc, const char *filename, pdf_obj *byte_range, int digest_offset, int digest_length, pdf_signer *signer)
{
    BIO *bdata = NULL;
    BIO *bsegs = NULL;
    BIO *bp7in = NULL;
    BIO *bp7 = NULL;
    PKCS7 *p7 = NULL;
    PKCS7_SIGNER_INFO *si;
    FILE *f = NULL;
    
    int (*brange)[2] = NULL;
    int brange_len = pdf_array_len(ctx, byte_range)/2;
    
    fz_var(bdata);
    fz_var(bsegs);
    fz_var(bp7in);
    fz_var(bp7);
    fz_var(p7);
    fz_var(f);
    
    fz_try(ctx)
    {
        unsigned char *p7_ptr;
        int p7_len;
        int i;
        
        brange = fz_calloc(ctx, brange_len, sizeof(*brange));
        for (i = 0; i < brange_len; i++)
        {
            brange[i][0] = pdf_to_int(ctx, pdf_array_get(ctx, byte_range, 2*i));
            brange[i][1] = pdf_to_int(ctx, pdf_array_get(ctx, byte_range, 2*i+1));
        }
        
        bdata = BIO_new(BIO_s_file());
        if (bdata == NULL)
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to create file BIO");
        BIO_read_filename(bdata, filename);
        
        bsegs = BIO_new(BIO_f_segments());
        if (bsegs == NULL)
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to create segment filter");
        
        bsegs->next_bio = bdata;
        BIO_set_segments(bsegs, brange, brange_len);
        
        p7 = PKCS7_new();
        if (p7 == NULL)
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to create p7 object");
        
        PKCS7_set_type(p7, NID_pkcs7_signed);
        si = PKCS7_add_signature(p7, signer->x509, signer->pkey, EVP_sha1());
        if (si == NULL)
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to add signature");
        
        PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
        PKCS7_add_certificate(p7, signer->x509);
        
        PKCS7_content_new(p7, NID_pkcs7_data);
        PKCS7_set_detached(p7, 1);
        
        bp7in = PKCS7_dataInit(p7, NULL);
        if (bp7in == NULL)
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to write to digest");
        
        while(1)
        {
            char buf[4096];
            int n = BIO_read(bsegs, buf, sizeof(buf));
            if (n <= 0)
                break;
            BIO_write(bp7in, buf, n);
        }
        
        if (!PKCS7_dataFinal(p7, bp7in))
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to write to digest");
        
        BIO_free(bsegs);
        bsegs = NULL;
        BIO_free(bdata);
        bdata = NULL;
        
        bp7 = BIO_new(BIO_s_mem());
        if (bp7 == NULL || !i2d_PKCS7_bio(bp7, p7))
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to create memory buffer for digest");
        
        p7_len = BIO_get_mem_data(bp7, &p7_ptr);
        if (p7_len*2 + 2 > digest_length)
            fz_throw(ctx, FZ_ERROR_GENERIC, "Insufficient space for digest");
        
        f = fz_fopen(filename, "rb+");
        if (f == NULL)
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to write digest");
        
        fz_fseek(f, digest_offset+1, SEEK_SET);
        
        for (i = 0; i < p7_len; i++)
            fprintf(f, "%02x", p7_ptr[i]);
    }
    fz_always(ctx)
    {
        PKCS7_free(p7);
        BIO_free(bsegs);
        BIO_free(bdata);
        BIO_free(bp7in);
        BIO_free(bp7);
        if (f)
            fclose(f);
    }
    fz_catch(ctx)
    {
        fz_rethrow(ctx);
    }
}


static void complete_signatures(fz_context *ctx, struct pdf_document_s *doc, pdf_write_options *opts, char *filename)
{
    pdf_unsaved_sig *usig;
    FILE *f;
    char buf[5120];
    int i;
    int flen;
    int last_end;
    
    if (doc->unsaved_sigs)
    {
        pdf_obj *byte_range;
        
        f = fopen(filename, "rb+");
        if (!f)
            fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to open %s to complete signatures", filename);
        
        fseek(f, 0, SEEK_END);
        flen = ftell(f);
        
        /* Locate the byte ranges and contents in the saved file */
        for (usig = doc->unsaved_sigs; usig; usig = usig->next)
        {
            char *bstr, *cstr, *fstr;
            int pnum = pdf_obj_parent_num(ctx, pdf_dict_getp(ctx, usig->field, "V/ByteRange"));
            fseek(f, opts->ofs_list[pnum], SEEK_SET);
            (void)fread(buf, 1, sizeof(buf), f);
            buf[sizeof(buf)-1] = 0;
            
            bstr = strstr(buf, "/ByteRange");
            cstr = strstr(buf, "/Contents");
            fstr = strstr(buf, "/Filter");
            
            if (bstr && cstr && fstr && bstr < cstr && cstr < fstr)
            {
                usig->byte_range_start = bstr - buf + 10 + opts->ofs_list[pnum];
                usig->byte_range_end = cstr - buf + opts->ofs_list[pnum];
                usig->contents_start = cstr - buf + 9 + opts->ofs_list[pnum];
                usig->contents_end = fstr - buf + opts->ofs_list[pnum];
            }
        }
        
        /* Recreate ByteRange with correct values. Initially store the
         * recreated object in the first of the unsaved signatures */
        byte_range = pdf_new_array(ctx, doc, 4);
        pdf_dict_putp_drop(ctx, doc->unsaved_sigs->field, "V/ByteRange", byte_range);
        
        last_end = 0;
        for (usig = doc->unsaved_sigs; usig; usig = usig->next)
        {
            pdf_array_push_drop(ctx, byte_range, pdf_new_int(ctx, doc, last_end));
            pdf_array_push_drop(ctx, byte_range, pdf_new_int(ctx, doc, usig->contents_start - last_end));
            last_end = usig->contents_end;
        }
        pdf_array_push_drop(ctx, byte_range, pdf_new_int(ctx, doc, last_end));
        pdf_array_push_drop(ctx, byte_range, pdf_new_int(ctx, doc, flen - last_end));
        
        /* Copy the new ByteRange to the other unsaved signatures */
        for (usig = doc->unsaved_sigs->next; usig; usig = usig->next)
            pdf_dict_putp_drop(ctx, usig->field, "V/ByteRange", pdf_copy_array(ctx, byte_range));
        
        /* Write the byte range into buf, padding with spaces*/
        i = pdf_sprint_obj(ctx, buf, sizeof(buf), byte_range, 1);
        memset(buf+i, ' ', sizeof(buf)-i);
        
        /* Write the byte range to the file */
        for (usig = doc->unsaved_sigs; usig; usig = usig->next)
        {
            fseek(f, usig->byte_range_start, SEEK_SET);
            fwrite(buf, 1, usig->byte_range_end - usig->byte_range_start, f);
        }
        
        fclose(f);
        
        /* Write the digests into the file */
        for (usig = doc->unsaved_sigs; usig; usig = usig->next)
            pdf_write_digest(ctx, doc, filename, byte_range, usig->contents_start, usig->contents_end - usig->contents_start, usig->signer);
        
        /* delete the unsaved_sigs records */
        while ((usig = doc->unsaved_sigs) != NULL)
        {
            doc->unsaved_sigs = usig->next;
            pdf_drop_obj(ctx, usig->field);
            pdf_drop_signer(ctx, usig->signer);
            fz_free(ctx, usig);
        }
    }
}

int pdf_check_signature(fz_context *ctx, pdf_document *doc, pdf_widget *widget, char *file, char *ebuf, int ebufsize)
{
    int (*byte_range)[2] = NULL;
    int byte_range_len;
    char *contents = NULL;
    int contents_len;
    int res = 0;
    
    if (pdf_xref_obj_is_unsaved_signature(doc, ((pdf_annot *)widget)->obj))
    {
        fz_strlcpy(ebuf, "Signed but document yet to be saved", ebufsize);
        if (ebufsize > 0)
            ebuf[ebufsize-1] = 0;
        return 0;
    }
    
    fz_var(byte_range);
    fz_var(res);
    fz_try(ctx)
    {
        byte_range_len = pdf_signature_widget_byte_range(ctx, doc, widget, NULL);
        if (byte_range_len)
        {
            byte_range = fz_calloc(ctx, byte_range_len, sizeof(*byte_range));
            pdf_signature_widget_byte_range(ctx, doc, widget, byte_range);
        }
        
        contents_len = pdf_signature_widget_contents(ctx, doc, widget, &contents);
        if (byte_range && contents)
        {
            res = verify_sig(contents, contents_len, file, byte_range, byte_range_len, ebuf, ebufsize);
        }
        else
        {
            res = 0;
            fz_strlcpy(ebuf, "Not signed", ebufsize);
        }
        
    }
    fz_always(ctx)
    {
        fz_free(ctx, byte_range);
    }
    fz_catch(ctx)
    {
        res = 0;
        fz_strlcpy(ebuf, fz_caught_message(ctx), ebufsize);
    }
    
    if (ebufsize > 0)
        ebuf[ebufsize-1] = 0;
    
    return res;
}

fz_rect * pdf_to_rect_s(fz_context *ctx, pdf_obj *array, fz_rect *r)
{
    float a = pdf_to_real(ctx, pdf_array_get(ctx, array, 0));
    float b = pdf_to_real(ctx, pdf_array_get(ctx, array, 1));
    float c = pdf_to_real(ctx, pdf_array_get(ctx, array, 2));
    float d = pdf_to_real(ctx, pdf_array_get(ctx, array, 3));
    r->x0 = fz_min(a, c);
    r->y0 = fz_min(b, d);
    r->x1 = fz_max(a, c);
    r->y1 = fz_max(b, d);
    if (!pdf_is_array(ctx, array))
        *r = fz_empty_rect;
    else
    {
        float a = pdf_to_real(ctx, pdf_array_get(ctx, array, 0));
        float b = pdf_to_real(ctx, pdf_array_get(ctx, array, 1));
        float c = pdf_to_real(ctx, pdf_array_get(ctx, array, 2));
        float d = pdf_to_real(ctx, pdf_array_get(ctx, array, 3));
        r->x0 = fz_min(a, c);
        r->y0 = fz_min(b, d);
        r->x1 = fz_max(a, c);
        r->y1 = fz_max(b, d);
    }
    return r;
}

//pdf_obj *pdf_new_string_s(fz_context *ctx, pdf_document *doc, const char *str, int len)
//{
//    pdf_obj_string *obj;
//    obj = Memento_label(fz_malloc(ctx, offsetof(pdf_obj_string, buf) + len + 1), "pdf_obj(string)");
//    obj->super.refs = 1;
//    obj->super.kind = PDF_STRING;
//    obj->super.flags = 0;
//    obj->len = len;
//    memcpy(obj->buf, str, len);
//    obj->buf[len] = '\0';
//    return &obj->super;
//}

void pdf_signature_set_value(fz_context *ctx, pdf_document *doc, pdf_obj *field, pdf_signer *signer)
{
    pdf_obj *v;
    pdf_obj *indv;
    int vnum;
    pdf_obj *byte_range;
    pdf_obj *contents;
    char buf[2048];
    
    memset(buf, 0, sizeof(buf));
    
    vnum = pdf_create_object(ctx, doc);
    indv = pdf_new_indirect(ctx, doc, vnum, 0);
    pdf_dict_put_drop(ctx, field, PDF_NAME_V, indv);
    
    fz_var(v);
    fz_try(ctx)
    {
        v = pdf_new_dict(ctx, doc, 4);
        pdf_update_object(ctx, doc, vnum, v);
    }
    fz_always(ctx)
    {
        pdf_drop_obj(ctx, v);
    }
    fz_catch(ctx)
    {
        fz_rethrow(ctx);
    }
    
    byte_range = pdf_new_array(ctx, doc, 4);
    pdf_dict_put_drop(ctx, v, PDF_NAME_ByteRange, byte_range);
    
    contents = pdf_new_string(ctx, doc, buf, sizeof(buf));
    pdf_dict_put_drop(ctx, v, PDF_NAME_Contents, contents);
    
    pdf_dict_put_drop(ctx, v, PDF_NAME_Filter, PDF_NAME_Adobe_PPKLite);
    pdf_dict_put_drop(ctx, v, PDF_NAME_SubFilter, PDF_NAME_adbe_pkcs7_detached);
    
    /* Record details within the document structure so that contents
     * and byte_range can be updated with their correct values at
     * saving time */
    pdf_xref_store_unsaved_signature(ctx, doc, field, signer);
}

void pdf_sign_signature_s(fz_context *ctx, pdf_document *doc, pdf_widget *widget, X509 *pX509, EVP_PKEY *pPkey)
{
    pdf_signer *signer = pdf_read_pfx_s(ctx, pX509, pPkey);
    pdf_designated_name *dn = NULL;
    fz_buffer *fzbuf = NULL;
    
    fz_try(ctx)
    {
        const char *dn_str;
        pdf_obj *wobj = ((pdf_annot *)widget)->obj;
        fz_rect rect = fz_empty_rect;
        
        pdf_signature_set_value(ctx, doc, wobj, signer);
        pdf_obj *dict = pdf_dict_get(ctx, wobj, PDF_NAME_Rect);
        pdf_to_rect_s(ctx, dict, &rect);
        /* Create an appearance stream only if the signature is intended to be visible */
        if (!fz_is_empty_rect(&rect))
        {
            dn = pdf_signer_designated_name(ctx, signer);
            fzbuf = fz_new_buffer(ctx, 256);
            if (!dn->cn)
                fz_throw(ctx, FZ_ERROR_GENERIC, "Certificate has no common name");
            
            fz_buffer_printf(ctx, fzbuf, "cn=%s", dn->cn);
            
            if (dn->o)
                fz_buffer_printf(ctx, fzbuf, ", o=%s", dn->o);
            
            if (dn->ou)
                fz_buffer_printf(ctx, fzbuf, ", ou=%s", dn->ou);
            
            if (dn->email)
                fz_buffer_printf(ctx, fzbuf, ", email=%s", dn->email);
            
            if (dn->c)
                fz_buffer_printf(ctx, fzbuf, ", c=%s", dn->c);
            
            dn_str = fz_string_from_buffer(ctx, fzbuf);
            pdf_set_signature_appearance(ctx, doc, (pdf_annot *)widget, dn->cn, dn_str, NULL);
        }
    }
    fz_always(ctx)
    {
        pdf_drop_signer(ctx, signer);
        pdf_drop_designated_name(ctx, dn);
        fz_drop_buffer(ctx, fzbuf);
    }
    fz_catch(ctx)
    {
        fz_rethrow(ctx);
    }
}
