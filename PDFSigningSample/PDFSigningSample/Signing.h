//
//  Signing.h
//  PDFSigningSample
//
//  Created by Volodymyr Khmil on 2/9/17.
//  Copyright © 2017 Bindeks. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "mupdf/MuDocRef.h"
#import "mupdf/MuDocumentController.h"
#import "mupdf/fitz.h"
#import "mupdf/common.h"
#import "mupdf/pdf/object.h"
#import "mupdf/pdf/document.h"

void pdf_sign_signature_s(fz_context *ctx, pdf_document *doc, pdf_widget *widget, const char *sigfile, const char *password);
