/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cm_pfx.h"

#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type_inner.h"

static int32_t CmGetAppCertChain(X509 *cert, STACK_OF(X509) *caCert, struct AppCert *appCert)
{
    int32_t ret = CM_SUCCESS; uint32_t certCount = 0;
    X509 *xCert = NULL; char *data = NULL; BIO *out = NULL;

    if (cert == NULL) {
        CM_LOG_E("app terminal cert is null");
        return CM_FAILURE;
    }

    do {
        out = BIO_new(BIO_s_mem());
        if (out == NULL) {
            CM_LOG_E("BIO_new_mem_buf faild");
            ret = CM_FAILURE;
            break;
        }
        /* copy app terminal cert to bio */
        if (PEM_write_bio_X509(out, cert) == 0) {
            CM_LOG_E("Copy app cert to bio faild");
            ret = CM_FAILURE;
            break;
        }
        certCount++;
        /* copy app ca cert to bio */
        for (int32_t i = 0; i < sk_X509_num(caCert); i++) {
            xCert = sk_X509_value(caCert, i);
            if (PEM_write_bio_X509(out, xCert) == 0) {
                CM_LOG_E("Copy app ca cert to bio faild");
                ret = CM_FAILURE;
                break;
            }
            certCount++;
        }

        long len = BIO_get_mem_data(out, &data);
        if (len <= 0) {
            CM_LOG_E("BIO_get_mem_data faild");
            ret = CM_FAILURE;
            break;
        }
        if (memcpy_s(appCert->appCertdata, MAX_LEN_CERTIFICATE_CHAIN, data, len) != EOK) {
            CM_LOG_E("Copy appCert->appCertdata faild");
            ret = CM_FAILURE;
            break;
        }
        /* default certificate chain is packaged as a whole */
        appCert->certCount = certCount;
        appCert->certSize = (uint32_t)len;
    } while (0);

    if (out != NULL) {
        BIO_free(out);
    }
    return ret;
}

int32_t CmParsePkcs12Cert(const struct CmBlob *p12Cert, char *passWd, EVP_PKEY **pkey, struct AppCert *appCert)
{
    BIO *bio = NULL;
    X509 *cert = NULL;
    PKCS12 *p12 = NULL;
    int32_t ret = CM_SUCCESS;
    STACK_OF(X509) *caCert = NULL;

    if (p12Cert == NULL || p12Cert->data == NULL || p12Cert->size > MAX_LEN_CERTIFICATE_CHAIN) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    do {
        bio = BIO_new_mem_buf(p12Cert->data, p12Cert->size);
        if (bio == NULL) {
            ret = CM_FAILURE;
            CM_LOG_E("BIO_new_mem_buf faild");
            break;
        }

        p12 = d2i_PKCS12_bio(bio, NULL);
        if (p12 == NULL) {
            ret = CM_FAILURE;
            CM_LOG_E("D2i_PKCS12_bio faild:%s", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        /* 1 the return value of PKCS12_parse 1 is success */
        if (PKCS12_parse(p12, passWd, pkey, &cert, &caCert) != 1) {
            ret = CM_FAILURE;
            CM_LOG_E("Parsing  PKCS#12 file faild:%s", ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        ret = CmGetAppCertChain(cert, caCert, appCert);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetAppCertChain failed");
            break;
        }
    } while (0);

    if (bio != NULL) {
        BIO_free(bio);
    }
    if (p12 != NULL) {
        PKCS12_free(p12);
    }
    if (caCert != NULL) {
        sk_X509_pop_free(caCert, X509_free);
    }
    if (cert != NULL) {
        X509_free(cert);
    }
    return ret;
}

