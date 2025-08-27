/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "cm_x509.h"

// LCOV_EXCL_START
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
            CM_LOG_E("BIO_new_mem_buf failed");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }
        /* copy app terminal cert to bio */
        if (PEM_write_bio_X509(out, cert) == 0) {
            CM_LOG_E("Copy app cert to bio faild");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }
        certCount++;
        /* copy app ca cert to bio */
        for (int32_t i = 0; i < sk_X509_num(caCert); i++) {
            xCert = sk_X509_value(caCert, i);
            if (PEM_write_bio_X509(out, xCert) == 0) {
                CM_LOG_E("Copy app ca cert to bio failed");
                ret = CMR_ERROR_OPENSSL_FAIL;
                break;
            }
            certCount++;
        }

        long len = BIO_get_mem_data(out, &data);
        if (len <= 0) {
            CM_LOG_E("BIO_get_mem_data faild");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }
        if (memcpy_s(appCert->appCertdata, MAX_LEN_CERTIFICATE_CHAIN, data, len) != EOK) {
            CM_LOG_E("Copy appCert->appCertdata faild");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
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

int32_t CmParsePkcs12Cert(const struct CmBlob *p12Cert, char *passWd, EVP_PKEY **pkey,
    struct AppCert *appCert, X509 **x509Cert)
{
    BIO *bio = NULL;
    X509 *cert = NULL;
    PKCS12 *p12 = NULL;
    int32_t ret = CM_SUCCESS;
    STACK_OF(X509) *caCert = NULL;

    if (p12Cert == NULL || p12Cert->data == NULL || p12Cert->size > MAX_LEN_CERTIFICATE_CHAIN) {
        return CMR_ERROR_INVALID_ARGUMENT_APP_CERT;
    }

    do {
        bio = BIO_new_mem_buf(p12Cert->data, p12Cert->size);
        if (bio == NULL) {
            ret = CMR_ERROR_OPENSSL_FAIL;
            CM_LOG_E("BIO_new_mem_buf faild");
            break;
        }

        p12 = d2i_PKCS12_bio(bio, NULL);
        if (p12 == NULL) {
            ret = CMR_ERROR_INVALID_CERT_FORMAT;
            CM_LOG_E("D2i_PKCS12_bio faild:%s", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        /* 1 the return value of PKCS12_parse 1 is success */
        if (PKCS12_parse(p12, passWd, pkey, &cert, &caCert) != 1) {
            ret = CMR_ERROR_PASSWORD_IS_ERR;
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
        *x509Cert = cert;
    }
    return ret;
}


static int32_t CmGetPemDerCertChain(const struct CmBlob *certChain, STACK_OF(X509) *fullChain)
{
    X509 *tmpCert = NULL;
    BIO *bio = NULL;
    int32_t ret = CM_SUCCESS;

    do {
        bio = BIO_new_mem_buf(certChain->data, certChain->size);
        if (bio == NULL) {
            CM_LOG_E("BIO_new_mem_buf faild");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }

        if (certChain->data[0] == ASN1_TAG_TYPE_SEQ) {
            // Der format
            while ((tmpCert = d2i_X509_bio(bio, NULL)) != NULL) {
                sk_X509_push(fullChain, tmpCert);
                // avoid double free
                tmpCert = NULL;
            }
        } else {
            // Pem format and other format
            while ((tmpCert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
                sk_X509_push(fullChain, tmpCert);
                tmpCert = NULL;
            };
        }
    } while (0);

    if (bio != NULL) {
        BIO_free(bio);
    }
    return ret;
}

// certChain contains a terminal certificate, trans certChain to appCert and get terminal certificate
static int32_t CmParseCertChain(const struct CmBlob *certChain, struct AppCert *appCert, X509 **cert)
{
    int32_t ret = CM_SUCCESS;
    STACK_OF(X509) *fullChain;

    do {
        fullChain = sk_X509_new_null();
        if (fullChain == NULL) {
            CM_LOG_E("x509 fullChain is null");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }

        ret = CmGetPemDerCertChain(certChain, fullChain);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetX509CertChain failed");
            break;
        }

        int32_t certCount = sk_X509_num(fullChain);
        if (certCount <= 0) {
            CM_LOG_E("cert chain has no cert");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }

        if (memcpy_s(appCert->appCertdata, MAX_LEN_CERTIFICATE_CHAIN, certChain->data, certChain->size) != EOK) {
            CM_LOG_E("Copy certChain->data faild");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }

        /* default certificate chain is packaged as a whole */
        appCert->certCount = (uint32_t)certCount;
        appCert->certSize = certChain->size;
        *cert = sk_X509_value(fullChain, 0);
        // Increase the reference count to prevent it from being released
        if (*cert != NULL) {
            X509_up_ref(*cert);
        }
    } while (0);

    if (fullChain != NULL) {
        sk_X509_pop_free(fullChain, X509_free);
    }
    return ret;
}


static int32_t CmGetPemDerPrivKey(const struct CmBlob *privKey, EVP_PKEY **pkey)
{
    BIO *bio = NULL;
    int32_t ret = CM_SUCCESS;

    do {
        bio = BIO_new_mem_buf(privKey->data, privKey->size);
        if (bio == NULL) {
            ret = CMR_ERROR_OPENSSL_FAIL;
            CM_LOG_E("BIO_new_mem_buf faild");
            break;
        }

        // The private key info contains the corresponding public key info
        if (privKey->data[0] == ASN1_TAG_TYPE_SEQ) {
            // Der format
            if (d2i_PrivateKey_bio(bio, pkey) == NULL) {
                ret = CMR_ERROR_OPENSSL_FAIL;
                CM_LOG_E("der read bio private key faild");
                break;
            }
        } else {
            // Pem and other format
            if (PEM_read_bio_PrivateKey(bio, pkey, NULL, NULL) == NULL) {
                ret = CMR_ERROR_OPENSSL_FAIL;
                CM_LOG_E("pem or other format read bio private key faild");
                break;
            }
        }
    } while (0);

    if (bio != NULL) {
        BIO_free(bio);
    }
    return ret;
}

static int32_t CmParsePrivKey(const struct CmBlob *privKey, X509 *cert, EVP_PKEY **pkey)
{
    if (cert == NULL) {
        CM_LOG_E("user cert is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = CM_SUCCESS;

    do {
        ret = CmGetPemDerPrivKey(privKey, pkey);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetPemDerPrivKey failed");
            break;
        }

        EVP_PKEY* pubkey = X509_get_pubkey(cert);
        if (!pubkey) {
            ret = CMR_ERROR_OPENSSL_FAIL;
            CM_LOG_E("x509 get pubkey failed");
            break;
        }

        // Verify that the public and private keys match
        if (EVP_PKEY_cmp(*pkey, pubkey) != 1) {
            ret = CMR_ERROR_INVALID_CERT_FORMAT;
            CM_LOG_E("The public key does not match the private key");
            EVP_PKEY_free(pubkey);
            break;
        }
        EVP_PKEY_free(pubkey);
    } while (0);

    return ret;
}

int32_t CmParseCertChainAndPrivKey(const struct CmBlob *certChain, const struct CmBlob *privKey, EVP_PKEY **pkey,
    struct AppCert *appCert, X509 **x509Cert)
{
    X509 *cert = NULL;
    if (certChain == NULL || certChain->data == NULL || certChain->size > MAX_LEN_CERTIFICATE_CHAIN) {
        return CMR_ERROR_INVALID_ARGUMENT_APP_CERT;
    }

    int32_t ret = CM_SUCCESS;
    do {
        ret = CmParseCertChain(certChain, appCert, &cert);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("parse cert chain failed");
            break;
        }

        ret = CmParsePrivKey(privKey, cert, pkey);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("parse private key failed");
            break;
        }
    } while (0);

    if (cert != NULL) {
        *x509Cert = cert;
    }
    return ret;
}
// LCOV_EXCL_STOP
