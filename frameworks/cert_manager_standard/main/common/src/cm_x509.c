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

#include "cm_x509.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <string.h>

#include "securec.h"

#include "cm_log.h"

typedef X509_NAME *(FUNC)(const X509 *);
typedef ASN1_TIME *(TIME_FUNC)(const X509 *);
#define CONVERT(p) (((p)[0] - '0') * 10 + (p)[1] - '0')

X509 *InitCertContext(const uint8_t *certBuf, uint32_t size)
{
    X509 *x509 = NULL;
    if (certBuf == NULL || size > MAX_LEN_CERTIFICATE) {
        return NULL;
    }
    BIO *bio = BIO_new_mem_buf(certBuf, (int)size);
    if (!bio) {
        return NULL;
    }
    if (certBuf[0] == '-') {
        // PEM format
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    } else if (certBuf[0] == ASN1_TAG_TYPE_SEQ) {
        // Der format
        x509 = d2i_X509_bio(bio, NULL);
    } else {
        CM_LOG_E("invalid certificate format.");
    }
    BIO_free(bio);
    return x509;
}

int32_t GetX509SerialNumber(X509 *x509cert, char *outBuf, uint32_t outBufMaxSize)
{
    if (outBuf == NULL || x509cert == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    ASN1_INTEGER *serial = X509_get_serialNumber(x509cert);
    if (serial == NULL) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn == NULL) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    char *hex = BN_bn2hex(bn);
    if (hex == NULL) {
        BN_free(bn);
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    uint32_t len = (uint32_t)strlen(hex);
    if (len >= outBufMaxSize) {
        OPENSSL_free(hex);
        BN_free(bn);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    if (strncpy_s(outBuf, outBufMaxSize, hex, len) != EOK) {
        OPENSSL_free(hex);
        BN_free(bn);
        return CMR_ERROR_INVALID_OPERATION;
    }

    OPENSSL_free(hex);
    BN_free(bn);
    return (int32_t)len;
}
static int32_t ToStringName(FUNC func, const X509 *x509cert, const char *objname, char *outBuf, uint32_t outBufMaxSize)
{
    int32_t length = 0;
    if (func == NULL || x509cert == NULL || outBuf == NULL || outBufMaxSize == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    X509_NAME *name = func(x509cert);
    if (name == NULL) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    for (int i = 0; i < X509_NAME_entry_count(name); ++i) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
        const char *strname = OBJ_nid2sn(OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry)));

        if (strcmp(objname, strname) == 0) {
            char *data = NULL;
            length = ASN1_STRING_to_UTF8((unsigned char **)&data, X509_NAME_ENTRY_get_data(entry));
            if (length < 0) {
                return CMR_ERROR_INVALID_CERT_FORMAT;
            } else if ((uint32_t)length >= outBufMaxSize) {
                OPENSSL_free(data);
                return CMR_ERROR_BUFFER_TOO_SMALL;
            }
            if (strncpy_s(outBuf, outBufMaxSize, data, length) != EOK) {
                OPENSSL_free(data);
                return CMR_ERROR_INVALID_OPERATION;
            }
            OPENSSL_free(data);
            break;
        }
    }
    return length;
}

static int32_t GetX509IssueName(const X509 *x509cert, const char *issuerObjName, char *outBuf, uint32_t outBufMaxSize)
{
    return ToStringName(X509_get_issuer_name, x509cert, issuerObjName, outBuf, outBufMaxSize);
}

int32_t GetX509SubjectName(const X509 *x509cert, const char *subjectObjName, char *outBuf, uint32_t outBufMaxSize)
{
    return ToStringName(X509_get_subject_name, x509cert, subjectObjName, outBuf, outBufMaxSize);
}

int32_t GetX509SubjectNameLongFormat(const X509 *x509cert, char *outBuf, uint32_t outBufMaxSize)
{
    if (outBuf == NULL || outBufMaxSize == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uint32_t offset = 0;
    const char *subjectNameList[] = {CM_COMMON_NAME, CM_ORGANIZATION_UNIT_NAME, CM_ORGANIZATION_NAME};
    uint32_t sizeList = sizeof(subjectNameList) / sizeof(subjectNameList[0]);
    for (uint32_t j = 0; j < sizeList; ++j) {
        char subjectName[NAME_MAX_SIZE] = {0};
        int32_t length = GetX509SubjectName(x509cert, subjectNameList[j], subjectName, NAME_MAX_SIZE);
        if (length < 0) {
            return length;
        }
        if (snprintf_s(outBuf + offset, outBufMaxSize - offset, outBufMaxSize - offset - 1, "%s=%s%c",
            subjectNameList[j], subjectName, (char)(((j + 1) == sizeList) ? '\0' : ',')) < 0) {
            return CMR_ERROR_INVALID_OPERATION;
        }
        offset += strlen(subjectNameList[j]) + strlen(subjectName) + NAME_DELIMITER_SIZE;
    }
    return (int32_t)strlen(outBuf);
}

int32_t GetX509IssueNameLongFormat(const X509 *x509cert, char *outBuf, uint32_t outBufMaxSize)
{
    if (outBuf == NULL || outBufMaxSize == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uint32_t offset = 0;

    const char *issueNameList[] = {CM_COMMON_NAME, CM_ORGANIZATION_UNIT_NAME, CM_ORGANIZATION_NAME};
    uint32_t sizeList = sizeof(issueNameList) / sizeof(issueNameList[0]);
    for (uint32_t j = 0; j < sizeList; ++j) {
        char issueName[NAME_MAX_SIZE] = {0};
        int32_t length = GetX509IssueName(x509cert, issueNameList[j], issueName, NAME_MAX_SIZE);
        if (length < 0) {
            return length;
        }
        if (snprintf_s(outBuf + offset, outBufMaxSize - offset, outBufMaxSize - offset - 1, "%s=%s%c",
            issueNameList[j], issueName, (char)(((j + 1) == sizeList) ? '\0' : ',')) < 0) {
            return CMR_ERROR_INVALID_OPERATION;
        }
        offset += strlen(issueNameList[j]) + strlen(issueName) + NAME_DELIMITER_SIZE;
    }
    return (int32_t)strlen(outBuf);
}

static int32_t GetX509Time(TIME_FUNC fuc, const X509 *x509cert, struct DataTime *pDataTime)
{
    if (x509cert == NULL || fuc == NULL || pDataTime == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    ASN1_TIME *bufTime = fuc(x509cert);
    if (!bufTime) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    if (bufTime->length < NAME_ANS1TIME_LEN) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    /* Convent the asn1 time to the readable time */
    pDataTime->year = CONVERT(bufTime->data);
    if (pDataTime->year < 50) { /* 50 is used for the readable time */
        pDataTime->year += 100; /* 100 is used for the readable time */
    }
    pDataTime->year += 1900;    /* 1900 is used for the readable time */
    pDataTime->month = CONVERT(bufTime->data + 2);
    pDataTime->day = CONVERT(bufTime->data + 4);
    pDataTime->hour = CONVERT(bufTime->data + 6);
    pDataTime->min = CONVERT(bufTime->data + 8);
    pDataTime->second = CONVERT(bufTime->data + 10);
    return 0;
}

static int32_t GetX509TimeFormat(TIME_FUNC fuc, const X509 *x509cert, char *outBuf, uint32_t outBufMaxSize)
{
    if (x509cert == NULL || outBuf == NULL || outBufMaxSize == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct DataTime dataTime;
    int32_t ret = GetX509Time(fuc, x509cert, &dataTime);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    char buf[TIME_FORMAT_MAX_SIZE] = {0};
    if (snprintf_s(buf, TIME_FORMAT_MAX_SIZE, TIME_FORMAT_MAX_SIZE - 1,
        "%d-%d-%d", (int)dataTime.year, (int)dataTime.month, (int)dataTime.day) < 0) {
        return  CMR_ERROR_INVALID_OPERATION;
    }

    uint32_t length = (uint32_t)strlen(buf);
    if (length >= outBufMaxSize) {
        CM_LOG_E("GetX509TimeFormat buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    if (strncpy_s(outBuf, outBufMaxSize, buf, length) != EOK) {
        return  CMR_ERROR_INVALID_OPERATION;
    }
    return (int32_t)length;
}
int32_t GetX509NotBefore(const X509 *x509cert, char *outBuf, uint32_t outBufMaxSize)
{
    return GetX509TimeFormat(X509_getm_notBefore, x509cert, outBuf, outBufMaxSize);
}

int32_t GetX509NotAfter(const X509 *x509cert, char *outBuf, uint32_t outBufMaxSize)
{
    return GetX509TimeFormat(X509_getm_notAfter, x509cert, outBuf, outBufMaxSize);
}

int32_t GetX509Fingerprint(const X509 *x509cert, char *outBuf, uint32_t outBufMaxSize)
{
    uint32_t size = 0;
    uint8_t md[EVP_MAX_MD_SIZE] = {0};
    if (x509cert == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t res = X509_digest(x509cert, EVP_sha256(), md, &size);
    if (res < 0) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }
    char buf[FINGERPRINT_MAX_SIZE] = {0};
    for (uint32_t i = 0; i < size; ++i) {
        if (snprintf_s(buf + 3 * i, FINGERPRINT_MAX_SIZE - 3 * i, /* 3 is  array index */
            FINGERPRINT_MAX_SIZE - 3 * i - 1,  /* 3 is  array index */
            "%02X%c", md[i], (char)(((i + 1) == size) ? '\0' : ':')) < 0) {
            return  CMR_ERROR_INVALID_OPERATION;
        }
    }
    uint32_t length = (uint32_t)strlen(buf);
    if (length >= outBufMaxSize) {
        CM_LOG_E("GetX509Fingerprint buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (strncpy_s(outBuf, outBufMaxSize, buf, length) != EOK) {
        return  CMR_ERROR_INVALID_OPERATION;
    }
    return (int32_t)length;
}

void FreeCertContext(X509 *x509cert)
{
    if (!x509cert) {
        return;
    }
    X509_free(x509cert);
}
