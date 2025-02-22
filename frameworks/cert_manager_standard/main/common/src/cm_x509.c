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

#include "cm_x509.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <string.h>
#include <time.h>

#include "securec.h"

#include "cm_log.h"

typedef X509_NAME *(FUNC)(const X509 *);
typedef ASN1_TIME *(TIME_FUNC)(const X509 *);
#define CONVERT(p) (((p)[0] - '0') * 10 + (p)[1] - '0')
#define BASE_YEAR 1900

X509 *InitCertContext(const uint8_t *certBuf, uint32_t size)
{
    X509 *x509 = NULL;
    if (certBuf == NULL || size > MAX_LEN_CERTIFICATE || size == 0) {
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
        return CMR_ERROR_MEM_OPERATION_COPY;
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

        if (strname == NULL) {
            continue;
        }

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
                return CMR_ERROR_MEM_OPERATION_COPY;
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

static int32_t GetX509FirstSubjectName(const X509 *x509cert, struct CmBlob *displaytName)
{
    char *outBuf = (char *)displaytName->data;
    const char *subjectNameList[] = {CM_COMMON_NAME, CM_ORGANIZATION_UNIT_NAME, CM_ORGANIZATION_NAME};
    uint32_t sizeList = sizeof(subjectNameList) / sizeof(subjectNameList[0]);
    for (uint32_t j = 0; j < sizeList; ++j) {
        int32_t length = 0;
        char subjectName[NAME_MAX_SIZE] = { 0 };
        length = GetX509SubjectName(x509cert, subjectNameList[j], subjectName, NAME_MAX_SIZE);
        if (length < 0) {
            return CMR_ERROR_INVALID_CERT_FORMAT;
        } else if ((uint32_t)length >= displaytName->size) {
            return CMR_ERROR_BUFFER_TOO_SMALL;
        }
        if (strlen(subjectName) > 0) {
            if (strncpy_s(outBuf, displaytName->size, subjectName, strlen(subjectName)) != EOK) {
                return CMR_ERROR_MEM_OPERATION_COPY;
            }
            outBuf[length] = '\0';
            displaytName->size = (uint32_t)(length + 1);
            break;
        }
    }
    return CM_SUCCESS;
}

static int32_t GetX509FirstSubjectProp(const X509 *x509cert, struct CmBlob *displaytName)
{
    int32_t length = 0;
    char *outBuf = (char *)displaytName->data;
    X509_NAME *name = X509_get_subject_name(x509cert);
    if (name == NULL) {
        CM_LOG_E("X509_get_subject_name get name faild");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }
    X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, 0);
    char *data = NULL;
    length = ASN1_STRING_to_UTF8((unsigned char **)&data, X509_NAME_ENTRY_get_data(entry));
    if (length < 0) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    } else if ((uint32_t)length >= displaytName->size) {
        OPENSSL_free(data);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    if (strncpy_s(outBuf, displaytName->size, data, length) != EOK) {
        OPENSSL_free(data);
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    outBuf[length] = '\0';
    displaytName->size = (uint32_t)(length + 1);
    OPENSSL_free(data);
    return CM_SUCCESS;
}

static int32_t GetDisplayName(X509 *x509cert, const struct CmBlob *certAlias,
    const char *subjectName, struct CmBlob *displaytName)
{
    int32_t ret = CM_SUCCESS;
    if (strcmp("", (char *)certAlias->data) == 0) {
        if (strcmp(CM_SUBJECT_NAME_NULL, subjectName) == 0) {
            ret = GetX509FirstSubjectProp(x509cert, displaytName);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("GetX509FirstSubjectProp failed");
                return ret;
            }
        } else {
            ret = GetX509FirstSubjectName(x509cert, displaytName);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("GetX509FirstSubjectName failed");
                return ret;
            }
        }
    } else {
        if (memcpy_s(displaytName->data, displaytName->size, certAlias->data, certAlias->size) != EOK) {
            CM_LOG_E("copy displayname failed");
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
        displaytName->size = certAlias->size;
    }
    return ret;
}

int32_t GetSubjectNameAndAlias(X509 *x509cert, const struct CmBlob *certAlias,
    struct CmBlob *subjectName, struct CmBlob *displaytName)
{
    if ((x509cert == NULL) || (CmCheckBlob(certAlias) != CM_SUCCESS) ||
        (subjectName == NULL) || (displaytName == NULL)) {
        CM_LOG_E("input param is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t subjectLen = GetX509SubjectNameLongFormat(x509cert, (char *)subjectName->data, MAX_LEN_SUBJECT_NAME);
    if (subjectLen <= 0) {
        CM_LOG_E("get cert subjectName failed");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }
    subjectName->size = (uint32_t)subjectLen + 1;

    int32_t ret = GetDisplayName(x509cert, certAlias, (char *)subjectName->data, displaytName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetDisplayName failed");
        return ret;
    }
    return CM_SUCCESS;
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
            return CMR_ERROR_MEM_OPERATION_PRINT;
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
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }
        offset += strlen(issueNameList[j]) + strlen(issueName) + NAME_DELIMITER_SIZE;
    }
    return (int32_t)strlen(outBuf);
}

static struct tm *GetLocalTime(ASN1_TIME *asn1Time)
{
    time_t curLocalTimeSec = time(NULL);
    if (curLocalTimeSec < 0) {
        CM_LOG_E("Failed to get current local time");
        return NULL;
    }

    struct tm *gmTime = gmtime(&curLocalTimeSec);
    if (gmTime == NULL) {
        CM_LOG_E("Failed to convert current local time to utc time");
        return NULL;
    }

    time_t curUtcTimeSec = mktime(gmTime);
    if (curUtcTimeSec < 0) {
        CM_LOG_E("Failed to get current utc time");
        return NULL;
    }

    struct tm utcTime;
    int ret = ASN1_TIME_to_tm(asn1Time, &utcTime);
    if (ret == 0) {
        CM_LOG_E("invalid asn1 time format");
        return NULL;
    }

    time_t utcTimeSec = mktime(&utcTime);
    if (utcTimeSec < 0) {
        CM_LOG_E("Failed to get utc time");
        return NULL;
    }
    time_t localTimeSec = utcTimeSec + curLocalTimeSec - curUtcTimeSec;
    return localtime(&localTimeSec);
}

static int32_t GetX509Time(TIME_FUNC fuc, const X509 *x509cert, struct DataTime *pDataTime)
{
    if (x509cert == NULL || fuc == NULL || pDataTime == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    ASN1_TIME *asn1Time = fuc(x509cert);
    if (asn1Time == NULL) {
        CM_LOG_E("Failed to get asn1 time from x509Cert");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    if (asn1Time->length < NAME_ANS1TIME_LEN) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    struct tm *localTime = GetLocalTime(asn1Time);
    if (localTime == NULL) {
        CM_LOG_E("Failed to get local time by utc time");
        return CMR_ERROR_GET_LOCAL_TIME_FAILED;
    }

    pDataTime->year = (uint32_t)(localTime->tm_year + BASE_YEAR);
    pDataTime->month = (uint32_t)(localTime->tm_mon + 1);
    pDataTime->day = (uint32_t)localTime->tm_mday;
    pDataTime->hour = (uint32_t)localTime->tm_hour;
    pDataTime->min = (uint32_t)localTime->tm_min;
    pDataTime->second = (uint32_t)localTime->tm_sec;
    return CM_SUCCESS;
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
        return  CMR_ERROR_MEM_OPERATION_PRINT;
    }

    uint32_t length = (uint32_t)strlen(buf);
    if (length >= outBufMaxSize) {
        CM_LOG_E("GetX509TimeFormat buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    if (strncpy_s(outBuf, outBufMaxSize, buf, length) != EOK) {
        return  CMR_ERROR_MEM_OPERATION_COPY;
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
            return  CMR_ERROR_MEM_OPERATION_PRINT;
        }
    }
    uint32_t length = (uint32_t)strlen(buf);
    if (length >= outBufMaxSize) {
        CM_LOG_E("GetX509Fingerprint buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (strncpy_s(outBuf, outBufMaxSize, buf, length) != EOK) {
        return  CMR_ERROR_MEM_OPERATION_PRINT;
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
