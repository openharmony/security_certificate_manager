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

#ifndef CERT_MANAGER_X509_H
#define CERT_MANAGER_X509_H

#include <stdint.h>
#include <stdlib.h>
#include <openssl/x509.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SN_MAX_SIZE 64
#define TIME_FORMAT_MAX_SIZE 16
#define NAME_MAX_SIZE 256
#define FINGERPRINT_MAX_SIZE  128
#define NAME_DELIMITER_SIZE 2
#define NAME_ANS1TIME_LEN   12

#define CM_COMMON_NAME "CN"
#define CM_SURNAME   "SN"
#define CM_COUNTRY_NAME "C"
#define CM_LOCALITY_NAME "L"
#define CM_STATE_OR_PROVINCE_NAME "ST"
#define CM_STREET_ADDRESS "street"
#define CM_ORGANIZATION_NAME "O"
#define CM_ORGANIZATION_UNIT_NAME  "OU"

#define ASN1_TAG_TYPE_SEQ 0x30
enum CmCertFormat {
    CM_CERT_FORMAT_PEM,
    CM_CERT_FORMAT_DER
};

struct DataTime {
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t min;
    uint32_t second;
};

X509 *InitCertContext(const uint8_t *certBuf, uint32_t size);

int32_t GetX509SerialNumber(X509 *x509cert, char *outBuf, uint32_t outBufMaxSize);

int32_t GetX509SubjectName(const X509 *x509cert, const char *subjectObjName, char* outBuf, uint32_t outBufMaxSize);

int32_t GetX509SubjectNameLongFormat(const X509 *x509cert, char* outBuf, uint32_t outBufMaxSize);
int32_t GetX509IssueNameLongFormat(const X509 *x509cert, char* outBuf, uint32_t outBufMaxSize);

int32_t GetX509NotBefore(const X509 *x509cert, char* outBuf, uint32_t outBufMaxSize);
int32_t GetX509NotAfter(const X509 *x509cert, char* outBuf, uint32_t outBufMaxSize);

int32_t GetX509Fingerprint(const X509 *x509cert, char* outBuf, uint32_t outBufMaxSize);

void FreeCertContext(X509 *x509cert);
#ifdef __cplusplus
}
#endif
#endif
