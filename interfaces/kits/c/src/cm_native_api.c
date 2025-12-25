/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cm_native_api.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cert_manager_api.h"
#include "securec.h"

#define APPLICATION_PUBLIC_CERTIFICATION_STORE  0
#define APPLICATION_PRIVATE_CERTIFICATION_STORE 3

struct CmErrorCodeAdapter {
    int32_t nativeErrCode;
    int32_t ndkErrCode;
};

static struct CmErrorCodeAdapter g_errCodeTable[] = {
    // success
    { CM_SUCCESS, OH_CM_SUCCESS},
    // invalid params
    { CMR_ERROR_INVALID_ARGUMENT, OH_CM_PARAMETER_VALIDATION_FAILED },

    // no permission
    { CMR_ERROR_PERMISSION_DENIED, OH_CM_HAS_NO_PERMISSION },

    { CMR_ERROR_INVALID_CERT_FORMAT, OH_CM_INVALID_CERT_FORMAT },
    { CMR_ERROR_INSUFFICIENT_DATA, OH_CM_INVALID_CERT_FORMAT },
    { CMR_ERROR_NOT_FOUND, OH_CM_NOT_FOUND },
    { CMR_ERROR_NOT_EXIST, OH_CM_NOT_FOUND },
    { CMR_ERROR_MAX_CERT_COUNT_REACHED, OH_CM_MAX_CERT_COUNT_REACHED },
    { CMR_ERROR_AUTH_CHECK_FAILED, OH_CM_NO_AUTHORIZATION },
    { CMR_ERROR_DEVICE_ENTER_ADVSECMODE, OH_CM_DEVICE_ENTER_ADVSECMODE },

    // ukey
    { CMR_ERROR_UKEY_GENERAL_ERROR, OH_CM_ACCESS_UKEY_SERVICE_FAILED },
    { CMR_ERROR_UKEY_DEVICE_SUPPORT, OH_CM_CAPABILITY_NOT_SUPPORTED },
    { CMR_ERROR_HUKS_GENERAL_ERROR, OH_CM_INNER_FAILURE },
};

static int32_t TranformErrorCode(int32_t errorCode)
{
    uint32_t errCodeCount = sizeof(g_errCodeTable) / sizeof(g_errCodeTable[0]);
    for (uint32_t i = 0; i < errCodeCount; ++i) {
        if (errorCode == g_errCodeTable[i].nativeErrCode) {
            return g_errCodeTable[i].ndkErrCode;
        }
    }
    return OH_CM_INNER_FAILURE;
}

static int32_t InitUkeyCertList(OH_CM_CredentialDetailList *certificateList)
{
    if (certificateList == NULL) {
        CM_LOG_E("certificateList is NULL");
        return CMR_ERROR_NULL_POINTER;
    }
    uint32_t buffSize = (MAX_COUNT_UKEY_CERTIFICATE * sizeof(OH_CM_Credential));
    certificateList->credential = (OH_CM_Credential *)CmMalloc(buffSize);
    if (certificateList->credential == NULL) {
        CM_LOG_E("malloc credential buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(certificateList->credential, buffSize, 0, buffSize);
    certificateList->credentialCount = MAX_COUNT_UKEY_CERTIFICATE;
    for (uint32_t i = 0; i < MAX_COUNT_UKEY_CERTIFICATE; ++i) {
        certificateList->credential[i].credData.data = (uint8_t *)CmMalloc(MAX_LEN_CERTIFICATE_CHAIN);
        if (certificateList->credential[i].credData.data == NULL) {
            CM_LOG_E("malloc credData buffer failed");
            return CMR_ERROR_MALLOC_FAIL;
        }
        (void)memset_s(certificateList->credential[i].credData.data, MAX_LEN_CERTIFICATE_CHAIN,
            0, MAX_LEN_CERTIFICATE_CHAIN);
        certificateList->credential[i].credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    }
    return CM_SUCCESS;
}

static int32_t InitAppCert(OH_CM_Credential *credential)
{
    if (credential == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }
    credential->credData.data = (uint8_t *)(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    if (credential->credData.data == NULL) {
        CM_LOG_E("malloc file buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(credential->credData.data, MAX_LEN_CERTIFICATE_CHAIN, 0, MAX_LEN_CERTIFICATE_CHAIN);
    credential->credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    return CM_SUCCESS;
}

static bool CheckCertPurpose(uint32_t certPurpose)
{
    switch (certPurpose) {
        case CM_CERT_PURPOSE_DEFAULT:
        case CM_CERT_PURPOSE_ALL:
        case CM_CERT_PURPOSE_SIGN:
        case CM_CERT_PURPOSE_ENCRYPT:
            return true;
        default:
            CM_LOG_E("invalid cert purpose: %u", certPurpose);
            return false;
    }
}

int32_t OH_CertManager_GetUkeyCertificate(const OH_CM_Blob *keyUri,
    const OH_CM_UkeyInfo *ukeyInfo, OH_CM_CredentialDetailList *certificateList)
{
    if (ukeyInfo == NULL || !CheckCertPurpose(ukeyInfo->certPurpose)) {
        CM_LOG_E("cert purpose is invalid");
        return OH_CM_PARAMETER_VALIDATION_FAILED;
    }
    int32_t result = InitUkeyCertList(certificateList);
    if (result != CM_SUCCESS) {
        return TranformErrorCode(result);
    }
    result = CmGetUkeyCert((const struct CmBlob *) keyUri, (const struct UkeyInfo *) ukeyInfo,
        (struct CredentialDetailList *) certificateList);
    if (result == CM_SUCCESS && certificateList->credentialCount == 0) {
        CM_LOG_E("no available cert");
        result = CMR_ERROR_NOT_FOUND;
    }
    return TranformErrorCode(result);
}

int32_t OH_CertManager_GetPrivateCertificate(const OH_CM_Blob *keyUri, OH_CM_Credential *certificate)
{
    int32_t result = InitAppCert(certificate);
    if (result != CM_SUCCESS) {
        return TranformErrorCode(result);
    }
    result = CmGetAppCert((struct CmBlob *)keyUri, APPLICATION_PRIVATE_CERTIFICATION_STORE,
        (struct Credential *)certificate);
    return TranformErrorCode(result);
}

int32_t OH_CertManager_GetPublicCertificate(const OH_CM_Blob *keyUri, OH_CM_Credential *certificate)
{
    int32_t result = InitAppCert(certificate);
    if (result != CM_SUCCESS) {
        return TranformErrorCode(result);
    }
    result = CmGetAppCert((struct CmBlob *)keyUri, APPLICATION_PUBLIC_CERTIFICATION_STORE,
        (struct Credential *)certificate);
    return TranformErrorCode(result);
}

void OH_CertManager_FreeUkeyCertificate(OH_CM_CredentialDetailList *certificateList)
{
    CmFreeUkeyCertificate((struct CredentialDetailList *)certificateList);
}

void OH_CertManager_FreeCredential(OH_CM_Credential *certificate)
{
    CmFreeCredential((struct Credential *)certificate);
}