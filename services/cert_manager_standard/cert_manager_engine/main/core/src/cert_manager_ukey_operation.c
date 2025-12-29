/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cert_manager_ukey_operation.h"

#include "securec.h"

#include "cm_type_free.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_param.h"
#include "cm_mem.h"
#include "cert_manager_uri.h"
#include "cert_manager_query.h"
#include "cm_ipc_service_serialization.h"

#include "hks_api.h"
#include "hks_type.h"
#include "hks_param.h"

#define UKEY_TYPE_INDEX    5
#define CERT_NUM          (-1)
#define KEY_NUM           (-1)

static int32_t ConvertHuksErrCode(int32_t huksErrCode)
{
    switch (huksErrCode) {
        case HKS_ERROR_API_NOT_SUPPORTED:
            return CMR_ERROR_UKEY_DEVICE_SUPPORT;
        case HKS_ERROR_REMOTE_OPERATION_FAILED:
            return CMR_ERROR_UKEY_GENERAL_ERROR;
        default:
            return CMR_ERROR_HUKS_GENERAL_ERROR;
    }
}

static int32_t ParseParamsToHuksParamSet(uint32_t certPurpose, struct HksParamSet **paramSetIn,
    uint32_t paramsCount)
{
    struct HksParam params[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = certPurpose },
    };

    int32_t ret = HksInitParamSet(paramSetIn);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("HksInitParamSet failed");
        return ret;
    }
    ret = HksAddParams(*paramSetIn, params, paramsCount - 1);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("HksAddParams failed");
        return ret;
    }
    ret = HksBuildParamSet(paramSetIn);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("HksBuildParamSet failed");
        return ret;
    }
    return ret;
}

static int32_t BuildCmBlobToHuksParams(const struct CmBlob *cmParam, uint32_t certPurpose,
    uint32_t paramsCount, struct HksBlob *hksParam, struct HksParamSet **paramSetIn)
{
    CM_LOG_I("enter BuildCmBlobToHuksParams");
    if (cmParam == NULL) {
        CM_LOG_E("cmParam is NULL");
        return CMR_ERROR_NULL_POINTER;
    }
    if (cmParam->size != 0) {
        hksParam->data = (uint8_t *)CmMalloc(cmParam->size);
        if (hksParam->data == NULL) {
            CM_LOG_E("malloc buffer failed!");
            return CMR_ERROR_MALLOC_FAIL;
        }
        hksParam->size = cmParam->size;
        if (memcpy_s(hksParam->data, cmParam->size, cmParam->data, cmParam->size) != EOK) {
            CM_LOG_E("copy hksParam failed!");
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
    }
    int32_t ret = ParseParamsToHuksParamSet(certPurpose, paramSetIn, paramsCount);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("ParseParamsToHuksParamSet failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

static int32_t GetCertAliasByCertInfo(const struct HksExtCertInfo *certInfo, struct Credential *credential)
{
    if ((certInfo == NULL) || (certInfo->index.data == NULL) || (certInfo->cert.data == NULL)) {
        CM_LOG_E("GetCertAliasByCertInfo params is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CmBlob certBlob = { certInfo->cert.size, certInfo->cert.data };

    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    (void)memset_s(credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);

    uint32_t aliasLen = (uint32_t)certInfo->index.size;
    int32_t ret = CmGetAliasFromSubjectName(&certBlob, &certAlias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("failed to get cert subject name, ret = %d", ret);
        if (aliasLen > MAX_LEN_CERT_ALIAS) {
            aliasLen = MAX_LEN_CERT_ALIAS - 1; // truncate copy
        }
        if (memcpy_s(credential->alias, MAX_LEN_CERT_ALIAS, certInfo->index.data, aliasLen) != EOK) {
            CM_LOG_E("failed to copy certAlias->data");
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
        credential->alias[aliasLen] = '\0';
    } else {
        if (memcpy_s(credential->alias, MAX_LEN_CERT_ALIAS, certAlias.data, certAlias.size) != EOK) {
            CM_LOG_E("failed to copy certAlias->data");
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
    }
    return CM_SUCCESS;
}

static int32_t ParseUkeyCertFromHuksCertInfo(const struct HksExtCertInfo *certInfo, struct Credential *credential)
{
    if ((certInfo == NULL) || (certInfo->index.data == NULL) || (certInfo->cert.data == NULL)) {
        CM_LOG_E("ParseUkeyCertFromHuksCertInfo params is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = CM_SUCCESS;
    (void)memset_s(credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    if (memcpy_s(credential->type, MAX_LEN_SUBJECT_NAME, g_types[UKEY_TYPE_INDEX], strlen(g_types[UKEY_TYPE_INDEX]) + 1)
        != EOK) {
        CM_LOG_E("failed to copy type!");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    (void)memset_s(credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    if (certInfo->index.size > MAX_LEN_URI) {
        CM_LOG_E("invalid uri!");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (memcpy_s(credential->keyUri, MAX_LEN_URI, certInfo->index.data, certInfo->index.size) != EOK) {
        CM_LOG_E("failed to copy keyUri");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }

    ret = GetCertAliasByCertInfo(certInfo, credential);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("failed to GetCertAliasByCertInfo");
        return ret;
    }
    return CM_SUCCESS;
}

static int32_t CopyCertSize(const struct HksExtCertInfo *certInfo, struct Credential *credential)
{
    uint32_t certCount = (((certInfo->cert.size > 0) && (certInfo->cert.data != NULL)) ? 1 : 0);

    credential->isExist = certCount;
    if (certCount == 0) {
        CM_LOG_E("app cert not exist");
        return CMR_ERROR_NOT_EXIST;
    }
    return CM_SUCCESS;
}

static int32_t CopyCertificateInfoToCredential(const struct HksExtCertInfo *certInfo, struct Credential *credential)
{
    credential->certNum = CERT_NUM;
    credential->keyNum = KEY_NUM;

    struct CmBlob ukeyCertBlob = { certInfo->cert.size, certInfo->cert.data };

    if (memcpy_s(credential->credData.data, credential->credData.size, ukeyCertBlob.data, ukeyCertBlob.size)
        != EOK) {
        CM_LOG_E("failed to copy credData!");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }

    return CM_SUCCESS;
}

static int32_t BuildCertInfoToCredential(const struct HksExtCertInfo *certInfo, struct Credential *credential)
{
    int32_t ret = CM_SUCCESS;
    if (CopyCertSize(certInfo, credential) != CM_SUCCESS) {
        CM_LOG_E("copy isExist failed");
        return CMR_ERROR_NOT_EXIST;
    }

    ret = ParseUkeyCertFromHuksCertInfo(certInfo, credential);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("ParseUkeyCertFromHuksCertInfo failed");
        return ret;
    }

    ret = CopyCertificateInfoToCredential(certInfo, credential);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CopyCertificateInfoToCredential failed");
        return ret;
    }
    credential->certPurpose = (enum CmCertificatePurpose)certInfo->purpose;
    return ret;
}

static int32_t BuildCertSetToCmBlob(const struct HksExtCertInfoSet *certSet,
    struct CredentialDetailList *credentialList)
{
    CM_LOG_I("enter BuildCertSetToCmBlob");
    // build certCount
    credentialList->credentialCount = certSet->count;
    CM_LOG_D("get ukey cert count: %u", certSet->count);
    uint32_t buffSize = certSet->count * sizeof(struct Credential);
    credentialList->credential = (struct Credential*)(CmMalloc(buffSize));
    if (credentialList->credential == NULL) {
        CM_LOG_E("malloc file buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(credentialList->credential, buffSize, 0, buffSize);
    int32_t ret = CM_SUCCESS;
    for (uint32_t i = 0; i < certSet->count; i++) {
        uint32_t credDataSize = certSet->certs[i].cert.size;
        credentialList->credential[i].credData.data = (uint8_t*)(CmMalloc(credDataSize));
        if (credentialList->credential[i].credData.data == NULL) {
            CM_LOG_E("malloc the credData failed, the idx is %u", i);
            return CMR_ERROR_MALLOC_FAIL;
        }
        credentialList->credential[i].credData.size = credDataSize;
        ret = BuildCertInfoToCredential(&certSet->certs[i], &credentialList->credential[i]);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("BuildCertInfoToCredential failed");
            CM_FREE_BLOB(credentialList->credential[i].credData);
            return ret;
        }
    }
    return ret;
}

int32_t CmGetUkeyCertListByHksCertInfoSet(const struct CmBlob *ukeyProvider, uint32_t certPurpose, uint32_t paramsCount,
    struct CredentialDetailList *credentialDetailList)
{
    if (ukeyProvider == NULL || credentialDetailList == NULL) {
        CM_LOG_E("CmGetUkeyCertByHksCertInfoSet arguments invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct HksBlob providerName = { 0, NULL };
    struct HksParamSet *paramSetIn = NULL;
    struct HksExtCertInfoSet certSet = { 0, NULL };
    int32_t ret = CM_SUCCESS;
    do {
        ret = BuildCmBlobToHuksParams(ukeyProvider, certPurpose, paramsCount, &providerName, &paramSetIn);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("BuildCmBlobToHuksParams failed, ret = %d", ret);
            break;
        }
        ret = HksExportProviderCertificates(&providerName, paramSetIn, &certSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get HksCertInfoSet from huks failed, ret = %d", ret);
            ret = ConvertHuksErrCode(ret);
            break;
        }
        ret = BuildCertSetToCmBlob(&certSet, credentialDetailList);
        if (ret != CM_SUCCESS) {
            CmFreeUkeyCertList(credentialDetailList);
            CM_LOG_E("BuildCertSetToCmBlob failed, ret = %d", ret);
            break;
        }
    } while (0);
    HksFreeExtCertSet(&certSet);
    HksFreeParamSet(&paramSetIn);
    CM_FREE_BLOB(providerName);
    return ret;
}

int32_t CmGetUkeyCertByHksCertInfoSet(const struct CmBlob *keyUri, uint32_t certPurpose, uint32_t paramsCount,
    struct CredentialDetailList *credentialDetailList)
{
    if (keyUri == NULL || keyUri->data == NULL || credentialDetailList == NULL) {
        CM_LOG_E("CmGetUkeyCertByHksCertInfoSet arguments invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct HksBlob index = { 0, NULL };
    struct HksParamSet *paramSetIn = NULL;
    struct HksExtCertInfoSet certSet = { 0, NULL };
    int32_t ret = CM_SUCCESS;
    do {
        ret = BuildCmBlobToHuksParams(keyUri, certPurpose, paramsCount, &index, &paramSetIn);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("BuildCmBlobToHuksParams failed, ret = %d", ret);
            break;
        }
        ret = HksExportCertificate(&index, paramSetIn, &certSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get HksCertInfoSet from huks failed, ret = %d", ret);
            ret = ConvertHuksErrCode(ret);
            break;
        }
        ret = BuildCertSetToCmBlob(&certSet, credentialDetailList);
        if (ret != CM_SUCCESS) {
            CmFreeUkeyCertList(credentialDetailList);
            CM_LOG_E("BuildCertSetToCmBlob failed, ret = %d", ret);
            break;
        }
    } while (0);
    HksFreeExtCertSet(&certSet);
    HksFreeParamSet(&paramSetIn);
    CM_FREE_BLOB(index);
    return ret;
}
