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

static int32_t GetCertAliasByCertInfo(const struct HksExtCertInfo *certInfo, struct CmBlob *certAlias)
{
    if ((certInfo == NULL) || (certInfo->index.data == NULL) || (certInfo->cert.data == NULL)) {
        CM_LOG_E("GetCertAliasByCertInfo params is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CmBlob certBlob = { certInfo->cert.size, certInfo->cert.data };

    int32_t ret = CmGetAliasFromSubjectName(&certBlob, certAlias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("failed to get cert subject name, ret = %d", ret);
        uint32_t aliasLen = (uint32_t)certInfo->index.size;
        if (certInfo->index.size > MAX_LEN_CERT_ALIAS) {
            aliasLen = MAX_LEN_CERT_ALIAS; // truncate copy
        }
        if (memcpy_s(certAlias->data, certAlias->size, certInfo->index.data, aliasLen) != EOK) {
            CM_LOG_E("failed to copy certAlias->data");
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
    }
    return CM_SUCCESS;
}

static int32_t ParseUkeyCertFromHuksCertInfo(const struct HksExtCertInfo *certInfo, struct CmBlob *certType,
    struct CmBlob *certUri,  struct CmBlob *certAlias)
{
    if ((certInfo == NULL) || (certInfo->index.data == NULL) || (certInfo->cert.data == NULL)) {
        CM_LOG_E("ParseUkeyCertFromHuksCertInfo params is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = CM_SUCCESS;
    if (memcpy_s(certType->data, certType->size, g_types[UKEY_TYPE_INDEX], strlen(g_types[UKEY_TYPE_INDEX]) + 1)
        != EOK) {
        CM_LOG_E("failed to copy certType->type!");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    certType->size = strlen(g_types[UKEY_TYPE_INDEX]) + 1;

    if (memcpy_s(certUri->data, certUri->size, certInfo->index.data, certInfo->index.size) != EOK) {
        CM_LOG_E("failed to copy certUri->data");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    certUri->size = certInfo->index.size;

    ret = GetCertAliasByCertInfo(certInfo, certAlias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("failed to GetCertAliasByCertInfo");
        return ret;
    }
    return CM_SUCCESS;
}

static int32_t CopyCertSize(const struct HksExtCertInfo *certInfo, struct CmBlob *certificateList,
    uint32_t *offset)
{
    uint32_t certCount = (((certInfo->cert.size > 0) && (certInfo->cert.data != NULL)) ? 1 : 0);

    int32_t ret = CopyUint32ToBuffer(certCount, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy credential->isExist failed");
        return ret;
    }
    if (certCount == 0) {
        CM_LOG_E("app cert not exist");
        return CMR_ERROR_NOT_EXIST;
    }
    return ret;
}

static int32_t CopyCertificateInfoToBuffer(const struct HksExtCertInfo *certInfo, struct CmBlob *certificateList,
    uint32_t *offset)
{
    int32_t ret = CopyUint32ToBuffer(CERT_NUM, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy credential->certNum failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(KEY_NUM, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get credential->keyNum failed");
        return ret;
    }

    struct CmBlob ukeyCertBlob = { certInfo->cert.size, certInfo->cert.data };
    ret = CopyBlobToBuffer(&ukeyCertBlob, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy credential->cred failed");
    }

    return ret;
}

static int32_t BuildCredentialToCmBlob(const struct HksExtCertInfo *certInfo, struct CmBlob *certificateList,
    uint32_t *offset)
{
    int32_t ret = CM_SUCCESS;
    if (CopyCertSize(certInfo, certificateList, offset) != CM_SUCCESS) {
        CM_LOG_E("BuildCredentialToCmBlob failed");
        return CMR_ERROR_NOT_EXIST;
    }
    uint8_t typeBuf[MAX_LEN_SUBJECT_NAME] = {0};
    struct CmBlob certType = { sizeof(typeBuf), typeBuf };
    uint8_t certUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob certUri = { sizeof(certUriBuf), certUriBuf };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    ret = ParseUkeyCertFromHuksCertInfo(certInfo, &certType, &certUri, &certAlias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmCertListGetAppCertInfo failed");
        return ret;
    }
    ret = CopyBlobToBuffer(&certType, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certType failed");
        return ret;
    }
    ret = CopyBlobToBuffer(&certUri, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certUri failed");
        return ret;
    }
    ret = CopyBlobToBuffer(&certAlias, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certAlies failed");
        return ret;
    }
    ret = CopyCertificateInfoToBuffer(certInfo, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy CertificateInfo failed");
        return ret;
    }
    ret = CopyUint32ToBuffer(certInfo->purpose, certificateList, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certificate count failed");
        return ret;
    }
    return ret;
}

static int32_t BuildCertSetToCmBlob(const struct HksExtCertInfoSet *certSet, struct CmBlob *certificateList)
{
    CM_LOG_I("enter BuildCertSetToCmBlob");
    // build certCount
    uint32_t offset = 0;
    int32_t ret = CopyUint32ToBuffer(certSet->count, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certificate count failed");
        return ret;
    }
    CM_LOG_I("get ukey cert count: %u", certSet->count);
    for (uint32_t i = 0; i < certSet->count; i++) {
        ret = BuildCredentialToCmBlob(&certSet->certs[i], certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("BuildCredentialToCmBlob failed");
            return ret;
        }
    }
    return ret;
}

int32_t CmGetUkeyCertListByHksCertInfoSet(const struct CmBlob *ukeyProvider, uint32_t certPurpose, uint32_t paramsCount,
    struct CmBlob *certificateList)
{
    if (ukeyProvider == NULL || certificateList->data == NULL) {
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
        ret = BuildCertSetToCmBlob(&certSet, certificateList);
        if (ret != CM_SUCCESS) {
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
    struct CmBlob *certificateList)
{
    if (keyUri == NULL || keyUri->data == NULL || certificateList->data == NULL) {
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
        ret = BuildCertSetToCmBlob(&certSet, certificateList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("BuildCertSetToCmBlob failed, ret = %d", ret);
            break;
        }
    } while (0);
    HksFreeExtCertSet(&certSet);
    HksFreeParamSet(&paramSetIn);
    CM_FREE_BLOB(index);
    return ret;
}
