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

#include "cm_ipc_service_serialization.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_param.h"

#include "cert_manager_check.h"
#include "cert_manager_query.h"

int32_t CopyUint32ToBuffer(uint32_t value, const struct CmBlob *destBlob, uint32_t *destOffset)
{
    if ((*destOffset > destBlob->size) || ((destBlob->size - *destOffset) < sizeof(value))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &value, sizeof(value)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    *destOffset += sizeof(value);
    return CM_SUCCESS;
}

int32_t CopyBlobToBuffer(const struct CmBlob *blob, const struct CmBlob *destBlob, uint32_t *destOffset)
{
    if ((*destOffset > destBlob->size) ||
        ((destBlob->size - *destOffset) < (sizeof(blob->size) + ALIGN_SIZE(blob->size)))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset,
                 &(blob->size), sizeof(blob->size)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    *destOffset += sizeof(blob->size);

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, blob->data, blob->size) != EOK) {
        *destOffset -= sizeof(blob->size);
        return CMR_ERROR_INVALID_OPERATION;
    }
    *destOffset += ALIGN_SIZE(blob->size);
    return CM_SUCCESS;
}

static int32_t GetNormalParam(const struct CmParam *param, struct CmParamOut *outParams)
{
    switch (GetTagType(outParams->tag)) {
        case CM_TAG_TYPE_INT:
            *(outParams->int32Param) = param->int32Param;
            break;
        case CM_TAG_TYPE_UINT:
            *(outParams->uint32Param) = param->uint32Param;
            break;
        case CM_TAG_TYPE_ULONG:
            *(outParams->uint64Param) = param->uint64Param;
            break;
        case CM_TAG_TYPE_BOOL:
            *(outParams->boolParam) = param->boolParam;
            break;
        case CM_TAG_TYPE_BYTES:
            *(outParams->blob) = param->blob;
            break;
        default:
            CM_LOG_I("invalid tag type:%x", GetTagType(outParams->tag));
            return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static int32_t GetNullBlobParam(const struct CmParamSet *paramSet, struct CmParamOut *outParams)
{
    if (GetTagType(outParams->tag) != CM_TAG_TYPE_BYTES) {
        CM_LOG_E("param tag[0x%x] is not bytes", outParams->tag);
        return CMR_ERROR_PARAM_NOT_EXIST;
    }

    struct CmParam *param = NULL;
    int32_t ret = CmGetParam(paramSet, outParams->tag + CM_PARAM_BUFFER_NULL_INTERVAL, &param);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get param tag[0x%x] from ipc buffer failed", outParams->tag + CM_PARAM_BUFFER_NULL_INTERVAL);
        return ret;
    }

    outParams->blob->data = NULL;
    outParams->blob->size = 0;
    return CM_SUCCESS;
}

int32_t CmParamSetToParams(const struct CmParamSet *paramSet, struct CmParamOut *outParams, uint32_t cnt)
{
    struct CmParam *param = NULL;
    for (uint32_t i = 0; i < cnt; i++) {
        int32_t ret = CmGetParam(paramSet, outParams[i].tag, &param);
        if (ret == CM_SUCCESS) {
            ret = GetNormalParam(param, &outParams[i]);
        } else {
            ret = GetNullBlobParam(paramSet, &outParams[i]);
        }
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get param failed, ret = %d", ret);
            return ret;
        }
    }
    return CM_SUCCESS;
}

static int32_t CmGetCertListPack(const struct CertBlob *certBlob, uint32_t *status, uint32_t certCount,
    struct CmBlob *certificateList)
{
    uint32_t offset = 0;
    uint32_t buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) +
        sizeof(uint32_t) + MAX_LEN_URI + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;
    if (certificateList->size < buffSize) {
        CM_LOG_E("outdata size too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    certificateList->size = buffSize;

    int32_t ret = CopyUint32ToBuffer(certCount, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy cert count failed");
        return ret;
    }

    for (uint32_t i = 0; i < certCount; i++) {
        ret = CopyBlobToBuffer(&(certBlob->subjectName[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate subject failed");
            return ret;
        }
        ret = CopyUint32ToBuffer(status[i], certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate status failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->uri[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate uri failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->certAlias[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate certAlias failed");
            return ret;
        }
    }
    return ret;
}

int32_t CmServiceGetCertListPack(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CmBlob *certificateList)
{
    uint32_t status[MAX_COUNT_CERTIFICATE] = {0};
    struct CertBlob certBlob;
    (void)memset_s(&certBlob, sizeof(struct CertBlob), 0, sizeof(struct CertBlob));
    int32_t ret = CmGetCertListInfo(context, store, certFileList, &certBlob, status);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertListInfo fail");
        CmFreeCertBlob(&certBlob);
        return ret;
    }

    ret = CmGetCertListPack(&certBlob, status, certFileList->size, certificateList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertListPack fail");
        CmFreeCertBlob(&certBlob);
        return ret;
    }

    CmFreeCertBlob(&certBlob);
    return ret;
}

int32_t CmServiceGetCertInfoPack(const uint32_t store, const struct CmBlob *certificateData,
    uint32_t status, const struct CmBlob *certUri, struct CmBlob *certificateInfo)
{
    if (certificateData->size == 0) {
        CM_LOG_I("cert file is not exist");
        return CM_SUCCESS;
    }

    uint32_t buffSize = sizeof(uint32_t) + MAX_LEN_CERTIFICATE + sizeof(uint32_t) +
        MAX_LEN_CERT_ALIAS + sizeof(uint32_t);
    if (certificateInfo->size < buffSize) {
        CM_LOG_E("outdata size too small");
        return CMR_ERROR_MALLOC_FAIL;
    }
    certificateInfo->size = buffSize;

    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(certificateData, certificateInfo, &offset); /* certData */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert data failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(status, certificateInfo, &offset); /* status */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert status failed");
        return ret;
    }

    struct CmBlob certAlias;
    certAlias.size = MAX_LEN_CERT_ALIAS;
    certAlias.data = (uint8_t *)CmMalloc(MAX_LEN_CERT_ALIAS);
    if (certAlias.data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(certAlias.data, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);

    ret = CmGetCertAlias(store, (char *)certUri->data, certificateData, &(certAlias));
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert certAlias");
        CM_FREE_BLOB(certAlias);
        return CM_FAILURE;
    }

    ret = CopyBlobToBuffer(&certAlias, certificateInfo, &offset); /* certAlias */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert data failed");
        CM_FREE_BLOB(certAlias);
        return ret;
    }
    CM_FREE_BLOB(certAlias);
    return ret;
}

