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

#include "cm_ipc_serialization.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_param.h"

#include "cm_ipc_check.h"

static int32_t GetContextFromBuffer(struct CmContext *cmContext, const struct CmBlob *srcData, uint32_t *offset)
{
    struct CmBlob blob = {0};
    int32_t ret = GetUint32FromBuffer(&(cmContext->userId), srcData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cmContext->userId failed");
        return ret;
    }

    ret = GetUint32FromBuffer(&(cmContext->uid), srcData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cmContext->uri failed");
        return ret;
    }
    ret = CmGetBlobFromBuffer(&blob, srcData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("malloc packageName data failed");
        return ret;
    }
    if (memcpy_s(cmContext->packageName, MAX_LEN_PACKGE_NAME, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy packageName failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return ret;
}

int32_t CmTrustCertificateListUnpack(const struct CmBlob *srcData, struct CmContext *cmContext, uint32_t *store)
{
    uint32_t offset = 0;

    int32_t ret = GetContextFromBuffer(cmContext, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cmContext failed");
        return ret;
    }

    ret = GetUint32FromBuffer(store, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get store failed");
        return ret;
    }

    return ret;
}

int32_t CmTrustCertificateInfoUnpack(const struct CmBlob *srcData, struct CmContext *cmContext,
    struct CmBlob *uriBlob, uint32_t *store)
{
    uint32_t offset = 0;

    int32_t ret = GetContextFromBuffer(cmContext, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cmContext failed");
        return ret;
    }

    ret = CmGetBlobFromBuffer(uriBlob, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("malloc packageName data failed");
        return ret;
    }

    ret = GetUint32FromBuffer(store, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get store failed");
        return ret;
    }

    return ret;
}

int32_t CmCertificateStatusUnpack(const struct CmBlob *srcData, struct CmContext *cmContext,
    struct CmBlob *uriBlob, uint32_t *store, uint32_t *status)
{
    uint32_t offset = 0;

    int32_t ret = GetContextFromBuffer(cmContext, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("StatusUnpack get cmContext failed");
        return ret;
    }

    ret = CmGetBlobFromBuffer(uriBlob, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("StatusUnpack malloc packageName data failed");
        return ret;
    }

    ret = GetUint32FromBuffer(store, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("StatusUnpack get store failed");
        return ret;
    }

    ret = GetUint32FromBuffer(status, srcData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("StatusUnpack get status failed");
        return ret;
    }

    return ret;
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
    int32_t ret;
    struct CmParam *param = NULL;
    for (uint32_t i = 0; i < cnt; i++) {
        ret = CmGetParam(paramSet, outParams[i].tag, &param);
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
