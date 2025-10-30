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

#include "cm_ipc_service_serialization.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_param.h"

int32_t CopyUint32ToBuffer(uint32_t value, const struct CmBlob *destBlob, uint32_t *destOffset)
{
    if (CmCheckBlob(destBlob) != CM_SUCCESS || destOffset == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if ((*destOffset > destBlob->size) || ((destBlob->size - *destOffset) < sizeof(value))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &value, sizeof(value)) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    *destOffset += sizeof(value);
    return CM_SUCCESS;
}

int32_t CopyBlobToBuffer(const struct CmBlob *blob, const struct CmBlob *destBlob, uint32_t *destOffset)
{
    if (CmCheckBlob(blob) != CM_SUCCESS || CmCheckBlob(destBlob) != CM_SUCCESS || destOffset == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if ((*destOffset > destBlob->size) ||
        ((destBlob->size - *destOffset) < (sizeof(blob->size) + ALIGN_SIZE(blob->size)))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset,
                 &(blob->size), sizeof(blob->size)) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    *destOffset += sizeof(blob->size);

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, blob->data, blob->size) != EOK) {
        *destOffset -= sizeof(blob->size);
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    *destOffset += ALIGN_SIZE(blob->size);
    return CM_SUCCESS;
}

static int32_t GetNormalParam(const struct CmParam *param, struct CmParamOut *outParams)
{
    switch (CmGetTagType(outParams->tag)) {
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
            CM_LOG_E("invalid tag type:%x", CmGetTagType(outParams->tag));
            return CMR_ERROR_INVALID_PARAMSET_ARG;
    }
    return CM_SUCCESS;
}

static int32_t GetNullBlobParam(const struct CmParamSet *paramSet, struct CmParamOut *outParams)
{
    if (CmGetTagType(outParams->tag) != CM_TAG_TYPE_BYTES) {
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
    if (paramSet == NULL || outParams == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
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

