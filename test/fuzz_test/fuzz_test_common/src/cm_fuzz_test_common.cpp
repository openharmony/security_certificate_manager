/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "cm_fuzz_test_common.h"

#include "cm_ipc_client_serialization.h"
#include "message_parcel.h"

namespace CmFuzzTest {
bool GetUintFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, uint32_t *outVal)
{
    if (*remSize < sizeof(uint32_t)) {
        return false;
    }

    (void)memcpy_s(outVal, sizeof(uint32_t), srcData + *offset, sizeof(uint32_t));
    *remSize -= sizeof(uint32_t);
    *offset += sizeof(uint32_t);

    return true;
}

bool GetCmBlobFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CmBlob *outBlob)
{
    if (GetUintFromBuffer(srcData, remSize, offset, &(outBlob->size)) != true) {
        return false;
    }

    if (*remSize < outBlob->size) {
        return false;
    }
    outBlob->data = srcData + *offset;
    *remSize -= outBlob->size;
    *offset += outBlob->size;

    return true;
}

bool GetCertListFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CertList *outList)
{
    if (GetUintFromBuffer(srcData, remSize, offset, &(outList->certsCount)) != true) {
        return false;
    }

    if (outList->certsCount > (*remSize / sizeof(struct CertAbstract))) {
        return false;
    }
    outList->certAbstract = reinterpret_cast<struct CertAbstract *>(srcData + *offset);

    return true;
}

bool GetCertInfoFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CertInfo *outInfo)
{
    if (*remSize < sizeof(struct CertInfo)) {
        return false;
    }

    outInfo = reinterpret_cast<struct CertInfo *>(srcData + *offset);
    *remSize -= sizeof(struct CertInfo);
    *offset += sizeof(struct CertInfo);

    if (*remSize < outInfo->certInfo.size) {
        return false;
    }

    outInfo->certInfo.data = const_cast<uint8_t *>(srcData + *offset);
    return true;
}

bool CopyMyData(const uint8_t *data, const size_t size, const uint32_t minSize, uint8_t **myData)
{
    if (data == nullptr|| static_cast<uint32_t>(size) < minSize) {
        return false;
    }

    uint8_t *tempData = static_cast<uint8_t *>(CmMalloc(sizeof(uint8_t) * size));
    if (tempData == nullptr) {
        return false;
    }
    (void)memcpy_s(tempData, size, data, size);

    *myData = tempData;
    return true;
}

constexpr uint32_t PARAM_COUNT_ONE = 1;
constexpr uint32_t PARAM_COUNT_TWO = 2;
constexpr uint32_t PARAM_COUNT_THREE = 3;
constexpr uint32_t PARAM_COUNT_FOUR = 4;

struct CmFuzzerCodeParams {
    CertManagerInterfaceCode code;
    uint32_t paramCnt;
    struct CmParam params[PARAM_COUNT_FOUR];
};

constexpr struct CmFuzzerCodeParams g_codeParams[] = {
    {   CM_MSG_GET_CERTIFICATE_LIST,
        PARAM_COUNT_ONE,
        {
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 }
        }
    },
    {   CM_MSG_GET_CERTIFICATE_INFO,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_SET_CERTIFICATE_STATUS,
        PARAM_COUNT_THREE,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_INSTALL_APP_CERTIFICATE,
        PARAM_COUNT_FOUR,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM2_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM3_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_UNINSTALL_APP_CERTIFICATE,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_UNINSTALL_ALL_APP_CERTIFICATE,
        0,
        {
        }
    },
    {   CM_MSG_GET_APP_CERTIFICATE_LIST,
        PARAM_COUNT_ONE,
        {
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_GET_APP_CERTIFICATE,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_GRANT_APP_CERT,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_GET_AUTHED_LIST,
        PARAM_COUNT_ONE,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
        }
    },
    {   CM_MSG_CHECK_IS_AUTHED_APP,
        PARAM_COUNT_ONE,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
        }
    },
    {   CM_MSG_REMOVE_GRANT_APP,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_INIT,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = { 0, nullptr } },
        }
    },
    {   CM_MSG_UPDATE,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = { 0, nullptr } },
        }
    },
    {   CM_MSG_FINISH,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = { 0, nullptr } },
        }
    },
    {   CM_MSG_ABORT,
        PARAM_COUNT_ONE,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
        }
    },
    {   CM_MSG_GET_USER_CERTIFICATE_LIST,
        PARAM_COUNT_ONE,
        {
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_GET_USER_CERTIFICATE_INFO,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_SET_USER_CERTIFICATE_STATUS,
        PARAM_COUNT_THREE,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = 0 },
        }
    },
    {   CM_MSG_INSTALL_USER_CERTIFICATE,
        PARAM_COUNT_TWO,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = { 0, nullptr } },
        }
    },
    {   CM_MSG_UNINSTALL_USER_CERTIFICATE,
        PARAM_COUNT_ONE,
        {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
        }
    },
    {   CM_MSG_UNINSTALL_ALL_USER_CERTIFICATE,
        0,
        {
        }
    },
};

bool ConstructParamSet(uint8_t *srcData, uint32_t *remainSize,
    uint32_t *offset, CertManagerInterfaceCode code, struct CmParamSet **paramSetOut)
{
    struct CmParam params[PARAM_COUNT_FOUR] = {};
    uint32_t paramCnt = 0;
    for (uint32_t i = 0; i < (sizeof(g_codeParams) / sizeof(g_codeParams[0])); ++i) {
        if (code == g_codeParams[i].code) {
            (void)memcpy_s(params, (sizeof(struct CmParam) * g_codeParams[i].paramCnt),
                g_codeParams[i].params, (sizeof(struct CmParam) * g_codeParams[i].paramCnt));
            paramCnt = g_codeParams[i].paramCnt;
            break;
        }
    }

    for (uint32_t i = 0; i < paramCnt; ++i) {
        switch (GetTagType(static_cast<enum CmTag>(params[i].tag))) {
            case CM_TAG_TYPE_BYTES:
                if (!GetCmBlobFromBuffer(srcData, remainSize, offset, &(params[i].blob))) {
                    return false;
                }
                break;
            case CM_TAG_TYPE_UINT:
                if (!GetUintFromBuffer(srcData, remainSize, offset, &(params[i].uint32Param))) {
                    return false;
                }
                break;
            case CM_TAG_TYPE_BOOL:
                uint32_t tmp;
                if (!GetUintFromBuffer(srcData, remainSize, offset, &tmp)) {
                    return false;
                }
                params[i].boolParam = (tmp % i == 0 ? true : false);
                break;
            default:
                break;
        }
    }

    if (CmParamsToParamSet(params, paramCnt, paramSetOut) != CM_SUCCESS) {
        return false;
    }

    return true;
}

bool IpcServiceApiFuzzerTest(const uint8_t *data, const size_t size, CertManagerInterfaceCode code,
    bool isParamsetToBlob, void (*ipcServiceApi)(const struct CmBlob *, struct CmBlob *, const struct CmContext *))
{
    uint32_t minSize = sizeof(struct CmBlob) + sizeof(struct CmBlob);
    uint8_t *myData = nullptr;
    if (!CopyMyData(data, size, minSize, &myData)) {
        return false;
    }

    uint32_t remSize = static_cast<uint32_t>(size);
    uint32_t offset = 0;

    struct CmBlob paramSetBlob = { 0, nullptr };
    struct CmParamSet *paramSet = nullptr;
    if (isParamsetToBlob) {
        if (ConstructParamSet(myData, &remSize, &offset, code, &paramSet) != true) {
            CmFree(myData);
            return false;
        }
        paramSetBlob = { paramSet->paramSetSize, reinterpret_cast<uint8_t *>(paramSet) };
    } else {
        if (GetCmBlobFromBuffer(myData, &remSize, &offset, &paramSetBlob) != true) {
            CmFree(myData);
            return false;
        }
    }

    struct CmBlob outData = { 0, nullptr };
    if (GetCmBlobFromBuffer(myData, &remSize, &offset, &outData) != true) {
        CmFree(myData);
        CmFreeParamSet(&paramSet);
        return false;
    }

    OHOS::MessageParcel context;
    (void)ipcServiceApi(&paramSetBlob, &outData, reinterpret_cast<struct CmContext *>(&context));

    CmFree(myData);
    CmFreeParamSet(&paramSet);
    return true;
}
}
