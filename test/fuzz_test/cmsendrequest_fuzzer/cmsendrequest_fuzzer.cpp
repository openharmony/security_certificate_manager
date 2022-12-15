/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cmsendrequest_fuzzer.h"

#include "cm_ipc_client_serialization.h"
#include "cm_ipc_msg_code.h"
#include "cm_fuzz_test_common.h"
#include "cm_param.h"
#include "cm_request.h"
#include "cm_test_common.h"

using namespace CmFuzzTest;
namespace OHOS {
    const uint32_t CMPARAM_BUFFER_TYPE_COUNT = 4;
    const uint32_t CMPARAM_UINT32_TYPE_COUNT = 4;
    const uint32_t CMPARAM_BOOL_TYPE_COUNT = 2;

    bool ConstructParamSet(uint8_t* myData, uint32_t *remainSize, uint32_t *offset, struct CmParamSet **paramSetOut)
    {
        struct CmParam params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM2_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM3_BUFFER, .blob = { 0, nullptr } },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = 0 },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = 0 },
            { .tag = CM_TAG_PARAM2_UINT32, .uint32Param = 0 },
            { .tag = CM_TAG_PARAM3_UINT32, .uint32Param = 0 },
            { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
            { .tag = CM_TAG_PARAM1_BOOL, .boolParam = false },
        };

        uint32_t pos = 0;
        for (uint32_t i = 0; i < CMPARAM_BUFFER_TYPE_COUNT; i++) {
            if (!GetCmBlobFromBuffer(myData, remainSize, offset, &(params[pos].blob))) {
                return false;
            }
            pos++;
        }

        for (uint32_t i = 0; i < CMPARAM_UINT32_TYPE_COUNT; i++) {
            if (!GetUintFromBuffer(myData, remainSize, offset, &(params[pos].uint32Param))) {
                return false;
            }
            pos++;
        }

        for (uint32_t i = 0; i < CMPARAM_BOOL_TYPE_COUNT; i++) {
            uint32_t tmp;
            if (!GetUintFromBuffer(myData, remainSize, offset, &tmp)) {
                return false;
            }
            params[pos].boolParam = (tmp % CMPARAM_BOOL_TYPE_COUNT == 0 ? true : false);
            pos++;
        }

        if (CmParamsToParamSet(params, sizeof(params) / sizeof(params[0]), paramSetOut) != CM_SUCCESS) {
            return false;
        }

        return true;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(enum CmMessage) + sizeof(struct CmParamSet) + sizeof(struct CmBlob);
        uint8_t *myData;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        enum CmMessage type = static_cast<enum CmMessage>(*(reinterpret_cast<uint32_t *>(myData)));
        type = static_cast<enum CmMessage>(
            static_cast<uint32_t>(type) % static_cast<uint32_t>(CM_MSG_MAX - CM_MSG_BASE) +
            static_cast<uint32_t>(CM_MSG_BASE));
        offset += sizeof(uint32_t);
        remainSize -= sizeof(uint32_t);

        struct CmParamSet *sendParamSet = NULL;
        if (ConstructParamSet(myData, &remainSize, &offset, &sendParamSet) == false) {
            CmFree(myData);
            return false;
        }

        struct CmBlob inBlob = { sendParamSet->paramSetSize, reinterpret_cast<uint8_t *>(sendParamSet) };

        struct CmBlob outBlob = { 0, nullptr };
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &outBlob)) {
            CmFree(myData);
            CmFreeParamSet(&sendParamSet);
            return false;
        }

        CertmanagerTest::SetATPermission();
        (void)SendRequest(type, &inBlob, &outBlob);

        CmFree(myData);
        CmFreeParamSet(&sendParamSet);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
