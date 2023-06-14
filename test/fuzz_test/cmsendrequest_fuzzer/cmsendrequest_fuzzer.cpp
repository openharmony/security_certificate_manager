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

#include "cmsendrequest_fuzzer.h"

#include "cm_fuzz_test_common.h"
#include "cm_param.h"
#include "cm_request.h"
#include "cm_test_common.h"

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(CertManagerInterfaceCode) + sizeof(struct CmParamSet) + sizeof(struct CmBlob);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        CertManagerInterfaceCode type;
        (void)memcpy_s(&type, sizeof(CertManagerInterfaceCode), myData, sizeof(CertManagerInterfaceCode));
        type = static_cast<CertManagerInterfaceCode>(static_cast<uint32_t>(type) %
            (static_cast<uint32_t>(CM_MSG_MAX) - static_cast<uint32_t>(CM_MSG_BASE)) +
            static_cast<uint32_t>(CM_MSG_BASE));
        offset += sizeof(uint32_t);
        remainSize -= sizeof(uint32_t);

        struct CmParamSet *sendParamSet = nullptr;
        if (ConstructParamSet(myData, &remainSize, &offset, type, &sendParamSet) == false) {
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
