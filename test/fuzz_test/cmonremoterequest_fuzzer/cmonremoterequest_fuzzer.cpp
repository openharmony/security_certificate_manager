/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cmonremoterequest_fuzzer.h"

#include "cm_fuzz_test_common.h"
#include "cm_sa.h"
#include "cm_test_common.h"
#include "message_option.h"
#include "message_parcel.h"

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(struct CmBlob);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        // get code
        uint32_t code;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &code)) {
            CmFree(myData);
            return false;
        }
        code = (code % static_cast<uint32_t>(CM_MSG_MAX - CM_MSG_BASE) + static_cast<uint32_t>(CM_MSG_BASE));

        // get data
        uint32_t outSize;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &outSize)) {
            CmFree(myData);
            return false;
        }
        struct CmParamSet *paramSet = nullptr;
        if (ConstructParamSet(myData, &remainSize, &offset,
            static_cast<CertManagerInterfaceCode>(code), &paramSet) == false) {
            CmFree(myData);
            return false;
        }
        struct CmBlob srcDataBlob = { paramSet->paramSetSize, reinterpret_cast<uint8_t *>(paramSet) };

        Security::CertManager::CertManagerService &myService = Security::CertManager::CertManagerService::GetInstance();

        std::u16string descriptor = myService.GetDescriptor();
        MessageParcel messageData;
        messageData.WriteInterfaceToken(descriptor);
        messageData.WriteUint32(outSize);
        messageData.WriteUint32(srcDataBlob.size);
        messageData.WriteBuffer(srcDataBlob.data, static_cast<size_t>(srcDataBlob.size));

        MessageParcel reply;
        MessageOption option;
        CertmanagerTest::SetATPermission();
        SystemAbilityOnDemandReason reason;
        (void)myService.OnStart(reason);
        (void)myService.OnRemoteRequest(code, messageData, reply, option);

        CmFree(myData);
        CmFreeParamSet(&paramSet);
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
