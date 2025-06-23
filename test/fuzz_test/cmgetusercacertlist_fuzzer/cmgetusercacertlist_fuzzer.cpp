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

#include "cmgetusercacertlist_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"

namespace {
const uint32_t MAX_SCOPE = 3;
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct UserCAProperty) + sizeof(struct CertList);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        uint32_t userId;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &userId)) {
            CmFree(myData);
            return false;
        }

        uint32_t scope;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &scope)) {
            CmFree(myData);
            return false;
        }
        scope = scope % MAX_SCOPE;

        struct UserCAProperty property = {
            .userId = userId
        };
        property.scope = static_cast<CmCertScope>(scope);
        struct CertList userCertList = { 0, nullptr };
        if (!GetCertListFromBuffer(myData, &remainSize, &offset, &userCertList)) {
            CmFree(myData);
            return false;
        }

        SetATPermission();
        (void)CmGetUserCACertList(&property, &userCertList);

        CmFree(myData);
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

