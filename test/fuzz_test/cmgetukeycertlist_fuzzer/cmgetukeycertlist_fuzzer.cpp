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

#include "cmgetukeycertlist_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"

namespace {
const uint32_t MAX_CERTPURPOSE = 6;
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) + sizeof(struct CredentialDetailList);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        struct CmBlob ukeyParam = { 0, nullptr };
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &ukeyParam)) {
            CmFree(myData);
            return false;
        }

        uint32_t certPurpose;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &certPurpose)) {
            CmFree(myData);
            return false;
        }

        struct UkeyInfo = {
            .certPurpose = static_cast<CmCertificatePurpose>(certPurpose);
        }

        struct CredentialDetailList certificateList = { 0, nullptr };
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &(certificateList.credentialCount))) {
            CmFree(myData);
            return false;
        }
        if (certificateList.credentialCount > (remainSize / sizeof(struct Credential))) {
            CmFree(myData);
            return false;
        }
        certificateList.credential = reinterpret_cast<struct Credential *>(myData + offset);

        CertmanagerTest::MockHapToken mockHap;
        (void)CmGetUkeyCertList(&ukeyParam, &UkeyInfo, &certificateList);

        (void)CmGetUkeyCert(&ukeyParam, &UkeyInfo, &certificateList);

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

