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

#include "cmgetappcert_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"

namespace {
const uint32_t UINT32_COUNT = 4;
const uint32_t CM_BLOB_COUNT = 2;
}

using namespace CmFuzzTest;
namespace OHOS {
    static bool CreateCredCert(struct Credential &credCert, uint8_t *myData,
        uint32_t &remainSize, uint32_t &offset)
    {
        struct CmBlob credData = { 0, nullptr };
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &credData)) {
            CmFree(myData);
            return false;
        }
        uint32_t isExist;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &isExist)) {
            CmFree(myData);
            return false;
        }
        uint32_t certNum;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &certNum)) {
            CmFree(myData);
            return false;
        }
        uint32_t keyNum;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &keyNum)) {
            CmFree(myData);
            return false;
        }
        credCert.isExist = isExist;
        credCert.certNum = certNum;
        credCert.keyNum = keyNum;
        credCert.credData = credData;
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT + sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct CmBlob appCertUri = { 0, nullptr };
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &appCertUri)) {
            CmFree(myData);
            return false;
        }
        uint32_t store;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &store)) {
            CmFree(myData);
            return false;
        }

        struct Credential credCert = {
            .type = "type",
            .alias = "alias",
            .keyUri = "uri",
        };

        if (!CreateCredCert(credCert, myData, remainSize, offset)) {
            CmFree(myData);
            return false;
        }

        SetATPermission();
        (void)CmGetAppCert(&appCertUri, store, &credCert);

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
