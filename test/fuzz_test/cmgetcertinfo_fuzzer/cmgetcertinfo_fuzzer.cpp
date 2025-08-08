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

#include "cmgetcertinfo_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"

namespace {
const uint32_t CM_BLOB_COUNT = 2;
const uint32_t MAX_BOOL = 2;
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t buffSize = sizeof(struct CmBlob) * CM_BLOB_COUNT + sizeof(uint32_t) + sizeof(uint32_t);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, buffSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct CmBlob sysUri = { 0, nullptr };
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &sysUri)) {
            CmFree(myData);
            return false;
        }

        uint32_t store;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &store)) {
            CmFree(myData);
            return false;
        }

        uint32_t status;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &status)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob certInfo = { 0, nullptr };
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &certInfo)) {
            CmFree(myData);
            return false;
        }

        struct CertInfo sysCertInfo = {
            .uri = "uri",
            .certAlias = "alias",
            .status = status % MAX_BOOL,
            .issuerName = "issuerName",
            .subjectName = "subjectName",
            .serial = "serial",
            .notBefore = "notBefore",
            .notAfter = "notAfter",
            .fingerprintSha256 = "sha256",
            .certInfo = certInfo
        };
        
        CertmanagerTest::MockHapToken mockHap;
        (void)CmGetCertInfo(&sysUri, store, &sysCertInfo);

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
