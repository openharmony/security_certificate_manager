/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cmcertmanagerapi_fuzzer.h"

#include <cstring>

#include "cert_manager_api.h"
#include "cm_event_process.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cm_x509.h"

namespace {
    const uint32_t UINT32_COUNT = 4;
    const uint32_t CM_BLOB_COUNT = 2;
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPIIpcGetCertStorePath(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT +sizeof(uint32_t) * UINT32_COUNT;
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

        char* path = nullptr;
        if (!GetDynamicStringFromBuffer(myData, &remainSize, &offset, &path)) {
            CmFree(myData);
            return false;
        }

        struct CredentialDetailList *ukeyList = nullptr;
        enum CmCertType certType = CM_CA_CERT_SYSTEM;
        (void)CmGetCertStorePath(certType, userId, path, strlen(path));
        (void)CmFreeUkeyCertificate(ukeyList);
        delete[] path;
        CmFree(myData);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIIpcCheckAppPermission(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT +sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        uint32_t appUid;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &appUid)) {
            CmFree(myData);
            return false;
        }

        uint8_t uriData[] = "oh:t=ak;o=TestNormalGrant;u=0;a=0";
        struct CmBlob keyUri = { sizeof(uriData), uriData };

        struct CmBlob huksAlias = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &huksAlias)) {
            CmFree(myData);
            return false;
        }

        struct Credential* pCredential = nullptr;
        enum CmPermissionState state = CM_PERMISSION_DENIED;
        (void)CmCheckAppPermission(&keyUri, appUid, &state, &huksAlias);
        (void)CmFreeCredential(pCredential);
        CmFree(myData);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPIIpcGetCertStorePath(data, size);
    OHOS::DoSomethingInterestingWithMyAPIIpcCheckAppPermission(data, size);
    return 0;
}