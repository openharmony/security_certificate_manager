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

#include "cmaddauthuid_fuzzer.h"

#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_uri.h"

namespace {
const uint32_t UINT32_COUNT = 4;
const uint32_t CM_BLOB_COUNT = 2;
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT +sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct CmContext cmContext = {0, 0, ""};
        if (!CreateCmContext(cmContext, myData, remainSize, offset)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob uri = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &uri)) {
            CmFree(myData);
            return false;
        }

        uint32_t appUidCount;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &appUidCount)) {
            CmFree(myData);
            return false;
        }

        uint32_t targetUid;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &targetUid)) {
            CmFree(myData);
            return false;
        }

        uint32_t userId;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &userId)) {
            CmFree(myData);
            return false;
        }

        bool isInAuthList;
        struct CmAppUidList cmAppUidList;
        cmAppUidList.appUidCount = appUidCount;
        cmAppUidList.appUid = &targetUid;
        CertmanagerTest::MockHapToken mockHap;
        (void)CmGetAuthList(&cmContext, &uri, &cmAppUidList);
        (void)CmDeleteAuthListFile(&cmContext, &uri);
        (void)CmCheckIsAuthUidExist(&cmContext, &uri, targetUid, &isInAuthList);
        (void)CmGetAuthListByUserId(userId, &uri, &cmAppUidList);
        (void)CmCheckIsAuthUidExistByUserId(userId, targetUid, &uri, &isInAuthList);
        (void)CmDeleteAuthListFileByUserId(userId, &uri);
        (void)CmCheckCredentialExist(&cmContext, &uri);
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

