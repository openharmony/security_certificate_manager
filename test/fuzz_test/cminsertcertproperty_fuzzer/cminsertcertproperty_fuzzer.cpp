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

#include "cminsertcertproperty_fuzzer.h"

#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_uri.h"
#include "cm_cert_property_rdb.h"

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
        uint32_t certStore;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &certStore)) {
            CmFree(myData);
            return false;
        }

        uint32_t userId;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &userId)) {
            CmFree(myData);
            return false;
        }

        uint32_t uid;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &uid)) {
            CmFree(myData);
            return false;
        }

        struct CertProperty certProperty;
        certProperty = {
            .userId = static_cast<int32_t>(userId),
            .uid = static_cast<int32_t>(uid),
            .certStore = static_cast<int32_t>(certStore),
            .uri = {'\0'},
            .alias = {'\0'},
            .subjectName = {'\0'},
            .certType = {'\0'},
            .level = CM_AUTH_STORAGE_LEVEL_EL1
        };

        CertmanagerTest::MockHapToken mockHap;
        (void)CreateCertPropertyRdb();
        (void)InsertCertProperty(&certProperty);
        (void)UpdateCertProperty(&certProperty);
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

