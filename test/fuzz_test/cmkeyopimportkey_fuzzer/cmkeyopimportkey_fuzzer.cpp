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

#include "cmkeyopimportkey_fuzzer.h"

#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_uri.h"
#include "cert_manager_key_operation.h"

namespace {
const uint32_t UINT32_COUNT = 4;
const uint32_t CM_BLOB_COUNT = 2;
}

using namespace CmFuzzTest;
namespace OHOS {
    bool CreateCmKeyProperties(uint8_t *myData, uint32_t &remainSize,
        uint32_t& offset, struct CmKeyProperties &properties)
    {
        uint32_t algType;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &algType)) {
            return false;
        }

        uint32_t keySize;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &keySize)) {
            return false;
        }

        uint32_t padding;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &padding)) {
            return false;
        }

        uint32_t digest;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &digest)) {
            return false;
        }

        uint32_t purpose;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &purpose)) {
            return false;
        }

        properties.algType = algType;
        properties.keySize = keySize;
        properties.padding = padding;
        properties.digest = digest;
        properties.purpose = purpose;
        properties.level = CM_AUTH_STORAGE_LEVEL_EL1;
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT +sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct CmBlob alias = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &alias)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob keyPair = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &keyPair)) {
            CmFree(myData);
            return false;
        }

        struct CmKeyProperties keyProperties;
        if (!CreateCmKeyProperties(myData, remainSize, offset, keyProperties)) {
            CmFree(myData);
            return false;
        }

        CertmanagerTest::MockHapToken mockHap;
        (void)CmKeyOpImportKey(&alias, &keyProperties, &keyPair);
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

