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

#include "getfilepath_fuzzer.h"

#include <cstring>

#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager.h"

namespace {
const uint32_t UINT32_COUNT = 4;
const uint32_t CM_BLOB_COUNT = 2;
const char* STR_CERT_PARAMS = "oh:o=certificate;t=1;u=admin;a=myapp?m=abc123&cu=user1&ca=app2";
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPIGetFilePath(const uint8_t* data, size_t size)
    {
        struct CmContext cmContext = {0, 0, ""};
        uint32_t store = 5;
        char pathPtr[] = "pathPtr";
        char suffix[] = "suffix";
        uint32_t suffixLen = 0;
        CertmanagerTest::MockHapToken mockHap;
        (void)GetFilePath(&cmContext, store, pathPtr, suffix, &suffixLen);
        return true;
    }

    bool DoSomethingInterestingWithMyAPICmGetFilePath(const uint8_t* data, size_t size)
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

        uint32_t store = 5;
        struct CmMutableBlob pathBlob = {0, nullptr};
        CertmanagerTest::MockHapToken mockHap;
        (void)CmGetFilePath(&cmContext, store, &pathBlob);
        CmFree(myData);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIFindObjectCert(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT +sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        uint32_t certCount;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &certCount)) {
            CmFree(myData);
            return false;
        }

        uint32_t store = 5;
        struct CmMutableBlob fNames = {0, nullptr};
        struct CmBlob certUri = {strlen(STR_CERT_PARAMS), (uint8_t*)STR_CERT_PARAMS};
        CertmanagerTest::MockHapToken mockHap;
        (void)FindObjectCert(&certUri, &fNames, certCount);
        CmFree(myData);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIGetGmSystemCaCertPath(const uint8_t* data, size_t size)
    {
        struct CmMutableBlob path = {0, nullptr};
        CertmanagerTest::MockHapToken mockHap;
        (void)GetGmSystemCaCertPath(&path);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIClearAuthInfo(const uint8_t* data, size_t size)
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
        
        uint32_t store = 5;
        struct CmMutableBlob fNames = {0, nullptr};
        struct CmBlob keyUri = { strlen(STR_CERT_PARAMS), (uint8_t*)STR_CERT_PARAMS };
        CertmanagerTest::MockHapToken mockHap;
        (void)ClearAuthInfo(&cmContext, &keyUri, store, CM_AUTH_STORAGE_LEVEL_EL1);
        CmFree(myData);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIGetUriAndDeleteRdbData(const uint8_t* data, size_t size)
    {
        struct CmBlob uriBlob = { strlen(STR_CERT_PARAMS), (uint8_t*)STR_CERT_PARAMS };
        CertmanagerTest::MockHapToken mockHap;
        (void)GetUriAndDeleteRdbData(STR_CERT_PARAMS, &uriBlob, &CM_AUTH_STORAGE_LEVEL_EL1);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIConstructCertUri(const uint8_t* data, size_t size)
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

        struct CmBlob certAlias = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &certAlias)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob certUri = {strlen(STR_CERT_PARAMS), (uint8_t*)STR_CERT_PARAMS};
        CertmanagerTest::MockHapToken mockHap;
        (void)ConstructCertUri(&cmContext, &certAlias, &certUri);
        CmFree(myData);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIHandleEmptyAlias(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT +sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct CmBlob certData = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &certData)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob objectName = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &objectName)) {
            CmFree(myData);
            return false;
        }

        CertmanagerTest::MockHapToken mockHap;
        (void)HandleEmptyAlias(&certData, &objectName);
        CmFree(myData);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIHandleNotEmptyAlias(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT +sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct CmBlob certAlias = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &certAlias)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob objectName = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &objectName)) {
            CmFree(myData);
            return false;
        }

        CertmanagerTest::MockHapToken mockHap;
        (void)HandleNotEmptyAlias(&certAlias, DEFAULT_FORMAT, &objectName);
        CmFree(myData);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPIGetFilePath(data, size);
    OHOS::DoSomethingInterestingWithMyAPICmGetFilePath(data, size);
    OHOS::DoSomethingInterestingWithMyAPIFindObjectCert(data, size);
    OHOS::DoSomethingInterestingWithMyAPIGetGmSystemCaCertPath(data, size);
    OHOS::DoSomethingInterestingWithMyAPIClearAuthInfo(data, size);
    OHOS::DoSomethingInterestingWithMyAPIGetUriAndDeleteRdbData(data, size);
    OHOS::DoSomethingInterestingWithMyAPIConstructCertUri(data, size);
    OHOS::DoSomethingInterestingWithMyAPIHandleEmptyAlias(data, size);
    OHOS::DoSomethingInterestingWithMyAPIHandleNotEmptyAlias(data, size);
    return 0;
}

