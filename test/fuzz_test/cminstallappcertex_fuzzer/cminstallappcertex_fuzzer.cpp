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

#include "cminstallappcertex_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"

namespace {
const uint32_t MAX_LEVEL = 5;
}

using namespace CmFuzzTest;
namespace OHOS {

    static bool CreateCertParam(struct CmAppCertParam &certParam, uint8_t *myData,
        uint32_t &remainSize, uint32_t &offset)
    {
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, certParam.appCert)) {
            return false;
        }

        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, certParam.appCertPwd)) {
            return false;
        }

        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, certParam.certAlias)) {
            return false;
        }

        uint32_t store;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &store)) {
            return false;
        }

        uint32_t userId;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &userId)) {
            return false;
        }

        uint32_t level;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &level)) {
            return false;
        }
        level = level % MAX_LEVEL;

        certParam.store = store;
        certParam.userId = userId;
        certParam.level = static_cast<CmAuthStorageLevel>(level);
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmAppCertParam) + sizeof(struct CmBlob);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        struct CmBlob appCert = { 0, nullptr };
        struct CmBlob appCertPwd = { 0, nullptr };
        struct CmBlob certAlias = { 0, nullptr };

        struct CmAppCertParam certParam = {
            certParam.appCert = &appCert,
            certParam.appCertPwd = &appCertPwd,
            certParam.certAlias = &certAlias
        };

        if (!CreateCertParam(certParam, myData, remainSize, offset)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob keyUri = { 0, nullptr };
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &keyUri)) {
            CmFree(myData);
            return false;
        }

        SetATPermission();
        (void)CmInstallAppCertEx(&certParam, &keyUri);

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
