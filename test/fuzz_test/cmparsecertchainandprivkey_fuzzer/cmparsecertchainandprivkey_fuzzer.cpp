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

#include "cmparsecertchainandprivkey_fuzzer.h"

#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_uri.h"
#include "cm_pfx.h"
#include "cm_x509.h"

namespace {
const uint32_t UINT32_COUNT = 4;
const uint32_t CM_BLOB_COUNT = 2;
}

using namespace CmFuzzTest;
namespace OHOS {
    static bool CreateAppCert(uint8_t *myData, uint32_t &remainSize, uint32_t &offset, struct AppCert *appCert)
    {
        uint32_t certCount;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &certCount)) {
            return false;
        }

        uint32_t keyCount;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &keyCount)) {
            return false;
        }

        uint32_t certSize;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &certSize)) {
            return false;
        }

        appCert->certCount = certCount;
        appCert->keyCount = keyCount;
        appCert->certSize = certSize;
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
        struct CmBlob certChain = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &certChain)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob privKey = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &privKey)) {
            CmFree(myData);
            return false;
        }

        struct AppCert appCert = {};
        if (!CreateAppCert(myData, remainSize, offset, &appCert)) {
            CmFree(myData);
        }

        EVP_PKEY *priKey = NULL;
        X509 *x509 = nullptr;
        CertmanagerTest::MockHapToken mockHap;
        (void)CmParseCertChainAndPrivKey(&certChain, &priKey, &priKey, &appCert, &x509);
        CmFree(myData);
        EVP_PKEY_free(priKey);
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

