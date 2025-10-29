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

#include "cmservicinstallappcert_fuzzer.h"

#include "cert_manager_auth_list_mgr.h"
#include "cert_manager_service.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_uri.h"

namespace {
const uint32_t UINT32_COUNT = 4;
const uint32_t CM_BLOB_COUNT = 2;
}

using namespace CmFuzzTest;
namespace OHOS {
    static bool CreateCmAppCertParam(struct CmAppCertParam &cmAppCertParam, uint8_t *myData,
        uint32_t &remainSize, uint32_t &offset)
{
    uint32_t store;
    uint32_t userId;
    if (!GetUintFromBuffer(myData, &remainSize, &offset, &store) ||
        !GetUintFromBuffer(myData, &remainSize, &offset, &userId)) {
        return false;
    }

    auto cleanup = [](struct CmBlob *cert, struct CmBlob *pwd, struct CmBlob *key) {
        CmFree(cert);
        CmFree(pwd);
        CmFree(key);
    };

    struct CmBlob *appCert = (struct CmBlob *)malloc(sizeof(struct CmBlob));
    struct CmBlob *appCertPwd = (struct CmBlob *)malloc(sizeof(struct CmBlob));
    struct CmBlob *appCertPrivKey = (struct CmBlob *)malloc(sizeof(struct CmBlob));
    
    if (!appCert || !appCertPwd || !appCertPrivKey) {
        cleanup(appCert, appCertPwd, appCertPrivKey);
        return false;
    }

    memset_s(appCert, sizeof(struct CmBlob), 0, sizeof(struct CmBlob));
    memset_s(appCertPwd, sizeof(struct CmBlob), 0, sizeof(struct CmBlob));
    memset_s(appCertPrivKey, sizeof(struct CmBlob), 0, sizeof(struct CmBlob));
    bool success = GetCmBlobFromBuffer(myData, &remainSize, &offset, appCert) &&
                   GetCmBlobFromBuffer(myData, &remainSize, &offset, appCertPwd) &&
                   GetCmBlobFromBuffer(myData, &remainSize, &offset, appCertPrivKey);
    if (!success) {
        cleanup(appCert, appCertPwd, appCertPrivKey);
        return false;
    }

    cmAppCertParam = {
        .appCert = appCert,
        .appCertPwd = appCertPwd,
        .appCertPrivKey = appCertPrivKey,
        .store = store,
        .userId = userId,
        .level = CM_AUTH_STORAGE_LEVEL_EL1,
        .credFormat = FILE_P12,
        .aliasFormat = DEFAULT_FORMAT
    };
    
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
        struct CmContext cmContext = {0, 0, ""};
        if (!CreateCmContext(cmContext, myData, remainSize, offset)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob keyUri = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &keyUri)) {
            CmFree(myData);
            return false;
        }

        struct CmAppCertParam certParam;
        if (!CreateCmAppCertParam(certParam, myData, remainSize, offset)) {
            CmFree(myData);
            return false;
        }

        CertmanagerTest::MockHapToken mockHap;
        (void)CmServicInstallAppCert(&cmContext, &certParam, &keyUri);
        CmFree(myData);
        CmFree(certParam.appCertPwd);
        CmFree(certParam.appCertPrivKey);
        CmFree(certParam.appCert);
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

