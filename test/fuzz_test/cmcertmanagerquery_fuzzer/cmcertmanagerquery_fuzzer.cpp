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

#include "cmcertmanagerquery_fuzzer.h"

#include <cstring>


#include "cert_manager.h"
#include "cert_manager_api.h"
#include "cert_manager_app_cert_process.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_x509.h"
#include "cert_manager_query.h"
#include "cm_cert_data_user.h"

#define  MAX_OUT_BLOB_SIZE (5 * 1024 * 1024)

namespace {
    const struct CmBlob g_eccAppCert = { sizeof(g_eccP256P12CertInfo), const_cast<uint8_t *>(g_eccP256P12CertInfo) };
    const struct CmBlob g_appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    const uint32_t  UINT32_COUNT = 4;
    const uint32_t  CM_BLOB_COUNT = 2;
    const uint32_t uid = 20020156;
    const uint32_t userId = 100;
}

using namespace CmFuzzTest;
namespace OHOS {
    struct CertOperationContext {
        CmContext* context;
        uint32_t store;
        CmBlob* keyUri;
        CmBlob* certAlias;
        CmBlob* userCertData;
        CmMutableBlob* path;
        CertBlob* certBlob;
    };

    class CertPathManager {
    public:
        static void ExecutePathOperations(CertOperationContext& ctx)
        {
            (void)CmGetSysCertPathList(ctx.context, ctx.path);
        }
    };

    class CertAliasManager {
    public:
        static void ExecuteAliasOperations(CertOperationContext& ctx)
        {
            (void)CmGetCertAlias(ctx.store, reinterpret_cast<const char*>(ctx.keyUri->data),
                ctx.userCertData, ctx.certAlias);
        }
    };

    class CertUninstallManager {
    public:
        static void ExecuteUninstallOperations(CertOperationContext& ctx)
        {
            (void)CmUninstallAppCert(ctx.keyUri, CM_CREDENTIAL_STORE);
        }
    };

    static void ExecuteCertOperations(CertOperationContext& ctx)
    {
        CertPathManager::ExecutePathOperations(ctx);
        CertAliasManager::ExecuteAliasOperations(ctx);
        CertUninstallManager::ExecuteUninstallOperations(ctx);
    }

    static bool InitializeCertResources(char* retUriBuf, uint8_t* certAliasBuf,
        struct CmBlob* keyUri, struct CmBlob* certAlias)
    {
        size_t retUriSize = MAX_OUT_BLOB_SIZE;
        (void)memset_s(retUriBuf, retUriSize, 0, retUriSize);
        *keyUri = { retUriSize, reinterpret_cast<uint8_t*>(retUriBuf) };

        size_t certAliasSize = sizeof("PrivKeyA");
        (void)memcpy_s(certAliasBuf, certAliasSize, "PrivKeyA", certAliasSize);
        *certAlias = { certAliasSize, certAliasBuf };

        return true;
    }

    bool DoSomethingInterestingWithMyAPICertManager(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT + sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        char retUriBuf[MAX_OUT_BLOB_SIZE] = {0};
        uint8_t certAliasBuf[sizeof("PrivKeyA")] = {0};
        uint8_t certAliasBuf1[sizeof("PrivKeyA")] = {0};
        struct CmBlob keyUri;
        struct CmBlob certAlias;
        struct CmBlob certAlias1 = { sizeof(certAliasBuf1), certAliasBuf1 };
        if (!InitializeCertResources(retUriBuf, certAliasBuf, &keyUri, &certAlias)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob privKey = { 0, NULL };
        struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
            &certAlias, CM_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2,
            FILE_P12, &privKey, DEFAULT_FORMAT };
        CmContext cmContext;
        cmContext.uid = uid;
        cmContext.userId = userId;
        if (CertManagerInitialize() != 0) {
            CmFree(myData);
            return false;
        }

        uint32_t store;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &store)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob userCertData = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
        const uint32_t STORE_VALUE = 5;
        store %= STORE_VALUE;
        CmInstallAppCertPro(&cmContext, &appCertParam, &keyUri);
        struct CmMutableBlob path = { 0, nullptr };
        struct CertBlob certBlob = {
            { keyUri },
            { certAlias },
            { certAlias1 },
        };
        
        CertmanagerTest::MockHapToken mockHap;
        CertOperationContext ctx = {&cmContext, store, &keyUri, &certAlias, &userCertData, &path, &certBlob};
        ExecuteCertOperations(ctx);
        CmFree(myData);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPICertManager(data, size);
    return 0;
}

