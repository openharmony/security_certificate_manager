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

#include "cmcertmanager_fuzzer.h"

#include <cstring>


#include "cert_manager.h"
#include "cert_manager_api.h"
#include "cert_manager_app_cert_process.h"
#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_uri.h"
#include "cm_cert_data_chain_key.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_p7b.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_cert_data_user.h"
#include "cm_pfx.h"
#include "cm_x509.h"

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

        uint32_t store;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &store)) {
            CmFree(myData);
            return false;
        }
        bool isGmSysCert = store % 2;
        const uint32_t STORE_VALUE = 5;
        store %= STORE_VALUE;
        struct CmBlob path;
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &path)) {
            CmFree(myData);
            return false;
        }

        struct CmMutableBlob pathList;
        pathList.data = path.data;
        pathList.size = sizeof(path.data);
        CertmanagerTest::MockHapToken mockHap;
        struct CmBlob certData = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01)};
        static uint8_t certAliasBuf01[] = "40dc992e";
        struct CmBlob certAlias = { sizeof(certAliasBuf01), certAliasBuf01};
        const enum AliasTransFormat aliasFormat = DEFAULT_FORMAT;
        struct CmBlob objectName;
        (void)memset_s(&objectName, sizeof(struct CmBlob), 0, sizeof(struct CmBlob));
        uint8_t certUriData[] = "oh:t=ak;o=Test024;u=0;a=0";
        struct CmBlob certUri = { sizeof(certUriData), certUriData};
        char userConfigFilePath[] = { 0 };
        (void)GetObjNameFromCertData(&certData, &certAlias, &objectName, aliasFormat);
        (void)CmRemoveBackupUserCert(&cmContext, &certUri, userConfigFilePath);
        (void)CmRemoveAllUserCert(&cmContext, store, &pathList);
        (void)CertManagerFindCertFileNameByUri(&cmContext, &certUri, store, isGmSysCert, &pathList);
        (void)CertManagerFindCertFileNameByUri(&cmContext, &certUri, store, true, &pathList);
        return true;
    }

    bool DoSomethingInterestingWithMyAPICmWriteUserCert(const uint8_t* data, size_t size)
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

        struct CmBlob userCert;
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &userCert)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob certAlias;
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &certAlias)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob certUri;
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &certUri)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob path;
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &path)) {
            CmFree(myData);
            return false;
        }

        struct CmMutableBlob pathList;
        pathList.data = path.data;
        pathList.size = sizeof(path.data);
        CertmanagerTest::MockHapToken mockHap;
        (void)CmWriteUserCert(&cmContext, &pathList, &userCert, &certAlias, &certUri);
        return true;
    }

    struct CertOperationContext {
        CmContext* context;
        uint32_t store;
        bool isGmSysCert;
        CmBlob* keyUri;
    };

    class CertFileManager {
    public:
        static void ExecuteFileOperations(CertOperationContext& ctx)
        {
            struct CmMutableBlob path;
            (void)memset_s(&path, sizeof(CmMutableBlob), 0, sizeof(CmMutableBlob));
            (void)CertManagerFindCertFileNameByUri(ctx.context, ctx.keyUri, ctx.store, ctx.isGmSysCert, &path);
        }
    };

    class CertRemoveManager {
    public:
        static void ExecuteRemoveOperations(CertOperationContext& ctx)
        {
            (void)CmRemoveAppCert(ctx.context, ctx.keyUri, ctx.store);
            (void)CmRemoveAllAppCert(ctx.context);
        }
    };

    class UriManager {
    public:
        static void ExecuteUriOperations(CertOperationContext& ctx)
        {
            struct CmBlob uriBlob;
            (void)memset_s(&uriBlob, sizeof(CmBlob), 0, sizeof(CmBlob));
            const char *fileName = "fileName";
            (void)CmGetUri(reinterpret_cast<const char*>(ctx.keyUri->data), &uriBlob);
            (void)CmGetDisplayNameByURI(ctx.keyUri, fileName, &uriBlob);
        }
    };

    class CertCountManager {
    public:
        static void ExecuteCountOperations(CertOperationContext& ctx)
        {
            const char *fileName = "fileName";
            (void)GetCertOrCredCount(ctx.context, ctx.store, &ctx.store);
            (void)CmCheckCertCount(ctx.context, ctx.store, fileName);
        }
    };

    static void ExecuteCertOperations(CertOperationContext& ctx)
    {
        CertFileManager::ExecuteFileOperations(ctx);
        CertRemoveManager::ExecuteRemoveOperations(ctx);
        UriManager::ExecuteUriOperations(ctx);
        CertCountManager::ExecuteCountOperations(ctx);
    }

    static bool GenerateRandomUri(const char* retUriBuf, uint8_t* myData,
        uint32_t* remainSize, uint32_t* offset,
        struct CmBlob* randomUri)
    {
        char* random = nullptr;
        if (!GetDynamicStringFromBuffer(myData, remainSize, offset, &random)) {
            return false;
        }

        std::string randomString = std::string(retUriBuf) + random;
        size_t len = randomString.length();
        uint8_t* heapData = new uint8_t[len + 1];
        std::copy(randomString.c_str(), randomString.c_str() + len, heapData);
        heapData[len] = '\0';
        *randomUri = {len, heapData};
        delete[] random;
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
        struct CmBlob keyUri = {sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
        uint8_t certAliasBuf[] = "PrivKeyA";
        struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };
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

        const uint32_t STORE_VALUE = 5;
        const uint32_t BOOL_VALUE = 2;
        store %= STORE_VALUE;
        bool isGmSysCert = store % BOOL_VALUE;
        CmInstallAppCertPro(&cmContext, &appCertParam, &keyUri);
        struct CmAppUidList appUidList = { MAX_OUT_BLOB_SIZE + 1, nullptr };
        CmGetAuthorizedAppList(&keyUri, &appUidList);
        CertmanagerTest::MockHapToken mockHap;
        struct CertOperationContext ctx = {&cmContext, store, isGmSysCert, &keyUri};
        ExecuteCertOperations(ctx);
        struct CmBlob randomUri;
        if (!GenerateRandomUri(retUriBuf, myData, &remainSize, &offset, &randomUri)) {
            CmFree(myData);
            return false;
        }

        ctx.keyUri = &randomUri;
        ExecuteCertOperations(ctx);
        (void)CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
        CmFree(myData);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    OHOS::DoSomethingInterestingWithMyAPICmWriteUserCert(data, size);
    OHOS::DoSomethingInterestingWithMyAPICertManager(data, size);
    return 0;
}

