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

#include "cmauthlistmgr_fuzzer.h"

#include <cstring>

#include "cert_manager.h"
#include "cert_manager_api.h"
#include "cert_manager_app_cert_process.h"
#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_auth_mgr.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_p7b.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_x509.h"

#define MAX_OUT_BLOB_SIZE (5 * 1024 * 1024)

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
    struct AuthOperationContext {
        CmContext* context;
        uint32_t userId;
        CmBlob* keyUri;
        uint32_t uid;
        uint32_t randomTagitUid;
        CmAppUidList* appUidList;
    };

    class AuthUidManager {
    public:
        static void AddAuthUids(AuthOperationContext& ctx)
        {
            (void)CmAddAuthUid(ctx.context, ctx.keyUri, ctx.uid);
            (void)CmAddAuthUid(ctx.context, ctx.keyUri, ctx.randomTagitUid);
        }

        static void RemoveAuthUids(AuthOperationContext& ctx)
        {
            (void)CmRemoveAuthUid(ctx.context, ctx.keyUri, ctx.uid);
            (void)CmRemoveAuthUid(ctx.context, ctx.keyUri, ctx.randomTagitUid);
        }

        static void RemoveAuthUidByUserId(AuthOperationContext& ctx)
        {
            (void)CmRemoveAuthUidByUserId(ctx.userId, ctx.uid, ctx.keyUri);
        }
    };

    class AuthListManager {
    public:
        static void GetAuthList(AuthOperationContext& ctx)
        {
            (void)CmGetAuthList(ctx.context, ctx.keyUri, ctx.appUidList);
        }

        static void GetAuthListByUserId(AuthOperationContext& ctx)
        {
            (void)CmGetAuthListByUserId(ctx.userId, ctx.keyUri, ctx.appUidList);
        }

        static void DeleteAuthListFile(AuthOperationContext& ctx)
        {
            (void)CmDeleteAuthListFile(ctx.context, ctx.keyUri);
        }

        static void DeleteAuthListFileByUserId(AuthOperationContext& ctx)
        {
            (void)CmDeleteAuthListFileByUserId(ctx.userId, ctx.keyUri);
        }
    };

    class AuthCheckManager {
    public:
        static void CheckAuthUidExist(AuthOperationContext& ctx)
        {
            bool isInAuthList = true;
            (void)CmCheckIsAuthUidExist(ctx.context, ctx.keyUri, ctx.uid, &isInAuthList);
        }

        static void CheckAuthUidExistByUserId(AuthOperationContext& ctx)
        {
            bool isInAuthList = true;
            (void)CmCheckIsAuthUidExistByUserId(ctx.userId, ctx.uid, ctx.keyUri, &isInAuthList);
        }

        static void CheckCredentialExist(AuthOperationContext& ctx)
        {
            (void)CmCheckCredentialExist(ctx.context, ctx.keyUri);
        }
    };

    class TempAuthManager {
    public:
        static void ExecuteTempAuthOperations()
        {
            CmContext tempContext;
            tempContext.uid = 0;
            tempContext.userId = 0;
            uint8_t uriData[] = "oh:t=ak;o=TestNormalGrant;u=0;a=0";
            struct CmBlob keyUri1 = { sizeof(uriData), uriData };
            uint32_t uid = 20020156;
            (void)CmAddAuthUid(&tempContext, &keyUri1, uid);
        }
    };

    static void ExecuteAuthOperations(AuthOperationContext& ctx)
    {
        AuthUidManager::AddAuthUids(ctx);
        TempAuthManager::ExecuteTempAuthOperations();
        AuthUidManager::RemoveAuthUids(ctx);
        AuthListManager::GetAuthList(ctx);
        AuthListManager::DeleteAuthListFile(ctx);
        AuthCheckManager::CheckAuthUidExist(ctx);
        AuthUidManager::RemoveAuthUidByUserId(ctx);
        AuthListManager::GetAuthListByUserId(ctx);
        AuthListManager::DeleteAuthListFileByUserId(ctx);
        AuthCheckManager::CheckAuthUidExistByUserId(ctx);
        AuthCheckManager::CheckCredentialExist(ctx);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
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

        uint32_t randomTagitUid;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &randomTagitUid)) {
            CmFree(myData);
            return false;
        }

        CmInstallAppCertPro(&cmContext, &appCertParam, &keyUri);
        struct CmAppUidList appUidList = { MAX_OUT_BLOB_SIZE + 1, nullptr };
        CmGetAuthorizedAppList(&keyUri, &appUidList);
        AuthOperationContext ctx = {&cmContext, userId, &keyUri, uid, randomTagitUid, &appUidList};
        ExecuteAuthOperations(ctx);
        char* random;
        if (!GetDynamicStringFromBuffer(myData, &remainSize, &offset, &random)) {
            CmFree(myData);
            return false;
        }

        std::string randomString = std::string(retUriBuf) + random;
        struct CmBlob randomUri = {
            randomString.length(),
            reinterpret_cast<uint8_t *>(const_cast<char*>(randomString.c_str()))
        };
        
        ctx.keyUri = &randomUri;
        ExecuteAuthOperations(ctx);
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
    return 0;
}