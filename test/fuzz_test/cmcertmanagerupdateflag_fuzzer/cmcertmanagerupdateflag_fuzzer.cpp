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

#include "cmcertmanagerupdateflag_fuzzer.h"

#include <cstring>

#include "cert_manager.h"
#include "cert_manager_api.h"
#include "cert_manager_app_cert_process.h"
#include "cert_manager_auth_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_x509.h"
#include "cert_manager_updateflag.h"


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
    struct CertBackupContext {
        uint32_t userId;
        uint32_t uid;
        CmBlob* uri;
        bool needUpdate;
        uint32_t store;
        CmContext* cmContext;
        CmBlob* userCertData;
    };

    class CertBackupManager {
    public:
        static void ExecuteCertBackupOperations(CertBackupContext& ctx)
        {
            (void)IsCertNeedBackup(ctx.userId, ctx.uid, ctx.uri, &ctx.needUpdate);
            (void)CmReadCertData(ctx.store, ctx.cmContext, ctx.uri, ctx.userCertData);
            (void)CmBackupUserCert(ctx.cmContext, ctx.uri, ctx.userCertData);
            if (ctx.uri == nullptr || ctx.uri->size == 0 || ctx.uri->data == nullptr) {
                return ;
            }

            if (ctx.uri->data[ctx.uri->size - 1] != '\0') {
                return ;
            }

            (void)CmConstructContextFromUri(reinterpret_cast<const char*>(ctx.uri->data), ctx.cmContext);
        }
    };

    class StoreUpdateReader {
    public:
        static bool GetStoreAndUpdateFromBuffer(uint8_t* myData, uint32_t* remainSize, uint32_t* offset,
            uint32_t* store, bool* needUpdate)
        {
            if (!GetUintFromBuffer(myData, remainSize, offset, store)) {
                return false;
            }

            const uint32_t STORE_VALUE = 5;
            *store %= STORE_VALUE;
            uint32_t update;
            if (!GetUintFromBuffer(myData, remainSize, offset, &update)) {
                return false;
            }

            const int updateValue = 2;
            *needUpdate = update % updateValue;
            return true;
        }
    };

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

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT +sizeof(uint32_t) * UINT32_COUNT;
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
        bool needUpdate;
        if (!StoreUpdateReader::GetStoreAndUpdateFromBuffer(myData, &remainSize, &offset, &store, &needUpdate)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob userCertData;
        (void)memset_s(&userCertData, sizeof(CmBlob), 0, sizeof(CmBlob));
        CmInstallAppCertPro(&cmContext, &appCertParam, &keyUri);
        struct CmAppUidList appUidList = { MAX_OUT_BLOB_SIZE + 1, nullptr };
        CmGetAuthorizedAppList(&keyUri, &appUidList);
        CertmanagerTest::MockHapToken mockHap;
        CertBackupContext ctx = {userId, uid, &keyUri, needUpdate, store, &cmContext, &userCertData};
        CertBackupManager::ExecuteCertBackupOperations(ctx);
        (void)CmBackupAllSaUserCerts();
        struct CmBlob randomUri;
        if (!GenerateRandomUri(retUriBuf, myData, &remainSize, &offset, &randomUri)) {
            CmFree(myData);
            return false;
        }

        ctx.uri = &randomUri;
        CertBackupManager::ExecuteCertBackupOperations(ctx);
        (void)CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
        (void)CmBackupAllSaUserCerts();
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