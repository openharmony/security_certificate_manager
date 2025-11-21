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

#include "cmcertmanagerservice_fuzzer.h"

#include <cstring>

#include "cert_manager.h"
#include "cert_manager_api.h"
#include "cert_manager_app_cert_process.h"
#include "cert_manager_service.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_x509.h"
#include "cert_manager_updateflag.h"
#include "cm_cert_data_p7b.h"


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
    struct CertificateOperationContext {
        CmContext* cmContext;
        CmBlob* uri;
        uint32_t store;
        uint32_t uid;
        CmSignatureSpec* spec;
    };

    class CertificateInstaller {
    public:
        static void InstallAppCertificate(CertificateOperationContext& ctx, CmAppCertParam* appCertParam)
        {
            (void)CmInstallAppCertPro(ctx.cmContext, appCertParam, ctx.uri);
        }

        static void InstallMultiUserCertificate(CertificateOperationContext& ctx,
            CmBlob* userCert,
            CmBlob* certAlias)
        {
            (void)CmInstallMultiUserCert(ctx.cmContext, userCert, certAlias, ctx.store, ctx.uri);
        }
    };

    class CertificateRetriever {
    public:
        static void GetAppCertificate(CertificateOperationContext& ctx, CmBlob* certBlob)
        {
            (void)CmServiceGetAppCert(ctx.cmContext, ctx.store, ctx.uri, certBlob);
        }

        static void GetCertificateInfo(CertificateOperationContext& ctx, CmBlob* certBlob)
        {
            (void)CmServiceGetCertInfo(ctx.cmContext, ctx.uri, ctx.store, certBlob, &ctx.store);
        }
    };

    class AuthorizationManager {
    public:
        static void GrantAppCertificate(CertificateOperationContext& ctx, CmBlob* authUri)
        {
            (void)CmServiceGrantAppCertificate(ctx.cmContext, ctx.uri, ctx.uid, authUri);
        }

        static void GetAuthorizedAppList(CertificateOperationContext& ctx, CmAppUidList* appUidList)
        {
            (void)CmServiceGetAuthorizedAppList(ctx.cmContext, ctx.uri, appUidList);
        }

        static bool IsAuthorizedApp(CertificateOperationContext& ctx)
        {
            return CmServiceIsAuthorizedApp(ctx.cmContext, ctx.uri);
        }

        static void RemoveGrantedApp(CertificateOperationContext& ctx)
        {
            (void)CmServiceRemoveGrantedApp(ctx.cmContext, ctx.uri, ctx.uid);
        }
    };

    class SignatureManager {
    public:
        static void InitializeSignature(CertificateOperationContext& ctx, CmBlob* authUri)
        {
            (void)CmServiceInit(ctx.cmContext, ctx.uri, ctx.spec, authUri);
        }
    };

    class CertificateUninstaller {
    public:
        static void UninstallUserCertificate(CertificateOperationContext& ctx)
        {
            (void)CmUninstallUserCert(ctx.cmContext, ctx.uri);
        }

        static void UninstallAppCertificate(CmBlob* uri)
        {
            (void)CmUninstallAppCert(uri, CM_CREDENTIAL_STORE);
        }

        static void RemoveCertificateFiles(CmBlob* uri)
        {
            (void)CmRmSaConf(reinterpret_cast<char*>(uri->data));
            (void)CmRmUserCert(reinterpret_cast<char*>(uri->data));
        }
    };

    static void InitializeCertOperationStructs(CmSignatureSpec* spec, CmBlob* certBlob,
        CmBlob* authUri, CmAppUidList* appUidList)
    {
        if (spec != nullptr) {
            (void)memset_s(spec, sizeof(CmSignatureSpec), 0, sizeof(CmSignatureSpec));
        }
        
        if (certBlob != nullptr) {
            (void)memset_s(certBlob, sizeof(CmBlob), 0, sizeof(CmBlob));
        }
        
        if (authUri != nullptr) {
            (void)memset_s(authUri, sizeof(CmBlob), 0, sizeof(CmBlob));
        }
        
        if (appUidList != nullptr) {
            (void)memset_s(appUidList, sizeof(CmAppUidList), 0, sizeof(CmAppUidList));
        }
    }

    static void ProcessCertificateOperations(CertificateOperationContext& ctx,
        CmAppCertParam* appCertParam,
        CmBlob* userCert,
        CmBlob* certAlias)
    {
        struct CmBlob certBlob;
        struct CmBlob authUri;
        struct CmAppUidList appUidList;
        
        InitializeCertOperationStructs(ctx.spec, &certBlob, &authUri, &appUidList);

        CertificateInstaller::InstallAppCertificate(ctx, appCertParam);
        CertificateRetriever::GetAppCertificate(ctx, &certBlob);
        AuthorizationManager::GrantAppCertificate(ctx, &authUri);
        AuthorizationManager::GetAuthorizedAppList(ctx, &appUidList);
        AuthorizationManager::IsAuthorizedApp(ctx);
        SignatureManager::InitializeSignature(ctx, &authUri);
        AuthorizationManager::RemoveGrantedApp(ctx);
        CertificateUninstaller::UninstallUserCertificate(ctx);
        CertificateUninstaller::RemoveCertificateFiles(ctx.uri);
        CertificateInstaller::InstallMultiUserCertificate(ctx, userCert, certAlias);
        CertificateRetriever::GetCertificateInfo(ctx, &certBlob);
        CertificateUninstaller::UninstallAppCertificate(ctx.uri);
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
        *randomUri = { len, heapData };
        delete[] random;
        return true;
    }

    static bool GetStoreAndUpdateFromBuffer(uint8_t* myData, uint32_t* remainSize, uint32_t* offset,
        uint32_t* store, uint32_t* update)
    {
        if (myData == nullptr || remainSize == nullptr || offset == nullptr ||
            store == nullptr || update == nullptr) {
            return false;
        }

        if (!GetUintFromBuffer(myData, remainSize, offset, store)) {
            return false;
        }

        const uint32_t STORE_VALUE = 5;
        *store %= STORE_VALUE;
        
        if (!GetUintFromBuffer(myData, remainSize, offset, update)) {
            return false;
        }

        return true;
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

        uint32_t store;
        uint32_t update;
        if (!GetStoreAndUpdateFromBuffer(myData, &remainSize, &offset, &store, &update)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob userCert = {sizeof(g_p7bUserCertInfo), const_cast<uint8_t *>(g_p7bUserCertInfo)};
        struct CmSignatureSpec spec;
        struct CmBlob certBlob;
        struct CmBlob authUri;
        struct CmAppUidList appUidList;
        InitializeCertOperationStructs(&spec, &certBlob, &authUri, &appUidList);
        CertmanagerTest::MockHapToken mockHap;
        CertificateOperationContext ctx = {&cmContext, &keyUri, store, uid, &spec};
        ProcessCertificateOperations(ctx, &appCertParam, &userCert, &certAlias);
        struct CmBlob randomUri;
        if (!GenerateRandomUri(retUriBuf, myData, &remainSize, &offset, &randomUri)) {
            CmFree(myData);
            return false;
        }

        ctx.uri = &randomUri;
        ProcessCertificateOperations(ctx, &appCertParam, &userCert, &certAlias);
        CmFree(myData);
        return true;
    }

    bool DoSomethingInterestingWithMyAPICmService(const uint8_t* data, size_t size)
    {
        char retUriBuf[MAX_OUT_BLOB_SIZE] = {0};
        struct CmBlob keyUri = {sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
        uint8_t certAliasBuf[] = "PrivKeyA";
        struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };
        struct CmBlob privKey = { 0, NULL };
        struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
            &certAlias, CM_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2,
            FILE_P12, &privKey, DEFAULT_FORMAT };
        uint32_t uid = 20020156;
        uint32_t userId = 100;
        CmContext cmContext;
        cmContext.uid = uid;
        cmContext.userId = userId;
        if (CertManagerInitialize() != 0) {
            return false;
        }

        struct CmBlob certificateData = { 0, nullptr };
        uint32_t status = 0;
        CmInstallAppCertPro(&cmContext, &appCertParam, &keyUri);
        (void)CmServicInstallAppCert(&cmContext, &appCertParam, &keyUri);
        (void)CmServiceGetCertInfo(&cmContext, &keyUri, CM_SYSTEM_TRUSTED_STORE, &certificateData, &status);
        (void)CmServiceGetCertInfo(&cmContext, &keyUri, CM_USER_TRUSTED_STORE, &certificateData, &status);
        (void)CmServiceGetCertInfo(&cmContext, &keyUri, CM_CREDENTIAL_STORE, &certificateData, &status);
        (void)CmServiceGetAppCert(&cmContext, CM_CREDENTIAL_STORE, &keyUri, &certificateData);
        (void)CmServiceGetAppCert(&cmContext, CM_PRI_CREDENTIAL_STORE, &keyUri, &certificateData);
        (void)CmServiceGetAppCert(&cmContext, CM_SYS_CREDENTIAL_STORE, &keyUri, &keyUri);
        (void)CmServiceGrantAppCertificate(&cmContext, &keyUri, userId, &certificateData);
        (void)CmServiceIsAuthorizedApp(&cmContext, &keyUri);
        (void)CmServiceRemoveGrantedApp(&cmContext, &keyUri, uid);
        (void)CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
        return true;
    }

    bool DoSomethingInterestingWithMyAPICmServiceManager(const uint8_t* data, size_t size)
    {
        char retUriBuf[MAX_OUT_BLOB_SIZE] = {0};
        struct CmBlob keyUri = {sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
        uint8_t certAliasBuf[] = "PrivKeyA";
        struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };
        struct CmBlob privKey = { 0, NULL };
        struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
            &certAlias, CM_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2,
            FILE_P12, &privKey, DEFAULT_FORMAT };
        uint32_t uid = 20020156;
        uint32_t userId = 100;
        CmContext cmContext;
        cmContext.uid = uid;
        cmContext.userId = userId;
        if (CertManagerInitialize() != 0) {
            return false;
        }

        struct CmBlob certificateData = { 0, nullptr };
        uint32_t status = 0;
        CmInstallAppCertPro(&cmContext, &appCertParam, &keyUri);
        (void)CmServiceAbort(&cmContext, &keyUri);
        (void)CmServiceGetCertInfo(&cmContext, &keyUri, CM_SYSTEM_TRUSTED_STORE, &certificateData, &status);
        (void)CmServiceGetCertInfo(&cmContext, &keyUri, CM_USER_TRUSTED_STORE, &certificateData, &status);
        (void)CmUninstallUserCert(&cmContext, &keyUri);
        (void)CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    OHOS::DoSomethingInterestingWithMyAPICmService(data, size);
    OHOS::DoSomethingInterestingWithMyAPICmServiceManager(data, size);
    return 0;
}