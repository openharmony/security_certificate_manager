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

#include "cmkeyopprocess_fuzzer.h"

#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_key_operation.h"
#include "cert_manager.h"
#include "cert_manager_api.h"
#include "cert_manager_app_cert_process.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_x509.h"
#include "cert_manager_permission_check.h"

namespace {
    const struct CmBlob g_eccAppCert = { sizeof(g_eccP256P12CertInfo), const_cast<uint8_t *>(g_eccP256P12CertInfo) };
    const struct CmBlob g_appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    const uint32_t UINT32_COUNT = 4;
    const uint32_t CM_BLOB_COUNT = 2;
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
        struct CmBlob inData = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &inData)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob handle = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &handle)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob outData = {0, nullptr};
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &outData)) {
            CmFree(myData);
            return false;
        }

        struct CmContext cmContext;
        if (!CreateCmContext(cmContext, myData, remainSize, offset)) {
            CmFree(myData);
            return false;
        }

        CmSignVerifyCmd cmdId = SIGN_VERIFY_CMD_UPDATE;
        CertmanagerTest::MockHapToken mockHap;
        (void)CmKeyOpProcess(cmdId, &cmContext, &handle, &inData, &outData);
        CmFree(myData);
        return true;
    }

    bool DoSomethingInterestingWithMyAPICmKey(const uint8_t* data, size_t size)
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
        CmContext cmContext1;
        cmContext1.uid = 0;
        cmContext1.userId = 0;
        if (CertManagerInitialize() != 0) {
            return false;
        }

        CmInstallAppCertPro(&cmContext, &appCertParam, &keyUri);
        struct CmBlob handle;
        (void)memset_s(&handle, sizeof(CmBlob), 0, sizeof(CmBlob));
        struct CmBlob inData;
        (void)memset_s(&inData, sizeof(CmBlob), 0, sizeof(CmBlob));
        struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
        CertmanagerTest::MockHapToken mockHap;
        (void)CmKeyOpInit(&cmContext, &certAlias, &spec, CM_AUTH_STORAGE_LEVEL_EL1, &handle);
        (void)CmKeyOpProcess(SIGN_VERIFY_CMD_UPDATE, &cmContext, &handle, &inData, &handle);
        (void)CmKeyOpProcess(SIGN_VERIFY_CMD_FINISH, &cmContext, &handle, &inData, &handle);
        (void)CmKeyOpProcess(SIGN_VERIFY_CMD_ABORT, &cmContext, &handle, &inData, &handle);
        (void)CmHasSystemAppPermission();
        (void)CmIsSystemApp();
        (void)CmIsSystemAppByStoreType(CM_CREDENTIAL_STORE);
        (void)CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
        return true;
    }
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    OHOS::DoSomethingInterestingWithMyAPICmKey(data, size);
    return 0;
}

