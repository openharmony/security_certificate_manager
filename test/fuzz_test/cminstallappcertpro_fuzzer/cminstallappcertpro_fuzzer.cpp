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

#include "cminstallappcertpro_fuzzer.h"

#include "cert_manager_app_cert_process.h"
#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_uri.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_ed25519.h"
#include "cm_cert_property_rdb.h"

namespace {
    const uint32_t UINT32_COUNT = 4;
    const uint32_t CM_BLOB_COUNT = 2;
    const struct CmBlob g_appCert = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    const struct CmBlob g_appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    const struct CmBlob g_eccAppCert = { sizeof(g_eccP256P12CertInfo), const_cast<uint8_t *>(g_eccP256P12CertInfo) };
    const struct CmBlob g_ed25519Cert = { sizeof(g_ed25519P12CertInfo), const_cast<uint8_t *>(g_ed25519P12CertInfo) };
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

        struct CmAppCertParam appCertParam;
        uint8_t certAliasBuf[] = "PrikeyA";
        struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };
        struct CmBlob privKey = { 0, nullptr };
        appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
            &certAlias, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
            CM_AUTH_STORAGE_LEVEL_EL1, FILE_P12, &privKey, DEFAULT_FORMAT};
        uint8_t uriData[] = "oh:t=ak;o=TestNormalGrant;u=0;a=0";
        struct CmBlob keyUri = { sizeof(uriData), uriData };
        uint8_t certAliasBuf001[] = "prikeyB";
        struct CmBlob certAlias01 = { sizeof(certAliasBuf001), certAliasBuf001 };
        struct CmAppCertParam appCertParam01 = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
            &certAlias01, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
            CM_AUTH_STORAGE_LEVEL_EL1, FILE_P12, &privKey, DEFAULT_FORMAT};
        uint8_t certAliasBuf002[] = "prikeyC";
        struct CmBlob certAlias02 = { sizeof(certAliasBuf002), certAliasBuf002 };
        struct CmAppCertParam appCertParam02 = { (struct CmBlob *)&g_ed25519Cert, (struct CmBlob *)&g_appCertPwd,
            &certAlias02, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
            CM_AUTH_STORAGE_LEVEL_EL1, FILE_P12, &privKey, DEFAULT_FORMAT};
        CertmanagerTest::MockHapToken mockHap;
        (void)CreateCertPropertyRdb();
        (void)CmInstallAppCertPro(&cmContext, &appCertParam, &keyUri);
        (void)CmInstallAppCertPro(&cmContext, &appCertParam01, &keyUri);
        (void)CmInstallAppCertPro(&cmContext, &appCertParam02, &keyUri);
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

