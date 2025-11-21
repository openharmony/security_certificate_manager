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

#include "cmpfx_fuzzer.h"

#include <cstring>

#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_uri.h"
#include "cm_cert_data_chain_key.h"
#include "cm_cert_data_p7b.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_cert_data_user.h"
#include "cm_pfx.h"
#include "cm_x509.h"


using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        CertmanagerTest::MockHapToken mockHap;
        struct AppCert appCert;
        (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
        EVP_PKEY *pkey = nullptr;
        struct CmBlob cerInfo = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
        char temPwd[] = "this is a test";
        X509 *cert = nullptr;
        (void)CmParsePkcs12Cert(&cerInfo, temPwd, &pkey, &appCert, &cert);
        (void)CmParsePkcs12Cert(&cerInfo, reinterpret_cast<char *>(const_cast<uint8_t *>(g_certPwd)),
            &pkey, &appCert, &cert);
        static const struct CmBlob g_appDerCertPrivKey = { sizeof(g_rsa2048DERPrivKey),
            const_cast<uint8_t *>(g_rsa2048DERPrivKey) };
        static const struct CmBlob g_appDerCertChain = { sizeof(g_rsa2048DERCertChain),
            const_cast<uint8_t *>(g_rsa2048DERCertChain) };
        EVP_PKEY *pkey1 = nullptr;
        struct AppCert appCert1;
        (void)memset_s(&appCert1, sizeof(struct AppCert), 0, sizeof(struct AppCert));
        X509 *cert1 = nullptr;
        (void)CmParseCertChainAndPrivKey(&g_appDerCertChain, &g_appDerCertPrivKey, &pkey1, &appCert1, &cert1);
        FreeCertContext(cert);
        FreeCertContext(cert1);
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

