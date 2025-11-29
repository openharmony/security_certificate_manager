/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "cm_test_common.h"
#include "cm_pfx.h"
#include "cm_cert_data_chain_key.h"
#include "cm_advsecmode_check.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
static uint32_t g_selfTokenId = 0;
static MockHapToken* g_MockHap = nullptr;

static const struct CmBlob g_appDerCertChain = { sizeof(g_rsa2048DERCertChain),
    const_cast<uint8_t *>(g_rsa2048DERCertChain) };
static const struct CmBlob g_appDerCertPrivKey = { sizeof(g_rsa2048DERPrivKey),
    const_cast<uint8_t *>(g_rsa2048DERPrivKey) };

class CmPfxTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmPfxTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmPfxTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmPfxTest::SetUp()
{
    g_MockHap = new (std::nothrow) MockHapToken();
}

void CmPfxTest::TearDown()
{
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }
}

/**
* @tc.name: CmPfxTest001
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParsePkcs12Cert
*/
HWTEST_F(CmPfxTest, CmPfxTest001, TestSize.Level0)
{
    uint8_t p12CertBuf[] = "p12CertBuf";
    struct CmBlob p12Cert = { sizeof(p12CertBuf), p12CertBuf };
    char passWd[] = "passWd";
    EVP_PKEY *pkey = NULL;
    X509 *x509Cert = NULL;
    struct AppCert *appCert = NULL;
    int32_t ret = CmParsePkcs12Cert(&p12Cert, passWd, &pkey, appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT);
}

/**
* @tc.name: CmPfxTest002
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest002, TestSize.Level0)
{
    struct CmBlob *certChain = NULL;
    struct CmBlob *privKey = NULL;;
    EVP_PKEY *pkey = NULL;
    X509 *x509Cert = NULL;
    struct AppCert *appCert = NULL;
    int32_t ret = CmParseCertChainAndPrivKey(certChain, privKey, &pkey, appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
}

/**
* @tc.name: CmPfxTest003
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest003, TestSize.Level0)
{
    uint8_t certChainBuf[] = "certChainBuf";
    struct CmBlob certChain = { sizeof(certChainBuf), certChainBuf };
    struct CmBlob *privKey = NULL;;
    EVP_PKEY *pkey = NULL;
    X509 *x509Cert = NULL;
    struct AppCert *appCert = NULL;
    int32_t ret = CmParseCertChainAndPrivKey(&certChain, privKey, &pkey, appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_OPENSSL_FAIL);
}

/**
* @tc.name: CmPfxTest004
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest004, TestSize.Level0)
{
    bool *isAdvSecMode = NULL;
    int32_t ret = CheckAdvSecMode(isAdvSecMode);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmPfxTest005
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest005, TestSize.Level0)
{
    EVP_PKEY *pkey = NULL;
    X509 *x509Cert = NULL;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    int32_t ret = CmParseCertChainAndPrivKey(&g_appDerCertChain, &g_appDerCertPrivKey, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CM_SUCCESS);
}
} // end of namespace
