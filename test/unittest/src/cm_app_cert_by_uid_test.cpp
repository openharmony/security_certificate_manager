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

#include "cert_manager_api.h"
#include "cm_mem.h"
#include "cert_manager_uri.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_cert_data_chain_key.h"

#include "cm_test_common.h"
#include "cm_test_log.h"

#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "access_token.h"

using namespace testing::ext;
using namespace CertmanagerTest;
using namespace OHOS::Security::AccessToken;
namespace {
static uint32_t g_selfTokenId = 0;
static MockHapToken* g_MockHap = nullptr;
struct CredentialResult {
    struct Credential certificate;
    bool bExpectResult;
};

struct CredentialAbstractResult {
    struct CredentialAbstract credentialAbstract;
    bool bExpectResult;
};

static const struct CmBlob g_appCert = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
static const struct CmBlob g_appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };

class CmGetAppCertListByUidTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmGetAppCertListByUidTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmGetAppCertListByUidTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmGetAppCertListByUidTest::SetUp()
{
    g_MockHap = new (std::nothrow) MockHapToken();
}

void CmGetAppCertListByUidTest::TearDown()
{
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }
}

/**
 * @tc.name: CmGetAppCertListPerformanceTest001
 * @tc.desc: Test CertManager get app cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetAppCertListByUidTest, CmGetAppCertListPerformanceTest001, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertListPerformanceTest001 private install failed, retcode:" << ret;

    struct CredentialList certificateList = { 0, nullptr };
    uint32_t buffSize = MAX_COUNT_CERTIFICATE * sizeof(struct CredentialAbstract);
    certificateList.credentialAbstract = static_cast<struct CredentialAbstract *>(CmMalloc(buffSize));
    ASSERT_TRUE(certificateList.credentialAbstract != nullptr);
    uint32_t times = 1;
    for (uint32_t i = 0; i < times; i++) {
        certificateList.credentialCount = MAX_COUNT_CERTIFICATE;
        (void)memset_s(certificateList.credentialAbstract, buffSize, 0, buffSize);
        ret = CmGetAppCertListByUid(CM_PRI_CREDENTIAL_STORE, 0, &certificateList);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertListByUidTest test failed, retcode:" << ret;
    }

    if (certificateList.credentialAbstract != nullptr) {
        CmFree(certificateList.credentialAbstract);
    }
}

/**
 * @tc.name: CmGetAppCertListByUidAbnormalTest002
 * @tc.desc: Test CertManager get app cert list interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetAppCertListByUidTest, CmGetAppCertListByUidAbnormalTest002, TestSize.Level0)
{
    int32_t ret = CmGetAppCertListByUid(CM_PRI_CREDENTIAL_STORE , 0, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Abnormal CmGetAppCertListByUidAbnormalTest002 test failed, retcode:" << ret;
}
} // end of namespace

