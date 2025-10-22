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

#include <string>
#include <gtest/gtest.h>
#include "cm_test_log.h"
#include "cm_test_common.h"
#include "cm_mem.h"
#include "cert_manager_api.h"
#include "cm_cert_data_part1_rsa.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static uint32_t g_selfTokenId = 0;
static MockHapToken* g_MockHap = nullptr;

class CmGetUkeyCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();

    struct CertList *lstCert;
};

void CmGetUkeyCertTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmGetUkeyCertTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmGetUkeyCertTest::SetUp()
{
    InitCertList(&lstCert);
    g_MockHap = new (std::nothrow) MockHapToken();
}

void CmGetUkeyCertTest::TearDown()
{
    FreeCertList(lstCert);
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }
}

static const struct CmBlob g_appCert = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
static const struct CmBlob g_appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };

static void InitUkeyCertList(struct CredentialDetailList *certificateList)
{
    uint32_t buffSize = (MAX_COUNT_UKEY_CERTIFICATE * sizeof(struct Credential));
    certificateList->credential = static_cast<struct Credential *>(CmMalloc(buffSize));
    ASSERT_TRUE(certificateList->credential != nullptr);
    (void)memset_s(certificateList->credential, buffSize, 0, buffSize);
    certificateList->credentialCount = MAX_COUNT_UKEY_CERTIFICATE;
    for (uint32_t i = 0; i < MAX_COUNT_UKEY_CERTIFICATE; ++i) {
        certificateList->credential[i].credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
        ASSERT_TRUE(certificateList->credential[i].credData.data != nullptr);

        (void)memset_s(certificateList->credential[i].credData.data, MAX_LEN_CERTIFICATE_CHAIN, 0, MAX_LEN_CERTIFICATE_CHAIN);
        certificateList->credential[i].credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    }
}

static void FreeUkeyCertList(struct CredentialDetailList *certificateList)
{
    if (certificateList == NULL || certificateList->credential == NULL) {
        return;
    }
    for (uint32_t i = 0; i < MAX_COUNT_UKEY_CERTIFICATE; ++i) {
        CM_FREE_BLOB(certificateList->credential[i].credData);
    }
    certificateList->credentialCount = 0;
    CM_FREE_PTR(certificateList->credential);
    certificateList = NULL;
}

static int32_t buildCertIndex(const string providerName, CmBlob &providerNameBlob)
{
    char *data = static_cast<char*>(CmMalloc(providerName.length() + 1));
    memcpy_s(data, providerName.length() + 1, providerName.c_str(), providerName.length() + 1);

    providerNameBlob.data = reinterpret_cast<uint8_t *>(data);
    providerNameBlob.size = static_cast<uint32_t>((providerName.length() + 1) & UINT32_MAX);

    return CM_SUCCESS;
}

/**
 * @tc.name: CmGetUkeyCertBaseTest001
 * @tc.desc: Test CertManager get ukey cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmGetUkeyCertTestBaseTest001, TestSize.Level0)
{
    string providerName = "testHap";
    CmBlob providerNameBlob = { 0, nullptr };
    int32_t ret = buildCertIndex(providerName, providerNameBlob);
    struct UkeyInfo ukeyInfo1;
    ukeyInfo1.certPurpose = CM_CERT_PURPOSE_SIGN;

    struct CredentialDetailList ukeyList = { 0, nullptr };
    InitUkeyCertList(&ukeyList);
    ASSERT_TRUE(ukeyList.credential[0].credData.data != nullptr);
    providerNameBlob.size -= 1;
    ret = CmGetUkeyCertList(&providerNameBlob, &ukeyInfo1, &ukeyList);
    EXPECT_EQ(ret, CM_FAILURE) << "CmGetUkeyCertList test failed, retcode:" << ret;

    uint8_t *uriBuf = static_cast<uint8_t*>(CmMalloc(sizeof(ukeyList.credential[0].alias)));
    memcpy_s(uriBuf, sizeof(ukeyList.credential[0].alias), ukeyList.credential[0].alias, sizeof(ukeyList.credential[0].alias));
    struct CmBlob retUri = { sizeof(ukeyList.credential[0].alias), uriBuf };

    struct CredentialDetailList certificateList = { 0, nullptr };
    InitUkeyCertList(&certificateList);
    ASSERT_TRUE(certificateList.credential[0].credData.data != nullptr);

    struct UkeyInfo ukeyInfo2;
    ukeyInfo2.certPurpose = CM_CERT_PURPOSE_SIGN;

    ret = CmGetUkeyCert(&retUri, &ukeyInfo2, &certificateList);
    EXPECT_EQ(ret, CM_FAILURE) << "CmGetAppCertBaseTest001 test failed, retcode:" << ret;

    FreeUkeyCertList(&certificateList);
    FreeUkeyCertList(&ukeyList);
}

/**
 * @tc.name: CmGetUkeyCertTestAbnormalTest002
 * @tc.desc: Test CertManager get ukey cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmGetUkeyCertTestAbnormalTest002, TestSize.Level0)
{
    struct UkeyInfo ukeyInfo1;
    ukeyInfo1.certPurpose = CM_CERT_PURPOSE_SIGN;

    struct CredentialDetailList ukeyList = { 0, nullptr };
    InitUkeyCertList(&ukeyList);
    ASSERT_TRUE(ukeyList.credential[0].credData.data != nullptr);
    int32_t ret = CmGetUkeyCertList(nullptr, &ukeyInfo1, &ukeyList);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER) << "CmGetUkeyCertList test failed, retcode:" << ret;

    struct CredentialDetailList certificateList = { 0, nullptr };
    InitUkeyCertList(&certificateList);
    ASSERT_TRUE(certificateList.credential[0].credData.data != nullptr);

    struct UkeyInfo ukeyInfo2;
    ukeyInfo2.certPurpose = CM_CERT_PURPOSE_SIGN;

    ret = CmGetUkeyCert(nullptr, &ukeyInfo2, &certificateList);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER) << "CmGetAppCertBaseTest002 test failed, retcode:" << ret;

    FreeUkeyCertList(&certificateList);
    FreeUkeyCertList(&ukeyList);
}

/**
 * @tc.name: CmCheckAppPermissionBaseTest001
 * @tc.desc: Test CertManager check app permission interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmCheckAppPermissionBaseTest001, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmCheckAppPermissionBaseTest001 private install failed, retcode:" << ret;

    enum CmPermissionState hasPermission;
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    ret = CmCheckAppPermission(&keyUri, 0, &hasPermission, &alias);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmCheckAppPermission  failed, retcode:" << ret;
}

/**
 * @tc.name: CmCheckAppPermissionAbnormalTest001
 * @tc.desc: Test CertManager check app permission interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmCheckAppPermissionAbnormalTest001, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmCheckAppPermissionBaseTest001 private install failed, retcode:" << ret;

    enum CmPermissionState hasPermission;
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    ret = CmCheckAppPermission(&keyUri, 1, &hasPermission, &alias);
    EXPECT_EQ(ret, CMR_ERROR_NOT_PERMITTED) << "CmCheckAppPermission  failed, retcode:" << ret;
}

/**
 * @tc.name: CmFreeUkeyCertificateBaseTest001
 * @tc.desc: Test CertManager free ukey certlist interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmFreeUkeyCertificateBaseTest001, TestSize.Level0)
{
    struct CredentialDetailList ukeyList = { 0, nullptr };
    InitUkeyCertList(&ukeyList);
    CmFreeUkeyCertificate(&ukeyList);
}

/**
 * @tc.name: CmFreeUkeyCertificateAbnormalTest001
 * @tc.desc: Test CertManager free ukey certlist interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmFreeUkeyCertificateAbnormalTest001, TestSize.Level0)
{
    struct CredentialDetailList ukeyList = { 0, nullptr };
    CmFreeUkeyCertificate(&ukeyList);
}

/**
 * @tc.name: CmFreeCredentialBaseTest001
 * @tc.desc: Test CertManager free credential interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmFreeCredentialBaseTest001, TestSize.Level0)
{
    struct Credential *cred = static_cast<struct Credential *>(CmMalloc(sizeof(struct Credential)));
    cred->credData.data = (uint8_t *)(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    CmFreeCredential(cred);
}

/**
 * @tc.name: CmFreeCredentialAbnormalTest001
 * @tc.desc: Test CertManager free credential interface abnarmal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmFreeCredentialAbnormalTest001, TestSize.Level0)
{
    struct Credential *cred = nullptr;
    CmFreeCredential(cred);
}
}
