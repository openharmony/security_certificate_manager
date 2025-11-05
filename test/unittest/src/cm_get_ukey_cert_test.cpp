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
#include "cm_native_api.h"
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

        (void)memset_s(certificateList->credential[i].credData.data, MAX_LEN_CERTIFICATE_CHAIN, 0,
            MAX_LEN_CERTIFICATE_CHAIN);
        certificateList->credential[i].credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    }
}

static void FreeUkeyCertList(struct CredentialDetailList *certificateList)
{
    if (certificateList == nullptr || certificateList->credential == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < MAX_COUNT_UKEY_CERTIFICATE; ++i) {
        CM_FREE_BLOB(certificateList->credential[i].credData);
    }
    certificateList->credentialCount = 0;
    CM_FREE_PTR(certificateList->credential);
    certificateList = nullptr;
}

static void FreeCredential(Credential *credential)
{
    if (credential == nullptr) {
        return;
    }
    CM_FREE_BLOB(credential->credData);
    credential = nullptr;
}

static void buildCertIndex(const string providerName, CmBlob &providerNameBlob)
{
    char *data = static_cast<char*>(CmMalloc(providerName.length() + 1));
    ASSERT_TRUE(data != nullptr);
    if (memcpy_s(data, providerName.length() + 1, providerName.c_str(), providerName.length()
         + 1) != EOK) {
        return;
    }

    providerNameBlob.data = reinterpret_cast<uint8_t *>(data);
    providerNameBlob.size = static_cast<uint32_t>((providerName.length() + 1) & UINT32_MAX);

    return;
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
    buildCertIndex(providerName, providerNameBlob);
    struct UkeyInfo ukeyInfo1;
    ukeyInfo1.certPurpose = CM_CERT_PURPOSE_SIGN;

    struct CredentialDetailList ukeyList = { 0, nullptr };
    InitUkeyCertList(&ukeyList);
    ASSERT_TRUE(ukeyList.credential[0].credData.data != nullptr);
    providerNameBlob.size -= 1;
    int32_t ret = CmGetUkeyCertList(&providerNameBlob, &ukeyInfo1, &ukeyList);
    EXPECT_EQ(ret, CMR_ERROR_UKEY_GENERAL_ERROR) << "CmGetUkeyCertList test failed, retcode:" << ret;

    uint8_t *uriBuf = static_cast<uint8_t*>(CmMalloc(sizeof(ukeyList.credential[0].alias)));
    ASSERT_TRUE(uriBuf != nullptr);
    EXPECT_EQ(memcpy_s(uriBuf, sizeof(ukeyList.credential[0].alias), ukeyList.credential[0].alias,
        sizeof(ukeyList.credential[0].alias)), EOK) << "copy failed";
    struct CmBlob retUri = { sizeof(ukeyList.credential[0].alias), uriBuf };

    struct CredentialDetailList certificateList = { 0, nullptr };
    InitUkeyCertList(&certificateList);
    ASSERT_TRUE(certificateList.credential[0].credData.data != nullptr);

    struct UkeyInfo ukeyInfo2;
    ukeyInfo2.certPurpose = CM_CERT_PURPOSE_SIGN;

    ret = CmGetUkeyCert(&retUri, &ukeyInfo2, &certificateList);
    EXPECT_EQ(ret, CMR_ERROR_UKEY_GENERAL_ERROR) << "CmGetAppCertBaseTest001 test failed, retcode:" << ret;

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
 * @tc.desc: Test CertManager check private app permission interface base function
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

    ret = CmUninstallAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert private uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: CmCheckAppPermissionAbnormalTest002
 * @tc.desc: Test CertManager check private app permission interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmCheckAppPermissionAbnormalTest002, TestSize.Level0)
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

    ret = CmUninstallAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert private uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: CmCheckAppPermissionBaseTest003
 * @tc.desc: Test CertManager check public app permission interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmCheckAppPermissionBaseTest003, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmInstallAppCert failed, retcode:" << ret;

    uint8_t authUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob authUri = { sizeof(authUriBuf), authUriBuf };
    ret = CmGrantAppCertificate(&keyUri, 0, &authUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate  failed, retcode:" << ret;

    enum CmPermissionState hasPermission;
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    ret = CmCheckAppPermission(&authUri, 0, &hasPermission, &alias);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmCheckAppPermission  failed, retcode:" << ret;

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert private uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: CmCheckAppPermissionAbnormalTest004
 * @tc.desc: Test CertManager check public app permission interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmCheckAppPermissionAbnormalTest004, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmInstallAppCert failed, retcode:" << ret;

    uint8_t authUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob authUri = { sizeof(authUriBuf), authUriBuf };
    ret = CmGrantAppCertificate(&keyUri, 0, &authUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate  failed, retcode:" << ret;

    enum CmPermissionState hasPermission;
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    ret = CmCheckAppPermission(&authUri, 1, &hasPermission, &alias);
    EXPECT_EQ(ret, CMR_ERROR_NOT_PERMITTED) << "CmCheckAppPermission  failed, retcode:" << ret;

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert private uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: CmGetUkeyCertNDKBaseTest001
 * @tc.desc: Test CertManager get ukey cert NDK interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmGetUkeyCertNDKBaseTest001, TestSize.Level0)
{
    string providerName = "testHap";
    CmBlob providerNameBlob = { 0, nullptr };
    buildCertIndex(providerName, providerNameBlob);
    struct UkeyInfo ukeyInfo1;
    ukeyInfo1.certPurpose = CM_CERT_PURPOSE_SIGN;

    struct CredentialDetailList ukeyList = { 0, nullptr };
    InitUkeyCertList(&ukeyList);
    ASSERT_TRUE(ukeyList.credential[0].credData.data != nullptr);
    providerNameBlob.size -= 1;
    int32_t ret = CmGetUkeyCertList(&providerNameBlob, &ukeyInfo1, &ukeyList);
    EXPECT_EQ(ret, CMR_ERROR_UKEY_GENERAL_ERROR) << "CmGetUkeyCertList test failed, retcode:" << ret;

    uint8_t *uriBuf = static_cast<uint8_t*>(CmMalloc(sizeof(ukeyList.credential[0].keyUri)));
    ASSERT_TRUE(uriBuf != nullptr);
    EXPECT_EQ(memcpy_s(uriBuf, sizeof(ukeyList.credential[0].keyUri), ukeyList.credential[0].keyUri,
        sizeof(ukeyList.credential[0].keyUri)), EOK) << "copy failed";
    struct CmBlob retUri = { sizeof(ukeyList.credential[0].keyUri), uriBuf };

    struct CredentialDetailList certificateList = { 0, nullptr };
    InitUkeyCertList(&certificateList);
    ASSERT_TRUE(certificateList.credential[0].credData.data != nullptr);

    struct UkeyInfo ukeyInfo2;
    ukeyInfo2.certPurpose = CM_CERT_PURPOSE_SIGN;

    ret = OH_CertManager_GetUkeyCertificate(reinterpret_cast<OH_CM_Blob*>(&retUri),
        reinterpret_cast<OH_CM_UkeyInfo*>(&ukeyInfo2),
        reinterpret_cast<OH_CM_CredentialDetailList*>(&certificateList));
    EXPECT_EQ(ret, OH_CM_ACCESS_UKEY_SERVICE_FAILED) <<
        "OH_CertManager_GetUkeyCertificate test failed, retcode:" << ret;

    FreeUkeyCertList(reinterpret_cast<CredentialDetailList*>(&certificateList));
    FreeUkeyCertList(reinterpret_cast<CredentialDetailList*>(&ukeyList));
}

/**
 * @tc.name: CmGetPrivateCertNDKBaseTest002
 * @tc.desc: Test CertManager get private cert NDK interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmGetPrivateCertNDKBaseTest002, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmCheckAppPermissionBaseTest001 private install failed, retcode:" << ret;

    struct Credential cert;

    ret = OH_CertManager_GetPrivateCertificate(reinterpret_cast<OH_CM_Blob*>(&keyUri),
        reinterpret_cast<OH_CM_Credential*>(&cert));
    
    EXPECT_EQ(ret, CM_SUCCESS) << "OH_CertManager_GetPrivateCertificate  failed, retcode:" << ret;

    ret = CmUninstallAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert private uninstall failed, retcode:" << ret;
    FreeCredential(reinterpret_cast<Credential*>(&cert));
}

/**
 * @tc.name: CmGetPublicCertNDKBaseTest003
 * @tc.desc: Test CertManager get public cert NDK interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmGetPublicCertNDKBaseTest003, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmCheckAppPermissionBaseTest001 private install failed, retcode:" << ret;

    uint8_t authUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob authUri = { sizeof(authUriBuf), authUriBuf };
    ret = CmGrantAppCertificate(&keyUri, 0, &authUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate  failed, retcode:" << ret;

    struct Credential cert;

    ret = OH_CertManager_GetPublicCertificate(reinterpret_cast<OH_CM_Blob*>(&authUri),
        reinterpret_cast<OH_CM_Credential*>(&cert));
    EXPECT_EQ(ret, CM_SUCCESS) << "OH_CertManager_GetPublicCertificate  failed, retcode:" << ret;

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert public uninstall failed, retcode:" << ret;
    FreeCredential(reinterpret_cast<Credential*>(&cert));
}

/**
 * @tc.name: CmGetUkeyCertNDKAbnormalTest001
 * @tc.desc: Test CertManager get ukey cert NDK interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmGetUkeyCertNDKAbnormalTest001, TestSize.Level0)
{
    string providerName = "testHap";
    CmBlob providerNameBlob = { 0, nullptr };
    buildCertIndex(providerName, providerNameBlob);
    struct UkeyInfo ukeyInfo1;
    ukeyInfo1.certPurpose = CM_CERT_PURPOSE_SIGN;

    struct CredentialDetailList ukeyList = { 0, nullptr };
    InitUkeyCertList(&ukeyList);
    ASSERT_TRUE(ukeyList.credential[0].credData.data != nullptr);
    providerNameBlob.size -= 1;
    int32_t ret = CmGetUkeyCertList(&providerNameBlob, &ukeyInfo1, &ukeyList);
    EXPECT_EQ(ret, CMR_ERROR_UKEY_GENERAL_ERROR) << "CmGetUkeyCertList test failed, retcode:" << ret;

    uint8_t *uriBuf = static_cast<uint8_t*>(CmMalloc(sizeof(ukeyList.credential[0].keyUri)));
    ASSERT_TRUE(uriBuf != nullptr);
    EXPECT_EQ(memcpy_s(uriBuf, sizeof(ukeyList.credential[0].keyUri), ukeyList.credential[0].keyUri,
        sizeof(ukeyList.credential[0].keyUri)), EOK) << "copy failed";
    struct CmBlob retUri = { sizeof(ukeyList.credential[0].keyUri), uriBuf };

    struct CredentialDetailList certificateList = { 0, nullptr };
    InitUkeyCertList(&certificateList);
    ASSERT_TRUE(certificateList.credential[0].credData.data != nullptr);

    struct UkeyInfo ukeyInfo2;
    ukeyInfo2.certPurpose = CM_CERT_PURPOSE_ENCRYPT;
    retUri.data[0] = 0x99;
    ret = OH_CertManager_GetUkeyCertificate(reinterpret_cast<OH_CM_Blob*>(&retUri),
        reinterpret_cast<OH_CM_UkeyInfo*>(&ukeyInfo2),
        reinterpret_cast<OH_CM_CredentialDetailList*>(&certificateList));
    EXPECT_EQ(ret, OH_CM_ACCESS_UKEY_SERVICE_FAILED) << "CmGetAppCertBaseTest001 test failed, retcode:" << ret;

    FreeUkeyCertList(reinterpret_cast<CredentialDetailList*>(&certificateList));
    FreeUkeyCertList(reinterpret_cast<CredentialDetailList*>(&ukeyList));
}

/**
 * @tc.name: CmGetPrivateCertNDKAbnormalTest002
 * @tc.desc: Test CertManager get private cert NDK interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmGetPrivateCertNDKAbnormalTest002, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmCheckAppPermissionBaseTest001 private install failed, retcode:" << ret;

    ret = CmUninstallAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert private uninstall failed, retcode:" << ret;

    struct Credential cert;
    ret = OH_CertManager_GetPrivateCertificate(reinterpret_cast<OH_CM_Blob*>(&keyUri),
        reinterpret_cast<OH_CM_Credential*>(&cert));
    
    EXPECT_EQ(ret, OH_CM_NOT_FOUND) << "OH_CertManager_GetPrivateCertificate  failed, retcode:" << ret;

    FreeCredential(reinterpret_cast<Credential*>(&cert));
}

/**
 * @tc.name: CmGetPublicCertNDKAbnormalTest003
 * @tc.desc: Test CertManager get public cert NDK interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmGetUkeyCertTest, CmGetPublicCertNDKAbnormalTest003, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmCheckAppPermissionBaseTest001 private install failed, retcode:" << ret;

    uint8_t authUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob authUri = { sizeof(authUriBuf), authUriBuf };
    ret = CmGrantAppCertificate(&keyUri, 0, &authUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate  failed, retcode:" << ret;

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert public uninstall failed, retcode:" << ret;

    struct Credential cert;
    ret = OH_CertManager_GetPublicCertificate(reinterpret_cast<OH_CM_Blob*>(&authUri),
        reinterpret_cast<OH_CM_Credential*>(&cert));
    EXPECT_EQ(ret, OH_CM_NOT_FOUND) << "OH_CertManager_GetPublicCertificate  failed, retcode:" << ret;
    FreeCredential(reinterpret_cast<Credential*>(&cert));
}
}
