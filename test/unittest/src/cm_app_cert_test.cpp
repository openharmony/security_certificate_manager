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
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_mem.h"
#include "cm_test_common.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
struct CredentialResult {
    struct Credential certificate;
    bool bExpectResult;
};

struct CredentialResult g_credentialexpectResult[] = {
    {
        { 1, "ak", "keyA", "oh:t=ak;o=keyA;u=0;a=0", 2, 1, { 1961, nullptr } }, true /* cert num is 2, len is 1961 */
    }
};

struct CredentialAbstractResult {
    struct CredentialAbstract credentialAbstract;
    bool bExpectResult;
};

struct CredentialAbstractResult g_expectList[] = {
    {
        { "ak", "keyA", "oh:t=ak;o=keyA;u=100;a=500" }, false
    },
    {
        { "ak", "keyA", "oh:t=ak;o=keyA;u=0;a=0" }, true
    },
    {
        { "ak", "keyA", "oh:t=ak;o=keyA;u=200;a=0" }, false
    }
};

static const struct CmBlob g_appCert = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
static const struct CmBlob g_eccAppCert = { sizeof(g_eccP256P12CertInfo), const_cast<uint8_t *>(g_eccP256P12CertInfo) };
static const struct CmBlob g_appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };

static const uint8_t g_p12AbnormalCertinfo[] = {
    0x30, 0x82, 0x0b, 0xc1, 0x02, 0x01, 0x03, 0x30, 0x82, 0x0b, 0x87, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x0b, 0x78, 0x04, 0x82, 0x0b, 0x74, 0x30, 0x82,
    0x0b, 0x70, 0x30, 0x82, 0x06, 0x27, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
    0x06, 0xa0, 0x82, 0x06, 0x18, 0x30, 0x82, 0x06, 0x14, 0x02, 0x01, 0x00, 0x30, 0x82, 0x06, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x1c, 0x06, 0x0a, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x0e, 0x04, 0x08, 0x1a, 0x8f, 0xc1,
    0xd1, 0xda, 0x6c, 0xd1, 0xa9, 0x02, 0x02, 0x08, 0x00, 0x80, 0x82, 0x05, 0xe0, 0xd0, 0x2f, 0x2d,
    0x52, 0x09, 0x86, 0x55, 0x53, 0xf0, 0x49, 0x8f, 0x00, 0xa1, 0x4d, 0x21, 0xc8, 0xb4, 0xad, 0x27,
    0x12, 0x44, 0xab, 0x4d, 0x10, 0x14, 0xe3, 0x3c, 0x9a, 0x05, 0x77, 0x51, 0x90, 0x4a, 0x3a, 0x8a,
    0x09, 0xa9, 0x4b, 0x36, 0x50, 0x60, 0x22, 0x4b, 0x77, 0x12, 0x5c, 0x2f, 0x60, 0xd3, 0xd9, 0x30,
    0x94, 0x4d, 0x9e, 0x81, 0xc3, 0xe9, 0x9d, 0xd9, 0x47, 0xb3, 0x54, 0xa2, 0x9a, 0x8f, 0xe7, 0x58,
    0x95, 0xd7, 0x48, 0x87, 0xc4, 0x40, 0xad, 0x9a, 0x42, 0x1d, 0x36, 0xb7, 0x48, 0xbc, 0x70, 0x8c,
    0x84, 0xcb, 0x3c, 0x02, 0x25, 0x9f, 0xfe, 0x2c, 0x4a, 0x76, 0xb1, 0x27, 0x94, 0x8f, 0xb0, 0x07,
    0xf0, 0xc0, 0x00, 0x3a, 0x69, 0x16, 0xe1, 0x63, 0x0c, 0xe5, 0x92, 0xc2, 0x7d, 0x99, 0xd9, 0x11,
    0x40, 0xd8, 0x64, 0xab, 0x13, 0xda, 0x73, 0x7b, 0x12, 0x53, 0xb1, 0x0b, 0x0c, 0x67, 0x81, 0xe1,
    0xf5, 0x59, 0x3a, 0xc7, 0xe0, 0xe9, 0xda, 0x12, 0xc7, 0x2b, 0xab, 0x3d, 0xbc, 0x10, 0x3d, 0x1a,
    0x88, 0xc7, 0x1d, 0x31, 0x5f, 0x39, 0x63, 0x51, 0x8b, 0x11, 0x99, 0x05, 0xf9, 0x40, 0x42, 0x27,
    0xad, 0x75, 0x6f, 0xe2, 0x2d, 0x66, 0x28, 0x97, 0x7c, 0x6f, 0xf4, 0xfc, 0x95, 0xaa, 0x67, 0x81,
    0xd8, 0x15, 0x3c, 0xf4, 0x7b, 0x97, 0x08, 0x7b, 0x1b, 0x8c, 0xd3, 0x45, 0x8b, 0x96, 0x54, 0x2c,
    0xb1, 0x00, 0x87, 0x59, 0x5c, 0x94, 0x78, 0x29, 0xaa, 0x7b, 0x9c, 0x5c, 0x61, 0xff, 0xcc, 0x32,
    0x14, 0x4e, 0xc3, 0x1b, 0x96
};

static bool FindCredentialAbstract(const struct CredentialAbstract *abstract, const struct CredentialList *listCert)
{
    if (abstract == nullptr || listCert == nullptr || listCert->credentialCount == 0) {
        return false;
    }
    for (uint32_t i = 0; i < listCert->credentialCount; ++i) {
        if (CompareCredentialList(abstract, &(listCert->credentialAbstract[i]))) {
            return true;
        }
    }
    return false;
}

class CmAppCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmAppCertTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmAppCertTest::TearDownTestCase(void)
{
}

void CmAppCertTest::SetUp()
{
}

void CmAppCertTest::TearDown()
{
}

/**
 * @tc.name: AppCertInstallBaseTest001
 * @tc.desc: Test CertManager Install app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertInstallBaseTest001, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertInstallBaseTest001 credentail test failed, retcode:" << ret;

    ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertInstallBaseTest001 pri_credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=ak;o=keyA;u=0;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)keyUri.data), 0) << "strcmp failed";
}

/**
 * @tc.name: AppCertInstallBaseTest002
 * @tc.desc: Test CertManager Install app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertInstallBaseTest002, TestSize.Level0)
{
    uint8_t keyUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(keyUriBuf), keyUriBuf };

    uint8_t appCertPwdBuf[] = "12345678";
    struct CmBlob appCertPwd = { sizeof(appCertPwdBuf), appCertPwdBuf };

    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_FAILURE) << "AppCertInstallBaseTest002 credentail test failed, retcode:" << ret;

    ret = CmInstallAppCert(&g_appCert, &appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_FAILURE) << "AppCertInstallBaseTest002 pri_credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: AppCertInstallTest003
 * @tc.desc: Test CertManager Install app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertInstallTest003, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "AppCertInstallTest003";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    struct CmBlob appCert = { sizeof(g_p12AbnormalCertinfo), const_cast<uint8_t *>(g_p12AbnormalCertinfo) };

    uint8_t keyUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(keyUriBuf), keyUriBuf };

    int32_t ret = CmInstallAppCert(&appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_FAILURE) << "AppCertInstallTest003 credentail test failed, retcode:" << ret;

    ret = CmInstallAppCert(&appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_FAILURE) << "AppCertInstallTest003 pri_credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: AppCertInstallAbnormalTest004
 * @tc.desc: Test CertManager install app cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertInstallAbnormalTest004, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t keyUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(keyUriBuf), keyUriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE + 1, &keyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "AppCertInstallAbnormalTest004 test failed, retcode:" << ret;

    ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE + 1, &keyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "AppCertInstallAbnormalTest004 privite test failed, retcode:" << ret;
}

/**
 * @tc.name: AppCertInstallBaseEccTest005
 * @tc.desc: Test CertManager Install app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertInstallBaseEccTest005, TestSize.Level0)
{
    uint8_t keyUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(keyUriBuf), keyUriBuf };

    uint8_t certAliasBuf[] = "keyB";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    int32_t ret = CmInstallAppCert(&g_eccAppCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertInstallBaseEccTest005 test failed, retcode:" << ret;

    ret = CmInstallAppCert(&g_eccAppCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertInstallBaseEccTest005 privite test failed, retcode:" << ret;

    ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertUnInstallAllTest 005 test failed, retcode:" << ret;
}

/**
 * @tc.name: CmGetAppCertBaseTest001
 * @tc.desc: Test CertManager get app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, CmGetAppCertBaseTest001, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob retUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &retUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertBaseTest001 test failed, retcode:" << ret;

    struct Credential certificate;
    (void)memset_s(&certificate, sizeof(Credential), 0, sizeof(Credential));
    certificate.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(certificate.credData.data != nullptr);
    certificate.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    ret = CmGetAppCert(&retUri, CM_CREDENTIAL_STORE, &certificate);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertBaseTest001 test failed, retcode:" << ret;

    FreeCMBlobData(&certificate.credData);
}

/**
 * @tc.name: CmGetAppCertPerformanceTest002
 * @tc.desc: Test CertManager get app cert interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, CmGetAppCertPerformanceTest002, TestSize.Level0)
{
    uint32_t times = 1;
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob retUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &retUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertPerformanceTest002 install failed, retcode:" << ret;

    struct Credential certificate;
    for (uint32_t i = 0; i < times; i++) {
        (void)memset_s(&certificate, sizeof(Credential), 0, sizeof(Credential));
        certificate.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
        ASSERT_TRUE(certificate.credData.data != nullptr);
        certificate.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

        ret = CmGetAppCert(&retUri, CM_CREDENTIAL_STORE, &certificate);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertPerformanceTest002 get failed,retcode:" << ret;

        EXPECT_EQ(CompareCredential(&certificate, &(g_credentialexpectResult[0].certificate)), true);
        FreeCMBlobData(&(certificate.credData));
    }
}

/**
 * @tc.name: CmGetAppBaseCertTest003
 * @tc.desc: Test CertManager get app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, CmGetAppBaseCertTest003, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyC";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob retUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &retUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppBaseCertTest003 install failed, retcode:" << ret;

    struct Credential firstcertificate;
    (void)memset_s(&firstcertificate, sizeof(Credential), 0, sizeof(Credential));
    firstcertificate.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(firstcertificate.credData.data != nullptr);
    firstcertificate.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    ret = CmGetAppCert(&retUri, CM_CREDENTIAL_STORE, &firstcertificate);
    EXPECT_EQ(ret, CM_SUCCESS) << "first CmGetAppCert failed, retcode:" << ret;

    struct Credential secondcertificate;
    (void)memset_s(&secondcertificate, sizeof(Credential), 0, sizeof(Credential));
    secondcertificate.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(secondcertificate.credData.data != nullptr);
    secondcertificate.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    ret = CmGetAppCert(&retUri, CM_CREDENTIAL_STORE, &secondcertificate);
    EXPECT_EQ(ret, CM_SUCCESS) << "second CmGetAppCert failed, retcode:" << ret;

    EXPECT_EQ(CompareCredential(&firstcertificate, &secondcertificate), true);
    FreeCMBlobData(&(firstcertificate.credData));
    FreeCMBlobData(&(secondcertificate.credData));
}

/**
 * @tc.name: CmGetAppCertAbnormalTest004
 * @tc.desc: Test CertManager get app cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, CmGetAppCertAbnormalTest004, TestSize.Level0)
{
    uint8_t keyUriBuf[] = "oh:t=ak;o=key004;u=0;a=0";
    struct CmBlob keyUri = { sizeof(keyUriBuf), keyUriBuf };

    struct Credential certificate;
    (void)memset_s(&certificate, sizeof(Credential), 0, sizeof(Credential));
    certificate.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(certificate.credData.data != nullptr);
    certificate.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    int32_t ret = CmGetAppCert(nullptr, CM_CREDENTIAL_STORE, &certificate);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "CmGetAppCertAbnormalTest004 01 failed, retcode:" << ret;

    ret = CmGetAppCert(&keyUri, CM_CREDENTIAL_STORE, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "CmGetAppCertAbnormalTest004 02 failed, retcode:" << ret;

    ret = CmGetAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE + 1, &certificate);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "CmGetAppCertAbnormalTest004 03 failed, retcode:" << ret;

    ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertUnInstallAllTest 004 test failed, retcode:" << ret;

    FreeCMBlobData(&(certificate.credData));
}

/**
 * @tc.name: CmGetAppCertListPerformanceTest001
 * @tc.desc: Test CertManager get app cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, CmGetAppCertListPerformanceTest001, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertListPerformanceTest001 install failed, retcode:" << ret;

    ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertListPerformanceTest001 private install failed, retcode:" << ret;

    struct CredentialList certificateList = { 0, nullptr };
    uint32_t buffSize = MAX_COUNT_CERTIFICATE * sizeof(struct CredentialAbstract);
    certificateList.credentialAbstract = static_cast<struct CredentialAbstract *>(CmMalloc(buffSize));
    ASSERT_TRUE(certificateList.credentialAbstract != nullptr);

    uint32_t times = 1;
    for (uint32_t i = 0; i < times; i++) {
        certificateList.credentialCount = MAX_COUNT_CERTIFICATE;
        (void)memset_s(certificateList.credentialAbstract, buffSize, 0, buffSize);
        ret = CmGetAppCertList(CM_PRI_CREDENTIAL_STORE, &certificateList);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertListTest test failed, retcode:" << ret;
    }

    if (certificateList.credentialAbstract != nullptr) {
        CmFree(certificateList.credentialAbstract);
    }
}

/**
 * @tc.name: CmGetAppCertListBaseTest002
 * @tc.desc: Test CertManager get app cert list interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, CmGetAppCertListBaseTest002, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertListBaseTest002 install failed, retcode:" << ret;

    struct CredentialList certificateList = { 0, nullptr };
    uint32_t buffSize = MAX_COUNT_CERTIFICATE * sizeof(struct CredentialAbstract);
    certificateList.credentialAbstract = static_cast<struct CredentialAbstract *>(CmMalloc(buffSize));
    ASSERT_TRUE(certificateList.credentialAbstract != nullptr);
    certificateList.credentialCount = MAX_COUNT_CERTIFICATE;
    (void)memset_s(certificateList.credentialAbstract, buffSize, 0, buffSize);

    ret = CmGetAppCertList(CM_CREDENTIAL_STORE, &certificateList);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAppCertListBaseTest002 test failed, retcode:" << ret;

    uint32_t length = sizeof(g_expectList) / sizeof(g_expectList[0]);
    for (uint32_t j = 0; j < length; ++j) {
        bool bFind = FindCredentialAbstract(&(g_expectList[j].credentialAbstract), &certificateList);
        EXPECT_EQ(bFind, g_expectList[j].bExpectResult);
    }

    if (certificateList.credentialAbstract != nullptr) {
        CmFree(certificateList.credentialAbstract);
    }
}

/**
 * @tc.name: CmGetAppCertListBaseTest003
 * @tc.desc: Test CertManager get app cert list interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, CmGetAppCertListBaseTest003, TestSize.Level0)
{
    int32_t ret = CmGetAppCertList(CM_CREDENTIAL_STORE, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Abnormal CmGetAppCertListBaseTest003 test failed, retcode:" << ret;
}

/**
 * @tc.name: CmGetAppCertListAbnormalTest004
 * @tc.desc: Test CertManager get app cert list interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, CmGetAppCertListAbnormalTest004, TestSize.Level0)
{
    struct CredentialList certificateList = { 0, nullptr };
    uint32_t buffSize = MAX_COUNT_CERTIFICATE * sizeof(struct CredentialAbstract);
    certificateList.credentialAbstract = static_cast<struct CredentialAbstract *>(CmMalloc(buffSize));
    ASSERT_TRUE(certificateList.credentialAbstract != nullptr);
    certificateList.credentialCount = MAX_COUNT_CERTIFICATE;
    (void)memset_s(certificateList.credentialAbstract, buffSize, 0, buffSize);

    int32_t ret = CmGetAppCertList(CM_PRI_CREDENTIAL_STORE + 1, &certificateList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Abnormal AppCertInstallTest04 test failed, retcode:" << ret;

    if (certificateList.credentialAbstract != nullptr) {
        CmFree(certificateList.credentialAbstract);
    }
}

/**
 * @tc.name: AppCertUnInstallBaseTest001
 * @tc.desc: Test CertManager unInstall app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertUnInstallBaseTest001, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob retUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &retUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertUnInstallBaseTest001 install failed, retcode:" << ret;

    ret = CmUninstallAppCert(&retUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertUnInstallBaseTest001 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: AppCertUnInstallAbnormalTest002
 * @tc.desc: Test CertManager unInstall app cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertUnInstallAbnormalTest002, TestSize.Level0)
{
    int32_t ret = CmUninstallAppCert(nullptr, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "AppCertUnInstallAbnormalTest002 test failed, retcode:" << ret;
}

/**
 * @tc.name: AppCertUnInstallAbnormalTest003
 * @tc.desc: Test CertManager unInstall app cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertUnInstallAbnormalTest003, TestSize.Level0)
{
    uint8_t keyUriBuf[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(keyUriBuf), keyUriBuf };

    int32_t ret = CmUninstallAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE + 1);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "AppCertUnInstallAbnormalTest003 test failed, retcode:" << ret;
}

/**
 * @tc.name: AppCertUnInstallAllAppCertBaseTest001
 * @tc.desc: Test CertManager unInstall all app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertUnInstallAllAppCertBaseTest001, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyB";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertUnInstallAllAppCertBaseTest001 1 failed, retcode:" << ret;

    ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertUnInstallAllAppCertBaseTest001 2 failed, retcode:" << ret;

    ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertUnInstallAllAppCertBaseTest001 test failed, retcode:" << ret;
}

/**
 * @tc.name: AppCertUnInstallAllAppCertAbnormalTest002
 * @tc.desc: Test CertManager unInstall all app cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertTest, AppCertUnInstallAllAppCertAbnormalTest002, TestSize.Level0)
{
    int32_t ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "AppCertUnInstallAllAppCertAbnormalTest002 test failed, retcode:" << ret;
}
} // end of namespace

