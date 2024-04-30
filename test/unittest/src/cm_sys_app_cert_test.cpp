/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "cm_cert_data_part3_rsa.h"
#include "cm_mem.h"
#include "cm_test_common.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {

static const struct CmBlob g_appCert = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
static const struct CmBlob g_eccAppCert = { sizeof(g_eccP256P12CertInfo), const_cast<uint8_t *>(g_eccP256P12CertInfo) };
static const struct CmBlob g_appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };

static const uint8_t g_abnormalCertData[] = {
    0x30, 0x82, 0x0b, 0xc1, 0x02, 0x01, 0x03, 0xf7, 0x0d, 0x01, 0x07, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x0b, 0x78, 0x04, 0x82, 0x0b, 0x74, 0x30, 0x82,
    0x00, 0x3a, 0x69, 0x16, 0xe1, 0x63, 0x0c, 0xe5, 0x92, 0xc2, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
    0x06, 0xa0, 0x82, 0x06, 0x18, 0x30, 0x82, 0x06, 0x14, 0x02, 0x01, 0x00, 0x30, 0x82, 0x06, 0x0d,
    0x06, 0x09, 0x0b, 0x74, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x1c, 0x06, 0x0a, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01
};

struct Credential g_credExpectResult[] = {
    /* cert num is 2, len is 1961 */
    { 1, "sk", "Syskey035", "oh:t=sk;o=Syskey035;u=100;a=0", 2, 1, { 1961, nullptr } }
};

class CmSysAppCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmSysAppCertTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmSysAppCertTest::TearDownTestCase(void)
{
}

void CmSysAppCertTest::SetUp()
{
}

void CmSysAppCertTest::TearDown()
{
}

/**
 * @tc.name: SysAppCertTest001
 * @tc.desc: Test CertManager Install sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest001, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SyskeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest001 credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=sk;o=SyskeyA;u=100;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)sysKeyUri.data), 0) << "strcmp failed";

    ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest001 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest002
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest002, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SyskeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t appCertPwdBuf[] = "123456789"; /* err password */
    struct CmBlob errAppCertPwd = { sizeof(appCertPwdBuf), appCertPwdBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, &errAppCertPwd,
        &certAlias, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CM_FAILURE) << "SysAppCertTest002 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest003
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest003, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SysAppCertTest003";
    struct CmBlob certAlias003 = { sizeof(certAliasBuf), certAliasBuf };

    /* sys app cert data is abnormal */
    struct CmBlob abnormalAppCert = { sizeof(g_abnormalCertData), const_cast<uint8_t *>(g_abnormalCertData) };

    struct CmAppCertParam appCertParam = { &abnormalAppCert, (struct CmBlob *)&g_appCertPwd,
        &certAlias003, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT) << "SysAppCertTest003 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest004
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest004, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    /* certParam is nullptr */
    int32_t ret = CmInstallSystemAppCert(nullptr, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest004 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest005
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest005, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SysAppCertTest005";
    struct CmBlob certAlias005 = { sizeof(certAliasBuf), certAliasBuf };

    /* certParam->appCert is nullptr */
    struct CmAppCertParam appCertParam = { nullptr, (struct CmBlob *)&g_appCertPwd,
        &certAlias005, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest005 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest006
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest006, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SysAppCertTest006";
    struct CmBlob certAlias006 = { sizeof(certAliasBuf), certAliasBuf };

    /* certParam->appCertPwd is nullptr */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, nullptr,
        &certAlias006, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest006 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest007
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest007, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    /* certParam->certAlias is nullptr */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
        nullptr, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest007 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest008
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest008, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SysAppCertTest008";
    struct CmBlob certAlias008 = { sizeof(certAliasBuf), certAliasBuf };

    /* certParam->store is not CM_SYS_CREDENTIAL_STORE */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
        &certAlias008, CM_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest008 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest009
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest009, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SysAppCertTest009";
    struct CmBlob certAlias008 = { sizeof(certAliasBuf), certAliasBuf };

    /* certParam->userId is 0 */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
        &certAlias008, CM_SYS_CREDENTIAL_STORE, 0 };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest009 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest010
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest010, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SysAppCertTest010";
    struct CmBlob certAlias008 = { sizeof(certAliasBuf), certAliasBuf };

    /* certParam->userId is INIT_INVALID_VALUE */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
        &certAlias008, CM_SYS_CREDENTIAL_STORE, INIT_INVALID_VALUE };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest010 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest011
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest011, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "SysAppCertTest011";
    struct CmBlob certAlias011 = { sizeof(certAliasBuf), certAliasBuf };
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias011, CM_SYS_CREDENTIAL_STORE, TEST_USERID };

    /* keyUri is nullptr */
    int32_t ret = CmInstallSystemAppCert(&appCertParam, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest011 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest012
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest012, TestSize.Level0)
{
    struct CmBlob sysKeyUri = { 0, nullptr };
    uint8_t certAliasBuf[] = "SysAppCertTest011";
    struct CmBlob certAlias012 = { sizeof(certAliasBuf), certAliasBuf };
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias012, CM_SYS_CREDENTIAL_STORE, TEST_USERID };

    /* keyUri data is nullptr */
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest012 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest013
 * @tc.desc: Test CertManager Install sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest013, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias013 = { sizeof(certAliasBuf), certAliasBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias013, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest013 credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=sk;o=SyskeyB;u=100;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)sysKeyUri.data), 0) << "strcmp failed";

    ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest013 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest014
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest014, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias014 = { sizeof(certAliasBuf) - 1, certAliasBuf }; /* not include '\0' */

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias014, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest014 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest015
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest015, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias015 = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t errPwdBuf[] = "123789";
    struct CmBlob errPwd = { sizeof(errPwdBuf) - 1, errPwdBuf }; /* not include '\0' */

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, &errPwd,
       &certAlias015, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest015 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest016
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest016, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias016 = { sizeof(certAliasBuf), nullptr }; /* certAlias data is nullptr */

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias016, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest016 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest017
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest017, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias017 = { 0, certAliasBuf }; /* certAlias size is 0 */

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias017, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest016 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest018
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest018, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "12345678901234567890123456789012345678901234567890123456789012345";
    struct CmBlob certAlias018 = { sizeof(certAliasBuf), certAliasBuf }; /* certAlias size beyond max */

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias018, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT) <<
        "SysAppCertTest018 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest019
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest019, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias019 = { sizeof(certAliasBuf), certAliasBuf };

    struct CmBlob appCert = { sizeof(g_rsa2048P12CertInfo), nullptr }; /* appCert data is nullptr */

    struct CmAppCertParam appCertParam = { &appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias019, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest019 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest020
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest020, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias020 = { sizeof(certAliasBuf), certAliasBuf };

    struct CmBlob appCert = { 0, const_cast<uint8_t *>(g_rsa2048P12CertInfo) }; /* appCert size is 0 */

    struct CmAppCertParam appCertParam = { &appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias020, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest020 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest021
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest021, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias021 = { sizeof(certAliasBuf), certAliasBuf };

    /* appCert size beyond max */
    uint8_t appCertData[MAX_LEN_APP_CERT + 1] = { 0 };
    struct CmBlob appCert = { MAX_LEN_APP_CERT + 1, appCertData };

    struct CmAppCertParam appCertParam = { &appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias021, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest021 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest022
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest022, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias022 = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t pwdBuf[] = "123789";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), nullptr }; /* appCertPwd data is nullptr */

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, &appCertPwd,
       &certAlias022, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest022 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest023
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest023, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias023 = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t pwdBuf[] = "123789";
    struct CmBlob appCertPwd = { 0, pwdBuf }; /* appCertPwd size is 0 */

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, &appCertPwd,
       &certAlias023, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest023 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest024
 * @tc.desc: Test CertManager Install sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest024, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "SyskeyB";
    struct CmBlob certAlias024 = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t pwdBuf[] = "123456789012345678901234567890123456";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf }; /* appCertPwd size beyond max */

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, &appCertPwd,
       &certAlias024, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest024 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest025
 * @tc.desc: Test CertManager Uninstall sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest025, TestSize.Level0)
{
    int32_t ret = CmUninstallAppCert(nullptr, CM_SYS_CREDENTIAL_STORE); /* keyUri is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest025 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest026
 * @tc.desc: Test CertManager Uninstall sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest026, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    int32_t ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE + 1); /* store is invalid */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest026 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest027
 * @tc.desc: Test CertManager Uninstall sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest027, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), nullptr };

    int32_t ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE); /* keyUri data is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest027 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest028
 * @tc.desc: Test CertManager Uninstall sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest028, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { 0, reinterpret_cast<uint8_t *>(retUriBuf) };

    int32_t ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE); /* keyUri size is 0 */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest028 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest029
 * @tc.desc: Test CertManager Uninstall sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest029, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf) - 1, reinterpret_cast<uint8_t *>(retUriBuf) };

    int32_t ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE); /* not include '\0' */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest029 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest030
 * @tc.desc: Test CertManager Uninstall sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest030, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf) + 1, reinterpret_cast<uint8_t *>(retUriBuf) };

    int32_t ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE); /* keyUri size beyond max */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest030 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest031
 * @tc.desc: Test CertManager Uninstall sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest031, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "SyskeyA";
    struct CmBlob certAlias031 = { sizeof(certAliasBuf), certAliasBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias031, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest031 credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=sk;o=SyskeyA;u=100;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)sysKeyUri.data), 0) << "strcmp failed";

    char errUriBuf01[] = "oh:t=ak;o=SyskeyA;u=100;a=0"; /* type is not CM_URI_TYPE_SYS_KEY */
    struct CmBlob errKeyUri01 = { sizeof(errUriBuf01), reinterpret_cast<uint8_t *>(errUriBuf01) };
    ret = CmUninstallAppCert(&errKeyUri01, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest031 uninstall failed, retcode:" << ret;

    char errUriBuf02[] = "oh:t=sk;o=SyskeyA;u=100;a=2"; /* uid is not equal to 0 */
    struct CmBlob errKeyUri02 = { sizeof(errUriBuf02), reinterpret_cast<uint8_t *>(errUriBuf02) };
    ret = CmUninstallAppCert(&errKeyUri02, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest031 uninstall failed, retcode:" << ret;

    ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest031 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest032
 * @tc.desc: Test CertManager uninstall all sys app cert list interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest032, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf01[] = "SyskeyA01";
    struct CmBlob alias01 = { sizeof(certAliasBuf01), certAliasBuf01 };

    struct CmAppCertParam appCertParam01 = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &alias01, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam01, &sysKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest032 credentail test failed, retcode:" << ret;

    uint8_t certAliasBuf02[] = "SyskeyA02";
    struct CmBlob alias02 = { sizeof(certAliasBuf02), certAliasBuf02 };

    struct CmAppCertParam appCertParam02 = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &alias02, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    ret = CmInstallSystemAppCert(&appCertParam02, &sysKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest032 credentail test failed, retcode:" << ret;

    ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest032 uninstall failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest033
 * @tc.desc: Test CertManager get sys app cert list interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest033, TestSize.Level0)
{
    struct CredentialList certificateList = { 0, nullptr };
    uint32_t buffSize = MAX_COUNT_CERTIFICATE * sizeof(struct CredentialAbstract);
    certificateList.credentialAbstract = static_cast<struct CredentialAbstract *>(CmMalloc(buffSize));
    ASSERT_TRUE(certificateList.credentialAbstract != nullptr);
    certificateList.credentialCount = MAX_COUNT_CERTIFICATE;
    (void)memset_s(certificateList.credentialAbstract, buffSize, 0, buffSize);

    int32_t ret = CmGetAppCertList(CM_SYS_CREDENTIAL_STORE + 1, &certificateList); /* store is invalid */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest033 get cert list test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest034
 * @tc.desc: Test CertManager get sys app cert list interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest034, TestSize.Level0)
{
    int32_t ret = CmGetAppCertList(CM_SYS_CREDENTIAL_STORE, nullptr); /* certificateList is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest034 get cert list test failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest035
 * @tc.desc: Test CertManager get sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest035, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "Syskey035";
    struct CmBlob certAlias035 = { sizeof(certAliasBuf), certAliasBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias035, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest035 credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=sk;o=Syskey035;u=100;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)sysKeyUri.data), 0) << "strcmp failed";

    struct Credential credInfo;
    (void)memset_s(&credInfo, sizeof(Credential), 0, sizeof(Credential));
    credInfo.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(credInfo.credData.data != nullptr);
    credInfo.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    ret = CmGetAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE, &credInfo);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest035 get app cert failed, retcode:" << ret;
    EXPECT_EQ(CompareCredential(&credInfo, &(g_credExpectResult[0])), true);
    FreeCMBlobData(&credInfo.credData);

    ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest035 uninstall failed, retcode:" << ret;
}


/**
 * @tc.name: SysAppCertTest036
 * @tc.desc: Test CertManager get sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest036, TestSize.Level0)
{
    struct Credential credInfo036;
    (void)memset_s(&credInfo036, sizeof(Credential), 0, sizeof(Credential));
    credInfo036.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(credInfo036.credData.data != nullptr);
    credInfo036.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    int32_t ret = CmGetAppCert(nullptr, CM_SYS_CREDENTIAL_STORE, &credInfo036); /* keyUri is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest036 get app cert failed, retcode:" << ret;
    FreeCMBlobData(&credInfo036.credData);
}

/**
 * @tc.name: SysAppCertTest037
 * @tc.desc: Test CertManager get sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest037, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    int32_t ret = CmGetAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE, nullptr); /* certificate is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest037 get app cert failed, retcode:" << ret;
}

/**
 * @tc.name: SysAppCertTest038
 * @tc.desc: Test CertManager get sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest038, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    struct Credential credInfo038;
    (void)memset_s(&credInfo038, sizeof(Credential), 0, sizeof(Credential));
    credInfo038.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(credInfo038.credData.data != nullptr);
    credInfo038.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    int32_t ret = CmGetAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE + 1, &credInfo038); /* store is invalid */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest038 get app cert failed, retcode:" << ret;
    FreeCMBlobData(&credInfo038.credData);
}

/**
 * @tc.name: SysAppCertTest039
 * @tc.desc: Test CertManager get sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest039, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), nullptr };

    struct Credential credInfo039;
    (void)memset_s(&credInfo039, sizeof(Credential), 0, sizeof(Credential));
    credInfo039.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(credInfo039.credData.data != nullptr);
    credInfo039.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    int32_t ret = CmGetAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE, &credInfo039); /* keyUri data is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest039 get app cert failed, retcode:" << ret;
    FreeCMBlobData(&credInfo039.credData);
}

/**
 * @tc.name: SysAppCertTest040
 * @tc.desc: Test CertManager get sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest040, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { 0, reinterpret_cast<uint8_t *>(retUriBuf) };

    struct Credential credInfo040;
    (void)memset_s(&credInfo040, sizeof(Credential), 0, sizeof(Credential));
    credInfo040.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(credInfo040.credData.data != nullptr);
    credInfo040.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    int32_t ret = CmGetAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE, &credInfo040); /* keyUri size is 0 */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest040 get app cert failed, retcode:" << ret;
    FreeCMBlobData(&credInfo040.credData);
}

/**
 * @tc.name: SysAppCertTest041
 * @tc.desc: Test CertManager get sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest041, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf) + 1, reinterpret_cast<uint8_t *>(retUriBuf) };

    struct Credential credInfo041;
    (void)memset_s(&credInfo041, sizeof(Credential), 0, sizeof(Credential));
    credInfo041.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(credInfo041.credData.data != nullptr);
    credInfo041.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    int32_t ret = CmGetAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE, &credInfo041); /* keyUri size beyond max*/
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest041 get app cert failed, retcode:" << ret;
    FreeCMBlobData(&credInfo041.credData);
}

/**
 * @tc.name: SysAppCertTest042
 * @tc.desc: Test CertManager get sys app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest042, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf) - 1, reinterpret_cast<uint8_t *>(retUriBuf) };

    struct Credential credInfo042;
    (void)memset_s(&credInfo042, sizeof(Credential), 0, sizeof(Credential));
    credInfo042.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(credInfo042.credData.data != nullptr);
    credInfo042.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    int32_t ret = CmGetAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE, &credInfo042); /* not include '\0'*/
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest042 get app cert failed, retcode:" << ret;
    FreeCMBlobData(&credInfo042.credData);
}

/**
 * @tc.name: SysAppCertTest043
 * @tc.desc: Test CertManager Uninstall sys app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmSysAppCertTest, SysAppCertTest043, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob sysKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "Syskey043";
    struct CmBlob certAlias043 = { sizeof(certAliasBuf), certAliasBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias043, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
    int32_t ret = CmInstallSystemAppCert(&appCertParam, &sysKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest043 credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=sk;o=Syskey043;u=100;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)sysKeyUri.data), 0) << "strcmp failed";

    struct Credential credInfo043;
    (void)memset_s(&credInfo043, sizeof(Credential), 0, sizeof(Credential));
    credInfo043.credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(credInfo043.credData.data != nullptr);
    credInfo043.credData.size = MAX_LEN_CERTIFICATE_CHAIN;

    char errUriBuf01[] = "oh:t=ak;o=Syskey043;u=100;a=0"; /* type is not CM_URI_TYPE_SYS_KEY */
    struct CmBlob errKeyUri01 = { sizeof(errUriBuf01), reinterpret_cast<uint8_t *>(errUriBuf01) };
    ret = CmGetAppCert(&errKeyUri01, CM_SYS_CREDENTIAL_STORE, &credInfo043);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest043 get app cert failed, retcode:" << ret;

    char errUriBuf02[] = "oh:t=ak;o=;u=100;a=0"; /* object is nullptr */
    struct CmBlob errKeyUri02 = { sizeof(errUriBuf02), reinterpret_cast<uint8_t *>(errUriBuf02) };
    ret = CmGetAppCert(&errKeyUri02, CM_SYS_CREDENTIAL_STORE, &credInfo043);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "SysAppCertTest043 get app cert failed, retcode:" << ret;

    FreeCMBlobData(&credInfo043.credData);
    ret = CmUninstallAppCert(&sysKeyUri, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "SysAppCertTest043 uninstall failed, retcode:" << ret;
}
}
