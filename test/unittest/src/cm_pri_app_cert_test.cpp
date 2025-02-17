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

#define TEST_USERID 100

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

class CmPriAppCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmPriAppCertTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmPriAppCertTest::TearDownTestCase(void)
{
}

void CmPriAppCertTest::SetUp()
{
}

void CmPriAppCertTest::TearDown()
{
}

/**
 * @tc.name: PriAppCertTest001
 * @tc.desc: Test CertManager Install private app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest001, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PrikeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };
    uint8_t certAliasBuf001[] = "PrikeyB";
    struct CmBlob certAlias01 = { sizeof(certAliasBuf001), certAliasBuf001 };

    /* test g_appCert */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest001 1 credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=ak;o=PrikeyA;u=0;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)priKeyUri.data), 0) << "strcmp failed, uri: %s" << (char *)priKeyUri.data;

    /* test g_eccAppCert, level=el1 */
    struct CmAppCertParam appCertParam01 = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias01, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    ret = CmInstallAppCertEx(&appCertParam01, &priKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest001 2 credentail test failed, retcode:" << ret;

    char uriBuf001[] = "oh:t=ak;o=PrikeyB;u=0;a=0";
    EXPECT_EQ(strcmp(uriBuf001, (char *)priKeyUri.data), 0) << "strcmp failed";

    ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest001 test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest002
 * @tc.desc: Test CertManager Install private app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest002, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PrikeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };
    uint8_t certAliasBuf002[] = "PrikeyB";
    struct CmBlob certAlias02 = { sizeof(certAliasBuf002), certAliasBuf002 };

    /* test g_appCert,level=el2 */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest002 1 credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=ak;o=PrikeyA;u=0;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)priKeyUri.data), 0) << "strcmp failed";

    /* test g_eccAppCert */
    struct CmAppCertParam appCertParam01 = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias02, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2 };
    ret = CmInstallAppCertEx(&appCertParam01, &priKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest002 2 credentail test failed, retcode:" << ret;

    char uriBuf001[] = "oh:t=ak;o=PrikeyB;u=0;a=0";
    EXPECT_EQ(strcmp(uriBuf001, (char *)priKeyUri.data), 0) << "strcmp failed";

    ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest002 test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest003
 * @tc.desc: Test CertManager Install private app cert interface base function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest003, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PrikeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };
    uint8_t certAliasBuf003[] = "PrikeyB";
    struct CmBlob certAlias03 = { sizeof(certAliasBuf003), certAliasBuf003 };

    /* test g_appCert, level=el4 */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL4 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest003 credentail test failed, retcode:" << ret;

    char uriBuf[] = "oh:t=ak;o=PrikeyA;u=0;a=0";
    EXPECT_EQ(strcmp(uriBuf, (char *)priKeyUri.data), 0) << "strcmp failed";

     /* test g_eccAppCert, level=el4 */
    struct CmAppCertParam appCertParam01 = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias03, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL4 };
    ret = CmInstallAppCertEx(&appCertParam01, &priKeyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest002 2 credentail test failed, retcode:" << ret;

    char uriBuf001[] = "oh:t=ak;o=PrikeyB;u=0;a=0";
    EXPECT_EQ(strcmp(uriBuf001, (char *)priKeyUri.data), 0) << "strcmp failed";

    ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "PriAppCertTest003 test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest004
 * @tc.desc: Test Install private app cert abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest004, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PrikeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    /* level is invalid */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, static_cast<CmAuthStorageLevel>(ERROR_LEVEL) };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest004 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest005
 * @tc.desc: Test Install private app cert abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest005, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PrikeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    /* store is not private cred */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias, CM_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest005 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest006
 * @tc.desc: Test Install private app cert abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest006, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PrikeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    /* pri app cert data is abnormal */
    struct CmBlob abnormalAppCert = { sizeof(g_abnormalCertData), const_cast<uint8_t *>(g_abnormalCertData) };

    struct CmAppCertParam appCertParam = { &abnormalAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT) << "PriAppCertTest006 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest007
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest007, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    /* certParam is nullptr */
    int32_t ret = CmInstallAppCertEx(nullptr, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest007 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest008
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest008, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PriAppCertTest008";
    struct CmBlob certAlias007 = { sizeof(certAliasBuf), certAliasBuf };

    /* certParam->appCert is nullptr */
    struct CmAppCertParam appCertParam = { nullptr, (struct CmBlob *)&g_appCertPwd,
        &certAlias007, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest008 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest009
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest009, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PriAppCertTest009";
    struct CmBlob certAlias008 = { sizeof(certAliasBuf), certAliasBuf };

    /* certParam->appCertPwd is nullptr */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, nullptr,
        &certAlias008, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest009 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest010
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest010, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    /* certParam->certAlias is nullptr */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
        nullptr, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest010 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest011
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest011, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "PriAppCertTest011";
    struct CmBlob certAlias010 = { sizeof(certAliasBuf), certAliasBuf };
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias010, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };

    /* keyUri is nullptr */
    int32_t ret = CmInstallAppCertEx(&appCertParam, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest011 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest012
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest012, TestSize.Level0)
{
    struct CmBlob priKeyUri = { 0, nullptr };
    uint8_t certAliasBuf[] = "PriAppCertTest012";
    struct CmBlob certAlias010 = { sizeof(certAliasBuf), certAliasBuf };
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias010, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };

    /* keyUri->data is nullptr */
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest012 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest013
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest013, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    /* certAlias not include '\0' */
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias013 = { sizeof(certAliasBuf) - 1, certAliasBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias013, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest013 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest014
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest014, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias014 = { sizeof(certAliasBuf), certAliasBuf };

    /* cert pwd not include '\0' */
    uint8_t errPwdBuf[] = "123789";
    struct CmBlob errPwd = { sizeof(errPwdBuf) - 1, errPwdBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, &errPwd,
       &certAlias014, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest014 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest015
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest015, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    /* certAlias data is nullptr */
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias015 = { sizeof(certAliasBuf), nullptr };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias015, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest015 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest016
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest016, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    /* certAlias size is 0 */
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias016 = { 0, certAliasBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias016, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest016 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest017
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest017, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    /* certAlias size beyond max */
    uint8_t certAliasBuf[] = "123456789012345678901234567890123456789012345678901234567890  \
        12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
    struct CmBlob certAlias018 = { sizeof(certAliasBuf), certAliasBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias018, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) <<
        "PriAppCertTest017 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest018
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest018, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias019 = { sizeof(certAliasBuf), certAliasBuf };

    /* appCert data is nullptr */
    struct CmBlob appCert = { sizeof(g_rsa2048P12CertInfo), nullptr };

    struct CmAppCertParam appCertParam = { &appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias019, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest018 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest019
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest019, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias019 = { sizeof(certAliasBuf), certAliasBuf };

    /* appCert size is 0 */
    struct CmBlob appCert = { 0, const_cast<uint8_t *>(g_rsa2048P12CertInfo) };

    struct CmAppCertParam appCertParam = { &appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias019, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest019 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest020
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest020, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias019 = { sizeof(certAliasBuf), certAliasBuf };

    /* appCert size beyond max */
    uint8_t appCertData[MAX_LEN_APP_CERT + 1] = { 0 };
    struct CmBlob appCert = { MAX_LEN_APP_CERT + 1, appCertData };

    struct CmAppCertParam appCertParam = { &appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias019, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest020 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest021
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest021, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias020 = { sizeof(certAliasBuf), certAliasBuf };

    /* appCertPwd->data is nullptr */
    uint8_t pwdBuf[] = "123789";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), nullptr };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, &appCertPwd,
       &certAlias020, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest021 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest022
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest022, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias021 = { sizeof(certAliasBuf), certAliasBuf };

    /* appCertPwd->size is 0 */
    uint8_t pwdBuf[] = "123789";
    struct CmBlob appCertPwd = { 0, pwdBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, &appCertPwd,
       &certAlias021, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest022 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest023
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest023, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };
    uint8_t certAliasBuf[] = "PrikeyB";
    struct CmBlob certAlias022 = { sizeof(certAliasBuf), certAliasBuf };

    /* appCertPwd->size beyond max */
    uint8_t pwdBuf[] = "123456789012345678901234567890123456";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_eccAppCert, &appCertPwd,
       &certAlias022, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest023 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest024
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest024, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PrikeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    /* err password */
    uint8_t appCertPwdBuf[] = "123456789";
    struct CmBlob errAppCertPwd = { sizeof(appCertPwdBuf), appCertPwdBuf };

    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, &errAppCertPwd,
        &certAlias, CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_PASSWORD_IS_ERR) << "PriAppCertTest024 credentail test failed, retcode:" << ret;
}

/**
 * @tc.name: PriAppCertTest025
 * @tc.desc: Test CertManager Install private app cert interface abnormal function
 * @tc.type: FUNC
 */
HWTEST_F(CmPriAppCertTest, PriAppCertTest025, TestSize.Level0)
{
    char retUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob priKeyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t *>(retUriBuf) };

    uint8_t certAliasBuf[] = "PrikeyA";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    /* userid is not invalid */
    struct CmAppCertParam appCertParam = { (struct CmBlob *)&g_appCert, (struct CmBlob *)&g_appCertPwd,
       &certAlias, CM_PRI_CREDENTIAL_STORE, TEST_USERID, CM_AUTH_STORAGE_LEVEL_EL1 };
    int32_t ret = CmInstallAppCertEx(&appCertParam, &priKeyUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "PriAppCertTest025 1 credentail test failed, retcode:" << ret;
}
}