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
#include "cm_test_log.h"
#include "cm_test_common.h"
#include "cert_manager_api.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static const int TIMES_PERFORMANCE = 10;
static const uint32_t PATH_LEN = 1000;

struct CertAbstractResult {
    struct CertAbstract certAbstract;
    bool bExpectResult;
};

struct CertAbstractResult g_listexpectResult[] = {
    {
        {
            "1d3472b9.0",
            "GlobalSign",
            true, "CN=GlobalSign,OU=GlobalSign ECC Root CA - R5,O=GlobalSign"
        },
        true
    },
    {
        {
            "4bfab552.0",
            "Starfield Technologies, Inc.",
            true,
            "CN=Starfield Root Certificate Authority - G2,OU=,O=Starfield Technologies, Inc."
        },
        true
    },
    {
        {
            "4f316efb.0",
            "SwissSign AG",
            true,
            "CN=SwissSign Gold CA - G2,OU=,O=SwissSign AG"
        },
        true
    }
};

class CmGetCertListTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();

    struct CertList *lstCert;
};

void CmGetCertListTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmGetCertListTest::TearDownTestCase(void)
{
}

void CmGetCertListTest::SetUp()
{
    InitCertList(&lstCert);
}

void CmGetCertListTest::TearDown()
{
    FreeCertList(lstCert);
}

/**
 * @tc.name: SimpleGetCertListTest001
 * @tc.desc: Test CertManager get cert list interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertListTest, SimpleGetCertListTest001, TestSize.Level0)
{
    int32_t ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, lstCert);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetCertList failed,retcode:" << ret;
}

/**
 * @tc.name: PerformanceGetCertListTest002
 * @tc.desc: Test CertManager get cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertListTest, PerformanceGetCertListTest002, TestSize.Level0)
{
    for (int times = 0; times < TIMES_PERFORMANCE; ++times) {
        struct CertList *listCert = NULL;
        ASSERT_TRUE(InitCertList(&listCert) == CM_SUCCESS);
        int32_t ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, listCert);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGetCertList Performance failed,retcode:" << ret;
        FreeCertList(listCert);
    }
}

/**
 * @tc.name: GetCertListContent003
 * @tc.desc: Test CertManager get cert list content interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertListTest, GetCertListContent003, TestSize.Level0)
{
    int32_t ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, lstCert);
    EXPECT_EQ(ret, CM_SUCCESS) << "firstUserCtx CmGetCertList failed,retcode:" << ret;

    uint32_t length = sizeof(g_listexpectResult) / sizeof(g_listexpectResult[0]);
    bool bFind = false;
    for (uint32_t j = 0; j < length; ++j) {
        bFind = FindCertAbstract(&(g_listexpectResult[j].certAbstract), lstCert);

        EXPECT_EQ(bFind, g_listexpectResult[j].bExpectResult) << DumpCertList(lstCert);
    }
}

/**
 * @tc.name: AppGetCertListCompare004
 * @tc.desc: Test CertManager get cert list compare interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertListTest, AppGetCertListCompare004, TestSize.Level0)
{
    int32_t ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, lstCert);
    EXPECT_EQ(ret, CM_SUCCESS) << "first  CmGetCertList failed,retcode:" << ret;

    struct CertList *secondListCert = NULL;
    ASSERT_TRUE(InitCertList(&secondListCert) == CM_SUCCESS);
    ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, secondListCert);
    EXPECT_EQ(ret, CM_SUCCESS) << "secondUserCtx CmGetCertList failed,retcode:" << ret;

    EXPECT_EQ(lstCert->certsCount, secondListCert->certsCount) << "firstUserCtx count:" << lstCert->certsCount
        << "secondUserCtx count:" << secondListCert->certsCount;

    FreeCertList(secondListCert);
}

/**
 * @tc.name: ExceptionGetCertList005
 * @tc.desc: Test CertManager get cert list interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertListTest, ExceptionGetCertList005, TestSize.Level0)
{
    EXPECT_EQ(CmGetCertList(CM_SYSTEM_TRUSTED_STORE, NULL), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(CmGetCertList(10, lstCert), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: GetCertStorePath001
 * @tc.desc: get system ca path
 * @tc.type: FUNC
 */
HWTEST_F(CmGetCertListTest, GetCertStorePath001, TestSize.Level0)
{
    char path[PATH_LEN] = {0};
    int32_t ret = CmGetCertStorePath(CM_CA_CERT_SYSTEM, 0, path, sizeof(path));
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(strcmp(path, CA_STORE_PATH_SYSTEM), 0);
}

/**
 * @tc.name: GetCertStorePath002
 * @tc.desc: get user ca path
 * @tc.type: FUNC
 */
HWTEST_F(CmGetCertListTest, GetCertStorePath002, TestSize.Level0)
{
    char path[PATH_LEN] = {0};
    uint32_t userId = 101;
    int32_t ret = CmGetCertStorePath(CM_CA_CERT_USER, userId, path, sizeof(path));
    EXPECT_EQ(ret, CM_SUCCESS);

    std::string expectPath = CA_STORE_PATH_USER_SERVICE_BASE + std::to_string(userId);
    std::cout << "1:" << path << std::endl;
    std::cout << "2:" << expectPath << std::endl;
    EXPECT_EQ(strcmp(path, expectPath.c_str()), 0);
}

/**
 * @tc.name: GetCertStorePath003
 * @tc.desc: type invalid
 * @tc.type: FUNC
 */
HWTEST_F(CmGetCertListTest, GetCertStorePath003, TestSize.Level0)
{
    char path[PATH_LEN] = {0};
    int32_t type = 3; /* type invalid */
    int32_t ret = CmGetCertStorePath(static_cast<enum CmCertType>(type), 0, path, sizeof(path));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: GetCertStorePath004
 * @tc.desc: path is null
 * @tc.type: FUNC
 */
HWTEST_F(CmGetCertListTest, GetCertStorePath004, TestSize.Level0)
{
    int32_t ret = CmGetCertStorePath(CM_CA_CERT_SYSTEM, 0, nullptr, PATH_LEN);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
}

/**
 * @tc.name: GetCertStorePath005
 * @tc.desc: get system ca path, len too small
 * @tc.type: FUNC
 */
HWTEST_F(CmGetCertListTest, GetCertStorePath005, TestSize.Level0)
{
    char path[PATH_LEN] = {0};
    uint32_t length = strlen(CA_STORE_PATH_SYSTEM);
    int32_t ret = CmGetCertStorePath(CM_CA_CERT_SYSTEM, 0, path, length);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: GetCertStorePath006
 * @tc.desc: get user ca path, len too small
 * @tc.type: FUNC
 */
HWTEST_F(CmGetCertListTest, GetCertStorePath006, TestSize.Level0)
{
    char path[PATH_LEN] = {0};
    uint32_t userId = 100;
    std::string expectPath = CA_STORE_PATH_USER_SERVICE_BASE + std::to_string(userId);
    uint32_t length = expectPath.length();
    int32_t ret = CmGetCertStorePath(CM_CA_CERT_USER, userId, path, length);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
}
}
