/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <gtest/hwext/gtest-multithread.h>

#include "cm_test_common.h"

#include "cert_manager_api.h"

using namespace testing::ext;
using namespace testing::mt;
using namespace CertmanagerTest;
namespace {
static constexpr uint32_t DEFAULT_AUTH_URI_LEN = 256;
static constexpr uint32_t DEFAULT_APP_ID = 1000;
static constexpr uint32_t REMOVE_TWICE = 2;
static constexpr uint32_t REMOVE_ONCE = 1;
static constexpr uint32_t REMOVE_NOT_EXIST_ID = 1001;
static constexpr uint32_t MULTI_THREAD_NUM = 10;
static uint32_t g_removeAppUid = 0;
static uint32_t g_removeCount = 0;

class CmRemoveGrantMultiThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmRemoveGrantMultiThreadTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmRemoveGrantMultiThreadTest::TearDownTestCase(void)
{
}

void CmRemoveGrantMultiThreadTest::SetUp()
{
}

void CmRemoveGrantMultiThreadTest::TearDown()
{
}

static void TestRemoveGrantPreAction(void)
{
    uint8_t aliasData[] = "TestRemoveGrant";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;

    uint8_t uriData[] = "oh:t=ak;o=TestRemoveGrant;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };
    uint32_t appId = DEFAULT_APP_ID;

    ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate failed, retcode:" << ret;
}

static void TestRemoveGrant(void)
{
    int32_t ret = 0;
    uint8_t uriData[] = "oh:t=ak;o=TestRemoveGrant;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    for (uint32_t i = 0; i < g_removeCount; ++i) {
        ret = CmRemoveGrantedApp(&keyUri, g_removeAppUid);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmRemoveGrantedApp failed, index:" << i << ", retcode:" << ret;
    }
}

static void TestRemoveGrantAfterAction(void)
{
    uint8_t uriData[] = "oh:t=ak;o=TestRemoveGrant;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    int32_t ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest001
 * @tc.desc: Test CmRemoveGrantMultiThreadTest keyUri is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest001, TestSize.Level0, MULTI_THREAD_NUM)
{
    struct CmBlob *keyUri = nullptr; /* keyUri is NULL */
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest002
 * @tc.desc: Test CmRemoveGrantMultiThreadTest keyUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest002, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { 0, uriData }; /* keyUri size is 0 */
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest003
 * @tc.desc: Test CmRemoveGrantMultiThreadTest keyUri data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest003, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), nullptr }; /* keyUri data is null */
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest004
 * @tc.desc: Test CmRemoveGrantMultiThreadTest keyUri data not end of '\0'
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest004, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { strlen((char *)uriData), uriData }; /* keyUri data not end of '\0' */
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest005
 * @tc.desc: Test CmRemoveGrantMultiThreadTest keyUri data has no app
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest005, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no app */
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest006
 * @tc.desc: Test CmRemoveGrantMultiThreadTest keyUri data has no user
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest006, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no user */
    uint8_t uriData[] = "oh:t=ak;o=keyA;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest007
 * @tc.desc: Test CmRemoveGrantMultiThreadTest keyUri data has no object
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest007, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no object */
    uint8_t uriData[] = "oh:t=ak;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest008
 * @tc.desc: Test CmRemoveGrantMultiThreadTest keyUri data type not ak
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest008, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data type not ak */
    uint8_t uriData[] = "oh:t=m;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest009
 * @tc.desc: Test CmRemoveGrantMultiThreadTest remove while keyUri not exist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest009, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = DEFAULT_APP_ID;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest010
 * @tc.desc: Test CmRemoveGrantMultiThreadTest remove while app uid not exist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest010, TestSize.Level0)
{
    TestRemoveGrantPreAction();
    g_removeAppUid = REMOVE_NOT_EXIST_ID;
    g_removeCount = REMOVE_ONCE;
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestRemoveGrant); /* remove not exist app uid */
    TestRemoveGrantAfterAction();
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest011
 * @tc.desc: Test CmRemoveGrantMultiThreadTest remove while app uid exist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest011, TestSize.Level0)
{
    TestRemoveGrantPreAction();
    g_removeAppUid = DEFAULT_APP_ID;
    g_removeCount = REMOVE_ONCE;
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestRemoveGrant); /* remove exist app uid */
    TestRemoveGrantAfterAction();
}

/**
 * @tc.name: CmRemoveGrantMultiThreadTest012
 * @tc.desc: Test CmRemoveGrantMultiThreadTest remove same app uid twice
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantMultiThreadTest, CmRemoveGrantMultiThreadTest012, TestSize.Level0)
{
    TestRemoveGrantPreAction();
    g_removeAppUid = DEFAULT_APP_ID;
    g_removeCount = REMOVE_TWICE;
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestRemoveGrant); /* remove same app uid twice */
    TestRemoveGrantAfterAction();
}
} // end of namespace
