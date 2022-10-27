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

#include "cert_manager_api.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static constexpr uint32_t DEFAULT_AUTH_URI_LEN = 256;
static constexpr uint32_t DEFAULT_APP_ID = 1000;
static constexpr uint32_t REMOVE_TWICE = 2;
static constexpr uint32_t REMOVE_ONCE = 1;
static constexpr uint32_t REMOVE_NOT_EXIST_ID = 1001;

class CmRemoveGrantTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmRemoveGrantTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmRemoveGrantTest::TearDownTestCase(void)
{
}

void CmRemoveGrantTest::SetUp()
{
}

void CmRemoveGrantTest::TearDown()
{
}

static void TestRemoveGrant(uint32_t removeAppUid, uint32_t removeCount)
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

    for (uint32_t i = 0; i < removeCount; ++i) {
        ret = CmRemoveGrantedApp(&keyUri, removeAppUid);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmRemoveGrantedApp failed, index:" << i << ", retcode:" << ret;
    }

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}

/**
 * @tc.name: CmRemoveGrantTest001
 * @tc.desc: Test CmRemoveGrantTest keyUri is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest001, TestSize.Level0)
{
    struct CmBlob *keyUri = nullptr; /* keyUri is NULL */
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantTest002
 * @tc.desc: Test CmRemoveGrantTest keyUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest002, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { 0, uriData }; /* keyUri size is 0 */
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantTest003
 * @tc.desc: Test CmRemoveGrantTest keyUri data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest003, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), nullptr }; /* keyUri data is null */
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantTest004
 * @tc.desc: Test CmRemoveGrantTest keyUri data not end of '\0'
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest004, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { strlen((char *)uriData), uriData }; /* keyUri data not end of '\0' */
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantTest005
 * @tc.desc: Test CmRemoveGrantTest keyUri data has no app
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest005, TestSize.Level0)
{
    /* keyUri data has no app */
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantTest006
 * @tc.desc: Test CmRemoveGrantTest keyUri data has no user
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest006, TestSize.Level0)
{
    /* keyUri data has no user */
    uint8_t uriData[] = "oh:t=ak;o=keyA;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantTest007
 * @tc.desc: Test CmRemoveGrantTest keyUri data has no object
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest007, TestSize.Level0)
{
    /* keyUri data has no object */
    uint8_t uriData[] = "oh:t=ak;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantTest008
 * @tc.desc: Test CmRemoveGrantTest keyUri data type not ak
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest008, TestSize.Level0)
{
    /* keyUri data type not ak */
    uint8_t uriData[] = "oh:t=m;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmRemoveGrantTest009
 * @tc.desc: Test CmRemoveGrantTest remove while keyUri not exist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest009, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = DEFAULT_APP_ID;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
 * @tc.name: CmRemoveGrantTest010
 * @tc.desc: Test CmRemoveGrantTest remove while app uid not exist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest010, TestSize.Level0)
{
    TestRemoveGrant(REMOVE_NOT_EXIST_ID, REMOVE_ONCE); /* remove not exist app uid */
}

/**
 * @tc.name: CmRemoveGrantTest011
 * @tc.desc: Test CmRemoveGrantTest remove while app uid exist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest011, TestSize.Level0)
{
    TestRemoveGrant(DEFAULT_APP_ID, REMOVE_ONCE); /* remove exist app uid */
}

/**
 * @tc.name: CmRemoveGrantTest012
 * @tc.desc: Test CmRemoveGrantTest remove same app uid twice
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmRemoveGrantTest, CmRemoveGrantTest012, TestSize.Level0)
{
    TestRemoveGrant(DEFAULT_APP_ID, REMOVE_TWICE); /* remove same app uid twice */
}
} // end of namespace
