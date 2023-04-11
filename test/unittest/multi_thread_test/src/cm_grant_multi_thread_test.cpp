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
static constexpr uint32_t INVALID_AUTH_URI_LEN = 100;
static constexpr uint32_t DEFAULT_APP_ID = 1000;
static constexpr uint32_t GRANT_ONE_APP_ID = 1;
static constexpr uint32_t GRANT_MULTIPLE_APP_ID = 10;
static constexpr uint32_t MULTI_THREAD_NUM = 10;
static uint32_t g_count = 0;
static uint32_t g_isSameUid = 0;

class CmGrantMultiThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmGrantMultiThreadTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmGrantMultiThreadTest::TearDownTestCase(void)
{
}

void CmGrantMultiThreadTest::SetUp()
{
}

void CmGrantMultiThreadTest::TearDown()
{
}

static void TestGrantAppCertificatePreAction(void)
{
    uint8_t aliasData[] = "TestNormalGrant";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;
}

static void TestGrantAppCertificate(void)
{
    uint8_t uriData[] = "oh:t=ak;o=TestNormalGrant;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };
    uint32_t appId = DEFAULT_APP_ID;
    int32_t ret = 0;

    for (uint32_t i = 0; i < g_count; ++i) {
        if (!g_isSameUid) {
            appId += i;
        }
        authUri.size = DEFAULT_AUTH_URI_LEN; /* clear authUri size */
        ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate failed, retcode:" << ret;
    }
}

static void TestGrantAppCertificateAfterAction(void)
{
    uint8_t uriData[] = "oh:t=ak;o=TestNormalGrant;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    int32_t ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}

/**
 * @tc.name: CmGrantMultiThreadTest001
 * @tc.desc: Test CmGrantMultiThreadTest keyUri is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest001, TestSize.Level0, MULTI_THREAD_NUM)
{
    struct CmBlob *keyUri = nullptr; /* keyUri is NULL */

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantMultiThreadTest002
 * @tc.desc: Test CmGrantMultiThreadTest keyUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest002, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { 0, uriData }; /* keyUri size is 0 */

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantMultiThreadTest003
 * @tc.desc: Test CmGrantMultiThreadTest keyUri data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest003, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), nullptr }; /* keyUri data is null */

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantMultiThreadTest004
 * @tc.desc: Test CmGrantMultiThreadTest keyUri data not end of '\0'
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest004, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { strlen((char *)uriData), uriData }; /* keyUri data not end of '\0' */

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantMultiThreadTest005
 * @tc.desc: Test CmGrantMultiThreadTest keyUri data has no app: can't find cert
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest005, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no app */
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: CmGrantMultiThreadTest006
 * @tc.desc: Test CmGrantMultiThreadTest keyUri data has no user: can't find cert
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest006, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no user */
    uint8_t uriData[] = "oh:t=ak;o=keyA;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: CmGrantMultiThreadTest007
 * @tc.desc: Test CmGrantMultiThreadTest keyUri data has no object: can't find cert
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest007, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no object */
    uint8_t uriData[] = "oh:t=ak;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: CmGrantMultiThreadTest008
 * @tc.desc: Test CmGrantMultiThreadTest keyUri data type not ak: can't find cert
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest008, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data type not ak */
    uint8_t uriData[] = "oh:t=m;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: CmGrantMultiThreadTest009
 * @tc.desc: Test CmGrantMultiThreadTest authUri null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest009, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = DEFAULT_APP_ID;
    struct CmBlob *authUri = nullptr; /* authUri nullptr */

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantMultiThreadTest010
 * @tc.desc: Test CmGrantMultiThreadTest authUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest010, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { 0, authUriData }; /* authUri size is 0 */

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantMultiThreadTest011
 * @tc.desc: Test CmGrantMultiThreadTest authUri data is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest011, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, nullptr }; /* authUri data is NULL */
    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantMultiThreadTest012
 * @tc.desc: Test CmGrantMultiThreadTest normal case: grant 1 app id
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest012, TestSize.Level0)
{
    g_count = GRANT_ONE_APP_ID;
    g_isSameUid = true; /* grant 1 app id */
    TestGrantAppCertificatePreAction();
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestGrantAppCertificate);
    TestGrantAppCertificateAfterAction();
}

/**
 * @tc.name: CmGrantMultiThreadTest013
 * @tc.desc: Test CmGrantMultiThreadTest normal case: grant 10 same app id
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest013, TestSize.Level0)
{
    g_count = GRANT_MULTIPLE_APP_ID;
    g_isSameUid = true; /* grant 10 same app id */
    TestGrantAppCertificatePreAction();
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestGrantAppCertificate);
    TestGrantAppCertificateAfterAction();
}

/**
 * @tc.name: CmGrantMultiThreadTest014
 * @tc.desc: Test CmGrantMultiThreadTest normal case: grant 10 different app id
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest014, TestSize.Level0)
{
    g_count = GRANT_MULTIPLE_APP_ID;
    g_isSameUid = false; /* grant 10 different app id */
    TestGrantAppCertificatePreAction();
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestGrantAppCertificate);
    TestGrantAppCertificateAfterAction();
}

static void TestBufferTooSmall(void)
{
    uint8_t uriData[] = "oh:t=ak;o=CmGrantMultiThreadTest014;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint8_t authUriData[INVALID_AUTH_URI_LEN] = {0}; /* size too small */
    struct CmBlob authUri = { INVALID_AUTH_URI_LEN, authUriData };
    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL) << "CmGrantAppCertificate failed, retcode:" << ret;
}

/**
 * @tc.name: CmGrantMultiThreadTest015
 * @tc.desc: Test CmGrantMultiThreadTest authUri size too small
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantMultiThreadTest, CmGrantMultiThreadTest015, TestSize.Level0)
{
    uint8_t aliasData[] = "CmGrantMultiThreadTest014";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;

    uint8_t uriData[] = "oh:t=ak;o=CmGrantMultiThreadTest014;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestBufferTooSmall);

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}
} // end of namespace

