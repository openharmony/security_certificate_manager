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
static constexpr uint32_t INVALID_AUTH_URI_LEN = 100;
static constexpr uint32_t DEFAULT_APP_ID = 1000;
static constexpr uint32_t GRANT_ONE_APP_ID = 1;
static constexpr uint32_t GRANT_MULTIPLE_APP_ID = 10;

class CmGrantTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmGrantTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmGrantTest::TearDownTestCase(void)
{
}

void CmGrantTest::SetUp()
{
}

void CmGrantTest::TearDown()
{
}

static void TestNormalGrant(uint32_t count, bool isSameUid)
{
    uint8_t aliasData[] = "TestNormalGrant";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;

    uint8_t uriData[] = "oh:t=ak;o=TestNormalGrant;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };
    uint32_t appId = DEFAULT_APP_ID;

    for (uint32_t i = 0; i < count; ++i) {
        if (!isSameUid) {
            appId += i;
        }
        authUri.size = DEFAULT_AUTH_URI_LEN; /* clear authUri size */
        ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate failed, retcode:" << ret;
    }

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}

/**
 * @tc.name: CmGrantTest001
 * @tc.desc: Test CmGrantTest keyUri is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest001, TestSize.Level0)
{
    struct CmBlob *keyUri = nullptr; /* keyUri is NULL */

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantTest002
 * @tc.desc: Test CmGrantTest keyUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest002, TestSize.Level0)
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
 * @tc.name: CmGrantTest003
 * @tc.desc: Test CmGrantTest keyUri data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest003, TestSize.Level0)
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
 * @tc.name: CmGrantTest004
 * @tc.desc: Test CmGrantTest keyUri data not end of '\0'
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest004, TestSize.Level0)
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
 * @tc.name: CmGrantTest005
 * @tc.desc: Test CmGrantTest keyUri data has no app: can't find cert
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest005, TestSize.Level0)
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
 * @tc.name: CmGrantTest006
 * @tc.desc: Test CmGrantTest keyUri data has no user: can't find cert
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest006, TestSize.Level0)
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
 * @tc.name: CmGrantTest007
 * @tc.desc: Test CmGrantTest keyUri data has no object: can't find cert
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest007, TestSize.Level0)
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
 * @tc.name: CmGrantTest008
 * @tc.desc: Test CmGrantTest keyUri data type not ak: can't find cert
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest008, TestSize.Level0)
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
 * @tc.name: CmGrantTest009
 * @tc.desc: Test CmGrantTest authUri null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest009, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint32_t appId = DEFAULT_APP_ID;
    struct CmBlob *authUri = nullptr; /* authUri nullptr */

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantTest010
 * @tc.desc: Test CmGrantTest authUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest010, TestSize.Level0)
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
 * @tc.name: CmGrantTest011
 * @tc.desc: Test CmGrantTest authUri data is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest011, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, nullptr }; /* authUri data is NULL */
    uint32_t appId = DEFAULT_APP_ID;

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGrantTest012
 * @tc.desc: Test CmGrantTest normal case: grant 1 app id
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest012, TestSize.Level0)
{
    TestNormalGrant(GRANT_ONE_APP_ID, true); /* grant 1 app id */
}

/**
 * @tc.name: CmGrantTest013
 * @tc.desc: Test CmGrantTest normal case: grant 10 same app id
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest013, TestSize.Level0)
{
    TestNormalGrant(GRANT_MULTIPLE_APP_ID, true); /* grant 10 same app id */
}

/**
 * @tc.name: CmGrantTest014
 * @tc.desc: Test CmGrantTest normal case: grant 10 different app id
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest014, TestSize.Level0)
{
    TestNormalGrant(GRANT_MULTIPLE_APP_ID, false); /* grant 10 different app id */
}

/**
 * @tc.name: CmGrantTest015
 * @tc.desc: Test CmGrantTest authUri size too small
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTest015, TestSize.Level0)
{
    uint8_t aliasData[] = "CmGrantTest014";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;

    uint8_t uriData[] = "oh:t=ak;o=CmGrantTest014;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint8_t authUriData[INVALID_AUTH_URI_LEN] = {0}; /* size too small */
    struct CmBlob authUri = { INVALID_AUTH_URI_LEN, authUriData };
    uint32_t appId = DEFAULT_APP_ID;

    ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL) << "CmGrantAppCertificate failed, retcode:" << ret;

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}

/**
 * @tc.name: CmGrantTestPerformance016
 * @tc.desc: 1000 times: grant and remove grant
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGrantTest, CmGrantTestPerformance016, TestSize.Level1)
{
    uint8_t aliasData[] = "TestGrantPer";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;

    uint8_t uriData[] = "oh:t=ak;o=TestGrantPer;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };
    uint32_t appId = DEFAULT_APP_ID;

    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        ret = CmGrantAppCertificate(&keyUri, appId, &authUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate failed, retcode:" << ret;

        ret = CmRemoveGrantedApp(&keyUri, appId);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmRemoveGrantedApp failed, retcode:" << ret;
    }

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}
} // end of namespace

