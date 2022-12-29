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

class CmIsAuthedTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmIsAuthedTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmIsAuthedTest::TearDownTestCase(void)
{
}

void CmIsAuthedTest::SetUp()
{
    uint8_t aliasData[] = "TestNormalGrant";
    struct CmBlob alias = { sizeof(aliasData), aliasData };

    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;
}

void CmIsAuthedTest::TearDown()
{
    uint8_t uriData[] = "oh:t=ak;o=TestNormalGrant;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    int32_t ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}

static void TestGrantApp(struct CmBlob *authUri)
{
    uint32_t appId = 0;
    uint8_t uriData[] = "oh:t=ak;o=TestNormalGrant;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    int32_t ret = CmGrantAppCertificate(&keyUri, appId, authUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate failed, retcode:" << ret;
}

/**
 * @tc.name: CmIsAuthedTest001
 * @tc.desc: Test CmIsAuthorizedApp authUri is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest001, TestSize.Level0)
{
    struct CmBlob *authUri = nullptr; /* authUri is NULL */
    int32_t ret = CmIsAuthorizedApp(authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest002
 * @tc.desc: Test CmIsAuthorizedApp authUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest002, TestSize.Level0)
{
    uint8_t uriData[] =
        "oh:t=ak;o=keyA;u=0;a=0?ca=1000&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { 0, uriData }; /* authUri size is 0 */
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest003
 * @tc.desc: Test CmIsAuthorizedApp authUri data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest003, TestSize.Level0)
{
    uint8_t uriData[] =
        "oh:t=ak;o=keyA;u=0;a=0?ca=1000&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { sizeof(uriData), nullptr }; /* authUri data is null */
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest004
 * @tc.desc: Test CmIsAuthorizedApp authUri data not end of '\0'
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest004, TestSize.Level0)
{
    uint8_t uriData[] =
        "oh:t=ak;o=keyA;u=0;a=0?ca=1000&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { strlen((char *)uriData), uriData }; /* authUri data not end of '\0' */
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest005
 * @tc.desc: Test CmIsAuthorizedApp authUri data has no app
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest005, TestSize.Level0)
{
    /* authUri data has no app */
    uint8_t uriData[] =
        "oh:t=ak;o=keyA;u=0?ca=1000&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { sizeof(uriData), uriData };
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest006
 * @tc.desc: Test CmIsAuthorizedApp authUri data has no user
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest006, TestSize.Level0)
{
    /* authUri data has no user */
    uint8_t uriData[] =
        "oh:t=ak;o=keyA;a=0?ca=1000&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { sizeof(uriData), uriData };
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest007
 * @tc.desc: Test CmIsAuthorizedApp authUri data has no object
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest007, TestSize.Level0)
{
    /* authUri data has no object */
    uint8_t uriData[] =
        "oh:t=ak;u=0;a=0?ca=1000&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { sizeof(uriData), uriData };
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest008
 * @tc.desc: Test CmIsAuthorizedApp authUri data type not ak
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest008, TestSize.Level0)
{
    /* authUri data type not ak */
    uint8_t uriData[] =
        "oh:t=m;o=keyA;u=0;a=0?ca=1000&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { sizeof(uriData), uriData };
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest009
 * @tc.desc: Test CmIsAuthorizedApp authUri data has no clientapp
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest009, TestSize.Level0)
{
    /* authUri data has no clientapp */
    uint8_t uriData[] =
        "oh:t=ak;o=keyA;u=0;a=0?m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { sizeof(uriData), uriData };
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest010
 * @tc.desc: Test CmIsAuthorizedApp authUri data has no macData
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest010, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0?ca=1000"; /* authUri data has no macData */
    struct CmBlob authUri = { sizeof(uriData), uriData };
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest011
 * @tc.desc: Test CmIsAuthorizedApp normal test
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest011, TestSize.Level0)
{
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };
    TestGrantApp(&authUri);

    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
 * @tc.name: CmIsAuthedTest012
 * @tc.desc: Test CmIsAuthorizedApp authUri macData size not 32
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest012, TestSize.Level0)
{
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };
    TestGrantApp(&authUri);

    /* authUri macData size 31 */
    uint8_t uriDataFail[] =
        "oh:t=ak;o=TestNormalGrant;u=0;a=0?ca=0&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FA";
    struct CmBlob authUriFail = { sizeof(uriDataFail), uriDataFail };
    int32_t ret = CmIsAuthorizedApp(&authUriFail);
    EXPECT_EQ(ret, CMR_ERROR_AUTH_CHECK_FAILED);
}

/**
 * @tc.name: CmIsAuthedTest013
 * @tc.desc: Test CmIsAuthorizedApp mac invalid
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest013, TestSize.Level0)
{
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };
    TestGrantApp(&authUri);

    /* authUri macData invalid */
    uint8_t uriDataFail[] =
        "oh:t=ak;o=TestNormalGrant;u=0;a=0?ca=0&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUriFail = { sizeof(uriDataFail), uriDataFail };
    int32_t ret = CmIsAuthorizedApp(&authUriFail);
    EXPECT_EQ(ret, CMR_ERROR_AUTH_CHECK_FAILED);
}

/**
 * @tc.name: CmIsAuthedTest014
 * @tc.desc: Test CmIsAuthorizedApp mac size is odd number
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest014, TestSize.Level0)
{
    /* authUri mac size is odd number */
    uint8_t uriDataFail[] =
        "oh:t=ak;o=TestNormalGrant;u=0;a=0?ca=0&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAF";
    struct CmBlob authUriFail = { sizeof(uriDataFail), uriDataFail };
    int32_t ret = CmIsAuthorizedApp(&authUriFail);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest015
 * @tc.desc: Test CmIsAuthorizedApp mac data can not change to hex
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest015, TestSize.Level0)
{
    /* authUri mac data can not change to hex */
    uint8_t uriDataFail[] =
        "oh:t=ak;o=TestNormalGrant;u=0;a=0?ca=0&m=BA632421B76F1059BC28184FB9E50D57mm232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUriFail = { sizeof(uriDataFail), uriDataFail };
    int32_t ret = CmIsAuthorizedApp(&authUriFail);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmIsAuthedTest016
 * @tc.desc: Test CmIsAuthorizedApp can not find mac key
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTest016, TestSize.Level0)
{
    uint8_t uriDataFail[] =
        "oh:t=ak;o=keyA;u=0;a=0?ca=0&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUriFail = { sizeof(uriDataFail), uriDataFail };
    int32_t ret = CmIsAuthorizedApp(&authUriFail);
    EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED);
}

/**
 * @tc.name: CmIsAuthedTestPerformance017
 * @tc.desc: 1000 times: Test CmIsAuthorizedApp normal test
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmIsAuthedTest, CmIsAuthedTestPerformance017, TestSize.Level1)
{
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };
    TestGrantApp(&authUri);

    int32_t ret;
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        ret = CmIsAuthorizedApp(&authUri);
        EXPECT_EQ(ret, CM_SUCCESS);
    }
}
} // end of namespace

