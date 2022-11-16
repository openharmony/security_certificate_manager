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
class CmAbortTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmAbortTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmAbortTest::TearDownTestCase(void)
{
}

void CmAbortTest::SetUp()
{
}

void CmAbortTest::TearDown()
{
}

/**
* @tc.name: CmAbortTest001
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmAbortTest, CmAbortTest001, TestSize.Level0)
{
    struct CmBlob *handle = nullptr;
    int32_t ret = CmAbort(handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmAbortTest002
 * @tc.desc: Test CmIsAuthorizedApp handle size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmAbortTest, CmAbortTest002, TestSize.Level0)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { 0, (uint8_t *)&handleValue };
    int32_t ret = CmAbort(&handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmAbortTest003
 * @tc.desc: Test CmIsAuthorizedApp handle data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmAbortTest, CmAbortTest003, TestSize.Level0)
{
    struct CmBlob handle = { sizeof(uint64_t), nullptr };
    int32_t ret = CmAbort(&handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmAbortTest004
* @tc.desc: Test CmIsAuthorizedApp handle not exist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmAbortTest, CmAbortTest004, TestSize.Level0)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
    int32_t ret = CmAbort(&handle);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmAbortTest005
* @tc.desc: Test CmIsAuthorizedApp handle exist then abort
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmAbortTest, CmAbortTest005, TestSize.Level0)
{
    uint8_t aliasData[] = "CmAbortTest005";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_ECC, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;

    uint8_t uriData[] = "oh:t=ak;o=CmAbortTest005;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };

    ret = CmInit(&keyUri, &spec, &handle);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmInit failed, retcode:" << ret;

    ret = CmAbort(&handle);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmAbort failed, retcode:" << ret;

    ret = CmUninstallAppCert(&keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}

/**
* @tc.name: CmAbortTestPerformance006
* @tc.desc: 1000 times abort handle not exist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmAbortTest, CmAbortTestPerformance006, TestSize.Level1)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
    int32_t ret;
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        ret = CmAbort(&handle);
        EXPECT_EQ(ret, CM_SUCCESS);
    }
}
} // end of namespace
