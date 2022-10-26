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

#include "cm_test_common.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static constexpr uint32_t DEFAULT_INDATA_SIZE = 10;
static constexpr uint32_t DEFAULT_HANDLE_SIZE = 8;

class CmUpdateTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmUpdateTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmUpdateTest::TearDownTestCase(void)
{
}

void CmUpdateTest::SetUp()
{
}

void CmUpdateTest::TearDown()
{
}

static const uint8_t g_inDataBuf[DEFAULT_INDATA_SIZE] = {0};
static const uint8_t g_handleBuf[DEFAULT_HANDLE_SIZE] = {0};
static const struct CmBlob g_inData = { DEFAULT_INDATA_SIZE, (uint8_t *)g_inDataBuf };
static const struct CmBlob g_handle = { DEFAULT_HANDLE_SIZE, (uint8_t *)g_handleBuf };

/**
* @tc.name: CmUpdateTest001
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmUpdateTest, CmUpdateTest001, TestSize.Level0)
{
    struct CmBlob *handle = nullptr;
    int32_t ret = CmUpdate(handle, &g_inData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmUpdateTest002
 * @tc.desc: Test CmIsAuthorizedApp handle size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmUpdateTest, CmUpdateTest002, TestSize.Level0)
{
    struct CmBlob handle = { 0, (uint8_t *)g_handleBuf };
    int32_t ret = CmUpdate(&handle, &g_inData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmUpdateTest003
 * @tc.desc: Test CmIsAuthorizedApp handle data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmUpdateTest, CmUpdateTest003, TestSize.Level0)
{
    struct CmBlob handle = { DEFAULT_HANDLE_SIZE, nullptr };
    int32_t ret = CmUpdate(&handle, &g_inData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmUpdateTest004
* @tc.desc: Test CmIsAuthorizedApp inData is null
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmUpdateTest, CmUpdateTest004, TestSize.Level0)
{
    struct CmBlob *inData = nullptr;
    int32_t ret = CmUpdate(&g_handle, inData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmUpdateTest005
 * @tc.desc: Test CmIsAuthorizedApp inData size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmUpdateTest, CmUpdateTest005, TestSize.Level0)
{
    struct CmBlob inData = { 0, (uint8_t *)g_inDataBuf };
    int32_t ret = CmUpdate(&g_handle, &inData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmUpdateTest006
* @tc.desc: Test CmIsAuthorizedApp inData data is null
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmUpdateTest, CmUpdateTest006, TestSize.Level0)
{
    struct CmBlob inData = { DEFAULT_INDATA_SIZE, nullptr };
    int32_t ret = CmUpdate(&g_handle, &inData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmUpdateTest007
* @tc.desc: Test CmIsAuthorizedApp handle not exist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmUpdateTest, CmUpdateTest007, TestSize.Level0)
{
    int32_t ret = CmUpdate(&g_handle, &g_inData);
    EXPECT_EQ(ret, CMR_ERROR_NOT_EXIST);
}
} // end of namespace
