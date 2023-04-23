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
static constexpr uint32_t DEFAULT_BASE_APP_ID = 1000;
static constexpr uint32_t APP_UID_COUNT_ONE = 1;
static constexpr uint32_t APP_UID_COUNT_MULTI = 10;
static constexpr uint32_t APP_UID_REMOVE_COUNT = 4;
static constexpr uint32_t DEFAULT_APP_UID_COUNT = 256;
static constexpr uint32_t MULTI_THREAD_NUM = 10;
static uint32_t g_checkListItemCount = 0;
static uint32_t g_checkBaseAppId = 0;

class CmGetAuthListMultiThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmGetAuthListMultiThreadTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmGetAuthListMultiThreadTest::TearDownTestCase(void)
{
}

static const uint8_t g_uriData[] = "oh:t=ak;o=GetAuthList;u=0;a=0";
static const CmBlob g_keyUri = { sizeof(g_uriData), (uint8_t *)g_uriData };

void CmGetAuthListMultiThreadTest::SetUp()
{
    uint8_t aliasData[] = "GetAuthList";
    struct CmBlob alias = { sizeof(aliasData), aliasData };

    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;

    uint32_t appId = DEFAULT_BASE_APP_ID;
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    ret = CmGrantAppCertificate(&g_keyUri, appId, &authUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate failed, retcode:" << ret;
}

void CmGetAuthListMultiThreadTest::TearDown()
{
    int32_t ret = CmUninstallAppCert(&g_keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;

    uint32_t appUid[DEFAULT_APP_UID_COUNT] = {0};
    struct CmAppUidList appUidList = { DEFAULT_APP_UID_COUNT, appUid };
    ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAuthorizedAppList failed, retcode:" << ret;

    uint32_t expectCount = 0;
    EXPECT_EQ(appUidList.appUidCount, expectCount);
}

static void TestRemoveGrant(uint32_t count, uint32_t baseAppId)
{
    int32_t ret;
    uint32_t appId;
    for (uint32_t i = 0; i < count; ++i) {
        appId = baseAppId + i;
        ret = CmRemoveGrantedApp(&g_keyUri, appId);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmRemoveGrantedApp failed, retcode:" << ret;
    }
}

static void TestGrant(uint32_t count, uint32_t baseAppId)
{
    uint32_t appId;
    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    int32_t ret;
    for (uint32_t i = 0; i < count; ++i) {
        appId = baseAppId + i;
        authUri.size = DEFAULT_AUTH_URI_LEN;
        ret = CmGrantAppCertificate(&g_keyUri, appId, &authUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGrantAppCertificate failed, retcode:" << ret;
        ret = CmIsAuthorizedApp(&authUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmIsAuthorizedApp failed, retcode:" << ret;
    }
}

static void TestGetAuthedList(void)
{
    uint32_t appUid[DEFAULT_APP_UID_COUNT] = {0};
    struct CmAppUidList appUidList = { DEFAULT_APP_UID_COUNT, appUid };
    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAuthorizedAppList failed, retcode:" << ret;
    EXPECT_EQ(appUidList.appUidCount, g_checkListItemCount);

    uint32_t uidValidCount = 0;
    for (uint32_t i = 0; i < g_checkListItemCount; ++i) {
        for (uint32_t j = 0; j < appUidList.appUidCount; ++j) {
            if ((g_checkBaseAppId + i) == appUidList.appUid[j]) {
                uidValidCount++;
            }
        }
    }
    EXPECT_EQ(uidValidCount, g_checkListItemCount);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest001
 * @tc.desc: Test CmGetAuthListMultiThreadTest keyUri is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest001, TestSize.Level0, MULTI_THREAD_NUM)
{
    struct CmBlob *keyUri = nullptr; /* keyUri is NULL */
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest002
 * @tc.desc: Test CmGetAuthListMultiThreadTest keyUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest002, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { 0, uriData }; /* keyUri size is 0 */
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest003
 * @tc.desc: Test CmGetAuthListMultiThreadTest keyUri data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest003, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), nullptr }; /* keyUri data is null */
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest004
 * @tc.desc: Test CmGetAuthListMultiThreadTest keyUri data not end of '\0'
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest004, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { strlen((char *)uriData), uriData }; /* keyUri data not end of '\0' */
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest005
 * @tc.desc: Test CmGetAuthListMultiThreadTest keyUri data has no app
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest005, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no app */
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest006
 * @tc.desc: Test CmGetAuthListMultiThreadTest keyUri data has no user
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest006, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no user */
    uint8_t uriData[] = "oh:t=ak;o=keyA;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest007
 * @tc.desc: Test CmGetAuthListMultiThreadTest keyUri data has no object
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest007, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data has no object */
    uint8_t uriData[] = "oh:t=ak;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest008
 * @tc.desc: Test CmGetAuthListMultiThreadTest keyUri data type not ak
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest008, TestSize.Level0, MULTI_THREAD_NUM)
{
    /* keyUri data type not ak */
    uint8_t uriData[] = "oh:t=m;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest009
 * @tc.desc: Test CmGetAuthListMultiThreadTest authUriList is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest009, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList *appUidList = nullptr; /* authUriList is NULL */
    int32_t ret = CmGetAuthorizedAppList(&keyUri, appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest010
 * @tc.desc: Test CmGetAuthListMultiThreadTest authlist count too small
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest010, TestSize.Level0, MULTI_THREAD_NUM)
{
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest011
 * @tc.desc: Test CmGetAuthListMultiThreadTest authlist data NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest011, TestSize.Level0, MULTI_THREAD_NUM)
{
    struct CmAppUidList appUidList = { APP_UID_COUNT_ONE, nullptr }; /* setup has granted 1 app uid */
    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest012
 * @tc.desc: Test CmGetAuthListMultiThreadTest authlist count too big > MAX_OUT_BLOB_SIZE
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest012, TestSize.Level0, MULTI_THREAD_NUM)
{
    struct CmAppUidList appUidList = { MAX_OUT_BLOB_SIZE + 1, nullptr }; /* count too big */
    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest013
 * @tc.desc: Test CmGetAuthListMultiThreadTest not grant, get grant list { 0, NULL }
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest013, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };

    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList); /* auth uid not exist */
    EXPECT_EQ(ret, CM_SUCCESS);

    uint32_t expectCount = 0;
    EXPECT_EQ(appUidList.appUidCount, expectCount);
}

/**
* @tc.name: CmGetAuthListMultiThreadTest014
* @tc.desc: Test CmGetAuthListMultiThreadTest grant 1, get authlist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWMTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest014, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint32_t tempUid = 0;
    struct CmAppUidList appUidList = { APP_UID_COUNT_ONE, &tempUid };

    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(appUidList.appUidCount, APP_UID_COUNT_ONE);
    EXPECT_EQ(*(appUidList.appUid), DEFAULT_BASE_APP_ID);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest015
 * @tc.desc: Test CmGetAuthListMultiThreadTest grant 10, get authlist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest015, TestSize.Level0)
{
    TestGrant(APP_UID_COUNT_MULTI, DEFAULT_BASE_APP_ID);
    g_checkListItemCount = APP_UID_COUNT_MULTI;
    g_checkBaseAppId = DEFAULT_BASE_APP_ID;
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestGetAuthedList);

    /* clear environment */
    TestRemoveGrant(APP_UID_COUNT_MULTI, DEFAULT_BASE_APP_ID);
    g_checkListItemCount = 0;
    g_checkBaseAppId = 0;
    GTEST_RUN_TASK(TestGetAuthedList);
}

/**
 * @tc.name: CmGetAuthListMultiThreadTest016
 * @tc.desc: Test CmGetAuthListMultiThreadTest grant 10, remove grant 4, get authlist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListMultiThreadTest, CmGetAuthListMultiThreadTest016, TestSize.Level0)
{
    TestGrant(APP_UID_COUNT_MULTI, DEFAULT_BASE_APP_ID);
    g_checkListItemCount = APP_UID_COUNT_MULTI;
    g_checkBaseAppId = DEFAULT_BASE_APP_ID;
    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestGetAuthedList);

    uint32_t remainCount = APP_UID_COUNT_MULTI - APP_UID_REMOVE_COUNT;
    uint32_t remainBaseAppId = DEFAULT_BASE_APP_ID + APP_UID_REMOVE_COUNT;

    if (APP_UID_REMOVE_COUNT != 0) {
        TestRemoveGrant(APP_UID_REMOVE_COUNT, DEFAULT_BASE_APP_ID);
        g_checkListItemCount = remainCount;
        g_checkBaseAppId = remainBaseAppId;
        GTEST_RUN_TASK(TestGetAuthedList);
    }

    /* clear environment */
    TestRemoveGrant(remainCount, remainBaseAppId);
    g_checkListItemCount = 0;
    g_checkBaseAppId = 0;
    GTEST_RUN_TASK(TestGetAuthedList);
}
} // end of namespace

