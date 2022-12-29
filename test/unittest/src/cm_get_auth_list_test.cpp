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
static constexpr uint32_t DEFAULT_BASE_APP_ID = 1000;
static constexpr uint32_t APP_UID_COUNT_ONE = 1;
static constexpr uint32_t APP_UID_COUNT_MULTI = 10;
static constexpr uint32_t APP_UID_REMOVE_COUNT = 4;
static constexpr uint32_t DEFAULT_APP_UID_COUNT = 256;

class CmGetAuthListTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmGetAuthListTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmGetAuthListTest::TearDownTestCase(void)
{
}

static const uint8_t g_uriData[] = "oh:t=ak;o=GetAuthList;u=0;a=0";
static const CmBlob g_keyUri = { sizeof(g_uriData), (uint8_t *)g_uriData };

void CmGetAuthListTest::SetUp()
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

void CmGetAuthListTest::TearDown()
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

static void CheckGetAuthedList(uint32_t count, uint32_t baseAppId)
{
    uint32_t appUid[DEFAULT_APP_UID_COUNT] = {0};
    struct CmAppUidList appUidList = { DEFAULT_APP_UID_COUNT, appUid };
    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetAuthorizedAppList failed, retcode:" << ret;

    EXPECT_EQ(appUidList.appUidCount, count);

    uint32_t uidValidCount = 0;
    for (uint32_t i = 0; i < count; ++i) {
        for (uint32_t j = 0; j < appUidList.appUidCount; ++j) {
            if ((baseAppId + i) == appUidList.appUid[j]) {
                uidValidCount++;
            }
        }
    }
    EXPECT_EQ(uidValidCount, count);
}

/* caller make sure grantCount is no smaller than removeCount */
static void TestGetAuthList(uint32_t grantCount, uint32_t removeCount)
{
    TestGrant(grantCount, DEFAULT_BASE_APP_ID);
    CheckGetAuthedList(grantCount, DEFAULT_BASE_APP_ID);

    uint32_t remainCount = grantCount - removeCount;
    uint32_t remainBaseAppId = DEFAULT_BASE_APP_ID + removeCount;

    if (removeCount != 0) {
        TestRemoveGrant(removeCount, DEFAULT_BASE_APP_ID);
        CheckGetAuthedList(remainCount, remainBaseAppId);
    }

    /* clear environment */
    TestRemoveGrant(remainCount, remainBaseAppId);
    CheckGetAuthedList(0, 0);
}

/**
 * @tc.name: CmGetAuthListTest001
 * @tc.desc: Test CmGetAuthListTest keyUri is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest001, TestSize.Level0)
{
    struct CmBlob *keyUri = nullptr; /* keyUri is NULL */
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest002
 * @tc.desc: Test CmGetAuthListTest keyUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest002, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { 0, uriData }; /* keyUri size is 0 */
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest003
 * @tc.desc: Test CmGetAuthListTest keyUri data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest003, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), nullptr }; /* keyUri data is null */
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest004
 * @tc.desc: Test CmGetAuthListTest keyUri data not end of '\0'
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest004, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { strlen((char *)uriData), uriData }; /* keyUri data not end of '\0' */
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest005
 * @tc.desc: Test CmGetAuthListTest keyUri data has no app
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest005, TestSize.Level0)
{
    /* keyUri data has no app */
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest006
 * @tc.desc: Test CmGetAuthListTest keyUri data has no user
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest006, TestSize.Level0)
{
    /* keyUri data has no user */
    uint8_t uriData[] = "oh:t=ak;o=keyA;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest007
 * @tc.desc: Test CmGetAuthListTest keyUri data has no object
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest007, TestSize.Level0)
{
    /* keyUri data has no object */
    uint8_t uriData[] = "oh:t=ak;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest008
 * @tc.desc: Test CmGetAuthListTest keyUri data type not ak
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest008, TestSize.Level0)
{
    /* keyUri data type not ak */
    uint8_t uriData[] = "oh:t=m;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest009
 * @tc.desc: Test CmGetAuthListTest authUriList is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest009, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmAppUidList *appUidList = nullptr; /* authUriList is NULL */
    int32_t ret = CmGetAuthorizedAppList(&keyUri, appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest010
 * @tc.desc: Test CmGetAuthListTest authlist count too small
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest010, TestSize.Level0)
{
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: CmGetAuthListTest011
 * @tc.desc: Test CmGetAuthListTest authlist data NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest011, TestSize.Level0)
{
    struct CmAppUidList appUidList = { APP_UID_COUNT_ONE, nullptr }; /* setup has granted 1 app uid */
    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest012
 * @tc.desc: Test CmGetAuthListTest authlist count too big > MAX_OUT_BLOB_SIZE
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest012, TestSize.Level0)
{
    struct CmAppUidList appUidList = { MAX_OUT_BLOB_SIZE + 1, nullptr }; /* count too big */
    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetAuthListTest013
 * @tc.desc: Test CmGetAuthListTest not grant, get grant list { 0, NULL }
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest013, TestSize.Level0)
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
* @tc.name: CmGetAuthListTest014
* @tc.desc: Test CmGetAuthListTest grant 1, get authlist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest014, TestSize.Level0)
{
    uint32_t tempUid = 0;
    struct CmAppUidList appUidList = { APP_UID_COUNT_ONE, &tempUid };

    int32_t ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(appUidList.appUidCount, APP_UID_COUNT_ONE);
    EXPECT_EQ(*(appUidList.appUid), DEFAULT_BASE_APP_ID);
}

/**
 * @tc.name: CmGetAuthListTest015
 * @tc.desc: Test CmGetAuthListTest grant 10, get authlist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest015, TestSize.Level0)
{
    TestGetAuthList(APP_UID_COUNT_MULTI, 0);
}

/**
 * @tc.name: CmGetAuthListTest016
 * @tc.desc: Test CmGetAuthListTest grant 10, remove grant 4, get authlist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmGetAuthListTest, CmGetAuthListTest016, TestSize.Level0)
{
    TestGetAuthList(APP_UID_COUNT_MULTI, APP_UID_REMOVE_COUNT);
}

/**
* @tc.name: CmGetAuthListTestPerformance017
* @tc.desc: 1000 times: grant 1, get authlist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmGetAuthListTest, CmGetAuthListTestPerformance017, TestSize.Level1)
{
    uint32_t tempUid = 0;
    struct CmAppUidList appUidList = { APP_UID_COUNT_ONE, &tempUid };

    int32_t ret;
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        ret = CmGetAuthorizedAppList(&g_keyUri, &appUidList);
        EXPECT_EQ(ret, CM_SUCCESS);
        EXPECT_EQ(appUidList.appUidCount, APP_UID_COUNT_ONE);
        EXPECT_EQ(*(appUidList.appUid), DEFAULT_BASE_APP_ID);
    }
}
} // end of namespace

