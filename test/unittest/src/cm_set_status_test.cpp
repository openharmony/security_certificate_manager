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
struct CertStatusExpectResult {
    char uri[MAX_LEN_URI];
    bool inparamStatus;
    bool expectStatus;
};

struct CertStatusExpectResult g_expectList[] = {
    {
        {"2add47b6.0"}, false, false
    },
    {
        {"85cde254.0"}, false, false
    },
    {
        {"3c860d51.0"}, true, true
    }
};

class CmSetCertStatusTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmSetCertStatusTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmSetCertStatusTest::TearDownTestCase(void)
{
}

void CmSetCertStatusTest::SetUp()
{
}

void CmSetCertStatusTest::TearDown()
{
}

/**
 * @tc.name: SimpleSetCertStatus001
 * @tc.desc: Test CertManager set cert status interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, SimpleSetCertStatus001, TestSize.Level0)
{
    struct CmBlob uriBlob = {strlen(g_expectList[0].uri) + 1, (uint8_t *)(g_expectList[0].uri)};

    int32_t ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, g_expectList[0].inparamStatus);
    EXPECT_EQ(ret, CM_SUCCESS) << "SimpleSetCertStatus failed,retcode:" << ret;

    ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, true);
    EXPECT_EQ(ret, CM_SUCCESS) << "SimpleSetCertStatus true failed,retcode:" << ret;
}

/**
 * @tc.name: SetCertStatusAndQueryStatus002
 * @tc.desc: Test CertManager set cert status and query status interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, SetCertStatusAndQueryStatus002, TestSize.Level0)
{
    uint32_t size = sizeof(g_expectList) / sizeof(g_expectList[0]);
    for (uint32_t i = 0; i < size; ++i) {
        struct CmBlob uriBlob = {strlen(g_expectList[i].uri) + 1, (uint8_t *)(g_expectList[i].uri)};

        int32_t ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, g_expectList[i].inparamStatus);
        EXPECT_EQ(ret, CM_SUCCESS) << " SetCertStatusAndQueryStatus, CmSetCertStatus failed,retcode: " << ret;

        struct CertInfo certDetailInfo;
        (void)memset_s(&certDetailInfo, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));
        ret = InitCertInfo(&certDetailInfo);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGetCertInfo malloc faild, retcode:" << ret;

        ret = CmGetCertInfo(&uriBlob, CM_SYSTEM_TRUSTED_STORE, &certDetailInfo);
        EXPECT_EQ(ret, CM_SUCCESS) << "SetCertStatusAndQueryStatus,CmGetCertInfo failed,retcode: " << ret;
        int32_t status = (g_expectList[i].expectStatus == certDetailInfo.status) ? 1 : 0;

        EXPECT_EQ(status, 1) << "SetCertStatusAndQueryStatus faild, cert info: " << DumpCertInfo(&certDetailInfo);
        FreeCMBlobData(&(certDetailInfo.certInfo));

        ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, true);
        EXPECT_EQ(ret, CM_SUCCESS) << " SetCertStatusAndQueryStatus, CmSetCertStatus failed,retcode: " << ret;
    }
}

/**
 * @tc.name: SetAllCertStatus003
 * @tc.desc: Test CertManager set all cert status interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, SetAllCertStatus003, TestSize.Level0)
{
    struct CertList *certlist = NULL;

    ASSERT_TRUE(InitCertList(&certlist) == CM_SUCCESS);
    // CA trusted list
    int32_t ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, certlist);

    EXPECT_EQ(ret, CM_SUCCESS) << "SetAllCertStatus,CmGetCertList failed,retcode:" << ret;

    for (uint32_t i = 0; i < certlist->certsCount; ++i) {
        struct CertAbstract *ptr = &(certlist->certAbstract[i]);
        ASSERT_TRUE(NULL != ptr);
        struct CmBlob uriBlob = {strlen(ptr->uri) + 1, (uint8_t *)(ptr->uri)};
        ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, false);
        EXPECT_EQ(ret, CM_SUCCESS);
    }

    for (uint32_t i = 0; i < certlist->certsCount; ++i) {
        struct CertAbstract *ptr2 = &(certlist->certAbstract[i]);
        ASSERT_TRUE(NULL != ptr2);
        struct CmBlob uriBlob2 = {strlen(ptr2->uri) + 1, (uint8_t *)(ptr2->uri)};
        ret = CmSetCertStatus(&uriBlob2, CM_SYSTEM_TRUSTED_STORE, true);
        EXPECT_EQ(ret, CM_SUCCESS);
    }
    FreeCertList(certlist);
}

/**
 * @tc.name: ExceptionSetStatus004
 * @tc.desc: Test CertManager set cert status interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, ExceptionSetStatus004, TestSize.Level0)
{
    struct CmBlob uriBlob = {strlen(g_expectList[1].uri) + 1, (uint8_t *)(g_expectList[1].uri)};
    EXPECT_EQ(CmSetCertStatus(NULL, CM_SYSTEM_TRUSTED_STORE, true),
        CMR_ERROR_NULL_POINTER);

    EXPECT_EQ(CmSetCertStatus(&uriBlob, 10, true), CMR_ERROR_INVALID_ARGUMENT);

    const char *invalidUri = "INVALIDXXXX";
    struct CmBlob invalidUriBlob = {strlen(invalidUri) + 1, (uint8_t *)invalidUri};
    EXPECT_EQ(CmSetCertStatus(&invalidUriBlob, CM_SYSTEM_TRUSTED_STORE, true),
        CMR_ERROR_NOT_FOUND);
}
}
