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
#include "cm_test_log.h"
#include "cert_manager_api.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
struct CertInfoResult {
    struct CertInfo CertInfo;
    bool bExpectResult;
};

struct CertInfoResult g_listCertInfoexpectResult[] = {
    {
        {
            "2add47b6.0",
            "GlobalSign",
            true,
            "CN=GlobalSign,OU=GlobalSign ECC Root CA - R5,O=GlobalSign",
            "CN=GlobalSign,OU=GlobalSign ECC Root CA - R5,O=GlobalSign",
            "605949E0262EBB55F90A778A71F94AD86C",
            "2012-11-13",
            "2038-1-19",
            "17:9F:BC:14:8A:3D:D0:0F:D2:4E:A1:34:58:CC:43:BF:A7:F5:9C:81:82:D7:83:A5:13:F6:EB:EC:10:0C:89:24"
        },
        true
    },
    {
        {
            "85cde254.0",
            "Starfield Technologies, Inc.",
            true,
            "CN=Starfield Root Certificate Authority - G2,OU=,O=Starfield Technologies, Inc.",
            "CN=Starfield Root Certificate Authority - G2,OU=,O=Starfield Technologies, Inc.",
            "0",
            "2009-9-1",
            "2037-12-31",
            "2C:E1:CB:0B:F9:D2:F9:E1:02:99:3F:BE:21:51:52:C3:B2:DD:0C:AB:DE:1C:68:E5:31:9B:83:91:54:DB:B7:F5"
        },
        true
    },
    {
        {
            "3c860d51.0",
            "SwissSign AG",
            true,
            "CN=SwissSign Gold CA - G2,OU=,O=SwissSign AG",
            "CN=SwissSign Gold CA - G2,OU=,O=SwissSign AG",
            "BB401C43F55E4FB0",
            "2006-10-25",
            "2036-10-25",
            "62:DD:0B:E9:B9:F5:0A:16:3E:A0:F8:E7:5C:05:3B:1E:CA:57:EA:55:C8:68:8F:64:7C:68:81:F2:C8:35:7B:95"
        },
        true
    },
    {
        {
            "b0f3e76e.0",
            "GlobalSign nv-sa",
            true,
            "CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa",
            "CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa",
            "040000000001154B5AC394",
            "1998-9-1",
            "2028-1-28",
            "EB:D4:10:40:E4:BB:3E:C7:42:C9:E3:81:D3:1E:F2:A4:1A:48:B6:68:5C:96:E7:CE:F3:C1:DF:6C:D4:33:1C:99"
        },
        true
    },
    {
        {
            "869fbf79.0",
            "eMudhra Inc",
            true,
            "CN=emSign ECC Root CA - C3,OU=emSign PKI,O=eMudhra Inc",
            "CN=emSign ECC Root CA - C3,OU=emSign PKI,O=eMudhra Inc",
            "7B71B68256B8127C9CA8",
            "2018-2-18",
            "2043-2-18",
            "BC:4D:80:9B:15:18:9D:78:DB:3E:1D:8C:F4:F9:72:6A:79:5D:A1:64:3C:A5:F1:35:8E:1D:DB:0E:DC:0D:7E:B3"
        },
        true
    }
};

class CmGetCertInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();

    struct CertList *lstCert;
};

void CmGetCertInfoTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmGetCertInfoTest::TearDownTestCase(void)
{
}

void CmGetCertInfoTest::SetUp()
{
    InitCertList(&lstCert);
}

void CmGetCertInfoTest::TearDown()
{
    FreeCertList(lstCert);
}

/**
 * @tc.name: SimpleCmGetCertInfo001
 * @tc.desc: Test CertManager get cert info interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertInfoTest, SimpleCmGetCertInfo001, TestSize.Level0)
{
    char *uri = g_listCertInfoexpectResult[0].CertInfo.uri;
    struct CmBlob uriBlob = {strlen(uri) + 1, (uint8_t *)(uri)};
    struct CertInfo certInfo;
    unsigned int len = sizeof(struct CertInfo);
    (void)memset_s(&certInfo, len, 0, len);
    int32_t ret = InitCertInfo(&certInfo);
    EXPECT_EQ(ret, CM_SUCCESS) << "CertInfo malloc faild, retcode:" << ret;

    ret = CmGetCertInfo(&uriBlob, CM_SYSTEM_TRUSTED_STORE, &certInfo);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetCertInfo failed, retcode:" << ret;

    EXPECT_EQ(CompareCertInfo(&certInfo, &(g_listCertInfoexpectResult[0].CertInfo)), true) <<DumpCertInfo(&certInfo);

    FreeCMBlobData(&(certInfo.certInfo));
}

/**
 * @tc.name: AppGetCertInfoCompare002
 * @tc.desc: Test CertManager get cert info compare interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertInfoTest, AppGetCertInfoCompare002, TestSize.Level0)
{
    int length = sizeof(g_listCertInfoexpectResult) / sizeof(g_listCertInfoexpectResult[0]);

    char *uri = g_listCertInfoexpectResult[length - 1].CertInfo.uri;
    struct CmBlob uriBlob = {strlen(uri) + 1, (uint8_t *)(uri)};

    struct CertInfo firstCertInfo, secondCertInfo;
    unsigned int len = sizeof(struct CertInfo);

    (void)memset_s(&firstCertInfo, len, 0, len);
    int32_t ret = InitCertInfo(&firstCertInfo);
    EXPECT_EQ(ret, CM_SUCCESS) << "firstCertInfo malloc faild, retcode:" << ret;

    (void)memset_s(&secondCertInfo, len, 0, len);
    ret = InitCertInfo(&secondCertInfo);
    EXPECT_EQ(ret, CM_SUCCESS) << "secondCertInfo malloc faild, retcode:" << ret;

    ret = CmGetCertInfo(&uriBlob, CM_SYSTEM_TRUSTED_STORE, &firstCertInfo);
    EXPECT_EQ(ret, CM_SUCCESS) << "first CmGetCertInfo failed,retcode:" << ret;

    ret = CmGetCertInfo(&uriBlob, CM_SYSTEM_TRUSTED_STORE, &secondCertInfo);
    EXPECT_EQ(ret, CM_SUCCESS) << "second CmGetCertInfo failed,retcode:" << ret;

    EXPECT_EQ(CompareCertInfo(&firstCertInfo, &secondCertInfo), true) << "Diffrent app do not get the same cert.";
    FreeCMBlobData(&(firstCertInfo.certInfo));
    FreeCMBlobData(&(secondCertInfo.certInfo));
}

/**
 * @tc.name: AppGetAllCertInfo003
 * @tc.desc: Test CertManager get all cert info interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertInfoTest, AppGetAllCertInfo003, TestSize.Level0)
{
    unsigned int len = sizeof(struct CertInfo);;
    struct CertInfo certInfo;
    int32_t ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, lstCert);

    EXPECT_EQ(ret, CM_SUCCESS) << "CmGetCertList failed,retcode:" << ret;

    for (uint32_t i = 0; i < lstCert->certsCount; ++i) {
        (void)memset_s(&certInfo, len, 0, len);
        ret = InitCertInfo(&certInfo);
        EXPECT_EQ(ret, CM_SUCCESS) << "CertInfo malloc faild, retcode:" << ret;

        struct CertAbstract *ptr = &(lstCert->certAbstract[i]);
        ASSERT_TRUE(ptr != NULL);

        struct CmBlob uriBlob = {strlen(ptr->uri) + 1, (uint8_t *)(ptr->uri)};

        ret = CmGetCertInfo(&uriBlob, CM_SYSTEM_TRUSTED_STORE, &certInfo);
        EXPECT_EQ(ret, CM_SUCCESS) << " CmGetCertInfo failed,retcode:" << ptr->uri;
        FreeCMBlobData(&(certInfo.certInfo));
    }
}

/**
 * @tc.name: ExceptionGetCertInfoTest004
 * @tc.desc: Test CertManager get cert info interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmGetCertInfoTest, ExceptionGetCertInfoTest004, TestSize.Level0)
{
    char *uri = g_listCertInfoexpectResult[1].CertInfo.uri;
    struct CmBlob uriBlob = {strlen(uri) + 1, (uint8_t *)(uri)};
    struct CertInfo certInfo;
    unsigned int len = sizeof(struct CertInfo);
    (void)memset_s(&certInfo, len, 0, len);
    int32_t ret = InitCertInfo(&certInfo);
    EXPECT_EQ(ret, CM_SUCCESS) << "CertInfo malloc faild, retcode:" << ret;

    EXPECT_EQ(CmGetCertInfo(NULL, CM_SYSTEM_TRUSTED_STORE, &certInfo), CMR_ERROR_NULL_POINTER);

    EXPECT_EQ(CmGetCertInfo(&uriBlob, 10,  &certInfo), CMR_ERROR_INVALID_ARGUMENT);

    EXPECT_EQ(CmGetCertInfo(&uriBlob, CM_SYSTEM_TRUSTED_STORE, NULL), CMR_ERROR_NULL_POINTER);

    const char *invalidUri = "INVALID";
    struct CmBlob invalidUriBlob = {strlen(invalidUri), (uint8_t *)invalidUri};
    EXPECT_EQ(CmGetCertInfo(&invalidUriBlob, CM_SYSTEM_TRUSTED_STORE, &certInfo),
        CMR_ERROR_INVALID_ARGUMENT);

    FreeCMBlobData(&(certInfo.certInfo));
}
}