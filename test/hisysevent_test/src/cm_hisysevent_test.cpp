/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "cm_hisysevent_test_common.h"
#include "cert_manager_api.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

static void SetATPermission(void)
{
    const char **perms = new const char *[2]; // 2 permissions
    perms[0] = "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL"; // system_basic
    perms[1] = "ohos.permission.ACCESS_CERT_MANAGER"; // normal
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "TestCertManager",
        .aplStr = "system_basic",
    };

    auto tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

using namespace testing::ext;
namespace {
#define MAX_URI_LEN            256
static constexpr uint32_t DEFAULT_AUTH_URI_LEN = 256;
static constexpr uint32_t DEFAULT_APP_ID = 1000;

static const uint8_t g_p12AbnormalCertinfo[] = {
    0x30, 0x82, 0x0b, 0xc1, 0x02, 0x01, 0x03, 0x30, 0x82, 0x0b, 0x87, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x0b, 0x78, 0x04, 0x82, 0x0b, 0x74, 0x30, 0x82,
    0x0b, 0x70, 0x30, 0x82, 0x06, 0x27, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
    0x06, 0xa0, 0x82, 0x06, 0x18, 0x30, 0x82, 0x06, 0x14, 0x02, 0x01, 0x00, 0x30, 0x82, 0x06, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x1c, 0x06, 0x0a, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x0e, 0x04, 0x08, 0x1a, 0x8f, 0xc1,
    0xd1, 0xda, 0x6c, 0xd1, 0xa9, 0x02, 0x02, 0x08, 0x00, 0x80, 0x82, 0x05, 0xe0, 0xd0, 0x2f, 0x2d,
    0x52, 0x09, 0x86, 0x55, 0x53, 0xf0, 0x49, 0x8f, 0x00, 0xa1, 0x4d, 0x21, 0xc8, 0xb4, 0xad, 0x27,
    0x12, 0x44, 0xab, 0x4d, 0x10, 0x14, 0xe3, 0x3c, 0x9a, 0x05, 0x77, 0x51, 0x90, 0x4a, 0x3a, 0x8a,
    0x09, 0xa9, 0x4b, 0x36, 0x50, 0x60, 0x22, 0x4b, 0x77, 0x12, 0x5c, 0x2f, 0x60, 0xd3, 0xd9, 0x30,
    0x94, 0x4d, 0x9e, 0x81, 0xc3, 0xe9, 0x9d, 0xd9, 0x47, 0xb3, 0x54, 0xa2, 0x9a, 0x8f, 0xe7, 0x58,
    0x95, 0xd7, 0x48, 0x87, 0xc4, 0x40, 0xad, 0x9a, 0x42, 0x1d, 0x36, 0xb7, 0x48, 0xbc, 0x70, 0x8c,
    0x84, 0xcb, 0x3c, 0x02, 0x25, 0x9f, 0xfe, 0x2c, 0x4a, 0x76, 0xb1, 0x27, 0x94, 0x8f, 0xb0, 0x07,
    0xf0, 0xc0, 0x00, 0x3a, 0x69, 0x16, 0xe1, 0x63, 0x0c, 0xe5, 0x92, 0xc2, 0x7d, 0x99, 0xd9, 0x11,
    0x40, 0xd8, 0x64, 0xab, 0x13, 0xda, 0x73, 0x7b, 0x12, 0x53, 0xb1, 0x0b, 0x0c, 0x67, 0x81, 0xe1,
    0xf5, 0x59, 0x3a, 0xc7, 0xe0, 0xe9, 0xda, 0x12, 0xc7, 0x2b, 0xab, 0x3d, 0xbc, 0x10, 0x3d, 0x1a,
    0x88, 0xc7, 0x1d, 0x31, 0x5f, 0x39, 0x63, 0x51, 0x8b, 0x11, 0x99, 0x05, 0xf9, 0x40, 0x42, 0x27,
    0xad, 0x75, 0x6f, 0xe2, 0x2d, 0x66, 0x28, 0x97, 0x7c, 0x6f, 0xf4, 0xfc, 0x95, 0xaa, 0x67, 0x81,
    0xd8, 0x15, 0x3c, 0xf4, 0x7b, 0x97, 0x08, 0x7b, 0x1b, 0x8c, 0xd3, 0x45, 0x8b, 0x96, 0x54, 0x2c,
    0xb1, 0x00, 0x87, 0x59, 0x5c, 0x94, 0x78, 0x29, 0xaa, 0x7b, 0x9c, 0x5c, 0x61, 0xff, 0xcc, 0x32,
    0x14, 0x4e, 0xc3, 0x1b, 0x96
};

static const uint8_t g_certData04[] = { /* invalid data */
    0xa0, 0x41, 0xa0, 0x3f, 0x86, 0x3d, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77,
    0x2e, 0x64, 0x2d, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x63, 0x72, 0x6c,
    0x2f, 0x64, 0x2d, 0x74, 0x72, 0x75, 0x73, 0x74, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x63, 0x6c,
    0x61, 0x73, 0x73, 0x5f, 0x33, 0x5f, 0x63, 0x61, 0x5f, 0x32, 0x5f, 0x32, 0x30, 0x30, 0x39, 0x2e,
    0x63, 0x72, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x7f, 0x97, 0xdb, 0x30, 0xc8, 0xdf, 0xa4, 0x9c, 0x7d,
    0x21, 0x7a, 0x80, 0x70, 0xce, 0x14, 0x12, 0x69, 0x88, 0x14, 0x95, 0x60, 0x44, 0x01, 0xac, 0xb2,
    0xe9, 0x30, 0x4f, 0x9b, 0x50, 0xc2, 0x66, 0xd8, 0x7e, 0x8d, 0x30, 0xb5, 0x70, 0x31, 0xe9, 0xe2,
    0x69, 0xc7, 0xf3, 0x70, 0xdb, 0x20, 0x15, 0x86, 0xd0, 0x0d, 0xf0, 0xbe, 0xac, 0x01, 0x75, 0x84,
    0xce, 0x7e, 0x9f, 0x4d, 0xbf, 0xb7, 0x60, 0x3b, 0x9c, 0xf3, 0xca, 0x1d, 0xe2, 0x5e, 0x68, 0xd8,
    0xa3, 0x9d, 0x97, 0xe5, 0x40, 0x60, 0xd2, 0x36, 0x21, 0xfe, 0xd0, 0xb4, 0xb8, 0x17, 0xda, 0x74,
    0xa3, 0x7f, 0xd4, 0xdf, 0xb0, 0x98, 0x02, 0xac, 0x6f, 0x6b, 0x6b, 0x2c, 0x25, 0x24, 0x72, 0xa1,
    0x65, 0xee, 0x25, 0x5a, 0xe5, 0xe6, 0x32, 0xe7, 0xf2, 0xdf, 0xab, 0x49, 0xfa, 0xf3, 0x90, 0x69,
    0x23, 0xdb, 0x04, 0xd9, 0xe7, 0x5c, 0x58, 0xfc, 0x65, 0xd4, 0x97, 0xbe, 0xcc, 0xfc, 0x2e, 0x0a,
    0xcc, 0x25, 0x2a, 0x35, 0x04, 0xf8, 0x60, 0x91, 0x15, 0x75, 0x3d, 0x41, 0xff, 0x23, 0x1f, 0x19,
    0xc8, 0x6c, 0xeb, 0x82, 0x53, 0x04, 0xa6, 0xe4, 0x4c, 0x22, 0x4d, 0x8d, 0x8c, 0xba, 0xce, 0x5b,
    0x73, 0xec, 0x64, 0x54, 0x50, 0x6d, 0xd1, 0x9c, 0x55, 0xfb, 0x69, 0xc3, 0x36, 0xc3, 0x8c, 0xbc,
    0x3c, 0x85, 0xa6, 0x6b, 0x0a, 0x26, 0x0d, 0xe0, 0x93, 0x98, 0x60, 0xae, 0x7e, 0xc6, 0x24, 0x97,
    0x8a, 0x61, 0x5f, 0x91, 0x8e, 0x66, 0x92, 0x09, 0x87, 0x36, 0xcd, 0x8b, 0x9b, 0x2d, 0x3e, 0xf6,
    0x51, 0xd4, 0x50, 0xd4, 0x59, 0x28, 0xbd, 0x83, 0xf2, 0xcc, 0x28, 0x7b, 0x53, 0x86, 0x6d, 0xd8,
    0x26, 0x88, 0x70, 0xd7, 0xea, 0x91, 0xcd, 0x3e, 0xb9, 0xca, 0xc0, 0x90, 0x6e, 0x5a, 0xc6, 0x5e,
    0x74, 0x65, 0xd7, 0x5c, 0xfe, 0xa3, 0xe2
};

struct UserCertInfoResult {
    struct CertInfo certInfo;
    bool bExpectResult;
};

struct UserCertInfoResult g_certInfoExpectResult[] = {
    {
        {
            "oh:t=c;o=40dc992e;u=0;a=0",
            "Hellenic Academic and Research Institutions Cert. Authority",
            true,
            "CN=Hellenic Academic and Research Institutions RootCA 2011,OU=,"
            "O=Hellenic Academic and Research Institutions Cert. Authority",
            "CN=Hellenic Academic and Research Institutions RootCA 2011,OU=,"
            "O=Hellenic Academic and Research Institutions Cert. Authority",
            "0",
            "2011-12-6",
            "2031-12-1",
            "BC:10:4F:15:A4:8B:E7:09:DC:A5:42:A7:E1:D4:B9:DF:6F:05:45:27:E8:02:EA:A9:2D:59:54:44:25:8A:FE:71"
        },
        true
    },
};


class CmHiSysEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmHiSysEventTest::SetUpTestCase(void)
{
    (void)SetATPermission();
}

void CmHiSysEventTest::TearDownTestCase(void)
{
}

void CmHiSysEventTest::SetUp()
{
}

void CmHiSysEventTest::TearDown()
{
}

/**
 * @tc.name: CmHiSysEventTest.CmHiSysEventTest001
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'CmIpcServiceInstallAppCert'.
 * @tc.type: FUNC
 * @tc.require: AR000HE22G /SR000HDQVV
 */
HWTEST_F(CmHiSysEventTest, CmHiSysEventTest001, TestSize.Level0)
{
    CmHiSysEventQueryStart();
    int32_t ret;
    uint32_t store = CM_CREDENTIAL_STORE;
    uint8_t appCertPwdBuf[] = "123456";
    uint8_t certAliasBuf[] = "keyA";
    uint8_t keyUriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { MAX_LEN_URI, keyUriBuf };

    struct CmBlob appCert = { sizeof(g_p12AbnormalCertinfo), (uint8_t*)g_p12AbnormalCertinfo };
    struct CmBlob appCertPwd = { sizeof(appCertPwdBuf), appCertPwdBuf };
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    (void)CmInstallAppCert(&appCert, &appCertPwd, &certAlias, store, &keyUri);
    ret = CmHiSysEventQueryResult("CmIpcServiceInstallAppCert");
    EXPECT_EQ(ret, CM_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;

}

/**
 * @tc.name: CmHiSysEventTest.CmHiSysEventTest002
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'CmIpcServiceInstallUserCert'.
 * @tc.type: FUNC
 * @tc.require: AR000HE22G /SR000HDQVV
 */
HWTEST_F(CmHiSysEventTest, CmHiSysEventTest002, TestSize.Level0)
{
    CmHiSysEventQueryStart();
    int32_t ret;
    uint8_t certAliasBuf[] = "abnormal-invalid-certdata";
    uint8_t certUriBuf[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData04), (uint8_t *)g_certData04 }; /* invalid certData */
    struct CmBlob certAliasTemp = { sizeof(certAliasBuf), certAliasBuf };
    struct CmBlob certUriTemp = { sizeof(certUriBuf), certUriBuf };

    (void)CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUriTemp);
    ret = CmHiSysEventQueryResult("CmIpcServiceInstallUserCert");
    EXPECT_EQ(ret, CM_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;
}

/**
 * @tc.name: CmHiSysEventTest.CmHiSysEventTest003
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'CmIpcServiceGetUserCertList'.
 * @tc.type: FUNC
 * @tc.require: AR000HE22G /SR000HDQVV
 */
HWTEST_F(CmHiSysEventTest, CmHiSysEventTest003, TestSize.Level0)
{
    CmHiSysEventQueryStart();
    int32_t ret;

    struct CertList *cList = nullptr;
    InitUserCertList(&cList);
    (void)CmGetUserCertList(100, cList); /* invalid store 100 */
    FreeCertList(cList);

    ret = CmHiSysEventQueryResult("CmIpcServiceGetUserCertList");
    EXPECT_EQ(ret, CM_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;
}

/**
 * @tc.name: CmHiSysEventTest.CmHiSysEventTest004
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'CmIpcServiceGetUserCertInfo'.
 * @tc.type: FUNC
 * @tc.require: AR000HE22G /SR000HDQVV
 */
HWTEST_F(CmHiSysEventTest, CmHiSysEventTest004, TestSize.Level0)
{
    CmHiSysEventQueryStart();
    int32_t ret;
    char *uri = g_certInfoExpectResult[0].certInfo.uri;
    struct CmBlob certUri = { strlen(uri) + 1, (uint8_t *)uri };

    struct CertInfo *cInfo = nullptr;
    InitUserCertInfo(&cInfo);
    (void)CmGetUserCertInfo(&certUri, 100, cInfo); /* invalid store 100 */
    FreeCMBlobData(&(cInfo->certInfo));

    ret = CmHiSysEventQueryResult("CmIpcServiceGetUserCertInfo");
    EXPECT_EQ(ret, CM_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;
}

/**
 * @tc.name: CmHiSysEventTest.CmHiSysEventTest005
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'CmIpcServiceUninstallUserCert'.
 * @tc.type: FUNC
 * @tc.require: AR000HE22G /SR000HDQVV
 */
HWTEST_F(CmHiSysEventTest, CmHiSysEventTest005, TestSize.Level0)
{
    CmHiSysEventQueryStart();
    int32_t ret;

    uint8_t invalidUriBuf[MAX_URI_LEN] = "*****"; /* error uri */
    struct CmBlob invalidUri = { sizeof(invalidUriBuf), invalidUriBuf };
    (void)CmUninstallUserTrustedCert(&invalidUri);

    ret = CmHiSysEventQueryResult("CmIpcServiceUninstallUserCert");
    EXPECT_EQ(ret, CM_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;
}

/**
 * @tc.name: CmHiSysEventTest.CmHiSysEventTest006
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'CmIpcServiceGrantAppCertificate'.
 * @tc.type: FUNC
 * @tc.require: AR000HE22G /SR000HDQVV
 */
HWTEST_F(CmHiSysEventTest, CmHiSysEventTest006, TestSize.Level0)
{
    CmHiSysEventQueryStart();
    int32_t ret;
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    uint8_t authUriData[DEFAULT_AUTH_URI_LEN] = {0};
    struct CmBlob authUri = { DEFAULT_AUTH_URI_LEN, authUriData };

    uint32_t appId = DEFAULT_APP_ID;

    (void)CmGrantAppCertificate(&keyUri, appId, &authUri);

    ret = CmHiSysEventQueryResult("CmIpcServiceGrantAppCertificate");
    EXPECT_EQ(ret, CM_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;
}

/**
 * @tc.name: CmHiSysEventTest.CmHiSysEventTest007
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'CmIpcServiceIsAuthorizedApp'.
 * @tc.type: FUNC
 * @tc.require: AR000HE22G /SR000HDQVV
 */
HWTEST_F(CmHiSysEventTest, CmHiSysEventTest007, TestSize.Level0)
{
    CmHiSysEventQueryStart();
    int32_t ret;

    /* authUri macData size 31 */
    uint8_t uriDataFail[] =
        "oh:t=ak;o=TestNormalGrant;u=0;a=0?ca=0&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FA";
    struct CmBlob authUriFail = { sizeof(uriDataFail), uriDataFail };
    (void)CmIsAuthorizedApp(&authUriFail);

    ret = CmHiSysEventQueryResult("CmIpcServiceIsAuthorizedApp");
    EXPECT_EQ(ret, CM_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;
}

/**
 * @tc.name: CmHiSysEventTest.CmHiSysEventTest008
 * @tc.desc: the abnormal test is for hisysevent;
             the test interface is 'CmIpcServiceRemoveGrantedApp'.
 * @tc.type: FUNC
 * @tc.require: AR000HE22G /SR000HDQVV
 */
HWTEST_F(CmHiSysEventTest, CmHiSysEventTest008, TestSize.Level0)
{
    CmHiSysEventQueryStart();
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { strlen((char *)uriData), uriData };
    uint32_t appId = 0;
    int32_t ret = CmRemoveGrantedApp(&keyUri, appId);

    ret = CmHiSysEventQueryResult("CmIpcServiceRemoveGrantedApp");
    EXPECT_EQ(ret, CM_HISYSEVENT_QUERY_SUCCESS) << "query failed, ret = " << ret;}

}