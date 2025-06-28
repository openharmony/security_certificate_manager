/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <cstring>
#include "cm_test_log.h"
#include "cm_test_common.h"
#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_cert_data_user.h"
#include "cm_cert_data_p7b.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
constexpr uint32_t MAX_URI_LEN = 256;

struct UserCertListResult {
    struct CertAbstract certAbstract;
    bool bExpectResult;
};

struct UserCertListResult g_certListExpectResult[] = {
    {
        {
            "oh:t=c;o=40dc992e;u=0;a=0",
            "40dc992e",
            true,
            "CN=Hellenic Academic and Research Institutions RootCA 2011,OU=,"
            "O=Hellenic Academic and Research Institutions Cert. Authority"
        },
        true
    },
    {
        {
            "oh:t=c;o=985c1f52;u=0;a=0",
            "985c1f52",
            true,
            "CN=GlobalSign,OU=GlobalSign Root CA - R6,O=GlobalSign"
        },
        true
    },
    {
        {
            "oh:t=c;o=1df5a75f;u=0;a=0",
            "1df5a75f",
            true,
            "CN=D-TRUST Root Class 3 CA 2 2009,OU=,O=D-Trust GmbH"
        },
        true
    },
    {
        {
            "oh:t=c;o=2e0g9ue5;u=0;a=0",
            "2e0g9ue5",
            true,
            "CN=TEST01,OU=TEST02,O=TEST03"
        },
        true
    }
};

struct UserCertInfoResult {
    struct CertInfo certInfo;
    bool bExpectResult;
};

struct UserCertInfoResult g_certInfoExpectResult[] = {
    {
        {
            "oh:t=c;o=40dc992e;u=0;a=0",
            "40dc992e",
            true,
            "CN=Hellenic Academic and Research Institutions RootCA 2011,OU=,"
            "O=Hellenic Academic and Research Institutions Cert. Authority",
            "CN=Hellenic Academic and Research Institutions RootCA 2011,OU=,"
            "O=Hellenic Academic and Research Institutions Cert. Authority",
            "0",
            "2011-12-6",
            "2031-12-1",
            "BC:10:4F:15:A4:8B:E7:09:DC:A5:42:A7:E1:D4:B9:DF:6F:05:45:27:E8:02:EA:A9:2D:59:54:44:25:8A:FE:71",
            { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) }
        },
        true
    },
    {
        {
            "oh:t=c;o=985c1f52;u=0;a=0",
            "985c1f52",
            true,
            "CN=GlobalSign,OU=GlobalSign Root CA - R6,O=GlobalSign",
            "CN=GlobalSign,OU=GlobalSign Root CA - R6,O=GlobalSign",
            "45E6BB038333C3856548E6FF4551",
            "2014-12-10",
            "2034-12-10",
            "2C:AB:EA:FE:37:D0:6C:A2:2A:BA:73:91:C0:03:3D:25:98:29:52:C4:53:64:73:49:76:3A:3A:B5:AD:6C:CF:69",
            { sizeof(g_certData02), const_cast<uint8_t *>(g_certData02) }
        },
        true
    },
    {
        {
            "oh:t=c;o=1df5a75f;u=0;a=0",
            "1df5a75f",
            true,
            "CN=D-TRUST Root Class 3 CA 2 2009,OU=,O=D-Trust GmbH",
            "CN=D-TRUST Root Class 3 CA 2 2009,OU=,O=D-Trust GmbH",
            "0983F3",
            "2009-11-5",
            "2029-11-5",
            "49:E7:A4:42:AC:F0:EA:62:87:05:00:54:B5:25:64:B6:50:E4:F4:9E:42:E3:48:D6:AA:38:E0:39:E9:57:B1:C1",
            { sizeof(g_certData03), const_cast<uint8_t *>(g_certData03) }
        },
        true
    },
    {
        {
            "oh:t=c;o=2e0g9ue5;u=0;a=0",
            "2e0g9ue5",
            true,
            "CN=Example Root CA,OU=,O=",
            "CN=TEST01,OU=TEST02,O=TEST03",
            "01",
            "2022-12-16",
            "2025-9-10",
            "60:57:A8:41:CD:4E:45:F6:7F:93:21:C4:E9:A0:F9:5F:45:CB:D5:39:02:43:A9:AF:4F:0A:04:D0:2C:41:99:68",
            { sizeof(g_certData05), const_cast<uint8_t *>(g_certData05) }
        },
        true
    }
};

struct UserCertInfoResult g_userCertInfoExpectResult[] = {
    {
        {
            "oh:t=c;o=882de061;u=100;a=0",
            "882de061",
            true,
            "CN=,OU=certSIGN ROOT CA,O=certSIGN",
            "CN=,OU=certSIGN ROOT CA,O=certSIGN",
            "200605167002",
            "2006-7-5",
            "2031-7-5",
            "EA:A9:62:C4:FA:4A:6B:AF:EB:E4:15:19:6D:35:1C:CD:88:8D:4F:53:F3:FA:8A:E6:D7:C4:66:A9:4E:60:42:BB",
            { sizeof(g_certData07), const_cast<uint8_t *>(g_certData07) }
        },
        true
    }
};

struct UserCertStatusExpectResult {
    char uri[MAX_URI_LEN];
    bool inparamStatus;
    bool expectStatus;
};

struct UserCertStatusExpectResult g_certStatusExpectResult[] = {
    {
        {"oh:t=c;o=40dc992e;u=0;a=0"}, false, false
    },
    {
        {"oh:t=c;o=985c1f52;u=0;a=0"}, false, false
    },
    {
        {"oh:t=c;o=1df5a75f;u=0;a=0"}, true, true
    },
    {
        {"oh:t=c;o=2e0g9ue5;u=0;a=0"}, true, true
    }
};

struct CmBlob userCert[] = {
    { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) },
    { sizeof(g_certData02), const_cast<uint8_t *>(g_certData02) },
    { sizeof(g_certData03), const_cast<uint8_t *>(g_certData03) },
    { sizeof(g_certData05), const_cast<uint8_t *>(g_certData05) }
};

static uint8_t certAliasBuf01[] = "40dc992e";
static uint8_t certAliasBuf02[] = "985c1f52";
static uint8_t certAliasBuf03[] = "1df5a75f";
static uint8_t certAliasBuf05[] = "2e0g9ue5";
static uint8_t certAliasBuf06[] = "3a2g6de7";

struct CmBlob certAlias[] = {
    { sizeof(certAliasBuf01), certAliasBuf01 },
    { sizeof(certAliasBuf02), certAliasBuf02 },
    { sizeof(certAliasBuf03), certAliasBuf03 },
    { sizeof(certAliasBuf05), certAliasBuf05 }
};

class CmUserCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmUserCertTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmUserCertTest::TearDownTestCase(void)
{
}

void CmUserCertTest::SetUp()
{
}

void CmUserCertTest::TearDown()
{
}

/**
 * @tc.name: InstallUserCertTest001
 * @tc.desc: Test CertManager Install user cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest001, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf001[MAX_URI_LEN] = {0};
    struct CmBlob certUri = { sizeof(uriBuf001), uriBuf001 };

    ret = CmInstallUserTrustedCert(&userCert[0], &certAlias[0], &certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest002
 * @tc.desc: Test CertManager Install cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest002, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf002[MAX_URI_LEN] = {0};
    struct CmBlob certUri = { sizeof(uriBuf002), uriBuf002 };

    ret = CmInstallUserTrustedCert(&userCert[1], &certAlias[1], &certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest003
 * @tc.desc: Test CertManager Install user cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest003, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf003[MAX_URI_LEN] = {0};
    struct CmBlob certUri = { sizeof(uriBuf003), uriBuf003 };

    ret = CmInstallUserTrustedCert(&userCert[2], &certAlias[2], &certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest004
 * @tc.desc: Test CertManager Update user cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest004, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf001[] = "40dc992e";
    uint8_t uriBuf004[MAX_URI_LEN] = {0};
    struct CmBlob userCertUpdate = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    struct CmBlob certAliasUpdate = { sizeof(aliasBuf001), aliasBuf001 };
    struct CmBlob certUriUpdate = { sizeof(uriBuf004), uriBuf004 };

    ret = CmInstallUserTrustedCert(&userCertUpdate, &certAliasUpdate, &certUriUpdate);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmInstallUserTrustedCert(&userCertUpdate, &certAliasUpdate, &certUriUpdate);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUriUpdate);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest005
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest005, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf002[] = "abnormal_invalid_certdata";
    uint8_t uriBuf005[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData04),
        const_cast<uint8_t *>(g_certData04) }; /* invalid certData */
    struct CmBlob certAliasTemp = { sizeof(aliasBuf002), aliasBuf002 };
    struct CmBlob certUriTemp = { sizeof(uriBuf005), uriBuf005 };

    ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUriTemp);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT) << "Normal user cert Install test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest006
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest006, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf003[] = "abnormal-inputparam-null";
    uint8_t uriBuf006[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData03), const_cast<uint8_t *>(g_certData03) };
    struct CmBlob certAliasTemp = { sizeof(aliasBuf003), aliasBuf003 };
    struct CmBlob certUriTemp = { sizeof(uriBuf006), uriBuf006 };

    ret = CmInstallUserTrustedCert(nullptr, &certAliasTemp, &certUriTemp);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmInstallUserTrustedCert(&userCertTemp, nullptr, &certUriTemp);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal user cert Install test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest007
 * @tc.desc: Test CertManager install max count user cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest007, TestSize.Level0)
{
    int32_t ret;
    struct CmBlob userCertTest = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };

    for (uint32_t i = 0; i < MAX_COUNT_CERTIFICATE; i++) { /* install 256 times user cert */
        char alias[] = "alias";
        char aliasBuf004[MAX_LEN_CERT_ALIAS];
        (void)snprintf_s(aliasBuf004, MAX_LEN_CERT_ALIAS, MAX_LEN_CERT_ALIAS - 1, "%s%u", alias, i);
        struct CmBlob certAliasTest = { strlen(aliasBuf004) + 1, reinterpret_cast<uint8_t *>(aliasBuf004) };

        uint8_t uriBuf007[MAX_URI_LEN] = {0};
        struct CmBlob certUriTest = { sizeof(uriBuf007), uriBuf007 };

        ret = CmInstallUserTrustedCert(&userCertTest, &certAliasTest, &certUriTest);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    uint8_t certAliasBuf257[] = "40dc992e"; /* install 257th user cert */
    uint8_t certUriBuf257[MAX_URI_LEN] = {0};
    struct CmBlob certAlias257 = { sizeof(certAliasBuf257), certAliasBuf257 };
    struct CmBlob certUri257 = { sizeof(certUriBuf257), certUriBuf257 };

    ret = CmInstallUserTrustedCert(&userCertTest, &certAlias257, &certUri257);
    EXPECT_EQ(ret, CMR_ERROR_MAX_CERT_COUNT_REACHED) << "Normal user cert Install test failed, recode:" << ret;

    uint8_t certAliasBuf000[] = "alias0"; /* update 001th user cert */
    uint8_t certUriBuf000[MAX_URI_LEN] = {0};
    struct CmBlob certAlias000 = { sizeof(certAliasBuf000), certAliasBuf000 };
    struct CmBlob certUri000 = { sizeof(certUriBuf000), certUriBuf000 };

    ret = CmInstallUserTrustedCert(&userCertTest, &certAlias000, &certUri000);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest008
 * @tc.desc: Test CertManager Install user cert interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest008, TestSize.Level0)
{
    int32_t ret;
    for (uint32_t times = 0; times < PERFORMACE_COUNT; ++times) {
        uint8_t uriBuf008[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf008), uriBuf008 };

        ret = CmInstallUserTrustedCert(&userCert[2], &certAlias[2], &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

        ret = CmUninstallUserTrustedCert(&certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
    }
}

/**
 * @tc.name: InstallUserCertTest009
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest009, TestSize.Level0)
{
    int32_t ret;
    /* size is 66, include 1 byte: the terminator('\0') */
    uint8_t largeAliasBuf[] = "large-size-input-cert-alias-0000000000000000000000000000000000000";
    uint8_t certUriBuf[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData02), const_cast<uint8_t *>(g_certData02) };
    struct CmBlob largeAlias = { sizeof(largeAliasBuf), largeAliasBuf };
    struct CmBlob certUriTemp = { sizeof(certUriBuf), certUriBuf };

    ret = CmInstallUserTrustedCert(&userCertTemp, &largeAlias, &certUriTemp);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal user cert Install test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest010
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest010, TestSize.Level0)
{
    int32_t ret;
    char errAliasBuf[] = "AliasNoEnd";
    uint8_t certUriBuf[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    struct CmBlob noEndAlias = { strlen(errAliasBuf), reinterpret_cast<uint8_t *>(errAliasBuf) };
    struct CmBlob certUriTemp = { sizeof(certUriBuf), certUriBuf };

    ret = CmInstallUserTrustedCert(&userCertTemp, &noEndAlias, &certUriTemp);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal user cert Install test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest011
 * @tc.desc: Test CertManager Install user cert interface normal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest011, TestSize.Level0)
{
    int32_t ret;
    char edgeAliasBuf[] = "alias_length_is_48_000000000000000000000000000000000000000000000"; /* size is 64 */
    uint8_t uriBuf[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    struct CmBlob edgeAlias = { strlen(edgeAliasBuf) + 1, reinterpret_cast<uint8_t *>(edgeAliasBuf) };
    struct CmBlob uri = { sizeof(uriBuf), uriBuf };

    ret = CmInstallUserTrustedCert(&userCertTemp, &edgeAlias, &uri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&uri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest012
 * @tc.desc: Test CertManager Install pem user cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest012, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf012[MAX_URI_LEN] = {0};
    struct CmBlob certUri = { sizeof(uriBuf012), uriBuf012 };

    struct CmBlob userCert012 = { strlen(g_certData06) + 1, reinterpret_cast<uint8_t *>(g_certData06) };
    struct CmBlob certAlias012 = { sizeof(certAliasBuf06), certAliasBuf06 };
    ret = CmInstallUserTrustedCert(&userCert012, &certAlias012, &certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest013
 * @tc.desc: Test CertManager Install user ca cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest013, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf013[MAX_URI_LEN] = {0};
    struct CmBlob certUri013 = { sizeof(uriBuf013), uriBuf013 };

    ret = CmInstallUserCACert(&userCert[0], &certAlias[0], TEST_USERID, true, &certUri013);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install user ca cert test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri013);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal uninstall user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest014
 * @tc.desc: Test CertManager Install user ca cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest014, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf014[MAX_URI_LEN] = {0};
    struct CmBlob certUri014 = { sizeof(uriBuf014), uriBuf014 };

    ret = CmInstallUserCACert(nullptr, &certAlias[0], TEST_USERID, true, &certUri014);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abnormal install user ca cert test failed, recode:" << ret;

    ret = CmInstallUserCACert(&userCert[0], nullptr, TEST_USERID, true, &certUri014);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abnormal install user ca cert test failed, recode:" << ret;

    ret = CmInstallUserCACert(&userCert[0], &certAlias[0], TEST_USERID, true, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abnormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest015
 * @tc.desc: Test CertManager Install user ca cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest015, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf015[MAX_URI_LEN] = {0};
    struct CmBlob certUri015 = { sizeof(uriBuf015), uriBuf015 };
    struct CmBlob userCertTemp = { sizeof(g_certData04),
        const_cast<uint8_t *>(g_certData04) }; /* invalid certData */

    ret = CmInstallUserCACert(&userCertTemp, &certAlias[0], TEST_USERID, true, &certUri015);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT) << "abnormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest016
 * @tc.desc: Test CertManager Install user ca cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest016, TestSize.Level0)
{
    int32_t ret;
    /* size is 66, include 1 byte: the terminator('\0') */
    uint8_t largeAliasBuf[] = "large-size-input-cert-alias-0000000000000000000000000000000000000";
    struct CmBlob largeAlias = { sizeof(largeAliasBuf), largeAliasBuf };
    uint8_t uriBuf016[MAX_URI_LEN] = {0};
    struct CmBlob certUri016 = { sizeof(uriBuf016), uriBuf016 };
    struct CmBlob userCertTemp = { sizeof(g_certData02), const_cast<uint8_t *>(g_certData02) };

    ret = CmInstallUserCACert(&userCertTemp, &largeAlias, TEST_USERID, true, &certUri016);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abnormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest017
 * @tc.desc: Test CertManager Install user ca cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest017, TestSize.Level0)
{
    int32_t ret;
    char errAliasBuf[] = "AliasNoEnd";
    struct CmBlob noEndAlias017 = { strlen(errAliasBuf), reinterpret_cast<uint8_t *>(errAliasBuf) };
    struct CmBlob userCertTemp = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    uint8_t uriBuf017[MAX_URI_LEN] = {0};
    struct CmBlob certUri016 = { sizeof(uriBuf017), uriBuf017 };

    ret = CmInstallUserCACert(&userCertTemp, &noEndAlias017, TEST_USERID, true, &certUri016);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abnormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest018
 * @tc.desc: Test CertManager Install user ca cert interface normal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest018, TestSize.Level0)
{
    int32_t ret;
    char edgeAliasBuf[] = "alias_length_is_48_000000000000000000000000000000000000000000000"; /* size is 64 */
    struct CmBlob edgeAlias018 = { strlen(edgeAliasBuf) + 1, reinterpret_cast<uint8_t *>(edgeAliasBuf) };
    uint8_t uriBuf[MAX_URI_LEN] = {0};
    struct CmBlob uri = { sizeof(uriBuf), uriBuf };
    struct CmBlob userCertTemp = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };

    ret = CmInstallUserCACert(&userCertTemp, &edgeAlias018, TEST_USERID, true, &uri);
    EXPECT_EQ(ret, CM_SUCCESS) << "normal install user ca cert test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&uri);
    EXPECT_EQ(ret, CM_SUCCESS) << "normal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest019
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest019, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf019[MAX_URI_LEN] = {0};
    struct CmBlob certUri19 = { sizeof(uriBuf019), nullptr };

    ret = CmInstallUserCACert(&userCert[0], &certAlias[0], TEST_USERID, true, &certUri19);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest020
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest020, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf020[MAX_URI_LEN] = {0};
    struct CmBlob certUri20 = { 0, uriBuf020 };

    ret = CmInstallUserCACert(&userCert[0], &certAlias[0], TEST_USERID, true, &certUri20);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest021
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest021, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf021[MAX_URI_LEN] = {0};
    struct CmBlob certUri21 = { sizeof(uriBuf021), uriBuf021 };

    struct CmBlob userCert021 = { sizeof(g_certData01), nullptr };

    ret = CmInstallUserCACert(&userCert021, &certAlias[0], TEST_USERID, true, &certUri21);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest022
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest022, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf022[MAX_URI_LEN] = {0};
    struct CmBlob certUri22 = { sizeof(uriBuf022), uriBuf022 };

    struct CmBlob userCert022 = { 0, const_cast<uint8_t *>(g_certData01) };

    ret = CmInstallUserCACert(&userCert022, &certAlias[0], TEST_USERID, true, &certUri22);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest023
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest023, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf023[MAX_URI_LEN] = {0};
    struct CmBlob certUri23 = { sizeof(uriBuf023), uriBuf023 };

    uint8_t userData[MAX_LEN_CERTIFICATE + 1] = { 0 };
    struct CmBlob userCert023 = { MAX_LEN_CERTIFICATE + 1, userData };

    ret = CmInstallUserCACert(&userCert023, &certAlias[0], TEST_USERID, true, &certUri23);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest024
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest024, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf024[MAX_URI_LEN] = {0};
    struct CmBlob certUri24 = { sizeof(uriBuf024), uriBuf024 };

    char aliasBuf[] = "alias-length";
    struct CmBlob alias024 = { strlen(aliasBuf) + 1, nullptr };

    ret = CmInstallUserCACert(&userCert[0], &alias024, TEST_USERID, true, &certUri24);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest025
 * @tc.desc: Test CertManager Install user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest025, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf025[MAX_URI_LEN] = {0};
    struct CmBlob certUri25 = { sizeof(uriBuf025), uriBuf025 };

    char aliasBuf[] = "alias-length";
    struct CmBlob alias025 = { 0, reinterpret_cast<uint8_t *>(aliasBuf) };

    ret = CmInstallUserCACert(&userCert[0], &alias025, TEST_USERID, true, &certUri25);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "abormal install user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest026
 * @tc.desc: Test CertManager Install user cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest026, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf026[MAX_URI_LEN] = {0};
    struct CmBlob certUri26 = { sizeof(uriBuf026), uriBuf026 };

    char aliasBuf[] = "";
    struct CmBlob alias026 = { strlen(aliasBuf) + 1, reinterpret_cast<uint8_t *>(aliasBuf) };

    ret = CmInstallUserCACert(&userCert[0], &alias026, TEST_USERID, true, &certUri26);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install user ca cert test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri26);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal uninstall user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest027
 * @tc.desc: Test CertManager Install user p7b cert interface  function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest027, TestSize.Level0)
{
    int32_t ret;
    struct CertUriList certUriList = { 0, nullptr };

    char aliasBuf[] = "";
    struct CmBlob alias027 = { strlen(aliasBuf) + 1, reinterpret_cast<uint8_t *>(aliasBuf) };

    struct CmInstallCertInfo installCertInfo = {
        .userCert = &g_p7bUserCert,
        .certAlias = &alias027,
        .userId = TEST_USERID
    };

    ret = CmInstallUserTrustedP7BCert(&installCertInfo, true, &certUriList);
    EXPECT_EQ(ret, CM_SUCCESS) << "install p7b user ca cert test failed, recode:" << ret;
    EXPECT_EQ(certUriList.certCount == 2, true) << "install p7b user ca cert test failed, certUriList.certCount != 2";
    CM_FREE_PTR(certUriList.uriList);
    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest028
 * @tc.desc: Test CertManager Install user p7b cert interface  function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest028, TestSize.Level0)
{
    int32_t ret;
    struct CertUriList certUriList = { 0, nullptr };

    char aliasBuf[] = "";
    struct CmBlob alias028 = { strlen(aliasBuf) + 1, reinterpret_cast<uint8_t *>(aliasBuf) };

    struct CmInstallCertInfo installCertInfo = {
        .userCert = &userCert[0],
        .certAlias = &alias028,
        .userId = TEST_USERID
    };

    ret = CmInstallUserTrustedP7BCert(&installCertInfo, true, &certUriList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT) << "install p7b user ca cert test failed, recode:" << ret;
    CM_FREE_PTR(certUriList.uriList);
}

/**
 * @tc.name: InstallUserCertTest029
 * @tc.desc: Test CertManager Install user p7b cert interface  function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest029, TestSize.Level0)
{
    int32_t ret;
    struct CertUriList certUriList = { 0, nullptr };

    char aliasBuf[] = "";
    struct CmBlob alias029 = { strlen(aliasBuf) + 1, reinterpret_cast<uint8_t *>(aliasBuf) };

    struct CmInstallCertInfo installCertInfo = {
        .userCert = &g_p7bUserCertTooLongSubj,
        .certAlias = &alias029,
        .userId = TEST_USERID
    };

    ret = CmInstallUserTrustedP7BCert(&installCertInfo, true, &certUriList);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL) << "install p7b user ca cert test failed, recode:" << ret;
    CM_FREE_PTR(certUriList.uriList);
    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest030
 * @tc.desc: Test CertManager Install user cert interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest030, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf0301[MAX_URI_LEN] = {0};
    struct CmBlob certUri301 = { sizeof(uriBuf0301), uriBuf0301 };

    char aliasBuf1[] = "test_alias";
    struct CmBlob alias0301 = { strlen(aliasBuf1) + 1, reinterpret_cast<uint8_t *>(aliasBuf1) };

    ret = CmInstallUserCACert(&userCert[0], &alias0301, TEST_USERID, true, &certUri301);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install user ca cert test failed, recode:" << ret;

    uint8_t uriBuf0302[MAX_URI_LEN] = {0};
    struct CmBlob certUri302 = { sizeof(uriBuf0302), uriBuf0302 };

    char aliasBuf2[] = "";
    struct CmBlob alias0302 = { strlen(aliasBuf2) + 1, reinterpret_cast<uint8_t *>(aliasBuf2) };

    ret = CmInstallUserCACert(&userCert[0], &alias0302, TEST_USERID, true, &certUri302);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install same user ca cert test failed, recode:" << ret;

    ret = strcmp((char *)uriBuf0301, (char *)uriBuf0302);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install same user ca test compare uri failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri301);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal uninstall same user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: InstallUserCertTest031
 * @tc.desc: Test CertManager Install user cert interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, InstallUserCertTest031, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf0311[MAX_URI_LEN] = {0};
    struct CmBlob certUri311 = { sizeof(uriBuf0311), uriBuf0311 };

    char aliasBuf[] = "test_alias";
    struct CmBlob alias031 = { strlen(aliasBuf) + 1, reinterpret_cast<uint8_t *>(aliasBuf) };

    ret = CmInstallUserCACert(&userCert[0], &alias031, TEST_USERID, true, &certUri311);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install user ca cert test failed, recode:" << ret;

    uint8_t uriBuf0312[MAX_URI_LEN] = {0};
    struct CmBlob certUri312 = { sizeof(uriBuf0312), uriBuf0312 };

    ret = CmInstallUserCACert(&userCert[0], &alias031, TEST_USERID, true, &certUri312);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install same user ca cert test failed, recode:" << ret;

    ret = strcmp((char *)uriBuf0311, (char *)uriBuf0312);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install same user ca test compare uri failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri311);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal uninstall same user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: UninstallUserCertTest001
 * @tc.desc: Test CertManager Uninstall user cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, UninstallUserCertTest001, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf005[] = "985c1f52";
    uint8_t uriBuf009[MAX_URI_LEN] = {0};
    struct CmBlob userCertTemp = { sizeof(g_certData02), const_cast<uint8_t *>(g_certData02) };
    struct CmBlob certAliasTemp = { sizeof(aliasBuf005), aliasBuf005 };
    struct CmBlob certUriTemp = { sizeof(uriBuf009), uriBuf009 };

    ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUriTemp);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUriTemp);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: UninstallUserCertTest002
 * @tc.desc: Test CertManager Uninstall user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, UninstallUserCertTest002, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf006[] = "40dc992e";
    uint8_t uriBuf010[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    struct CmBlob certAliasTemp = { sizeof(aliasBuf006), aliasBuf006 };
    struct CmBlob certUriTemp = { sizeof(uriBuf010), uriBuf010 };

    ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUriTemp);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(nullptr); /* uri is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal user cert Uninstall test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUriTemp);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: UninstallUserCertTest003
 * @tc.desc: Test CertManager Uninstall user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, UninstallUserCertTest003, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf007[] = "985c1f52";
    uint8_t uriBuf011[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData02), const_cast<uint8_t *>(g_certData02) };
    struct CmBlob certAliasTemp = { sizeof(aliasBuf007), aliasBuf007 };
    struct CmBlob certUriTemp = { sizeof(uriBuf011), uriBuf011 };

    ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUriTemp);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    uint8_t errUriBuf[MAX_URI_LEN] = "*****"; /* error uri */
    struct CmBlob errUri = { sizeof(errUriBuf), errUriBuf };
    ret = CmUninstallUserTrustedCert(&errUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal user cert Uninstall test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUriTemp);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: UninstallUserCertTest004
 * @tc.desc: Test CertManager Uninstall user cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, UninstallUserCertTest004, TestSize.Level0)
{
    int32_t ret;
    char invalidUriBuf[] = "oh:t=c;o=NOEXIST;u=0;a=0"; /* cert of uri is not exist */
    struct CmBlob invalidUri = { strlen(invalidUriBuf) + 1, reinterpret_cast<uint8_t *>(invalidUriBuf) };

    ret = CmUninstallUserTrustedCert(&invalidUri);
    EXPECT_EQ(ret, CMR_ERROR_NOT_EXIST) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: UninstallUserCertTest005
 * @tc.desc: Test CertManager Uninstall user ca cert interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, UninstallUserCertTest005, TestSize.Level0)
{
    int32_t ret;
    uint8_t uriBuf[MAX_URI_LEN] = {0};
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };

    ret = CmInstallUserCACert(&userCert[0], &certAlias[0], TEST_USERID, true, &certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install user ca cert test failed, recode:" << ret;

    uint8_t errUriBuf[] = "oh:t=c;o=40dc992e;u=100;a=1";
    struct CmBlob errCertUri = { sizeof(errUriBuf), errUriBuf };
    ret = CmUninstallUserTrustedCert(&errCertUri);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal uninstall user ca cert test failed, recode:" << ret;

    ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "abormal uninstall user ca cert test failed, recode:" << ret;
}

/**
 * @tc.name: UninstallALLUserCertTest001
 * @tc.desc: Test CertManager uninstall all user cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, UninstallALLUserCertTest001, TestSize.Level0)
{
    int32_t ret;

    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf012[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf012), uriBuf012 };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: UninstallALLUserCertTest002
 * @tc.desc: Test CertManager uninstall all user cert interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, UninstallALLUserCertTest002, TestSize.Level0)
{
    int32_t ret;

    for (uint32_t time = 0; time < PERFORMACE_COUNT; time++) {
        uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
        for (uint32_t i = 0; i < size; i++) {
            uint8_t uriBuf013[MAX_URI_LEN] = {0};
            struct CmBlob certUriTemp = { sizeof(uriBuf013), uriBuf013 };
            ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUriTemp);
            EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
        }

        ret = CmUninstallAllUserTrustedCert();
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    }
}

/**
 * @tc.name: GetUserCertListTest001
 * @tc.desc: Test CertManager Get user cert list interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertListTest001, TestSize.Level0)
{
    int32_t ret;

    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf014[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf014), uriBuf014 };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    struct CertList *certList001 = nullptr;
    InitCertList(&certList001);
    ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, certList001);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;
    FreeCertList(certList001);

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: GetUserCertListTest002
 * @tc.desc: Test CertManager Get user cert list And check content interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertListTest002, TestSize.Level0)
{
    int32_t ret;
    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf015[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf015), uriBuf015 };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    struct CertList *certList002 = nullptr;
    InitCertList(&certList002);
    ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, certList002);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;

    uint32_t len = sizeof(g_certListExpectResult) / sizeof(g_certListExpectResult[0]);
    bool found = false;
    for (uint32_t i = 0; i < len; i++) {
        found = FindCertAbstract(&(g_certListExpectResult[i].certAbstract), certList002);
        EXPECT_EQ(found, g_certListExpectResult[i].bExpectResult) << DumpCertList(certList002);
    }
    FreeCertList(certList002);

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: GetUserCertListTest003
 * @tc.desc: Test CertManager Get user cert list interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertListTest003, TestSize.Level0)
{
    int32_t ret;

    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf016[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf016), uriBuf016 };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, nullptr); /* cList is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);

    struct CertList *certList003 = nullptr;
    InitCertList(&certList003);
    ret = CmGetUserCertList(100, certList003); /* invalid store 100 */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    FreeCertList(certList003);

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: GetUserCertListTest004
 * @tc.desc: Test CertManager Get user cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertListTest004, TestSize.Level0)
{
    int32_t ret;

    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf017[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf017), uriBuf017 };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    for (uint32_t times = 0; times < PERFORMACE_COUNT; ++times) {
        struct CertList *certList004 = nullptr;
        InitCertList(&certList004);
        ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, certList004);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;
        FreeCertList(certList004);
    }

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: GetUserCertListTest005
 * @tc.desc: Test CertManager Get user cert list interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertListTest005, TestSize.Level0)
{
    struct CertList *certList005 = nullptr;
    InitCertList(&certList005);
    int32_t ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, certList005); /* empty dir */
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;
    FreeCertList(certList005);
}

/**
 * @tc.name: GetUserCertInfoTest001
 * @tc.desc: Test CertManager Get user cert info interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertInfoTest001, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf008[] = "40dc992e";
    uint8_t uriBuf018[MAX_URI_LEN] = {0};

    struct CmBlob testUserCert = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    struct CmBlob testCertAlias = { sizeof(aliasBuf008), aliasBuf008 };
    struct CmBlob testCertUri = { sizeof(uriBuf018), uriBuf018 };

    ret = CmInstallUserTrustedCert(&testUserCert, &testCertAlias, &testCertUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    struct CertInfo *certInfo001 = nullptr;
    InitUserCertInfo(&certInfo001);
    ret = CmGetUserCertInfo(&testCertUri, CM_USER_TRUSTED_STORE, certInfo001);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert info test failed, recode:" << ret;

    EXPECT_EQ(CompareCertInfo(certInfo001, &(g_certInfoExpectResult[0].certInfo)), true) << DumpCertInfo(certInfo001);
    EXPECT_EQ(CompareCertData(&(certInfo001->certInfo), &(g_certInfoExpectResult[0].certInfo.certInfo)), true);
    FreeCertInfo(certInfo001);

    ret = CmUninstallUserTrustedCert(&testCertUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: GetUserCertInfoTest002
 * @tc.desc: Test CertManager Get user cert info interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertInfoTest002, TestSize.Level0)
{
    int32_t ret;

    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf019[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf019), uriBuf019 };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    struct CertList *certList006 = nullptr;
    InitCertList(&certList006);
    ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, certList006);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;

    uint32_t certCnt = sizeof(g_certInfoExpectResult) / sizeof(g_certInfoExpectResult[0]);
    bool found = false;
    for (uint32_t i = 0; i < certCnt; i++) {
        struct CertAbstract *ptr = &(g_certListExpectResult[i].certAbstract);
        ASSERT_TRUE(ptr != nullptr);
        found = FindCertAbstract(ptr, certList006);
        EXPECT_EQ(found, g_certListExpectResult[i].bExpectResult);

        struct CmBlob uriBlob = { strlen(ptr->uri) + 1, reinterpret_cast<uint8_t *>(ptr->uri) };
        struct CertInfo *certInfo002 = nullptr;
        InitUserCertInfo(&certInfo002);
        ret = CmGetUserCertInfo(&uriBlob, CM_USER_TRUSTED_STORE, certInfo002);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert info test failed, recode:" << ret;

        EXPECT_EQ(CompareCertInfo(certInfo002, &(g_certInfoExpectResult[i].certInfo)), true) <<
            DumpCertInfo(certInfo002);
        EXPECT_EQ(CompareCertData(&(certInfo002->certInfo), &(g_certInfoExpectResult[i].certInfo.certInfo)), true);
        FreeCertInfo(certInfo002);
    }
    FreeCertList(certList006);

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: GetUserCertInfoTest003
 * @tc.desc: Test CertManager Get user cert info interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertInfoTest003, TestSize.Level0)
{
    int32_t ret;
    struct CertInfo *certInfo003 = nullptr;
    InitUserCertInfo(&certInfo003);
    ret = CmGetUserCertInfo(nullptr, CM_USER_TRUSTED_STORE, certInfo003);  /* uri is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
    FreeCertInfo(certInfo003);
}

/**
 * @tc.name: GetUserCertInfoTest004
 * @tc.desc: Test CertManager Get user cert info interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertInfoTest004, TestSize.Level0)
{
    int32_t ret;
    char *uri = g_certInfoExpectResult[0].certInfo.uri;
    struct CmBlob certUri = { strlen(uri) + 1, reinterpret_cast<uint8_t *>(uri) };

    struct CertInfo *certInfo004 = nullptr;
    InitUserCertInfo(&certInfo004);
    ret = CmGetUserCertInfo(&certUri, 100, certInfo004);  /* invalid store 100 */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    FreeCertInfo(certInfo004);
}

/**
 * @tc.name: GetUserCertInfoTest005
 * @tc.desc: Test CertManager Get user cert info interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertInfoTest005, TestSize.Level0)
{
    int32_t ret;
    char *uri = g_certInfoExpectResult[1].certInfo.uri;
    struct CmBlob certUri = { strlen(uri) + 1, reinterpret_cast<uint8_t *>(uri) };

    ret = CmGetUserCertInfo(&certUri, CM_USER_TRUSTED_STORE, nullptr);  /* cInfo not malloc */
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
}

/**
 * @tc.name: GetUserCertInfoTest006
 * @tc.desc: Test CertManager Get user cert info interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertInfoTest006, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf009[] = "40dc992e";
    uint8_t uriBuf020[MAX_URI_LEN] = {0};

    struct CmBlob userCertTemp = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    struct CmBlob certAliasTemp = { sizeof(aliasBuf009), aliasBuf009 };
    struct CmBlob certUri = { sizeof(uriBuf020), uriBuf020 };

    for (uint32_t time = 0; time < PERFORMACE_COUNT; time++) {
        ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

        struct CertInfo *certInfo005 = nullptr;
        InitUserCertInfo(&certInfo005);
        ret = CmGetUserCertInfo(&certUri, CM_USER_TRUSTED_STORE, certInfo005);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert info test failed, recode:" << ret;

        EXPECT_EQ(CompareCertInfo(certInfo005, &(g_certInfoExpectResult[0].certInfo)), true) <<
            DumpCertInfo(certInfo005);
        EXPECT_EQ(CompareCertData(&(certInfo005->certInfo), &(g_certInfoExpectResult[0].certInfo.certInfo)), true);
        FreeCertInfo(certInfo005);

        ret = CmUninstallUserTrustedCert(&certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
    }
}

/**
 * @tc.name: GetUserCertInfoTest007
 * @tc.desc: Test SA Get user cert info interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, GetUserCertInfoTest007, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf013[] = "882de061";
    uint8_t uriBuf027[MAX_URI_LEN] = {0};

    struct CmBlob testUserCert = { sizeof(g_certData07), const_cast<uint8_t *>(g_certData07) };
    struct CmBlob testCertAlias = { sizeof(aliasBuf013), aliasBuf013 };
    struct CmBlob testCertUri = { sizeof(uriBuf027), uriBuf027};

    ret = CmInstallUserCACert(&testUserCert, &testCertAlias, TEST_USERID, true, &testCertUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "normal install user ca cert test failed, recode:" << ret;

    struct CertInfo *certInfo008 = nullptr;
    InitUserCertInfo(&certInfo008);
    ret = CmGetUserCertInfo(&testCertUri, CM_USER_TRUSTED_STORE, certInfo008);

    EXPECT_EQ(CompareCertInfo(certInfo008, &(g_userCertInfoExpectResult[0].certInfo)), true) <<
            DumpCertInfo(certInfo008);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert info test failed, recode:" << ret;
    EXPECT_EQ(CompareCertData(&(certInfo008->certInfo), &(g_userCertInfoExpectResult[0].certInfo.certInfo)), true);
    FreeCertInfo(certInfo008);

    ret = CmUninstallUserTrustedCert(&testCertUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: SetUserCertStatusTest001
 * @tc.desc: Test CertManager Set user cert status interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, SetUserCertStatusTest001, TestSize.Level0)
{
    int32_t ret;

    uint8_t aliasBuf010[] = "1df5a75f";
    uint8_t uriBuf021[MAX_URI_LEN] = {0};
    struct CmBlob userCertTemp = { sizeof(g_certData03), const_cast<uint8_t *>(g_certData03) };
    struct CmBlob certAliasTemp = { sizeof(aliasBuf010), aliasBuf010 };
    struct CmBlob certUri = { sizeof(uriBuf021), uriBuf021 };
    ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    char *uri = g_certStatusExpectResult[2].uri;
    struct CmBlob uriTemp = { strlen(uri) + 1, reinterpret_cast<uint8_t *>(uri) };
    ret = CmSetUserCertStatus(&uriTemp, CM_USER_TRUSTED_STORE, g_certStatusExpectResult[2].inparamStatus);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;

    ret = CmSetUserCertStatus(&uriTemp, CM_USER_TRUSTED_STORE, true);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;
    ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}

/**
 * @tc.name: SetUserCertStatusTest002
 * @tc.desc: Test CertManager set user cert status interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, SetUserCertStatusTest002, TestSize.Level0)
{
    int32_t ret;

    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf022[MAX_URI_LEN] = {0};
        struct CmBlob certUriTemp = { sizeof(uriBuf022), uriBuf022 };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUriTemp);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    uint32_t len = sizeof(g_certStatusExpectResult) / sizeof(g_certStatusExpectResult[0]);
    for (uint32_t i = 0; i < len; i++) {
        struct CmBlob certUri = { strlen(g_certStatusExpectResult[i].uri) + 1,
            reinterpret_cast<uint8_t *>(g_certStatusExpectResult[i].uri) };

        ret = CmSetUserCertStatus(&certUri, CM_USER_TRUSTED_STORE, g_certStatusExpectResult[i].inparamStatus);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;

        struct CertInfo *certInfo006 = nullptr;
        InitUserCertInfo(&certInfo006);
        ret = CmGetUserCertInfo(&certUri, CM_USER_TRUSTED_STORE, certInfo006);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert info test failed, recode:" << ret;

        int32_t status = (g_certStatusExpectResult[i].expectStatus == certInfo006->status) ? 1 : 0;
        EXPECT_EQ(status, 1) << "set user cert status test failed, cert info: " <<
            DumpCertInfo(certInfo006);
        FreeCertInfo(certInfo006);

        ret = CmSetUserCertStatus(&certUri, CM_USER_TRUSTED_STORE, true);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;
    }

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: SetUserCertStatusTest003
 * @tc.desc: Test CertManager Set user cert status interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, SetUserCertStatusTest003, TestSize.Level0)
{
    int32_t ret;

    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf023[MAX_URI_LEN] = {0};
        struct CmBlob certUriTemp = { sizeof(uriBuf023), uriBuf023 };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUriTemp);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    struct CertList *certList007 = nullptr;
    InitCertList(&certList007);
    ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, certList007);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;

    for (uint32_t i = 0; i < certList007->certsCount; ++i) {
        struct CertAbstract *ptr = &(certList007->certAbstract[i]);
        struct CmBlob uri01 = { strlen(ptr->uri) + 1, reinterpret_cast<uint8_t *>(ptr->uri) };
        ret = CmSetUserCertStatus(&uri01, CM_USER_TRUSTED_STORE, false);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;
    }

    for (uint32_t i = 0; i < certList007->certsCount; ++i) {
        struct CertAbstract *ptr = &(certList007->certAbstract[i]);
        struct CmBlob uri02 = { strlen(ptr->uri) + 1, reinterpret_cast<uint8_t *>(ptr->uri) };
        ret = CmSetUserCertStatus(&uri02, CM_USER_TRUSTED_STORE, true);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;
    }

    FreeCertList(certList007);
    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: SetUserCertStatusTest004
 * @tc.desc: Test CertManager set user cert status interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, SetUserCertStatusTest004, TestSize.Level0)
{
    int32_t ret;

    ret = CmSetUserCertStatus(nullptr, CM_USER_TRUSTED_STORE, true); /* uri is nullptr */
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER) << "Normal set user cert status test failed, recode:" << ret;
}

/**
 * @tc.name: SetUserCertStatusTest005
 * @tc.desc: Test CertManager set user cert status interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, SetUserCertStatusTest005, TestSize.Level0)
{
    int32_t ret;
    struct CmBlob certUri = { strlen(g_certStatusExpectResult[1].uri) + 1,
        reinterpret_cast<uint8_t *>(g_certStatusExpectResult[1].uri) };

    ret = CmSetUserCertStatus(&certUri, 100, true); /* invalid store */
    EXPECT_EQ(ret, CM_FAILURE) << "Normal set user cert status test failed, recode:" << ret;
}

/**
 * @tc.name: SetUserCertStatusTest006
 * @tc.desc: Test CertManager set user cert status interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, SetUserCertStatusTest006, TestSize.Level0)
{
    int32_t ret;
    uint8_t invalidUriBuf[] = "oh:t=c;o=abcdefg;u=0;a=00000000";
    struct CmBlob invalidCertUri = { sizeof(invalidUriBuf), invalidUriBuf };

    ret = CmSetUserCertStatus(&invalidCertUri, CM_USER_TRUSTED_STORE, true);
    EXPECT_EQ(ret, CM_FAILURE) << "Normal set user cert status test failed, recode:" << ret;
}

/**
 * @tc.name: SetUserCertStatusTest007
 * @tc.desc: Test CertManager update user cert AND set user cert status interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, SetUserCertStatusTest007, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf011[] = "40dc992e";
    uint8_t uriBuf024[MAX_URI_LEN] = {0};
    struct CmBlob userCertTemp = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    struct CmBlob certAliasTemp = { sizeof(aliasBuf011), aliasBuf011 };
    struct CmBlob certUri = { sizeof(uriBuf024), uriBuf024 };

    ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUri); /* install */
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    ret = CmSetUserCertStatus(&certUri, CM_USER_TRUSTED_STORE, false); /* set status false */
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;

    ret = CmInstallUserTrustedCert(&userCertTemp, &certAliasTemp, &certUri); /* update cert */
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    struct CertInfo *certInfo007 = nullptr;
    InitUserCertInfo(&certInfo007);
    ret = CmGetUserCertInfo(&certUri, CM_USER_TRUSTED_STORE, certInfo007);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert info test failed, recode:" << ret;

    EXPECT_EQ(true, certInfo007->status);

    FreeCertInfo(certInfo007);

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
}

/**
 * @tc.name: SetUserCertStatusTest008
 * @tc.desc: Test CertManager set user cert status interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmUserCertTest, SetUserCertStatusTest008, TestSize.Level0)
{
    int32_t ret;
    uint8_t aliasBuf012[] = "1df5a75f";
    uint8_t uriBuf025[MAX_URI_LEN] = {0};
    struct CmBlob userCert = { sizeof(g_certData03), const_cast<uint8_t *>(g_certData03) };
    struct CmBlob certAlias = { sizeof(aliasBuf012), aliasBuf012 };
    struct CmBlob certUri = { sizeof(uriBuf025), uriBuf025 };

    ret = CmInstallUserTrustedCert(&userCert, &certAlias, &certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;

    for (uint32_t time = 0; time < PERFORMACE_COUNT; time++) {
        ret = CmSetUserCertStatus(&certUri, CM_USER_TRUSTED_STORE, g_certStatusExpectResult[2].inparamStatus);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;

        ret = CmSetUserCertStatus(&certUri, CM_USER_TRUSTED_STORE, true);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal set user cert status test failed, recode:" << ret;
    }

    ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall test failed, recode:" << ret;
}
}
