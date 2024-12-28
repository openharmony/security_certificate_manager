/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_cert_data_user.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
constexpr uint32_t MAX_URI_LEN = 256;
constexpr uint32_t ERROR_SCOPE = 3;

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

struct CmBlob certAlias[] = {
    { sizeof(certAliasBuf01), certAliasBuf01 },
    { sizeof(certAliasBuf02), certAliasBuf02 },
    { sizeof(certAliasBuf03), certAliasBuf03 },
    { sizeof(certAliasBuf05), certAliasBuf05 }
};

class CmGetUserCertListTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();

    struct CertList *lstCert;
};

void CmGetUserCertListTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmGetUserCertListTest::TearDownTestCase(void)
{
}

void CmGetUserCertListTest::SetUp()
{
    InitCertList(&lstCert);
}

void CmGetUserCertListTest::TearDown()
{
    FreeCertList(lstCert);
}

/* installation in the directory with userid 0 */
static uint32_t CmInstallTestCert()
{
    int32_t ret;
    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);

    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
        ret = CmInstallUserTrustedCert(&userCert[i], &certAlias[i], &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }

    return ret;
}

/* installation in any userid directory  */
static uint32_t CmInstallCATestCert(uint32_t userId)
{
    int32_t ret;
    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);

    for (uint32_t i = 0; i < size; i++) {
        uint8_t uriBuf[MAX_URI_LEN] = {0};
        struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
        ret = CmInstallUserCACert(&userCert[i], &certAlias[i], userId, true, &certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user CA cert Install test failed, recode:" << ret;
    }

    return ret;
}

/* install the maximum limit certs in userid 0 */
static uint32_t CmInstallBorderTestCert()
{
    int32_t ret;
    struct CmBlob userCertTest = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };

    for (uint32_t i = 0; i < MAX_COUNT_CERTIFICATE; i++) { /* install 256 times user cert */
        std::string alias = "alias_global_" + std::to_string(i);
        char *aliasBuf = const_cast<char *>(alias.c_str());
        struct CmBlob certAliasTest = { alias.length() + 1, reinterpret_cast<uint8_t *>(aliasBuf) };

        uint8_t uriBuf[MAX_URI_LEN] = {0};
        struct CmBlob certUriTest = { sizeof(uriBuf), uriBuf };

        ret =  CmInstallUserTrustedCert(&userCertTest, &certAliasTest, &certUriTest);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Install test failed, recode:" << ret;
    }
    return ret;
}

/* install the maximum limit certs in any directory */
static uint32_t CmInstallCABorderTestCert(uint32_t userId)
{
    int32_t ret;
    struct CmBlob userCertTest = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };

    for (uint32_t i = 0; i < MAX_COUNT_CERTIFICATE; i++) { /* install 256 times user cert */
        std::string alias = "alias_user_" + std::to_string(i);
        char *aliasBuf = const_cast<char *>(alias.c_str());
        struct CmBlob certAliasTest = { alias.length() + 1, reinterpret_cast<uint8_t *>(aliasBuf) };

        uint8_t uriBuf[MAX_URI_LEN] = {0};
        struct CmBlob certUriTest = { sizeof(uriBuf), uriBuf };

        ret = CmInstallUserCACert(&userCertTest, &certAliasTest, userId, true, &certUriTest);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal user CA cert Install test failed, recode:" << ret;
    }
    return ret;
}

/* uninstall the maximum limit certs in any directory */
static uint32_t CmUninstallCACertList(struct CertList *certList)
{
    int32_t ret;

    for (uint32_t i = 0; i < certList->certsCount; i++) {
        const struct CmBlob certUri = {
            .size = strlen(certList->certAbstract[i].uri) + 1,
            .data = reinterpret_cast<uint8_t *>(certList->certAbstract[i].uri)
        };
        ret = CmUninstallUserTrustedCert(&certUri);
        EXPECT_EQ(ret, CM_SUCCESS) << "Normal Uninstall trusted cert test failed, recode:" << ret;
    }
    return ret;
}

/* Initialize the minimum space */
static int32_t InitSmallCertList(struct CertList **cList)
{
    *cList = static_cast<struct CertList *>(CmMalloc(sizeof(struct CertList)));
    if (*cList == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }

    uint32_t buffSize = sizeof(struct CertAbstract);
    (*cList)->certAbstract = static_cast<struct CertAbstract *>(CmMalloc(buffSize));
    if ((*cList)->certAbstract == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s((*cList)->certAbstract, buffSize, 0, buffSize);
    (*cList)->certsCount = 1;

    return CM_SUCCESS;
}

/* If there is a failed use case, run the command to uninstall all certificates */
// /**
//  * @tc.name: CmUninstallAllUserCACert001
//  * @tc.desc: Test CertManager Get target user cert list interface performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmUninstallAllUserCACert001, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList001 = nullptr;
    InitCertList(&certList001);
    struct CertList *certList002 = nullptr;
    InitCertList(&certList002);

    struct UserCAProperty prop = { TEST_USERID, CM_CURRENT_USER };
    ret = CmGetUserCACertList(&prop, certList001);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;
    prop = { SA_USERID, CM_CURRENT_USER };
    ret = CmGetUserCACertList(&prop, certList002);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    ret = CmUninstallCACertList(certList001);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal uninstall CA cert list failed, recode:" << ret;
    ret = CmUninstallCACertList(certList002);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal uninstall CA cert list failed, recode:" << ret;
    FreeCertList(certList001);
    FreeCertList(certList002);
}

/**
 * @tc.name: CmGetUserCACertList001
 * @tc.desc: Test CertManager Get target user cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList001, TestSize.Level0)
{
    int32_t ret;
    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);

    ret = CmInstallTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Install test cert failed, recode:" << ret;

    struct CertList *certList001 = nullptr;
    InitCertList(&certList001);
    struct UserCAProperty prop = { SA_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList001);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;

    uint32_t certsCount001 = certList001->certsCount;
    EXPECT_EQ(certsCount001, size) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList001);
}

/**
 * @tc.name: CmGetUserCACertList002
 * @tc.desc: Test CertManager Get target user cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList002, TestSize.Level0)
{
    int32_t ret;
    int32_t size = sizeof(certAlias) / sizeof(certAlias[0]);

    ret = CmInstallTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Install test cert failed, recode:" << ret;

    struct CertList *certList002 = nullptr;
    InitCertList(&certList002);
    struct UserCAProperty prop = { SA_USERID, CM_CURRENT_USER };
    ret = CmGetUserCACertList(&prop, certList002);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;

    uint32_t certsCount002 = certList002->certsCount;
    EXPECT_EQ(certsCount002, size) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList002);
}

/**
 * @tc.name: CmGetUserCACertList003
 * @tc.desc: Test CertManager Get target user cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList003, TestSize.Level0)
{
    int32_t ret;
    int32_t size = sizeof(certAlias) / sizeof(certAlias[0]);

    ret = CmInstallTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Install test cert failed, recode:" << ret;

    struct CertList *certList003 = nullptr;
    InitCertList(&certList003);
    struct UserCAProperty prop = { SA_USERID, CM_GLOBAL_USER };
    ret = CmGetUserCACertList(&prop, certList003);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;

    uint32_t certsCount003 = certList003->certsCount;
    EXPECT_EQ(certsCount003, size) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList003);
}

/**
 * @tc.name: CmGetUserCACertList004
 * @tc.desc: Test CertManager Get target user cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList004, TestSize.Level0)
{
    int32_t ret;
    int32_t size = sizeof(certAlias) / sizeof(certAlias[0]);

    ret = CmInstallTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Install test cert failed, recode:" << ret;

    struct CertList *certList004 = nullptr;
    InitCertList(&certList004);
    struct UserCAProperty prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList004);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;

    uint32_t certsCount004 = certList004->certsCount;
    EXPECT_EQ(certsCount004, size) << "Get certs count wrong, recode:" << ret;


    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList004);
}

/**
 * @tc.name: CmGetUserCACertList005
 * @tc.desc: Test CertManager Get target user cert list interface performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList005, TestSize.Level0)
{
    int32_t ret;
    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);

    ret = CmInstallCATestCert(TEST_USERID);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install CA test cert failed, recode:" << ret;

    struct CertList *certList005 = nullptr;
    InitCertList(&certList005);
    struct UserCAProperty prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList005);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user cert list test failed, recode:" << ret;

    uint32_t certsCount005 = certList005->certsCount;
    EXPECT_EQ(certsCount005, size) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallCACertList(certList005);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal uninstall CA cert list failed, recode:" << ret;
    FreeCertList(certList005);
}

// /**
//  * @tc.name: CmGetUserCACertList006
//  * @tc.desc: Test CertManager Get target user cert list interface performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList006, TestSize.Level0)
{
    int32_t ret;
    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);

    ret = CmInstallTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install test cert failed, recode:" << ret;
    ret = CmInstallCATestCert(TEST_USERID);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install CA test cert failed, recode:" << ret;

    struct CertList *certList006 = nullptr;
    InitCertList(&certList006);
    struct CertList *certList007 = nullptr;
    InitCertList(&certList007);
    struct UserCAProperty prop = { SA_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList006);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount006 = certList006->certsCount;
    EXPECT_EQ(certsCount006, size) << "Get certs count wrong, recode:" << ret;

    prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList007);

    CmUninstallCACertList(certList007);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall CA test cert failed, recode:" << ret;
    FreeCertList(certList006);
    FreeCertList(certList007);
}

// /**
//  * @tc.name: CmGetUserCACertList007
//  * @tc.desc: Test CertManager Get target user cert list interface performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList007, TestSize.Level0)
{
    int32_t ret;
    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]) * 2;

    ret = CmInstallTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install test cert failed, recode:" << ret;
    ret = CmInstallCATestCert(TEST_USERID);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install CA test cert failed, recode:" << ret;

    struct CertList *certList007 = nullptr;
    InitCertList(&certList007);
    struct UserCAProperty prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList007);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount007 = certList007->certsCount;
    EXPECT_EQ(certsCount007, size) << "Get certs count wrong, recode:" << ret;

    CmUninstallCACertList(certList007);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall CA test cert failed, recode:" << ret;
    FreeCertList(certList007);
}

/**
 * @tc.name: CmGetUserCACertList008
 * @tc.desc: Test CertManager Get target user cert list interface Abnormal performance
 * @tc.type: FUNC
 * @tc.require: AR000H0MJ8 /SR000H09N7
 */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList008, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList008 = nullptr;
    InitCertList(&certList008);

    struct UserCAProperty prop = { SA_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList008);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount008 = certList008->certsCount;
    EXPECT_EQ(certsCount008, 0) << "Get certs count wrong, recode:" << ret;
    FreeCertList(certList008);
}

// /**
//  * @tc.name: CmGetUserCACertList009
//  * @tc.desc: Test CertManager Get target user cert list interface Abnormal performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList009, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList009 = nullptr;
    InitCertList(&certList009);

    struct UserCAProperty prop = { SA_USERID, CM_CURRENT_USER };
    ret = CmGetUserCACertList(&prop, certList009);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount009 = certList009->certsCount;
    EXPECT_EQ(certsCount009, 0) << "Get certs count wrong, recode:" << ret;
    FreeCertList(certList009);
}


// /**
//  * @tc.name: CmGetUserCACertList010
//  * @tc.desc: Test CertManager Get target user cert list interface Abnormal performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList010, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList010 = nullptr;
    InitCertList(&certList010);

    struct UserCAProperty prop = { SA_USERID, CM_GLOBAL_USER };
    ret = CmGetUserCACertList(&prop, certList010);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount010 = certList010->certsCount;
    EXPECT_EQ(certsCount010, 0) << "Get certs count wrong, recode:" << ret;
    FreeCertList(certList010);
}

// /**
//  * @tc.name: CmGetUserCACertList011
//  * @tc.desc: Test CertManager Get target user cert list interface Abnormal performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList011, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList011 = nullptr;
    InitCertList(&certList011);

    struct UserCAProperty prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList011);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount011 = certList011->certsCount;
    EXPECT_EQ(certsCount011, 0) << "Get certs count wrong, recode:" << ret;
    FreeCertList(certList011);
}

// /**
//  * @tc.name: CmGetUserCACertList012
//  * @tc.desc: Test CertManager Get target user cert list interface boundary performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7s
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList012, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList012 = nullptr;
    InitCertList(&certList012);

    ret = CmInstallBorderTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border test cert failed, recode:" << ret;

    struct UserCAProperty prop = { SA_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList012);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount012 = certList012->certsCount;
    EXPECT_EQ(certsCount012, MAX_COUNT_CERTIFICATE) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList012);
}

// /**
//  * @tc.name: CmGetUserCACertList013
//  * @tc.desc: Test CertManager Get target user cert list interface boundary performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7s
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList013, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList013 = nullptr;
    InitCertList(&certList013);

    ret = CmInstallBorderTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border test cert failed, recode:" << ret;

    struct UserCAProperty prop = { SA_USERID, CM_CURRENT_USER };
    ret = CmGetUserCACertList(&prop, certList013);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount013 = certList013->certsCount;
    EXPECT_EQ(certsCount013, MAX_COUNT_CERTIFICATE) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList013);
}

// /**
//  * @tc.name: CmGetUserCACertList014
//  * @tc.desc: Test CertManager Get target user cert list interface boundary performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList014, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList014 = nullptr;
    InitCertList(&certList014);

    ret = CmInstallBorderTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border test cert failed, recode:" << ret;

    struct UserCAProperty prop = { SA_USERID, CM_GLOBAL_USER };
    ret = CmGetUserCACertList(&prop, certList014);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount014 = certList014->certsCount;
    EXPECT_EQ(certsCount014, MAX_COUNT_CERTIFICATE) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList014);
}

// /**
//  * @tc.name: CmGetUserCACertList015
//  * @tc.desc: Test CertManager Get target user cert list interface boundary performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList015, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList015 = nullptr;
    InitCertList(&certList015);

    ret = CmInstallBorderTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border test cert failed, recode:" << ret;

    struct UserCAProperty prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList015);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount015 = certList015->certsCount;
    EXPECT_EQ(certsCount015, MAX_COUNT_CERTIFICATE) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList015);
}

// /**
//  * @tc.name: CmGetUserCACertList016
//  * @tc.desc: Test CertManager Get target user cert list interface boundary performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList016, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList016 = nullptr;
    InitCertList(&certList016);

    ret = CmInstallCABorderTestCert(TEST_USERID);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border CA test cert failed, recode:" << ret;

    struct UserCAProperty prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList016);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount016 = certList016->certsCount;
    EXPECT_EQ(certsCount016, MAX_COUNT_CERTIFICATE) << "Get certs count wrong, recode:" << ret;

    CmUninstallCACertList(certList016);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall CA test cert failed, recode:" << ret;
    FreeCertList(certList016);
}

// /**
//  * @tc.name: CmGetUserCACertList017
//  * @tc.desc: Test CertManager Get target user cert list interface boundary performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList017, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList017 = nullptr;
    InitCertList(&certList017);
    struct CertList *certList018 = nullptr;
    InitCertList(&certList018);

    ret = CmInstallBorderTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border test cert failed, recode:" << ret;
    ret = CmInstallCABorderTestCert(TEST_USERID);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border CA test cert failed, recode:" << ret;

    struct UserCAProperty prop = { SA_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList017);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;
    /* Make sure that the certificate can be completely unmounted */
    prop = { TEST_USERID, CM_CURRENT_USER };
    ret = CmGetUserCACertList(&prop, certList018);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount017 = certList017->certsCount;
    EXPECT_EQ(certsCount017, MAX_COUNT_CERTIFICATE) << "Get certs count wrong, recode:" << ret;
    uint32_t certsCountBak = certList018->certsCount;
    EXPECT_EQ(certsCountBak, MAX_COUNT_CERTIFICATE) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    ret = CmUninstallCACertList(certList018);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall CA test cert failed, recode:" << ret;

    FreeCertList(certList017);
    FreeCertList(certList018);
}

// /**
//  * @tc.name: CmGetUserCACertList018
//  * @tc.desc: Test CertManager Get target user cert list interface boundary performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList018, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList018 = nullptr;
    InitCertList(&certList018);

    ret = CmInstallBorderTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border test cert failed, recode:" << ret;
    ret = CmInstallCABorderTestCert(TEST_USERID);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install border CA test cert failed, recode:" << ret;

    struct UserCAProperty prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList018);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;

    uint32_t certsCount018 = certList018->certsCount;
    EXPECT_EQ(certsCount018, MAX_COUNT_CERTIFICATE_ALL) << "Get certs count wrong, recode:" << ret;

    ret = CmUninstallCACertList(certList018);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall CA test cert failed, recode:" << ret;

    FreeCertList(certList018);
}

// /**
//  * @tc.name: CmGetUserCACertList019
//  * @tc.desc: Test CertManager Get target user cert list interface Abnormal performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList019, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList019 = nullptr;
    InitCertList(&certList019);

    ret = CmGetUserCACertList(nullptr, certList019);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER) << "Normal get user ca cert list test failed, recode:" << ret;
    FreeCertList(certList019);
}

// /**
//  * @tc.name: CmGetUserCACertList020
//  * @tc.desc: Test CertManager Get target user cert list interface Abnormal performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList020, TestSize.Level0)
{
    int32_t ret;

    struct UserCAProperty prop = { SA_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER) << "Normal get user ca cert list test failed, recode:" << ret;
}

// /**
//  * @tc.name: CmGetUserCACertList021
//  * @tc.desc: Test CertManager Get target user cert list interface Abnormal performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList021, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList021 = nullptr;
    InitCertList(&certList021);

    struct UserCAProperty prop = { SA_USERID, static_cast<CmCertScope>(ERROR_SCOPE) };
    ret = CmGetUserCACertList(&prop, certList021);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "Normal get user ca cert list test failed, recode:" << ret;
    FreeCertList(certList021);
}

// /**
//  * @tc.name: CmGetUserCACertList022
//  * @tc.desc: Test CertManager Get target user cert list interface performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList022, TestSize.Level0)
{
    int32_t ret;
    struct CertList *certList022 = nullptr;
    InitSmallCertList(&certList022);

    ret = CmInstallTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Install test cert failed, recode:" << ret;

    struct UserCAProperty prop = { SA_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList022);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL) << "Normal get user ca cert list test failed, recode:" << ret;

    ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal user cert Uninstall All test failed, recode:" << ret;
    FreeCertList(certList022);
}

// /**
//  * @tc.name: CmGetUserCACertList023
//  * @tc.desc: Test CertManager Get target user cert list interface performance
//  * @tc.type: FUNC
//  * @tc.require: AR000H0MJ8 /SR000H09N7
//  */
HWTEST_F(CmGetUserCertListTest, CmGetUserCACertList023, TestSize.Level0)
{
    int32_t ret;
    uint32_t size = sizeof(certAlias) / sizeof(certAlias[0]);
    struct CertList *certList023 = nullptr;
    InitCertList(&certList023);
    struct CertList *certList024 = nullptr;
    InitCertList(&certList024);

    ret = CmInstallTestCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "Install test cert failed, recode:" << ret;
    ret = CmInstallCATestCert(TEST_USERID);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal install CA test cert failed, recode:" << ret;

    struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList023);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;
    uint32_t certsCount = certList023->certsCount;
    EXPECT_EQ(certsCount, size) << "Get certs count wrong, recode:" << ret;

    prop = { TEST_USERID, CM_ALL_USER };
    ret = CmGetUserCACertList(&prop, certList024);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal get user ca cert list test failed, recode:" << ret;
    ret = CmUninstallCACertList(certList024);
    EXPECT_EQ(ret, CM_SUCCESS) << "Normal uninstall CA cert list failed, recode:" << ret;
    FreeCertList(certList023);
    FreeCertList(certList024);
}
}