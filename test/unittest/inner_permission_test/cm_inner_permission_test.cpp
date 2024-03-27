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

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static constexpr uint32_t SIGNATURE_SIZE = 1024;
class CmInnerPermissionTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmInnerPermissionTest::SetUpTestCase(void)
{
    const char **permission = new const char *[1]; // 1 permission
    permission[0] = "ohos.permission.ACCESS_CERT_MANAGER"; // normal
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .dcaps = nullptr,
        .perms = permission,
        .acls = nullptr,
        .processName = "TestCmInnerPermisson",
        .aplStr = "system_basic",
    };

    auto tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    delete[] permission;
}

void CmInnerPermissionTest::TearDownTestCase(void)
{
}

void CmInnerPermissionTest::SetUp()
{
}

void CmInnerPermissionTest::TearDown()
{
}

/**
* @tc.name: CmInnerPermissionTest001
* @tc.desc: test CmGetAppCertList
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest001, TestSize.Level0)
{
    struct CertList *certList = nullptr;
    int32_t ret = InitCertList(&certList);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, certList);
    EXPECT_EQ(ret, CM_SUCCESS);

    FreeCertList(certList);
}

/**
* @tc.name: CmInnerPermissionTest002
* @tc.desc: test CmGetCertInfo
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest002, TestSize.Level0)
{
    struct CertInfo info;
    (void)memset_s(&info, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));
    int32_t ret = InitCertInfo(&info);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t uriData[] = "b7a5b843.0";
    struct CmBlob uri = { sizeof(uriData), uriData };
    ret = CmGetCertInfo(&uri, CM_SYSTEM_TRUSTED_STORE, &info);
    EXPECT_EQ(ret, CM_SUCCESS);

    FreeCMBlobData(&info.certInfo);
}

/**
* @tc.name: CmInnerPermissionTest003
* @tc.desc: test CmSetCertStatus
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest003, TestSize.Level0)
{
    uint8_t uriData[] = "CmInnerPermissionTest003";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmSetCertStatus(&uri, CM_SYSTEM_TRUSTED_STORE, false);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest004
* @tc.desc: test CmInstallAppCert pub credential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest004, TestSize.Level0)
{
    uint8_t aliasData[] = "inner004";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest005
* @tc.desc: test CmUninstallAppCert pub credential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest005, TestSize.Level0)
{
    uint8_t uriData[] = "inner005";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmUninstallAppCert(&uri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest006
* @tc.desc: test CmUninstallAllAppCert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest006, TestSize.Level0)
{
    int32_t ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest007
* @tc.desc: test CmGetAppCertList pub
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest007, TestSize.Level0)
{
    struct CredentialAbstract abstract[MAX_COUNT_CERTIFICATE];
    (void)memset_s(abstract, sizeof(abstract), 0, sizeof(abstract));
    struct CredentialList certList = { MAX_COUNT_CERTIFICATE, abstract };
    int32_t ret = CmGetAppCertList(CM_CREDENTIAL_STORE, &certList);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest008
* @tc.desc: test CmGetAppCertList pri
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest008, TestSize.Level0)
{
    struct CredentialAbstract abstract[MAX_COUNT_CERTIFICATE];
    (void)memset_s(abstract, sizeof(abstract), 0, sizeof(abstract));
    struct CredentialList certList = { MAX_COUNT_CERTIFICATE, abstract };
    int32_t ret = CmGetAppCertList(CM_PRI_CREDENTIAL_STORE, &certList);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest009
* @tc.desc: test CmGetAppCert pub
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest009, TestSize.Level0)
{
    struct Credential cred;
    (void)memset_s(&cred, sizeof(struct Credential), 0, sizeof(struct Credential));
    cred.credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    cred.credData.data = static_cast<uint8_t *>(malloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(cred.credData.data != nullptr);

    uint8_t uriData[] = "oh:t=ak;o=inner009;u=0;a=0";
    struct CmBlob uri = { sizeof(uriData), uriData };

    int32_t ret = CmGetAppCert(&uri, CM_CREDENTIAL_STORE, &cred);
    EXPECT_NE(ret, CMR_ERROR_PERMISSION_DENIED);

    free(cred.credData.data);
}

/**
* @tc.name: CmInnerPermissionTest010
* @tc.desc: test CmGetUserCertList
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest010, TestSize.Level0)
{
    struct CertList *certList = nullptr;
    int32_t ret = InitCertList(&certList);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, certList);
    EXPECT_EQ(ret, CM_SUCCESS);

    FreeCertList(certList);
}

/**
* @tc.name: CmInnerPermissionTest011
* @tc.desc: test CmGetUserCertInfo
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest011, TestSize.Level0)
{
    struct CertInfo info;
    (void)memset_s(&info, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));
    int32_t ret = InitCertInfo(&info);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t uriData[] = "inner011";
    struct CmBlob uri = { sizeof(uriData), uriData };
    ret = CmGetUserCertInfo(&uri, CM_USER_TRUSTED_STORE, &info);
    EXPECT_NE(ret, CMR_ERROR_PERMISSION_DENIED);

    FreeCMBlobData(&info.certInfo);
}

/**
* @tc.name: CmInnerPermissionTest012
* @tc.desc: test CmSetUserCertStatus
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest012, TestSize.Level0)
{
    uint8_t uriData[] = "inner012";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmSetUserCertStatus(&uri, CM_USER_TRUSTED_STORE, false);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest013
* @tc.desc: test CmInstallUserTrustedCert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest013, TestSize.Level0)
{
    uint8_t certData[] = "inner013";
    struct CmBlob userCert = { sizeof(certData), certData };
    uint8_t aliasData[] = "inner013";
    struct CmBlob certAlias = { sizeof(aliasData), aliasData };
    uint8_t uriData[] = "inner013";
    struct CmBlob certUri = { sizeof(uriData), uriData };

    int32_t ret = CmInstallUserTrustedCert(&userCert, &certAlias, &certUri);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest014
* @tc.desc: test CmUninstallUserTrustedCert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest014, TestSize.Level0)
{
    uint8_t uriData[] = "inner014";
    struct CmBlob certUri = { sizeof(uriData), uriData };

    int32_t ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest015
* @tc.desc: test CmUninstallAllUserTrustedCert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest015, TestSize.Level0)
{
    int32_t ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest016
* @tc.desc: test CmGrantAppCertificate
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest016, TestSize.Level0)
{
    uint8_t uriData[] = "inner016";
    struct CmBlob uri = { sizeof(uriData), uriData };
    uint8_t authUriData[] = "inner016";
    struct CmBlob authUri = { sizeof(authUriData), authUriData };

    int32_t ret = CmGrantAppCertificate(&uri, 0, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest017
* @tc.desc: test CmGetAuthorizedAppList
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest017, TestSize.Level0)
{
    uint8_t uriData[] = "inner017";
    struct CmBlob uri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&uri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest018
* @tc.desc: test CmIsAuthorizedApp
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest018, TestSize.Level0)
{
    uint8_t uriData[] =
        "oh:t=ak;o=inner018;u=0;a=0?ca=0&m=BA632421B76F1059BC28184FB9E50D5795232B6D5C535E0DCAC0114A7AD8FAFE";
    struct CmBlob authUri = { sizeof(uriData), uriData };
    int32_t ret = CmIsAuthorizedApp(&authUri);
    EXPECT_EQ(ret, CMR_ERROR_AUTH_CHECK_FAILED);
}

/**
* @tc.name: CmInnerPermissionTest019
* @tc.desc: test CmRemoveGrantedApp
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest019, TestSize.Level0)
{
    uint8_t uriData[] = "inner019";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmRemoveGrantedApp(&uri, 0);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmInnerPermissionTest020
* @tc.desc: test pri app cert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInnerPermissionTest, CmInnerPermissionTest020, TestSize.Level0)
{
    /* install pri app cert */
    uint8_t aliasData[] = "inner020";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_PRI_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS);

    /* sign */
    uint8_t uriData[] = "oh:t=ak;o=inner020;u=0;a=0";
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(uint64_t), reinterpret_cast<uint8_t *>(&handleValue) };
    ret = CmInit(&keyUri, &spec, &handle);
    EXPECT_EQ(ret, CM_SUCCESS);

    uint8_t messageData[] = "this is message for private credential sign and verify";
    struct CmBlob message = { sizeof(messageData), (uint8_t *)messageData };
    ret = CmUpdate(&handle, &message);
    EXPECT_EQ(ret, CM_SUCCESS);

    uint8_t signData[SIGNATURE_SIZE] = {0};
    struct CmBlob signature = { SIGNATURE_SIZE, signData };
    struct CmBlob inDataFinish = { 0, nullptr };
    ret = CmFinish(&handle, &inDataFinish, &signature);
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmAbort(&handle);
    EXPECT_EQ(ret, CM_SUCCESS);

    /* verify */
    spec.purpose = CM_KEY_PURPOSE_VERIFY;
    ret = CmInit(&keyUri, &spec, &handle);
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmUpdate(&handle, &message);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmBlob outDataFinish = { 0, nullptr };
    ret = CmFinish(&handle, &signature, &outDataFinish);
    EXPECT_EQ(ret, CM_SUCCESS);

    /* get pri app cert */
    struct Credential cred;
    (void)memset_s(&cred, sizeof(struct Credential), 0, sizeof(struct Credential));
    cred.credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    cred.credData.data = static_cast<uint8_t *>(malloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(cred.credData.data != nullptr);
    ret = CmGetAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE, &cred);
    EXPECT_EQ(ret, CM_SUCCESS);
    free(cred.credData.data);

    /* uninstall pri app cert */
    ret = CmUninstallAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS);
}
} // end of namespace

