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
class CmCommonPermissionTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmCommonPermissionTest::SetUpTestCase(void)
{
}

void CmCommonPermissionTest::TearDownTestCase(void)
{
}

void CmCommonPermissionTest::SetUp()
{
}

void CmCommonPermissionTest::TearDown()
{
}

/**
* @tc.name: CmCommonPermissionTest001
* @tc.desc: test CmGetAppCertList
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest001, TestSize.Level0)
{
    struct CertList *certList = nullptr;
    int32_t ret = InitCertList(&certList);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, certList);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);

    FreeCertList(certList);
}

/**
* @tc.name: CmCommonPermissionTest002
* @tc.desc: test CmGetCertInfo
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest002, TestSize.Level0)
{
    struct CertInfo info;
    (void)memset_s(&info, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));
    int32_t ret = InitCertInfo(&info);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t uriData[] = "CmCommonPermissionTest002";
    struct CmBlob uri = { sizeof(uriData), uriData };
    ret = CmGetCertInfo(&uri, CM_SYSTEM_TRUSTED_STORE, &info);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);

    FreeCMBlobData(&info.certInfo);
}

/**
* @tc.name: CmCommonPermissionTest003
* @tc.desc: test CmSetCertStatus
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest003, TestSize.Level0)
{
    uint8_t uriData[] = "CmCommonPermissionTest003";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmSetCertStatus(&uri, CM_SYSTEM_TRUSTED_STORE, false);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest004
* @tc.desc: test CmInstallAppCert pub credential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest004, TestSize.Level0)
{
    uint8_t aliasData[] = "Common004";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest005
* @tc.desc: test CmInstallAppCert pri credential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest005, TestSize.Level0)
{
    uint8_t aliasData[] = "Common005";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_PRI_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest006
* @tc.desc: test CmUninstallAppCert pub credential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest006, TestSize.Level0)
{
    uint8_t uriData[] = "Common006";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmUninstallAppCert(&uri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest007
* @tc.desc: test CmUninstallAppCert pri credential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest007, TestSize.Level0)
{
    uint8_t uriData[] = "Common007";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmUninstallAppCert(&uri, CM_PRI_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest008
* @tc.desc: test CmUninstallAllAppCert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest008, TestSize.Level0)
{
    int32_t ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest009
* @tc.desc: test CmGetAppCertList pub
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest009, TestSize.Level0)
{
    struct CredentialAbstract abstract[MAX_COUNT_CERTIFICATE];
    (void)memset_s(abstract, sizeof(abstract), 0, sizeof(abstract));
    struct CredentialList certList = { MAX_COUNT_CERTIFICATE, abstract };
    int32_t ret = CmGetAppCertList(CM_CREDENTIAL_STORE, &certList);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest010
* @tc.desc: test CmGetAppCertList pri
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest010, TestSize.Level0)
{
    struct CredentialAbstract abstract[MAX_COUNT_CERTIFICATE];
    (void)memset_s(abstract, sizeof(abstract), 0, sizeof(abstract));
    struct CredentialList certList = { MAX_COUNT_CERTIFICATE, abstract };
    int32_t ret = CmGetAppCertList(CM_PRI_CREDENTIAL_STORE, &certList);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest011
* @tc.desc: test CmGetAppCert pub
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest011, TestSize.Level0)
{
    struct Credential cred;
    (void)memset_s(&cred, sizeof(struct Credential), 0, sizeof(struct Credential));
    cred.credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    cred.credData.data = static_cast<uint8_t *>(malloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(cred.credData.data != nullptr);

    uint8_t uriData[] = "Common011";
    struct CmBlob uri = { sizeof(uriData), uriData };

    int32_t ret = CmGetAppCert(&uri, CM_CREDENTIAL_STORE, &cred);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);

    free(cred.credData.data);
}

/**
* @tc.name: CmCommonPermissionTest012
* @tc.desc: test CmGetAppCert pri
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest012, TestSize.Level0)
{
    struct Credential cred;
    (void)memset_s(&cred, sizeof(struct Credential), 0, sizeof(struct Credential));
    cred.credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    cred.credData.data = static_cast<uint8_t *>(malloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(cred.credData.data != nullptr);

    uint8_t uriData[] = "Common012";
    struct CmBlob uri = { sizeof(uriData), uriData };

    int32_t ret = CmGetAppCert(&uri, CM_PRI_CREDENTIAL_STORE, &cred);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);

    free(cred.credData.data);
}

/**
* @tc.name: CmCommonPermissionTest013
* @tc.desc: test CmGetUserCertList
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest013, TestSize.Level0)
{
    struct CertList *certList = nullptr;
    int32_t ret = InitCertList(&certList);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmGetUserCertList(CM_USER_TRUSTED_STORE, certList);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);

    FreeCertList(certList);
}

/**
* @tc.name: CmCommonPermissionTest014
* @tc.desc: test CmGetUserCertInfo
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest014, TestSize.Level0)
{
    struct CertInfo info;
    (void)memset_s(&info, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));
    int32_t ret = InitCertInfo(&info);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t uriData[] = "Common014";
    struct CmBlob uri = { sizeof(uriData), uriData };
    ret = CmGetUserCertInfo(&uri, CM_USER_TRUSTED_STORE, &info);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);

    FreeCMBlobData(&info.certInfo);
}

/**
* @tc.name: CmCommonPermissionTest015
* @tc.desc: test CmSetUserCertStatus
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest015, TestSize.Level0)
{
    uint8_t uriData[] = "common015";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmSetUserCertStatus(&uri, CM_USER_TRUSTED_STORE, false);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest016
* @tc.desc: test CmInstallUserTrustedCert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest016, TestSize.Level0)
{
    uint8_t certData[] = "common016";
    struct CmBlob userCert = { sizeof(certData), certData };
    uint8_t aliasData[] = "common016";
    struct CmBlob certAlias = { sizeof(aliasData), aliasData };
    uint8_t uriData[] = "common016";
    struct CmBlob certUri = { sizeof(uriData), uriData };

    int32_t ret = CmInstallUserTrustedCert(&userCert, &certAlias, &certUri);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest017
* @tc.desc: test CmUninstallUserTrustedCert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest017, TestSize.Level0)
{
    uint8_t uriData[] = "common017";
    struct CmBlob certUri = { sizeof(uriData), uriData };

    int32_t ret = CmUninstallUserTrustedCert(&certUri);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest018
* @tc.desc: test CmUninstallAllUserTrustedCert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest018, TestSize.Level0)
{
    int32_t ret = CmUninstallAllUserTrustedCert();
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest019
* @tc.desc: test CmGrantAppCertificate
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest019, TestSize.Level0)
{
    uint8_t uriData[] = "common019";
    struct CmBlob uri = { sizeof(uriData), uriData };
    uint8_t authUriData[] = "common019";
    struct CmBlob authUri = { sizeof(authUriData), authUriData };

    int32_t ret = CmGrantAppCertificate(&uri, 0, &authUri);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest020
* @tc.desc: test CmGetAuthorizedAppList
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest020, TestSize.Level0)
{
    uint8_t uriData[] = "common019";
    struct CmBlob uri = { sizeof(uriData), uriData };
    struct CmAppUidList appUidList = { 0, nullptr };
    int32_t ret = CmGetAuthorizedAppList(&uri, &appUidList);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest021
* @tc.desc: test CmIsAuthorizedApp
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest021, TestSize.Level0)
{
    uint8_t uriData[] = "common020";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmIsAuthorizedApp(&uri);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest022
* @tc.desc: test CmRemoveGrantedApp
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest022, TestSize.Level0)
{
    uint8_t uriData[] = "common021";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmRemoveGrantedApp(&uri, 0);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest023
* @tc.desc: test init
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest023, TestSize.Level0)
{
    uint8_t uriData[] = "common023";
    struct CmBlob authUri = { sizeof(uriData), uriData };
    uint8_t handleValue[] = "common023";
    struct CmBlob handle = { sizeof(handleValue), handleValue };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_NONE, CM_DIGEST_SHA256 };

    int32_t ret = CmInit(&authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest024
* @tc.desc: test update
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest024, TestSize.Level0)
{
    uint8_t handleValue[] = "common024";
    struct CmBlob handle = { sizeof(handleValue), handleValue };
    uint8_t inDataBuf[] = "common024";
    struct CmBlob inData = { sizeof(inDataBuf), inDataBuf };

    int32_t ret = CmUpdate(&handle, &inData);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest025
* @tc.desc: test finish
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest025, TestSize.Level0)
{
    uint8_t handleValue[] = "common025";
    struct CmBlob handle = { sizeof(handleValue), handleValue };
    uint8_t inDataBuf[] = "common025";
    struct CmBlob inData = { sizeof(inDataBuf), inDataBuf };
    uint8_t outDataBuf[] = "common025";
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    int32_t ret = CmFinish(&handle, &inData, &outData);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest026
* @tc.desc: test abort
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest026, TestSize.Level0)
{
    uint8_t handleValue[] = "common026";
    struct CmBlob handle = { sizeof(handleValue), handleValue };
    int32_t ret = CmAbort(&handle);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest027
* @tc.desc: test CmInstallAppCert sys credential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest027, TestSize.Level0)
{
    uint8_t aliasData[] = "Common027";
    struct CmBlob alias = { sizeof(aliasData), aliasData };
    int32_t ret = TestGenerateAppCert(&alias, CERT_KEY_ALG_RSA, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest028
* @tc.desc: test CmUninstallAppCert sys credential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest028, TestSize.Level0)
{
    uint8_t uriData[] = "Common028";
    struct CmBlob uri = { sizeof(uriData), uriData };
    int32_t ret = CmUninstallAppCert(&uri, CM_SYS_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);
}

/**
* @tc.name: CmCommonPermissionTest029
* @tc.desc: test CmGetAppCertList sys
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest029, TestSize.Level0)
{
    struct CredentialAbstract abstract[MAX_COUNT_CERTIFICATE];
    (void)memset_s(abstract, sizeof(abstract), 0, sizeof(abstract));
    struct CredentialList certList = { MAX_COUNT_CERTIFICATE, abstract };
    int32_t ret = CmGetAppCertList(CM_SYS_CREDENTIAL_STORE, &certList);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmCommonPermissionTest030
* @tc.desc: test CmGetAppCert sys
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCommonPermissionTest, CmCommonPermissionTest030, TestSize.Level0)
{
    struct Credential cred;
    (void)memset_s(&cred, sizeof(struct Credential), 0, sizeof(struct Credential));
    cred.credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    cred.credData.data = static_cast<uint8_t *>(malloc(MAX_LEN_CERTIFICATE_CHAIN));
    ASSERT_TRUE(cred.credData.data != nullptr);

    uint8_t uriData[] = "Common030";
    struct CmBlob uri = { sizeof(uriData), uriData };

    int32_t ret = CmGetAppCert(&uri, CM_SYS_CREDENTIAL_STORE, &cred);
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED);

    free(cred.credData.data);
}
} // end of namespace

