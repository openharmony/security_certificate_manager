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

#include "cm_log.h"
#include "cm_mem.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static constexpr uint32_t INIT_COUNT_MULTI = 16;

class CmInitTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmInitTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmInitTest::TearDownTestCase(void)
{
}

static const uint8_t g_rsaUriData[] = "oh:t=ak;o=TestInitRsa;u=0;a=0";
static const uint8_t g_eccUriData[] = "oh:t=ak;o=TestInitEcc;u=0;a=0";
static const uint8_t g_sm2UriData[] = "oh:t=ak;o=TestInitSM2;u=0;a=0";
static const CmBlob g_rsaKeyUri = { sizeof(g_rsaUriData), (uint8_t *)g_rsaUriData };
static const CmBlob g_eccKeyUri = { sizeof(g_eccUriData), (uint8_t *)g_eccUriData };
static const CmBlob g_sm2KeyUri = { sizeof(g_sm2UriData), (uint8_t *)g_sm2UriData };

void CmInitTest::SetUp()
{
    uint8_t aliasRsaData[] = "TestInitRsa";
    uint8_t aliasEccData[] = "TestInitEcc";
    uint8_t aliasSM2Data[] = "TestInitSM2";
    struct CmBlob aliasRsa = { sizeof(aliasRsaData), aliasRsaData };
    struct CmBlob aliasEcc = { sizeof(aliasEccData), aliasEccData };
    struct CmBlob aliasSM2 = { sizeof(aliasSM2Data), aliasSM2Data };

    int32_t ret = TestGenerateAppCert(&aliasRsa, CERT_KEY_ALG_RSA, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert rsa failed, retcode:" << ret;
    ret = TestGenerateAppCert(&aliasEcc, CERT_KEY_ALG_ECC, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert ecc failed, retcode:" << ret;
    ret = TestGenerateAppCert(&aliasSM2, CERT_KEY_ALG_SM2_1, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert sm2 failed, retcode:" << ret;
}

void CmInitTest::TearDown()
{
    int32_t ret = CmUninstallAppCert(&g_rsaKeyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert rsa failed, retcode:" << ret;
    ret = CmUninstallAppCert(&g_eccKeyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert ecc failed, retcode:" << ret;
    ret = CmUninstallAppCert(&g_sm2KeyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert sm2 failed, retcode:" << ret;
}

/**
* @tc.name: CmInitTest001
* @tc.desc: Test CmIsAuthorizedApp authUri is NULL
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInitTest, CmInitTest001, TestSize.Level0)
{
    struct CmBlob *authUri = nullptr; /* authUri is NULL */
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmInitTest002
 * @tc.desc: Test CmIsAuthorizedApp authUri size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest002, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob authUri = { 0, uriData }; /* authUri size is 0 */
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmInitTest003
* @tc.desc: Test CmIsAuthorizedApp authUri data is null
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInitTest, CmInitTest003, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob authUri = { sizeof(uriData), nullptr }; /* authUri data is null */
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmInitTest004
 * @tc.desc: Test CmIsAuthorizedApp authUri data not end of '\0'
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest004, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob authUri = { strlen((char *)uriData), uriData }; /* authUri data not end of '\0' */
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmInitTest005
* @tc.desc: Test CmIsAuthorizedApp authUri data has no app
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInitTest, CmInitTest005, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;u=0"; /* authUri data has no app */
    struct CmBlob authUri = { sizeof(uriData), uriData };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmInitTest006
 * @tc.desc: Test CmIsAuthorizedApp authUri data has no user
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest006, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=keyA;a=0"; /* authUri data has no user */
    struct CmBlob authUri = { sizeof(uriData), uriData };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmInitTest007
* @tc.desc: Test CmIsAuthorizedApp authUri data has no object
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInitTest, CmInitTest007, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;u=0;a=0"; /* authUri data has no object */
    struct CmBlob authUri = { sizeof(uriData), uriData };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmInitTest008
 * @tc.desc: Test CmIsAuthorizedApp authUri data type not ak
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest008, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=m;o=keyA;u=0;a=0"; /* authUri data type not ak */
    struct CmBlob authUri = { sizeof(uriData), uriData };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&authUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmInitTest009
* @tc.desc: Test CmIsAuthorizedApp spec is NULL
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInitTest, CmInitTest009, TestSize.Level0)
{
    struct CmSignatureSpec *spec = nullptr; /* spec is NULL */
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&g_rsaKeyUri, spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmInitTest010
 * @tc.desc: Test CmIsAuthorizedApp spec->purpose is not CM_KEY_PURPOSE_SIGN/VERIFY
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest010, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_AGREE }; /* purpose is not CM_KEY_PURPOSE_SIGN/VERIFY */
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&g_rsaKeyUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED);
}

/**
 * @tc.name: CmInitTest011
 * @tc.desc: Test CmIsAuthorizedApp handle is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest011, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    struct CmBlob *handle = nullptr; /* handle is NULL */

    int32_t ret = CmInit(&g_rsaKeyUri, &spec, handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmInitTest012
* @tc.desc: Test CmIsAuthorizedApp handle size is 0
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInitTest, CmInitTest012, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { 0, (uint8_t *)&handleValue }; /* handle size is 0 */

    int32_t ret = CmInit(&g_rsaKeyUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmInitTest013
 * @tc.desc: Test CmIsAuthorizedApp handle data is NULL
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest013, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    struct CmBlob handle = { sizeof(uint64_t), nullptr }; /* handle data is NULL */

    int32_t ret = CmInit(&g_rsaKeyUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmInitTest014
* @tc.desc: Test CmIsAuthorizedApp handle size smaller than sizeof(uint64_t)
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInitTest, CmInitTest014, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint32_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue }; /* size smaller than sizeof(uint64_t) */

    int32_t ret = CmInit(&g_rsaKeyUri, &spec, &handle);
    EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED);
}

/**
 * @tc.name: CmInitTest015
 * @tc.desc: Test CmIsAuthorizedApp huks key not exist
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest015, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=ak;o=NotExist64897;u=0;a=0";
    struct CmBlob authUri = { sizeof(uriData), uriData };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&authUri, &spec, &handle); /* key not exist */
    EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED);
}

/**
* @tc.name: CmInitTest016
* @tc.desc: Test CmIsAuthorizedApp normal case: caller is producer, init once rsa
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmInitTest, CmInitTest016, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&g_rsaKeyUri, &spec, &handle);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
 * @tc.name: CmInitTest017
 * @tc.desc: Test CmIsAuthorizedApp normal case: caller is producer, init once ecc
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest017, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_VERIFY, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret = CmInit(&g_eccKeyUri, &spec, &handle);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
 * @tc.name: CmInitTest018
 * @tc.desc: Test CmIsAuthorizedApp normal case: caller is producer, init max times + 1
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTest018, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_VERIFY, CM_PADDING_PSS, CM_DIGEST_SHA256 };

    for (uint32_t i = 0; i < INIT_COUNT_MULTI; ++i) {
        uint64_t handleValue = 0;
        struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

        int32_t ret = CmInit(&g_eccKeyUri, &spec, &handle);
        EXPECT_EQ(ret, CM_SUCCESS);
    }
}

/**
 * @tc.name: CmInitTestPerformance019
 * @tc.desc: 1000 times: caller is producer, init once ecc
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmInitTest, CmInitTestPerformance019, TestSize.Level1)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_VERIFY, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret;
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        ret = CmInit(&g_eccKeyUri, &spec, &handle);
        EXPECT_EQ(ret, CM_SUCCESS);
        ret = CmAbort(&handle);
        EXPECT_EQ(ret, CM_SUCCESS);
    }
}

/**
 * @tc.name: CmInitTest020
 * @tc.desc: normal case: caller is producer, init once sm2 with sm3
 * @tc.type: FUNC
 */
HWTEST_F(CmInitTest, CmInitTest020, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SM3 };
    uint64_t handleValue1 = 0;
    struct CmBlob handle1 = { sizeof(handleValue1), (uint8_t *)&handleValue1 };

    int32_t ret = CmInit(&g_sm2KeyUri, &spec, &handle1);
    EXPECT_EQ(ret, CM_SUCCESS);

    spec.purpose = CM_KEY_PURPOSE_VERIFY;
    uint64_t handleValue2 = 0;
    struct CmBlob handle2 = { sizeof(handleValue2), (uint8_t *)&handleValue2 };
    ret = CmInit(&g_sm2KeyUri, &spec, &handle2);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
 * @tc.name: CmInitTest021
 * @tc.desc: Abnormal case: Test init sm2 with SHA256
 * @tc.type: FUNC
 */
HWTEST_F(CmInitTest, CmInitTest021, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA256 };
    uint64_t handleValue1 = 0;
    struct CmBlob handle1 = { sizeof(handleValue1), (uint8_t *)&handleValue1 };

    int32_t ret = CmInit(&g_sm2KeyUri, &spec, &handle1);
    EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED);

    spec.purpose = CM_KEY_PURPOSE_VERIFY;
    uint64_t handleValue2 = 0;
    struct CmBlob handle2 = { sizeof(handleValue2), (uint8_t *)&handleValue2 };
    ret = CmInit(&g_sm2KeyUri, &spec, &handle2);
    EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED);
}

/**
 * @tc.name: CmInitTest022
 * @tc.desc: Abnormal case: Test init ecc with sm3
 * @tc.type: FUNC
 */
HWTEST_F(CmInitTest, CmInitTest022, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SM3 };
    uint64_t handleValue1 = 0;
    struct CmBlob handle1 = { sizeof(handleValue1), (uint8_t *)&handleValue1 };

    int32_t ret = CmInit(&g_eccKeyUri, &spec, &handle1);
    EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED);

    spec.purpose = CM_KEY_PURPOSE_VERIFY;
    uint64_t handleValue2 = 0;
    struct CmBlob handle2 = { sizeof(handleValue2), (uint8_t *)&handleValue2 };
    ret = CmInit(&g_eccKeyUri, &spec, &handle2);
    EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED);
}

/**
 * @tc.name: CmInitTest023
 * @tc.desc: normal case: caller is producer, init once sm2 with non_digest
 * @tc.type: FUNC
 */
HWTEST_F(CmInitTest, CmInitTest023, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_NONE };
    uint64_t handleValue1 = 0;
    struct CmBlob handle1 = { sizeof(handleValue1), (uint8_t *)&handleValue1 };

    int32_t ret = CmInit(&g_sm2KeyUri, &spec, &handle1);
    EXPECT_EQ(ret, CM_SUCCESS);

    spec.purpose = CM_KEY_PURPOSE_VERIFY;
    uint64_t handleValue2 = 0;
    struct CmBlob handle2 = { sizeof(handleValue2), (uint8_t *)&handleValue2 };
    ret = CmInit(&g_sm2KeyUri, &spec, &handle2);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
 * @tc.name: CmInitTestPerformance024
 * @tc.desc: 1000 times: caller is producer, init sm2
 * @tc.type: FUNC
 */
HWTEST_F(CmInitTest, CmInitTestPerformance024, TestSize.Level1)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SM3 };
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };

    int32_t ret;
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        ret = CmInit(&g_sm2KeyUri, &spec, &handle);
        EXPECT_EQ(ret, CM_SUCCESS);
        ret = CmAbort(&handle);
        EXPECT_EQ(ret, CM_SUCCESS);
    }
}
} // end of namespace
