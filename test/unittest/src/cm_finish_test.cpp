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
static constexpr uint32_t DEFAULT_SIGNATURE_LEN = 1024;
static constexpr uint32_t MAX_SESSION_NUM_MORE_1 = 16;

class CmFinishTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmFinishTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmFinishTest::TearDownTestCase(void)
{
}

void CmFinishTest::SetUp()
{
}

void CmFinishTest::TearDown()
{
}

static const uint8_t g_uriData[] = "oh:t=ak;o=TestFinishSignVerify;u=0;a=0";
static const CmBlob g_keyUri = { sizeof(g_uriData), (uint8_t *)g_uriData };

static const uint8_t g_messageData[] = "This_is_test_message_for_test_sign_and_verify";

static void TestInstallAppCert(uint32_t alg)
{
    uint8_t aliasData[] = "TestFinishSignVerify";
    struct CmBlob alias = { sizeof(aliasData), aliasData };

    int32_t ret = TestGenerateAppCert(&alias, alg, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestGenerateAppCert failed, retcode:" << ret;
}

static void TestUninstallAppCert(void)
{
    int32_t ret = CmUninstallAppCert(&g_keyUri, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmUninstallAppCert failed, retcode:" << ret;
}

static void TestSign(const struct CmBlob *keyUri, const struct CmBlob *message, struct CmBlob *signature)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(uint64_t), (uint8_t *)&handleValue };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN };

    int32_t ret = CmInit(keyUri, &spec, &handle);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestSign CmInit test failed";

    ret = CmUpdate(&handle, message);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestSign CmUpdate test failed";

    struct CmBlob inDataFinish = { 0, nullptr };
    ret = CmFinish(&handle, &inDataFinish, signature);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestSign CmFinish test failed";

    ret = CmAbort(&handle);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestSign CmAbort test failed";
}

static void TestVerify(const struct CmBlob *keyUri, const struct CmBlob *message, const struct CmBlob *signature,
    bool isValidSignature)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(uint64_t), (uint8_t *)&handleValue };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_VERIFY };

    int32_t ret = CmInit(keyUri, &spec, &handle);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestVerify CmInit test failed";

    ret = CmUpdate(&handle, message);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestVerify CmUpdate test failed";

    struct CmBlob inDataFinish = { signature->size, signature->data };
    if (!isValidSignature && signature->size > 0) {
        signature->data[0] += 0x01; /* change the first byte of signature, ignore data flipping */
    }

    struct CmBlob outDataFinish = { 0, nullptr };
    ret = CmFinish(&handle, &inDataFinish, &outDataFinish);
    if (isValidSignature) {
        EXPECT_EQ(ret, CM_SUCCESS) << "TestVerify CmFinish test failed";
    } else {
        EXPECT_EQ(ret, CMR_ERROR_KEY_OPERATION_FAILED) << "TestVerify CmFinish test failed";
    }

    ret = CmAbort(&handle);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestVerify CmAbort test failed";
}

static void TestSignVerify(uint32_t alg, bool isValidSignature)
{
    /* install credential */
    TestInstallAppCert(alg);

    struct CmBlob message = { sizeof(g_messageData), (uint8_t *)g_messageData };
    uint8_t signData[DEFAULT_SIGNATURE_LEN] = {0};
    struct CmBlob signature = { DEFAULT_SIGNATURE_LEN, signData };

    /* sign */
    TestSign(&g_keyUri, &message, &signature);

    /* verify */
    TestVerify(&g_keyUri, &message, &signature, isValidSignature);

    /* uninstall rsa credential */
    TestUninstallAppCert();
}

static void ProducerSessionMaxTest(void)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN };
    uint64_t handle[MAX_SESSION_NUM_MORE_1];
    int32_t ret;

    for (uint32_t i = 0; i < MAX_SESSION_NUM_MORE_1; ++i) {
        struct CmBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[i] };
        ret = CmInit(&g_keyUri, &spec, &handleBlob);
        EXPECT_EQ(ret, CM_SUCCESS) << "cm init failed, index[" << i << "]";
    }

    for (uint32_t i = 0; i < MAX_SESSION_NUM_MORE_1; ++i) {
        uint8_t tmpInput[] = "thisIstestForSessionMaxTestInData";
        struct CmBlob updateInput = { sizeof(tmpInput), tmpInput };
        struct CmBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[i] };

        int32_t expectRet = CM_SUCCESS;
        if (i == 0) {
            expectRet = CMR_ERROR_NOT_EXIST;
        }

        ret = CmUpdate(&handleBlob, &updateInput);
        EXPECT_EQ(ret, expectRet) << "update failed, i:" << i;

        uint8_t tmpOutput[DEFAULT_SIGNATURE_LEN] = {0};
        struct CmBlob finishInput = { 0, nullptr };
        struct CmBlob finishOutput = { sizeof(tmpOutput), tmpOutput };
        ret = CmFinish(&handleBlob, &finishInput, &finishOutput);
        EXPECT_EQ(ret, expectRet) << "finish failed, i:" << i;
    }

    for (uint32_t i = 0; i < MAX_SESSION_NUM_MORE_1; ++i) {
        struct CmBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handle[i] };
        ret = CmAbort(&handleBlob);
        EXPECT_EQ(ret, CM_SUCCESS) << "abort failed, i:" << i;
    }
}


/**
* @tc.name: CmFinishTest001
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest001, TestSize.Level0)
{
    struct CmBlob *handle = nullptr;
    struct CmBlob inData = { 0, nullptr };
    struct CmBlob outData = { 0, nullptr };

    int32_t ret = CmFinish(handle, &inData, &outData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmFinishTest002
 * @tc.desc: Test CmIsAuthorizedApp handle size is 0
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmFinishTest, CmFinishTest002, TestSize.Level0)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { 0, (uint8_t *)&handleValue };
    struct CmBlob inData = { 0, nullptr };
    struct CmBlob outData = { 0, nullptr };

    int32_t ret = CmFinish(&handle, &inData, &outData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmFinishTest003
 * @tc.desc: Test CmIsAuthorizedApp handle data is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmFinishTest, CmFinishTest003, TestSize.Level0)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), nullptr };
    struct CmBlob inData = { 0, nullptr };
    struct CmBlob outData = { 0, nullptr };

    int32_t ret = CmFinish(&handle, &inData, &outData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmFinishTest004
* @tc.desc: Test CmIsAuthorizedApp inData is null
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest004, TestSize.Level0)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
    struct CmBlob *inData = nullptr;
    struct CmBlob outData = { 0, nullptr };

    int32_t ret = CmFinish(&handle, inData, &outData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmFinishTest005
 * @tc.desc: Test CmIsAuthorizedApp outData is null
 * @tc.type: FUNC
 * @tc.require: AR000H0MIA /SR000H09NA
 */
HWTEST_F(CmFinishTest, CmFinishTest005, TestSize.Level0)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
    struct CmBlob inData = { 0, nullptr };
    struct CmBlob *outData = nullptr;

    int32_t ret = CmFinish(&handle, &inData, outData);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmFinishTest006
* @tc.desc: Test CmIsAuthorizedApp handle not exist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest006, TestSize.Level0)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
    struct CmBlob inData = { 0, nullptr };
    struct CmBlob outData = { 0, nullptr };

    int32_t ret = CmFinish(&handle, &inData, &outData);
    EXPECT_EQ(ret, CMR_ERROR_NOT_EXIST);
}

/**
* @tc.name: CmFinishTest007
* @tc.desc: Test CmIsAuthorizedApp normal case: caller is producer, rsa sign verify
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest007, TestSize.Level0)
{
    TestSignVerify(CERT_KEY_ALG_RSA, true);
}

/**
* @tc.name: CmFinishTest008
* @tc.desc: Test CmIsAuthorizedApp normal case: caller is producer, ecc sign verify
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest008, TestSize.Level0)
{
    TestSignVerify(CERT_KEY_ALG_ECC, true);
}

/**
* @tc.name: CmFinishTest009
* @tc.desc: Test CmIsAuthorizedApp abnormal case: caller is producer, rsa sign verify(sign invalid)
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest009, TestSize.Level0)
{
    TestSignVerify(CERT_KEY_ALG_RSA, false);
}

/**
* @tc.name: CmFinishTest010
* @tc.desc: Test CmIsAuthorizedApp abnormal case: caller is producer, ecc sign verify(sign invalid)
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest010, TestSize.Level0)
{
    TestSignVerify(CERT_KEY_ALG_ECC, false);
}

/**
* @tc.name: CmFinishTest011
* @tc.desc: Test CmIsAuthorizedApp normal case: normal case: caller is producer, max times + 1(first fail)
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest011, TestSize.Level0)
{
    TestInstallAppCert(CERT_KEY_ALG_ECC);
    ProducerSessionMaxTest();
    TestUninstallAppCert();
}

/**
* @tc.name: CmFinishTestPerformance012
* @tc.desc: 1000 times normal case: caller is producer, ecc sign verify
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTestPerformance012, TestSize.Level1)
{
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        TestSignVerify(CERT_KEY_ALG_ECC, true);
    }
}

/**
* @tc.name: CmFinishTestPerformance013
* @tc.desc: 1000 times normal case: caller is producer, rsa sign verify
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTestPerformance013, TestSize.Level1)
{
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        TestSignVerify(CERT_KEY_ALG_RSA, true);
    }
}
} // end of namespace

