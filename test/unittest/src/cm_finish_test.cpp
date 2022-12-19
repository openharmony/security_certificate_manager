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

static void TestSign(const struct CmBlob *keyUri, const struct CmSignatureSpec *spec,
    const struct CmBlob *message, struct CmBlob *signature)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    int32_t ret = CmInit(keyUri, spec, &handle);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestSign CmInit test failed";

    ret = CmUpdate(&handle, message);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestSign CmUpdate test failed";

    struct CmBlob inDataFinish = { 0, nullptr };
    ret = CmFinish(&handle, &inDataFinish, signature);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestSign CmFinish test failed";

    ret = CmAbort(&handle);
    EXPECT_EQ(ret, CM_SUCCESS) << "TestSign CmAbort test failed";
}

static void TestVerify(const struct CmBlob *keyUri, const struct CmSignatureSpec *spec,
    const struct CmBlob *message, const struct CmBlob *signature, bool isValidSignature)
{
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    int32_t ret = CmInit(keyUri, spec, &handle);
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

static void TestSignVerify(uint32_t alg, bool isValidSignature, struct CmSignatureSpec *spec)
{
    /* install credential */
    TestInstallAppCert(alg);

    struct CmBlob message = { 0, nullptr };
    uint8_t srcData[] = {
        0xc2, 0xa7, 0xc5, 0x33, 0x79, 0xb0, 0xcd, 0x86, 0x74, 0x09, 0x98, 0x16, 0xd5, 0x85, 0x1b, 0xd6,
        0x87, 0xe3, 0xe0, 0x53, 0x7d, 0xe0, 0xff, 0x1d, 0xdb, 0x27, 0x98, 0xe8, 0x87, 0xe5, 0xb7, 0x03,
    };
    if (spec->digest != CM_DIGEST_NONE) {
        message.size = sizeof(g_messageData);
        message.data = const_cast<uint8_t *>(g_messageData);
    } else {
        message.size = sizeof(srcData);
        message.data = srcData;
    }

    uint8_t signData[DEFAULT_SIGNATURE_LEN] = {0};
    struct CmBlob signature = { DEFAULT_SIGNATURE_LEN, signData };

    /* sign */
    spec->purpose = CM_KEY_PURPOSE_SIGN;
    TestSign(&g_keyUri, spec, &message, &signature);

    /* verify */
    spec->purpose = CM_KEY_PURPOSE_VERIFY;
    TestVerify(&g_keyUri, spec, &message, &signature, isValidSignature);

    /* uninstall rsa credential */
    TestUninstallAppCert();
}

static void ProducerSessionMaxTest(void)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
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
* @tc.desc: Test CmFinish handle is null
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
 * @tc.desc: Test CmFinish handle size is 0
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
 * @tc.desc: Test CmFinish handle data is null
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
* @tc.desc: Test CmFinish inData is null
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
 * @tc.desc: Test CmFinish outData is null
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
* @tc.desc: Test CmFinish handle not exist
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
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pss sha256
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest007, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest008
* @tc.desc: Test CmFinish normal case: caller is producer, ecc sign verify, sha256
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest008, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA256 };
    TestSignVerify(CERT_KEY_ALG_ECC, true, &spec);
}

/**
* @tc.name: CmFinishTest009
* @tc.desc: Test CmFinish abnormal case: caller is producer, rsa sign verify(sign invalid)
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest009, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    TestSignVerify(CERT_KEY_ALG_RSA, false, &spec);
}

/**
* @tc.name: CmFinishTest010
* @tc.desc: Test CmFinish abnormal case: caller is producer, ecc sign verify(sign invalid)
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest010, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA256 };
    TestSignVerify(CERT_KEY_ALG_ECC, false, &spec);
}

/**
* @tc.name: CmFinishTest011
* @tc.desc: Test CmFinish normal case: normal case: caller is producer, max times + 1(first fail)
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
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        TestSignVerify(CERT_KEY_ALG_ECC, true, &spec);
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
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    for (uint32_t i = 0; i < PERFORMACE_COUNT; ++i) {
        TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
    }
}

/**
* @tc.name: CmFinishTest014
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pss, sha512
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest014, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA512 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest015
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pss, sha384
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest015, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA384 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest016
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pss, sha224
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest016, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA224 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest017
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pss, sha1
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest017, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA1 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest018
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pkcs1, nosha
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest018, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_NONE };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest019
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pkcs1, md5
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest019, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_MD5 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest020
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pkcs1, sha224
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest020, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_SHA224 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

    /**
* @tc.name: CmFinishTest021
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pkcs1, sha256
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest021, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_SHA256 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

    /**
* @tc.name: CmFinishTest022
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pkcs1, sha384
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest022, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_SHA384 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest023
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pkcs1, sha512
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest023, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_SHA512 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest024
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, pkcs1, sha1
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest024, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_SHA1 };
    TestSignVerify(CERT_KEY_ALG_RSA, true, &spec);
}

/**
* @tc.name: CmFinishTest025
* @tc.desc: Test CmFinish normal case: caller is producer, ecc sign verify, sha1
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest025, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA1 };
    TestSignVerify(CERT_KEY_ALG_ECC, true, &spec);
}

/**
* @tc.name: CmFinishTest026
* @tc.desc: Test CmFinish normal case: caller is producer, ecc sign verify, sha224
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest026, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA224 };
    TestSignVerify(CERT_KEY_ALG_ECC, true, &spec);
}

/**
* @tc.name: CmFinishTest027
* @tc.desc: Test CmFinish normal case: caller is producer, ecc sign verify, sha384
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest027, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA384 };
    TestSignVerify(CERT_KEY_ALG_ECC, true, &spec);
}

/**
* @tc.name: CmFinishTest028
* @tc.desc: Test CmFinish normal case: caller is producer, ecc sign verify, sha512
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest028, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA512 };
    TestSignVerify(CERT_KEY_ALG_ECC, true, &spec);
}

/**
* @tc.name: CmFinishTest029
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, 512
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest029, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    TestSignVerify(CERT_KEY_ALG_RSA_512, true, &spec);
}

/**
* @tc.name: CmFinishTest030
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, 1024
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest030, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA384 };
    TestSignVerify(CERT_KEY_ALG_RSA_1024, true, &spec);
}

/**
* @tc.name: CmFinishTest031
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, 3072
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest031, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_NONE };
    TestSignVerify(CERT_KEY_ALG_RSA_3072, true, &spec);
}

/**
* @tc.name: CmFinishTest032
* @tc.desc: Test CmFinish normal case: caller is producer, rsa sign verify, 4096
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest032, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_SHA512 };
    TestSignVerify(CERT_KEY_ALG_RSA_4096, true, &spec);
}

/**
* @tc.name: CmFinishTest033
* @tc.desc: Test CmFinish normal case: caller is producer, ecc sign verify, P224
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest033, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA256 };
    TestSignVerify(CERT_KEY_ALG_ECC_P224, true, &spec);
}

/**
* @tc.name: CmFinishTest034
* @tc.desc: Test CmFinish normal case: caller is producer, ecc sign verify, P384
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest034, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA384 };
    TestSignVerify(CERT_KEY_ALG_ECC_P384, true, &spec);
}

/**
* @tc.name: CmFinishTest035
* @tc.desc: Test CmFinish normal case: caller is producer, ecc sign verify, P521
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest035, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, CM_DIGEST_SHA512 };
    TestSignVerify(CERT_KEY_ALG_ECC_P521, true, &spec);
}

/**
* @tc.name: CmFinishTest036
* @tc.desc: Test CmFinish normal case: caller is producer, ed25519 sign verify
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmFinishTest, CmFinishTest036, TestSize.Level0)
{
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, 0, 0 };
    TestSignVerify(CERT_KEY_ALG_ED25519, true, &spec);
}
} // end of namespace

