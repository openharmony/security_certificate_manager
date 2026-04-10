/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <string>
#include <gtest/gtest.h>

#include "cm_test_log.h"
#include "cm_test_common.h"
#include "cm_mem.h"
#include "cert_manager_api.h"
#include "cm_native_api.h"
#include "cm_cert_data_part1_rsa.h"

namespace {
const uint32_t INVALID_PURPOSE = 10;
}

using namespace testing::ext;
using namespace CertmanagerTest;

class CmImportUkeyCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CmImportUkeyCertTest::SetUpTestCase(void)
{
    uint32_t selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(selfTokenId);
}

void CmImportUkeyCertTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmImportUkeyCertTest::SetUp()
{
}

void CmImportUkeyCertTest::TearDown()
{
}

/**
 * @tc.name: CmImportUkeyCertBaseTest001
 * @tc.desc: Test CertManager import ukey cert interface - null keyUri
 * @tc.type: FUNC
 */
HWTEST_F(CmImportUkeyCertTest, CmImportUkeyCertBaseTest001, TestSize.Level0)
{
    uint8_t certData[] = "testCertData";
    struct CmBlob cert = { sizeof(certData), certData };
    struct UkeyInfo ukeyInfo = { CM_CERT_PURPOSE_DEFAULT };

    int32_t ret = CmImportUkeyCert(nullptr, &cert, &ukeyInfo);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER) << "CmImportUkeyCert test failed, retcode:" << ret;
}

/**
 * @tc.name: CmImportUkeyCertBaseTest002
 * @tc.desc: Test CertManager import ukey cert interface - null cert
 * @tc.type: FUNC
 */
HWTEST_F(CmImportUkeyCertTest, CmImportUkeyCertBaseTest002, TestSize.Level0)
{
    uint8_t keyUriData[] = "testKeyUri";
    struct CmBlob keyUri = { sizeof(keyUriData), keyUriData };
    struct UkeyInfo ukeyInfo = { CM_CERT_PURPOSE_DEFAULT };

    int32_t ret = CmImportUkeyCert(&keyUri, nullptr, &ukeyInfo);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER) << "CmImportUkeyCert test failed, retcode:" << ret;
}

/**
 * @tc.name: CmImportUkeyCertBaseTest003
 * @tc.desc: Test CertManager import ukey cert interface - null ukeyInfo
 * @tc.type: FUNC
 */
HWTEST_F(CmImportUkeyCertTest, CmImportUkeyCertBaseTest003, TestSize.Level0)
{
    uint8_t keyUriData[] = "testKeyUri";
    struct CmBlob keyUri = { sizeof(keyUriData), keyUriData };
    uint8_t certData[] = "testCertData";
    struct CmBlob cert = { sizeof(certData), certData };

    int32_t ret = CmImportUkeyCert(&keyUri, &cert, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER) << "CmImportUkeyCert test failed, retcode:" << ret;
}

/**
 * @tc.name: CmImportUkeyCertBaseTest004
 * @tc.desc: Test CertManager import ukey cert interface - empty keyUri
 * @tc.type: FUNC
 */
HWTEST_F(CmImportUkeyCertTest, CmImportUkeyCertBaseTest004, TestSize.Level0)
{
    uint8_t keyUriData[] = "";
    struct CmBlob keyUri = { 0, keyUriData };
    uint8_t certData[] = "testCertData";
    struct CmBlob cert = { sizeof(certData), certData };
    struct UkeyInfo ukeyInfo = { CM_CERT_PURPOSE_DEFAULT };

    int32_t ret = CmImportUkeyCert(&keyUri, &cert, &ukeyInfo);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "CmImportUkeyCert test failed, retcode:" << ret;
}

/**
 * @tc.name: CmImportUkeyCertBaseTest005
 * @tc.desc: Test CertManager import ukey cert interface - empty cert
 * @tc.type: FUNC
 */
HWTEST_F(CmImportUkeyCertTest, CmImportUkeyCertBaseTest005, TestSize.Level0)
{
    uint8_t keyUriData[] = "testKeyUri";
    struct CmBlob keyUri = { sizeof(keyUriData), keyUriData };
    uint8_t certData[] = "";
    struct CmBlob cert = { 0, certData };
    struct UkeyInfo ukeyInfo = { CM_CERT_PURPOSE_DEFAULT };

    int32_t ret = CmImportUkeyCert(&keyUri, &cert, &ukeyInfo);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "CmImportUkeyCert test failed, retcode:" << ret;
}

/**
 * @tc.name: CmImportUkeyCertAbnormalTest001
 * @tc.desc: Test CertManager import ukey cert interface - invalid certPurpose
 * @tc.type: FUNC
 */
HWTEST_F(CmImportUkeyCertTest, CmImportUkeyCertAbnormalTest001, TestSize.Level0)
{
    uint8_t keyUriData[] = "testKeyUri";
    struct CmBlob keyUri = { sizeof(keyUriData), keyUriData };
    uint8_t certData[] = "testCertData";
    struct CmBlob cert = { sizeof(certData), certData };
    struct UkeyInfo ukeyInfo;
    ukeyInfo.certPurpose = static_cast<enum CmCertificatePurpose>(INVALID_PURPOSE);

    int32_t ret = CmImportUkeyCert(&keyUri, &cert, &ukeyInfo);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "CmImportUkeyCert test failed, retcode:" << ret;
}

/**
 * @tc.name: CmImportUkeyCertAbnormalTest002
 * @tc.desc: Test CertManager import ukey cert interface - CM_CERT_PURPOSE_SIGN
 * @tc.type: FUNC
 */
HWTEST_F(CmImportUkeyCertTest, CmImportUkeyCertAbnormalTest002, TestSize.Level0)
{
    uint8_t keyUriData[] = "testKeyUri";
    struct CmBlob keyUri = { sizeof(keyUriData), keyUriData };
    uint8_t certData[] = "testCertData";
    struct CmBlob cert = { sizeof(certData), certData };
    struct UkeyInfo ukeyInfo;
    ukeyInfo.certPurpose = CM_CERT_PURPOSE_SIGN;

    int32_t ret = CmImportUkeyCert(&keyUri, &cert, &ukeyInfo);
    EXPECT_EQ(ret, CMR_ERROR_UKEY_DEVICE_SUPPORT) << "CmImportUkeyCert test failed, retcode:" << ret;
}

/**
 * @tc.name: CmImportUkeyCertAbnormalTest003
 * @tc.desc: Test CertManager import ukey cert interface - CM_CERT_PURPOSE_ENCRYPT
 * @tc.type: FUNC
 */
HWTEST_F(CmImportUkeyCertTest, CmImportUkeyCertAbnormalTest003, TestSize.Level0)
{
    uint8_t keyUriData[] = "testKeyUri";
    struct CmBlob keyUri = { sizeof(keyUriData), keyUriData };
    uint8_t certData[] = "testCertData";
    struct CmBlob cert = { sizeof(certData), certData };
    struct UkeyInfo ukeyInfo;
    ukeyInfo.certPurpose = CM_CERT_PURPOSE_ENCRYPT;

    int32_t ret = CmImportUkeyCert(&keyUri, &cert, &ukeyInfo);
    EXPECT_EQ(ret, CMR_ERROR_UKEY_DEVICE_SUPPORT) << "CmImportUkeyCert test failed, retcode:" << ret;
}