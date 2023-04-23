/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <gtest/hwext/gtest-multithread.h>

#include "cert_manager_api.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_mem.h"
#include "cm_test_common.h"

using namespace testing::ext;
using namespace testing::mt;
using namespace CertmanagerTest;
namespace {
static constexpr uint32_t MULTI_THREAD_NUM = 10;

static const struct CmBlob g_appCert = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
static const struct CmBlob g_appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };

class CmAppCertMultiThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmAppCertMultiThreadTest::SetUpTestCase(void)
{
    SetATPermission();
}

void CmAppCertMultiThreadTest::TearDownTestCase(void)
{
}

void CmAppCertMultiThreadTest::SetUp()
{
}

void CmAppCertMultiThreadTest::TearDown()
{
}

/**
 * @tc.name: CmAppCertMultiThreadTest001
 * @tc.desc: Test CertManager unInstall app cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWMTEST_F(CmAppCertMultiThreadTest, CmAppCertMultiThreadTest001, TestSize.Level0, MULTI_THREAD_NUM)
{
    int32_t ret = CmUninstallAppCert(nullptr, CM_CREDENTIAL_STORE);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "CmAppCertMultiThreadTest001 test failed, retcode:" << ret;
}

/**
 * @tc.name: CmAppCertMultiThreadTest002
 * @tc.desc: Test CertManager unInstall app cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWMTEST_F(CmAppCertMultiThreadTest, CmAppCertMultiThreadTest002, TestSize.Level0, MULTI_THREAD_NUM)
{
    uint8_t keyUriBuf[] = "oh:t=ak;o=keyA;u=0;a=0";
    struct CmBlob keyUri = { sizeof(keyUriBuf), keyUriBuf };

    int32_t ret = CmUninstallAppCert(&keyUri, CM_PRI_CREDENTIAL_STORE + 1);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "CmAppCertMultiThreadTest002 test failed, retcode:" << ret;
}

/**
 * @tc.name: CmAppCertMultiThreadTest003
 * @tc.desc: Test CertManager unInstall all app cert interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWMTEST_F(CmAppCertMultiThreadTest, CmAppCertMultiThreadTest003, TestSize.Level0, MULTI_THREAD_NUM)
{
    int32_t ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "CmAppCertMultiThreadTest003 test failed, retcode:" << ret;
}

static void TestUninstallAppCertMultiThread(void)
{
    int32_t ret = CmUninstallAllAppCert();
    EXPECT_EQ(ret, CM_SUCCESS) << "TestUninstallAppCertMultiThread test failed, retcode:" << ret;
}

/**
 * @tc.name: CmAppCertMultiThreadTest004
 * @tc.desc: Test CertManager unInstall all app cert interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MI8 /SR000H09N9
 */
HWTEST_F(CmAppCertMultiThreadTest, CmAppCertMultiThreadTest004, TestSize.Level0)
{
    uint8_t certAliasBuf[] = "keyB";
    struct CmBlob certAlias = { sizeof(certAliasBuf), certAliasBuf };

    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmAppCertMultiThreadTest004 1 failed, retcode:" << ret;

    ret = CmInstallAppCert(&g_appCert, &g_appCertPwd, &certAlias, CM_PRI_CREDENTIAL_STORE, &keyUri);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmAppCertMultiThreadTest004 2 failed, retcode:" << ret;

    SET_THREAD_NUM(MULTI_THREAD_NUM);
    GTEST_RUN_TASK(TestUninstallAppCertMultiThread);
}
} // end of namespace

