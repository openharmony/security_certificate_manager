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

#include "message_parcel.h"

#include "cm_type_free.h"
#include "cm_ipc_response_type.h"
#include "cm_data_parcel_processor.h"
#include "cert_manager_service_ipc_interface_code.h"
#include "cm_data_parcel_strategy.h"
#include "cm_mem.h"
#include "cm_type.h"

namespace {
const uint32_t INVALID_CODE = 100;
const uint32_t UkEY_CODE = 25;
}

using namespace testing::ext;
namespace OHOS {
class CmDataParcelProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmDataParcelProcessorTest::SetUpTestCase(void)
{
}

void CmDataParcelProcessorTest::TearDownTestCase(void)
{
}

void CmDataParcelProcessorTest::SetUp()
{
}

void CmDataParcelProcessorTest::TearDown()
{
}

/**
* @tc.name: ReadFromParcelTest001
* @tc.desc: test ReadFromParcel abnormal
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmDataParcelProcessorTest, ReadFromParcelTest001, TestSize.Level0)
{
    MessageParcel reply;
    void *data = nullptr;
    CmDataParcelProcessor processor;
    int32_t ret = processor.ReadFromParcel(reply, data);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);

    auto parcelStrategy = CmDataParcelStrategy::CreateParcelStrategy(
        static_cast<enum CertManagerInterfaceCode>(UkEY_CODE));
    CmDataParcelProcessor processor2(std::move(parcelStrategy));
    processor2.SetParcelStrategy(std::move(parcelStrategy));
    void *data2 = static_cast<void*>(CmMalloc(1));
    ret = processor2.ReadFromParcel(reply, data2);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
    CM_FREE_PTR(data2);
}

/**
* @tc.name: ReadFromParcelTest002
* @tc.desc: test ReadFromParcel
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmDataParcelProcessorTest, ReadFromParcelTest002, TestSize.Level0)
{
    MessageParcel reply;
    struct CredentialDetailList credList;
    void *data = reinterpret_cast<void*>(&credList);

    struct CredentialDetailList curCredList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &curCredList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    curCredList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    curCredList.credential->isExist = 1;
    (void)memset_s(curCredList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(curCredList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(curCredList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    curCredList.credential->certNum = 1;
    curCredList.credential->keyNum = 1;
    curCredList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(1));
    curCredList.credential->credData.size = 1;
    curCredList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    int32_t ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, true);
    auto parcelStrategy = CmDataParcelStrategy::CreateParcelStrategy(
        static_cast<enum CertManagerInterfaceCode>(UkEY_CODE));
    CmDataParcelProcessor processor(std::move(parcelStrategy));
    ret = processor.ReadFromParcel(reply, data);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_OPERATION);
    CmFreeUkeyCertList(&credList);
    CmFreeUkeyCertList(credentialDetailListParcelInfo.credentialDetailList);
}

/**
* @tc.name: WriteToParcelTest001
* @tc.desc: test ParcelWriteInvoke abnormal
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmDataParcelProcessorTest, WriteToParcelTest001, TestSize.Level0)
{
    MessageParcel reply;;
    void *data = nullptr;
    CmDataParcelProcessor processor;
    int32_t ret = processor.WriteToParcel(&reply, data);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
    auto parcelStrategy = CmDataParcelStrategy::CreateParcelStrategy(
        static_cast<enum CertManagerInterfaceCode>(INVALID_CODE));
    EXPECT_EQ(parcelStrategy, nullptr);
    auto parcelStrategy2 = CmDataParcelStrategy::CreateParcelStrategy(
        static_cast<enum CertManagerInterfaceCode>(UkEY_CODE));
    processor.SetParcelStrategy(std::move(parcelStrategy2));
    void *data2 = static_cast<void*>(CmMalloc(1));
    ret = processor.WriteToParcel(&reply, data2);
    EXPECT_EQ(ret, CM_SUCCESS);
    CM_FREE_PTR(data2);
}
} // end of namespace
