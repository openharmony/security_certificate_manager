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
#include "cm_ukeylist_data_helper.h"
#include "cm_mem.h"
#include "cm_type.h"

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
* @tc.desc: test ParcelReadInvoke abnormal
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmDataParcelProcessorTest, ReadFromParcelTest001, TestSize.Level0)
{
    MessageParcel reply;
    void *data = nullptr;
    int32_t ret = CmDataParcelProcessor::GetInstance().ReadFromParcel(reply, data);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);

    CmDataParcelProcessor::GetInstance().SetParcelStrategy(std::make_unique<CmUkeyListDataHelper>());
    ret = CmIpcDataParcelPacker::GetInstance().ParcelReadInvoke(code, reply, data2);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    code = CM_MSG_GET_UKEY_CERTIFICATE_LIST;
    ret = CmIpcDataParcelPacker::GetInstance().ParcelReadInvoke(code, reply, data2);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
    CM_FREE_PTR(data2);
}

/**
* @tc.name: ParcelReadInvokeTest002
* @tc.desc: test ParcelReadInvoke
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParcelPackerTest, ParcelReadInvokeTest002, TestSize.Level0)
{
    MessageParcel reply;
    uint32_t code = INVALID_CODE;
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
    ret = CmIpcDataParcelPacker::GetInstance().ParcelReadInvoke(code, reply, data);
    EXPECT_EQ(ret, CM_SUCCESS);
    CmFreeUkeyCertList(&credList);
    CmFreeUkeyCertList(credentialDetailListParcelInfo.credentialDetailList);
}

/**
* @tc.name: ParcelWriteInvokeTest001
* @tc.desc: test ParcelWriteInvoke abnormal
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParcelPackerTest, ParcelWriteInvokeTest001, TestSize.Level0)
{
    MessageParcel reply;
    uint32_t code = INVALID_CODE;
    void *data = nullptr;
    int32_t ret = CmIpcDataParcelPacker::GetInstance().ParcelWriteInvoke(code, &reply, data);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);

    void *data2 = static_cast<void*>(CmMalloc(1));
    ret = CmIpcDataParcelPacker::GetInstance().ParcelWriteInvoke(code, &reply, data2);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    code = CM_MSG_GET_UKEY_CERTIFICATE_LIST;
    ret = CmIpcDataParcelPacker::GetInstance().ParcelWriteInvoke(code, &reply, data2);
    EXPECT_EQ(ret, CM_SUCCESS);
    CM_FREE_PTR(data2);
}
} // end of namespace
