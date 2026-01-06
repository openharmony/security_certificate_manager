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

#include "cm_type_free.h"
#include "cm_ipc_response_type.h"
#include "cm_type.h"
#include "cm_mem.h"

namespace {
const uint32_t INVALID_LEN = 9000;
}

using namespace testing::ext;
namespace OHOS {
class CmIpcResponseTypeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmIpcResponseTypeTest::SetUpTestCase(void)
{
}

void CmIpcResponseTypeTest::TearDownTestCase(void)
{
}

void CmIpcResponseTypeTest::SetUp()
{
}

void CmIpcResponseTypeTest::TearDown()
{
}

/**
* @tc.name: CredentialDetailListMarshallingTest001
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListMarshallingTest001, TestSize.Level0)
{
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    credList.credential->isExist = 1;
    (void)memset_s(credList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(credList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(credList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    credList.credential->certNum = 1;
    credList.credential->keyNum = 1;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(1));
    credList.credential->credData.size = 1;
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    Parcel reply;
    int32_t ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest001
* @tc.desc: test UnMarshalling
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest001, TestSize.Level0)
{
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    credList.credential->isExist = 1;
    (void)memset_s(credList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(credList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(credList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    credList.credential->certNum = 1;
    credList.credential->keyNum = 1;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(1));
    credList.credential->credData.size = 1;
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    Parcel reply;
    int32_t ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, true);
    struct CredentialDetailListParcelInfo *credentialDetailListParcelInfo2 =
        CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_NE(credentialDetailListParcelInfo2, nullptr);
    CM_FREE_BLOB(credList.credential->credData);
    CM_FREE_PTR(credList.credential);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest002
* @tc.desc: test UnMarshalling abnormal
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest002, TestSize.Level0)
{
    struct CredentialDetailList *credListAbnormal = nullptr;
    CmFreeUkeyCertList(credListAbnormal);
    EXPECT_EQ(credListAbnormal, nullptr);
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    credList.credential->isExist = 1;
    (void)memset_s(credList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(credList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(credList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    credList.credential->certNum = 1;
    credList.credential->keyNum = 1;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(INVALID_LEN));
    credList.credential->credData.size = INVALID_LEN;
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    Parcel reply;
    int32_t ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, true);
    struct CredentialDetailListParcelInfo *credentialDetailListParcelInfo2 =
        CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(credentialDetailListParcelInfo2, nullptr);
    CM_FREE_BLOB(credList.credential->credData);
    CM_FREE_PTR(credList.credential);
}


/**
* @tc.name: CredentialDetailListTransportTest001
* @tc.desc: test TransportCredential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListTransportTest001, TestSize.Level0)
{
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    struct CredentialDetailList destParcelInfo;
    int32_t ret = credentialDetailListParcelInfo.TransPortUkeyCertList(&destParcelInfo);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    struct CredentialDetailList credList = {0, nullptr};
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    credList.credential->isExist = 1;
    (void)memset_s(credList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(credList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(credList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    credList.credential->certNum = 1;
    credList.credential->keyNum = 1;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(1));
    credList.credential->credData.size = 1;
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    ret = credentialDetailListParcelInfo.TransPortUkeyCertList(&destParcelInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
    CmFreeUkeyCertList(&credList);
    CmFreeUkeyCertList(&destParcelInfo);
}
} // end of namespace
