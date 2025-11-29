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

#include "cm_log.h"

#include "securec.h"

#include "cm_module_cert_data.h"
#include "cm_ipc_client_serialization.h"
#include "cm_ipc_service_serialization.h"
#include "cm_param.h"

using namespace testing::ext;
namespace {
static constexpr uint32_t DEFAULT_SIZE = 2048;
class CmLogTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmLogTest::SetUpTestCase(void)
{
}

void CmLogTest::TearDownTestCase(void)
{
}

void CmLogTest::SetUp()
{
}

void CmLogTest::TearDown()
{
}

struct CertInfoLen {
    bool isCertCountValid;
    uint32_t certCount;
    bool isSubjectNameLenValid;
    uint32_t subjectNameLen;
    bool isStatusValid;
    uint32_t status;
    bool isUriLenValid;
    uint32_t uriLen;
    bool isAliasLenValid;
    uint32_t aliasLen;
};

static int32_t ConstructBuf(const struct CertInfoLen *input, struct CmBlob *outData)
{
    /* construct certCount */
    uint32_t offset = 0;
    if (!input->isCertCountValid) {
        outData->size = sizeof(input->certCount) - 1;
        return CM_SUCCESS;
    }
    if (memcpy_s(outData->data + offset, outData->size - offset, &input->certCount, sizeof(input->certCount)) != EOK) {
        return CM_FAILURE;
    }
    offset += sizeof(input->certCount);

    /* construct subjectName */
    if (!input->isSubjectNameLenValid) {
        outData->size = offset;
        return CM_SUCCESS;
    }
    if (memcpy_s(outData->data + offset, outData->size - offset, &input->subjectNameLen,
        sizeof(input->subjectNameLen)) != EOK) {
        return CM_FAILURE;
    }
    offset += sizeof(input->subjectNameLen) + ALIGN_SIZE(input->subjectNameLen); /* len valid */

    /* construct status */
    if (!input->isStatusValid) {
        outData->size = offset;
        return CM_SUCCESS;
    }
    if (memcpy_s(outData->data + offset, outData->size - offset, &input->status, sizeof(input->status)) != EOK) {
        return CM_FAILURE;
    }
    offset += sizeof(input->status);

    /* construct uri */
    if (!input->isUriLenValid) {
        outData->size = offset;
        return CM_SUCCESS;
    }
    if (memcpy_s(outData->data + offset, outData->size - offset, &input->uriLen, sizeof(input->uriLen)) != EOK) {
        return CM_FAILURE;
    }
    offset += sizeof(input->uriLen) + ALIGN_SIZE(input->uriLen); /* len valid */

    /* construct alias */
    if (!input->isAliasLenValid) {
        outData->size = offset;
        return CM_SUCCESS;
    }
    if (memcpy_s(outData->data + offset, outData->size - offset, &input->aliasLen, sizeof(input->aliasLen)) != EOK) {
        return CM_FAILURE;
    }
    offset += sizeof(input->aliasLen) + ALIGN_SIZE(input->aliasLen);
    outData->size = offset;
    return CM_SUCCESS;
}

static int32_t ConstructCertBuf(const struct CertInfoLen *input, struct CmBlob *outBlob)
{
    /* copy certInfo data */
    uint32_t offset = 0;
    uint32_t certSize = sizeof(g_ed25519CaCert);
    if (memcpy_s(outBlob->data + offset, outBlob->size - offset, &certSize, sizeof(certSize)) != EOK) {
        return CM_FAILURE;
    }
    offset += sizeof(certSize);
    if (memcpy_s(outBlob->data + offset, outBlob->size - offset, g_ed25519CaCert, sizeof(g_ed25519CaCert)) != EOK) {
        return CM_FAILURE;
    }
    offset += ALIGN_SIZE(sizeof(g_ed25519CaCert));

    /* copy status */
    if (!input->isStatusValid) {
        outBlob->size = offset;
        return CM_SUCCESS;
    }
    if (memcpy_s(outBlob->data + offset, outBlob->size - offset, &input->status, sizeof(input->status)) != EOK) {
        return CM_FAILURE;
    }
    offset += sizeof(input->status);

    /* copy certAlias */
    if (!input->isAliasLenValid) {
        outBlob->size = offset;
        return CM_SUCCESS;
    }
    if (memcpy_s(outBlob->data + offset, outBlob->size - offset, &input->aliasLen, sizeof(input->aliasLen)) != EOK) {
        return CM_FAILURE;
    }
    offset += sizeof(input->aliasLen) + ALIGN_SIZE(input->aliasLen);
    outBlob->size = offset;
    return CM_SUCCESS;
}

/**
* @tc.name: CmIpcClientTest004
* @tc.desc: TestIpcClient: GetUint32FromBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest004, TestSize.Level0)
{
    /* Test Log Warn */
    CM_LOG_W("this is test for log");

    /* Test Log ID INVALID */
    CmLog(CM_LOG_LEVEL_D + 1, __func__, __LINE__, "this is test for default branch");

    /* Test Log info length more than 512 */
    CM_LOG_W("MoreThan512Bytes................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "..................................................................");

    uint8_t srcData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    struct CmBlob srcBlob = { sizeof(srcData), srcData };
    uint32_t value = 0;
    uint32_t srcOffset = sizeof(srcData) + 1; /* srcOffset invalid */
    int32_t ret = GetUint32FromBuffer(&value, &srcBlob, &srcOffset);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest05
* @tc.desc: TestIpcClient: GetUint32FromBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest005, TestSize.Level0)
{
    uint8_t srcData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    struct CmBlob srcBlob = { sizeof(srcData), srcData };
    uint32_t value = 0;
    uint32_t srcOffset = sizeof(srcData) - 1; /* srcOffset invalid */
    int32_t ret = GetUint32FromBuffer(&value, &srcBlob, &srcOffset);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest006
* @tc.desc: TestIpcClient: CmGetBlobFromBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest006, TestSize.Level0)
{
    uint8_t srcData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    struct CmBlob srcBlob = { sizeof(srcData), srcData };
    struct CmBlob blob = { 0, nullptr };
    uint32_t srcOffset = sizeof(srcData) + 1; /* srcOffset invalid */
    int32_t ret = CmGetBlobFromBuffer(&blob, &srcBlob, &srcOffset);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest007
* @tc.desc: TestIpcClient: CmGetBlobFromBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest007, TestSize.Level0)
{
    uint8_t srcData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    struct CmBlob srcBlob = { sizeof(srcData), srcData };
    struct CmBlob blob = { 0, nullptr };
    uint32_t srcOffset = sizeof(srcData) - 1; /* srcOffset invalid */
    int32_t ret = CmGetBlobFromBuffer(&blob, &srcBlob, &srcOffset);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest008
* @tc.desc: TestIpcClient: CmGetBlobFromBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest008, TestSize.Level0)
{
    uint8_t srcData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    struct CmBlob srcBlob = { sizeof(srcData), srcData }; /* srcData first 4 bytes invalid */
    struct CmBlob blob = { 0, nullptr };
    uint32_t srcOffset = 0;
    int32_t ret = CmGetBlobFromBuffer(&blob, &srcBlob, &srcOffset);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest009
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest009, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };
    int32_t ret = CmCertificateListUnpackFromService(nullptr, &certificateList); /* outData invalid */
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest010
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest010, TestSize.Level0)
{
    struct CmBlob outData = { 1, nullptr }; /* outData data invalid */
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest011
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest011, TestSize.Level0)
{
    uint8_t outDataBuf[] = { 0xaa };
    struct CmBlob outData = { 0, outDataBuf }; /* outData size invalid */
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest012
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest012, TestSize.Level0)
{
    uint8_t outDataBuf[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };
    int32_t ret = CmCertificateListUnpackFromService(&outData, nullptr); /* certificateList invalid */
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest013
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest013, TestSize.Level0)
{
    uint8_t outDataBuf[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };
    struct CertList certificateList = { 0, nullptr };
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList); /* abstract invalid */
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest014
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest014, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* get certCount failed */
    struct CertInfoLen infoLen = { false, 0, false, 0, false, 0, false, 0, false, 0 };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest015
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest015, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* certCount invalid */
    struct CertInfoLen infoLen = { true, certificateList.certsCount + 1, false, 0, false, 0, false, 0, false, 0 };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest016
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest016, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* get subjectNameLen failed */
    struct CertInfoLen infoLen = { true, certificateList.certsCount, false, 0, false, 0, false, 0, false, 0 };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest017
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest017, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* subjectNameLen invalid */
    struct CertInfoLen infoLen = {
        true, certificateList.certsCount, true, MAX_LEN_SUBJECT_NAME + 1, false, 0, false, 0, false, 0
    };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest018
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest018, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* get status failed */
    struct CertInfoLen infoLen = {
        true, certificateList.certsCount, true, MAX_LEN_SUBJECT_NAME, false, 0, false, 0, false, 0
    };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest019
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest019, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* get uriLen failed */
    struct CertInfoLen infoLen = {
        true, certificateList.certsCount, true, MAX_LEN_SUBJECT_NAME, true, 0, false, 0, false, 0
    };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest020
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest020, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* uriLen invalid */
    struct CertInfoLen infoLen = {
        true, certificateList.certsCount, true, MAX_LEN_SUBJECT_NAME, true, 0, true, MAX_LEN_URI + 1, false, 0
    };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest021
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest021, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* get aliasLen failed */
    struct CertInfoLen infoLen = {
        true, certificateList.certsCount, true, MAX_LEN_SUBJECT_NAME, true, 0, true, MAX_LEN_URI, false, 0
    };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest022
* @tc.desc: TestIpcClient: CmCertificateListUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest022, TestSize.Level0)
{
    struct CertAbstract abstract = { {0}, {0}, false, {0} };
    struct CertList certificateList = { 1, &abstract };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* aliasLen invalid */
    struct CertInfoLen infoLen = {
        true, 1, true, MAX_LEN_SUBJECT_NAME, true, 0, true, MAX_LEN_URI, true, MAX_LEN_CERT_ALIAS + 1
    };
    int32_t ret = ConstructBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateListUnpackFromService(&outData, &certificateList);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest023
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest023, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[DEFAULT_SIZE] = {0};
    certInfoStr.certInfo.size = 0; /* certInfo size invalid */
    certInfoStr.certInfo.data = certInfoData;

    uint8_t certUriData[] = "oh:t=ak;o=Test023;a=100;u=100";
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest024
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest024, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[DEFAULT_SIZE] = {0};
    certInfoStr.certInfo.size = sizeof(certInfoData);
    certInfoStr.certInfo.data = nullptr; /* certInfo data invalid */

    uint8_t certUriData[] = "oh:t=ak;o=Test024;a=100;u=100";
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[DEFAULT_SIZE] = { 0 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest025
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest025, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[] = { 0x01, 0x02, 0x03 };
    certInfoStr.certInfo.size = sizeof(certInfoData);
    certInfoStr.certInfo.data = certInfoData;

    uint8_t certUriData[] = "oh:t=ak;o=Test025;a=100;u=100";
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[] = { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf }; /* copy certInfo data failed */

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest026
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest026, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[DEFAULT_SIZE] = {0};
    certInfoStr.certInfo.size = sizeof(certInfoData);
    certInfoStr.certInfo.data = certInfoData;

    uint8_t certUriData[] = "oh:t=ak;o=Test026;a=100;u=100";
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[DEFAULT_SIZE] = {0};
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf }; /* invalid certInfo */

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest027
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest027, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[DEFAULT_SIZE] = {0};
    certInfoStr.certInfo.size = sizeof(certInfoData);
    certInfoStr.certInfo.data = certInfoData;

    uint8_t certUriData[] = "oh:t=ak;o=Test027;a=100;u=100";
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[] = { 0x01, 0x02, 0x03 }; /* invalid certInfo size */
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest028
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest028, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[DEFAULT_SIZE] = {0};
    certInfoStr.certInfo.size = sizeof(certInfoData);
    certInfoStr.certInfo.data = certInfoData;

    uint8_t certUriData[] = "oh:t=ak;o=Test028;a=100;u=100";
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[DEFAULT_SIZE] = {0};
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };
    struct CertInfoLen infoLen = { false, 0, false, 0, false, 0, false, 0, false, 0 }; /* get status failed */
    int32_t ret = ConstructCertBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest029
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest029, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[DEFAULT_SIZE] = {0};
    certInfoStr.certInfo.size = sizeof(certInfoData);
    certInfoStr.certInfo.data = certInfoData;

    uint8_t certUriData[] = "oh:t=ak;o=Test029;a=100;u=100";
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[DEFAULT_SIZE] = {0};
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };
    struct CertInfoLen infoLen = { false, 0, false, 0, true, 0, false, 0, false, 0 }; /* get certAliasLen failed */
    int32_t ret = ConstructCertBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest030
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest030, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[DEFAULT_SIZE] = {0};
    certInfoStr.certInfo.size = sizeof(certInfoData);
    certInfoStr.certInfo.data = certInfoData;

    uint8_t certUriData[] = "oh:t=ak;o=Test030;a=100;u=100";
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[DEFAULT_SIZE] = {0};
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };

    /* certAlias len invalid */
    struct CertInfoLen infoLen = { false, 0, false, 0, true, 0, false, 0, true, MAX_LEN_CERT_ALIAS + 1 };
    int32_t ret = ConstructCertBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest031
* @tc.desc: TestIpcClient: CmCertificateInfoUnpackFromService
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest031, TestSize.Level0)
{
    struct CertInfo certInfoStr;
    (void)memset_s(&certInfoStr, sizeof(certInfoStr), 0, sizeof(certInfoStr));

    uint8_t certInfoData[DEFAULT_SIZE] = {0};
    certInfoStr.certInfo.size = sizeof(certInfoData);
    certInfoStr.certInfo.data = certInfoData;

    uint8_t certUriData[MAX_LEN_URI + 1] = "oh:t=ak;o=Test031;a=100;u=100"; /* uri len invalid */
    struct CmBlob certUri = { sizeof(certUriData), certUriData };

    uint8_t outDataBuf[DEFAULT_SIZE] = {0};
    struct CmBlob outData = { sizeof(outDataBuf), outDataBuf };
    struct CertInfoLen infoLen = { false, 0, false, 0, true, 0, false, 0, true, MAX_LEN_CERT_ALIAS };
    int32_t ret = ConstructCertBuf(&infoLen, &outData);
    ASSERT_EQ(ret, CM_SUCCESS);

    ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest032
* @tc.desc: TestIpcClient: CopyUint32ToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest032, TestSize.Level0)
{
    uint32_t value = 12345;
    struct CmBlob *destBlob = nullptr;
    uint32_t *destOffset = nullptr;
    int32_t ret = CopyUint32ToBuffer(value, destBlob, destOffset);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmIpcClientTest033
* @tc.desc: TestIpcClient: CopyUint32ToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest033, TestSize.Level0)
{
    uint8_t certUriData[] = "oh:t=ak;o=Test031;a=100;u=100";
    struct CmBlob destBlob = { sizeof(certUriData), certUriData };
    uint32_t destOffset = MAX_LEN_URI;
    uint32_t value = 12345;
    int32_t ret = CopyUint32ToBuffer(value, &destBlob, &destOffset);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
}

/**
* @tc.name: CmIpcClientTest034
* @tc.desc: TestIpcClient: CopyUint32ToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest034, TestSize.Level0)
{
    char data1[] = "1234";  // 大小 4 字节（刚好容纳 uint32_t）
    struct CmBlob dest_blob = {
        .size = sizeof(data1),    // 4 字节，满足 sizeof(uint32_t)
        .data = (uint8_t *)data1  // 强制转换为 uint8_t*（实际仍为只读）
    };

    // 2. 构造其他参数（绕过前两个错误分支）
    uint32_t value = 0x12345678;  // 要拷贝的值
    uint32_t dest_offset = 0;     // 初始偏移 0，剩余空间 4 字节（足够）
    int32_t ret = CopyUint32ToBuffer(value, &dest_blob, &dest_offset);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest035
* @tc.desc: TestIpcClient: CopyUint32ToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest035, TestSize.Level0)
{
    uint32_t buffer_size = 1024;  // 缓冲区总大小（远大于 sizeof(uint32_t)）
    uint8_t *writable_data = (uint8_t *)malloc(buffer_size);
    // 2. 构造合法的 CmBlob 结构体（满足 CmCheckBlob 校验）
    struct CmBlob dest_blob = {
        .size = buffer_size,    // 总大小充足
        .data = writable_data   // 可写内存指针
    };

    // 3. 构造其他参数（确保无参数错误）
    uint32_t value = 0xABCD1234;  // 要拷贝的 32 位无符号整数
    uint32_t dest_offset = 0;     // 初始偏移量（从缓冲区起始位置开始拷贝）
    int32_t ret = CopyUint32ToBuffer(value, &dest_blob, &dest_offset);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest036
* @tc.desc: TestIpcClient: CopyBlobToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest036, TestSize.Level0)
{
    uint8_t src_data[4] = {0x11, 0x22, 0x33, 0x44};
    struct CmBlob src_blob = {.size = 4, .data = src_data};

    uint8_t dest_data[100];
    struct CmBlob dest_blob = {.size = 100, .data = dest_data};

    // 关键：destOffset 传 NULL
    int32_t ret = CopyBlobToBuffer(&src_blob, &dest_blob, NULL);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmIpcClientTest037
* @tc.desc: TestIpcClient: CopyBlobToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest037, TestSize.Level0)
{
    uint8_t src_data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    struct CmBlob src_blob = {.size = 5, .data = src_data};

    // 目标 blob：总大小=10 字节，初始偏移=0，剩余空间=10 < 12，触发不足
    uint8_t dest_data[10];
    struct CmBlob dest_blob = {.size = 10, .data = dest_data};
    uint32_t dest_offset = 0;

    int32_t ret = CopyBlobToBuffer(&src_blob, &dest_blob, &dest_offset);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
}

/**
* @tc.name: CmIpcClientTest038
* @tc.desc: TestIpcClient: CopyBlobToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest038, TestSize.Level0)
{
    uint8_t src_data[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    struct CmBlob src_blob = {.size = 4, .data = src_data};

    // 目标 blob：data 指向只读内存（字符串常量区），拷贝 blob->size 时失败
    char read_only_dest[] = "1234567890";  // 只读，大小11字节（足够空间，但不可写）
    struct CmBlob dest_blob = {.size = sizeof(read_only_dest), .data = (uint8_t *)read_only_dest};
    uint32_t dest_offset = 0;

    int32_t ret = CopyBlobToBuffer(&src_blob, &dest_blob, &dest_offset);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest039
* @tc.desc: TestIpcClient: CopyBlobToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest039, TestSize.Level0)
{
    uint8_t src_data[4] = {0xEE, 0xFF, 0x00, 0x11};
    struct CmBlob src_blob = {.size = 4, .data = src_data};

    // 目标 blob：前 4 字节可写（堆内存），后 4 字节只读（字符串常量区）
    // 第一个 memcpy_s（拷贝 size）成功，第二个 memcpy_s（拷贝 data）失败
    uint8_t *writable_part = (uint8_t *)malloc(4);  // 可写的前 4 字节
    char read_only_part[] = "abcd";           // 只读的后 4 字节
    struct CmBlob dest_blob = {
        .size = 4 + sizeof(read_only_part),  // 总大小 8 字节
        .data = writable_part                // 起始地址为可写内存
    };
    uint32_t dest_offset = 0;

    // 关键：第一个 memcpy_s 写入 writable_part（成功），第二个 memcpy_s 写入 writable_part+4（只读区域，失败）
    int32_t ret = CopyBlobToBuffer(&src_blob, &dest_blob, &dest_offset);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest040
* @tc.desc: TestIpcClient: CopyBlobToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest040, TestSize.Level0)
{
    uint8_t src_data[4] = {0xEE, 0xFF, 0x00, 0x11};
    struct CmBlob src_blob = {.size = 4, .data = src_data};

    // 目标 blob：前 4 字节可写（堆内存），后 4 字节只读（字符串常量区）
    // 第一个 memcpy_s（拷贝 size）成功，第二个 memcpy_s（拷贝 data）失败
    uint8_t *writable_part = (uint8_t *)malloc(4);  // 可写的前 4 字节
    char read_only_part[] = "abcd";           // 只读的后 4 字节
    struct CmBlob dest_blob = {
        .size = 4 + sizeof(read_only_part),  // 总大小 8 字节
        .data = writable_part                // 起始地址为可写内存
    };
    uint32_t dest_offset = 0;

    // 关键：第一个 memcpy_s 写入 writable_part（成功），第二个 memcpy_s 写入 writable_part+4（只读区域，失败）
    int32_t ret = CopyBlobToBuffer(&src_blob, &dest_blob, &dest_offset);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest041
* @tc.desc: TestIpcClient: CopyBlobToBuffer
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest041, TestSize.Level0)
{
    uint8_t src_data[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    struct CmBlob src_blob = {.size = 6, .data = src_data};

    // 目标 blob：可写堆内存，大小=100 字节（充足）
    uint8_t *dest_data = (uint8_t *)malloc(100);
    struct CmBlob dest_blob = {.size = 100, .data = dest_data};
    uint32_t dest_offset = 0;

    // 调用函数
    int32_t ret = CopyBlobToBuffer(&src_blob, &dest_blob, &dest_offset);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest042
* @tc.desc: TestIpcClient: CmParamSetToParams
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest042, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    struct CmParamOut *outParams = nullptr;
    const uint32_t cntCount = 1;
    uint32_t cnt = cntCount;
    int32_t ret = CmParamSetToParams(paramSet, outParams, cnt);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmIpcClientTest043
* @tc.desc: TestIpcClient: CmParamSetToParams
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest043, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmBlob keyUri = { 0, NULL };
    uint32_t store = CM_CREDENTIAL_STORE;

    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
    };
    uint32_t cnt = 0;
    ret = CmParamSetToParams(paramSet, params, cnt);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmIpcClientTest044
* @tc.desc: TestIpcClient: CmParamSetToParams
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmIpcClientTest044, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmBlob keyUri = { 0, NULL };
    uint32_t store = CM_CREDENTIAL_STORE;

    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
    };
    uint32_t cnt = 1;
    ret = CmParamSetToParams(paramSet, params, cnt);
    EXPECT_EQ(ret, CMR_ERROR_PARAM_NOT_EXIST);
}
}
// end of namespace
