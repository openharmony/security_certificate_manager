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

using namespace testing::ext;
namespace {
static constexpr uint32_t DEFAULT_SIZE = 1024;
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }

    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }
    int32_t ret = CmCertificateListUnpackFromService(&outData, &certificateList);
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
    if (ConstructCertBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
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
    if (ConstructCertBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
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
    if (ConstructCertBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
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
    if (ConstructCertBuf(&infoLen, &outData) != CM_SUCCESS) {
        return;
    }

    int32_t ret = CmCertificateInfoUnpackFromService(&outData, &certUri, &certInfoStr);
    EXPECT_NE(ret, CM_SUCCESS);
}
}
// end of namespace
