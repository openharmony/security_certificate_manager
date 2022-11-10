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

#include "cm_param.h"
#include "cm_type.h"

using namespace testing::ext;
namespace {
class CmParamTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmParamTest::SetUpTestCase(void)
{
}

void CmParamTest::TearDownTestCase(void)
{
}

void CmParamTest::SetUp()
{
}

void CmParamTest::TearDown()
{
}

/**
* @tc.name: CmParamTest001
* @tc.desc: test CmInitParamSet nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest001, TestSize.Level0)
{
    int32_t ret = CmInitParamSet(nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmParamTest002
* @tc.desc: test CmAddParams paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest002, TestSize.Level0)
{
    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    int32_t ret = CmAddParams(nullptr, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmParamTest003
* @tc.desc: test CmAddParams param is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest003, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmAddParams(paramSet, nullptr, 0);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest004
* @tc.desc: test CmAddParams paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest004, TestSize.Level0)
{
    struct CmParamSet paramSet = { CM_PARAM_SET_MAX_SIZE + 1, 0 };
    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    int32_t ret = CmAddParams(&paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmParamTest005
* @tc.desc: test CmAddParams param cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest005, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CmAddParams(paramSet, param, CM_DEFAULT_PARAM_CNT + 1);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest006
* @tc.desc: test CmAddParams paramSet cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest006, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    paramSet->paramsCnt = CM_DEFAULT_PARAM_CNT;

    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CmAddParams(paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest007
* @tc.desc: test CmAddParams param tag blob.data is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest007, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmBlob tempBlob = { 0, nullptr };
    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = tempBlob },
    };
    ret = CmAddParams(paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest008
* @tc.desc: test CmAddParams param tag blob.size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest008, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test";
    struct CmBlob tempBlob = { UINT32_MAX, tempBuf };
    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = tempBlob },
    };
    ret = CmAddParams(paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest009
* @tc.desc: test CmGetParam paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest009, TestSize.Level0)
{
    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(nullptr, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmParamTest010
* @tc.desc: test CmGetParam out param is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest010, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmGetParam(paramSet, CM_TAG_PARAM0_BUFFER, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest011
* @tc.desc: test CmGetParam paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest011, TestSize.Level0)
{
    struct CmParamSet paramSet = {CM_PARAM_SET_MAX_SIZE + 1, 1 };
    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(&paramSet, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmParamTest012
* @tc.desc: test CmGetParam paramSet size is invalid (smaller than struct size)
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest012, TestSize.Level0)
{
    struct CmParamSet paramSet = { sizeof(struct CmParamSet) - 1, 1 };
    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(&paramSet, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmParamTest013
* @tc.desc: test CmGetParam paramSet cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest013, TestSize.Level0)
{
    struct CmParamSet paramSet = { sizeof(struct CmParamSet), 1 };
    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(&paramSet, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

static void ConstrutParamSet(struct CmParamSet **paramSet)
{
    int32_t ret = CmInitParamSet(paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CmAddParams(*paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmBuildParamSet(paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmParamTest014
* @tc.desc: test CmGetParam normal testcase
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest014, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    ConstrutParamSet(&paramSet);

    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(paramSet, CM_TAG_PARAM0_BOOL, &param);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest015
* @tc.desc: test CmGetParam param not exist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest015, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    ConstrutParamSet(&paramSet);

    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(paramSet, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_PARAM_NOT_EXIST);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest016
* @tc.desc: test CmFreeParamSet paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest016, TestSize.Level0)
{
    CmFreeParamSet(nullptr);
}

/**
* @tc.name: CmParamTest017
* @tc.desc: test CmBuildParamSet paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest017, TestSize.Level0)
{
    int32_t ret = CmBuildParamSet(nullptr);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
}

/**
* @tc.name: CmParamTest018
* @tc.desc: test CmBuildParamSet *paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest018, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
}

/**
* @tc.name: CmParamTest019
* @tc.desc: test CmBuildParamSet paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest019, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (ret != CM_SUCCESS) {
        return;
    }
    paramSet->paramSetSize = sizeof(struct CmParamSet) - 1;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest020
* @tc.desc: test CmBuildParamSet param tag blob size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest020, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (ret != CM_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test020";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam);
    paramSet->params[0].tag = CM_TAG_PARAM1_BUFFER;
    paramSet->params[0].blob.size = UINT32_MAX;
    paramSet->params[0].blob.data = tempBuf;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest021
* @tc.desc: test CmBuildParamSet param tag blob data is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest021, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (ret != CM_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test021";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf);
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = nullptr;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_OPERATION);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest022
* @tc.desc: test CmBuildParamSet paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest022, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (ret != CM_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test022";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf) + 1; /* invalid size */
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = tempBuf;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest023
* @tc.desc: test CmGetParamSet paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest023, TestSize.Level0)
{
    struct CmParamSet *outParamSet = nullptr;
    int32_t ret = CmGetParamSet(nullptr, 0, &outParamSet);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
}

/**
* @tc.name: CmParamTest024
* @tc.desc: test CmGetParamSet normal testcase
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest024, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    ConstrutParamSet(&paramSet);
    if (paramSet == nullptr) {
        return;
    }

    struct CmParamSet *outParamSet = nullptr;
    int32_t ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest025
* @tc.desc: test CmGetParamSet param tag blob size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest025, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (ret != CM_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test025";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam);
    paramSet->params[0].tag = CM_TAG_PARAM1_BUFFER;
    paramSet->params[0].blob.size = UINT32_MAX;
    paramSet->params[0].blob.data = tempBuf;

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest026
* @tc.desc: test CmGetParamSet paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest026, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (ret != CM_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test026";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf) + 1; /* invalid size */
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = tempBuf;

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest027
* @tc.desc: test CmGetParamSet normal testcase tag include blob
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest027, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (ret != CM_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test027";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf);
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = tempBuf;

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}
} // end of namespace
