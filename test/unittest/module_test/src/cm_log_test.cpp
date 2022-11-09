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

using namespace testing::ext;
namespace {
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

/**
* @tc.name: CmLogTest001
* @tc.desc: Test Log Warn
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmLogTest001, TestSize.Level0)
{
    CM_LOG_W("this is test for log");
}

/**
* @tc.name: CmLogTest002
* @tc.desc: Test Log ID INVALID
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmLogTest002, TestSize.Level0)
{
    CmLog(CM_LOG_LEVEL_D + 1, __func__, __LINE__, "this is test for default branch");
}

/**
* @tc.name: CmLogTest003
* @tc.desc: Test Log info length more than 512
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmLogTest, CmLogTest003, TestSize.Level0)
{
    CM_LOG_W("MoreThan512Bytes................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "..................................................................");
}
} // end of namespace
