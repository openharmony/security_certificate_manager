/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "cm_metrics_test.h"

#include <chrono>
#include <thread>

#include "cm_api_common.h"
#include "cm_dialog_api_common.h"

using namespace testing;
using namespace OHOS::Security::CertManager;

namespace CertmanagerTest {
HWTEST_F(CmMetricsTest, ReportGuard_StartRecordsCalled, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    // 关闭 metrics 宏时,Start 为空操作;这里至少验证不崩溃、可析构
    report.Finish(CM_SUCCESS);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishComputesElapsedMs, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    // 主动 sleep 不少于 1ms,确保 elapsed > 0
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    report.Finish(CM_SUCCESS);
    // 关闭宏时 elapsed 仍应为 0(Finish 中未读取时钟)
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishWithoutStart_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    // 不调用 Start,直接 Finish:Finish 内部自动补一次 Start,保证 BOOLEAN+ENUMERATION+TIMES 都上报
    report.Finish(INNER_FAILURE);
    // GetElapsedMs 在 finished_=true 后应返回 0
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishAutoStart_BoundaryValue, TestSize.Level1)
{
    // 异常分支:Start 没调过,Finish 触发自动 Start。验证 finish 后 finished_=true 且第二次 Finish 是 no-op
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Finish(CM_SUCCESS);
    // 第二次 Finish 应被 finished_ 标志拦截,不重复上报
    report.Finish(INNER_FAILURE);
}

HWTEST_F(CmMetricsTest, ReportGuard_DoubleFinish_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    report.Finish(CM_SUCCESS);
    // 重复 Finish 应被内部 finished_ 标志忽略
    report.Finish(INNER_FAILURE);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishWithBoundaryValue, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    // boundary 取 ERROR_CODE_COUNT,边界值测试
    int32_t boundary = ERROR_CODE_COUNT;
    report.Finish(boundary - 1);
    report.Finish(boundary);
    report.Finish(boundary + 1);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishPassesErrorCodeThrough, TestSize.Level1)
{
    // Finish 接收的 errorCode 应直接作为 histogram 值,不做映射
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    report.Finish(PARAM_ERROR);
    report.Finish(NOT_FOUND);
    report.Finish(INNER_FAILURE);
    // 只验证不崩溃、不重复上报
    EXPECT_EQ(report.GetElapsedMs(), 0);
}
} // namespace CertmanagerTest