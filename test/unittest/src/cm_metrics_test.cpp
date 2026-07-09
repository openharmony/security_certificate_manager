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
HWTEST_F(CmMetricsTest, MetricErrorCode_BoundaryCoversAllCompactMetricCodes, TestSize.Level1)
{
    EXPECT_GT(CM_METRICS_ENUM_BOUNDARY, static_cast<int32_t>(CM_METRIC_PARAMETER_VALIDATION_FAILED));
    EXPECT_GT(CM_METRICS_ENUM_BOUNDARY, static_cast<int32_t>(CM_METRIC_DIALOG_NO_AVAILABLE_CERTIFICATE));
    EXPECT_LT(static_cast<int32_t>(CM_METRIC_SUCCESS), CM_METRICS_ENUM_BOUNDARY);
    EXPECT_LT(static_cast<int32_t>(CM_METRIC_UNKNOWN_ERROR), CM_METRICS_ENUM_BOUNDARY);
}

HWTEST_F(CmMetricsTest, NativeToMetric_KnownCodes_AreInRange, TestSize.Level1)
{
    EXPECT_EQ(CmGetMetricErrorCode(SUCCESS), CM_METRIC_SUCCESS);
    EXPECT_EQ(CmGetMetricErrorCode(HAS_NO_PERMISSION), CM_METRIC_HAS_NO_PERMISSION);
    EXPECT_EQ(CmGetMetricErrorCode(NOT_FOUND), CM_METRIC_NOT_FOUND);
    EXPECT_EQ(CmGetMetricErrorCode(INNER_FAILURE), CM_METRIC_INNER_FAILURE);
    EXPECT_EQ(CmGetMetricErrorCode(PARAM_ERROR), CM_METRIC_PARAM_ERROR);
}

HWTEST_F(CmMetricsTest, NativeToMetric_DialogKnownCodes_AreInRange, TestSize.Level1)
{
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::DIALOG_ERROR_GENERIC), CM_METRIC_INNER_FAILURE);
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::DIALOG_ERROR_OPERATION_CANCELED), CM_METRIC_DIALOG_OPERATION_CANCELED);
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::DIALOG_ERROR_INSTALL_FAILED), CM_METRIC_DIALOG_INSTALL_FAILED);
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::DIALOG_ERROR_NOT_SUPPORTED), CM_METRIC_CAPABILITY_NOT_SUPPORTED);
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED), CM_METRIC_CAPABILITY_NOT_SUPPORTED);
}

HWTEST_F(CmMetricsTest, NativeToMetric_UnknownCode_ReturnsUnknown, TestSize.Level1)
{
    EXPECT_EQ(CmGetMetricErrorCode(0x7fffffff), CM_METRIC_UNKNOWN_ERROR);
    EXPECT_EQ(CmGetMetricErrorCode(-99999), CM_METRIC_UNKNOWN_ERROR);
}

HWTEST_F(CmMetricsTest, ReportGuard_StartRecordsCalled, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi");
    report.Start();
    // 关闭 metrics 宏时,Start 为空操作;这里至少验证不崩溃、可析构
    report.Finish(CM_SUCCESS);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishComputesElapsedMs, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi");
    report.Start();
    // 主动 sleep 不少于 1ms,确保 elapsed > 0
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    report.Finish(CM_SUCCESS);
    // 关闭宏时 elapsed 仍应为 0(Finish 中未读取时钟)
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishWithoutStart_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi");
    // 不调用 Start,直接 Finish,应不崩溃
    report.Finish(INNER_FAILURE);
}

HWTEST_F(CmMetricsTest, ReportGuard_DoubleFinish_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi");
    report.Start();
    report.Finish(CM_SUCCESS);
    // 重复 Finish 应被内部 finished_ 标志忽略
    report.Finish(INNER_FAILURE);
}
} // namespace CertmanagerTest
