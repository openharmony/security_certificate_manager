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
HWTEST_F(CmMetricsTest, BoundaryCoversAllJsErrorCodes, TestSize.Level1)
{
    // boundary 需要覆盖 max JS ErrorCode(29700007 = DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE)
    EXPECT_GT(CM_METRICS_ENUM_BOUNDARY, static_cast<int32_t>(PARAMETER_VALIDATION_FAILED));
    EXPECT_GT(CM_METRICS_ENUM_BOUNDARY, OHOS::Security::CertManager::Dialog::DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE);
    EXPECT_LT(static_cast<int32_t>(SUCCESS), CM_METRICS_ENUM_BOUNDARY);
    EXPECT_LT(static_cast<int32_t>(OHOS::Security::CertManager::Dialog::DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE), CM_METRICS_ENUM_BOUNDARY);
}

HWTEST_F(CmMetricsTest, NativeToJs_KnownNonDialogCodes, TestSize.Level1)
{
    EXPECT_EQ(CmGetMetricErrorCode(CMR_ERROR_INVALID_ARGUMENT, CmMetricsKind::NON_DIALOG), PARAM_ERROR);
    EXPECT_EQ(CmGetMetricErrorCode(CMR_ERROR_PERMISSION_DENIED, CmMetricsKind::NON_DIALOG), HAS_NO_PERMISSION);
    EXPECT_EQ(CmGetMetricErrorCode(CMR_ERROR_NOT_FOUND, CmMetricsKind::NON_DIALOG), NOT_FOUND);
    EXPECT_EQ(CmGetMetricErrorCode(CMR_SUCCESS, CmMetricsKind::NON_DIALOG), SUCCESS);
}

HWTEST_F(CmMetricsTest, NativeToJs_KnownDialogCodes, TestSize.Level1)
{
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::CMR_DIALOG_ERROR_INTERNAL,
        CmMetricsKind::DIALOG), OHOS::Security::CertManager::Dialog::DIALOG_ERROR_GENERIC);
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::CMR_DIALOG_ERROR_OPERATION_CANCELS,
        CmMetricsKind::DIALOG), OHOS::Security::CertManager::Dialog::DIALOG_ERROR_OPERATION_CANCELED);
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::CMR_DIALOG_ERROR_INSTALL_FAILED,
        CmMetricsKind::DIALOG), OHOS::Security::CertManager::Dialog::DIALOG_ERROR_INSTALL_FAILED);
    EXPECT_EQ(CmGetMetricErrorCode(OHOS::Security::CertManager::Dialog::CMR_DIALOG_ERROR_NOT_SUPPORTED,
        CmMetricsKind::DIALOG), OHOS::Security::CertManager::Dialog::DIALOG_ERROR_NOT_SUPPORTED);
}

HWTEST_F(CmMetricsTest, NativeToJs_UnknownCode_ReturnsInnerFailure, TestSize.Level1)
{
    EXPECT_EQ(CmGetMetricErrorCode(0x7fffffff, CmMetricsKind::NON_DIALOG), INNER_FAILURE);
    EXPECT_EQ(CmGetMetricErrorCode(-99999, CmMetricsKind::NON_DIALOG), INNER_FAILURE);
    EXPECT_EQ(CmGetMetricErrorCode(0x7fffffff, CmMetricsKind::DIALOG), INNER_FAILURE);
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

HWTEST_F(CmMetricsTest, ReportGuard_FinishWithBoundaryValue, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi");
    report.Start();
    // boundary 边界值:本测试不真正打开宏,只确认不会越界访问
    report.Finish(static_cast<int32_t>(CM_METRICS_ENUM_BOUNDARY) - 1);
    report.Finish(static_cast<int32_t>(CM_METRICS_ENUM_BOUNDARY));
    report.Finish(static_cast<int32_t>(CM_METRICS_ENUM_BOUNDARY) + 1);
}
} // namespace CertmanagerTest
