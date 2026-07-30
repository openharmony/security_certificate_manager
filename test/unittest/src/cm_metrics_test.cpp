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
HWTEST_F(CmMetricsTest, JsCodeMap_LookupKnownNonDialogCodes, TestSize.Level1)
{
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(CMR_ERROR_INVALID_ARGUMENT, NATIVE_CODE_TO_JS_CODE_MAP,
        CmMetricsKind::NON_DIALOG), PARAM_ERROR);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(CMR_ERROR_PERMISSION_DENIED, NATIVE_CODE_TO_JS_CODE_MAP,
        CmMetricsKind::NON_DIALOG), HAS_NO_PERMISSION);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(CMR_ERROR_NOT_FOUND, NATIVE_CODE_TO_JS_CODE_MAP,
        CmMetricsKind::NON_DIALOG), NOT_FOUND);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(CMR_SUCCESS, NATIVE_CODE_TO_JS_CODE_MAP,
        CmMetricsKind::NON_DIALOG), SUCCESS);
}

HWTEST_F(CmMetricsTest, JsCodeMap_LookupKnownDialogCodes, TestSize.Level1)
{
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(Dialog::CMR_DIALOG_ERROR_INTERNAL,
        Dialog::DIALOG_CODE_TO_JS_CODE_MAP, CmMetricsKind::DIALOG), Dialog::DIALOG_ERROR_GENERIC);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(Dialog::CMR_DIALOG_ERROR_OPERATION_CANCELS,
        Dialog::DIALOG_CODE_TO_JS_CODE_MAP, CmMetricsKind::DIALOG), Dialog::DIALOG_ERROR_OPERATION_CANCELED);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(Dialog::CMR_DIALOG_ERROR_INSTALL_FAILED,
        Dialog::DIALOG_CODE_TO_JS_CODE_MAP, CmMetricsKind::DIALOG), Dialog::DIALOG_ERROR_INSTALL_FAILED);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(Dialog::CMR_DIALOG_ERROR_NOT_SUPPORTED,
        Dialog::DIALOG_CODE_TO_JS_CODE_MAP, CmMetricsKind::DIALOG), Dialog::DIALOG_ERROR_NOT_SUPPORTED);
}

HWTEST_F(CmMetricsTest, JsCodeMap_UnknownCode_FallbackByKind, TestSize.Level1)
{
    // 找不到时按 kind 区分兜底:
    // - 非 DIALOG → 17500001 (= INNER_FAILURE)
    // - DIALOG     → 29700001 (= DIALOG_ERROR_GENERIC)
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(0x7fffffff, NATIVE_CODE_TO_JS_CODE_MAP,
        CmMetricsKind::NON_DIALOG), 17500001);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(-99999, NATIVE_CODE_TO_JS_CODE_MAP,
        CmMetricsKind::NON_DIALOG), 17500001);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(0x7fffffff, Dialog::DIALOG_CODE_TO_JS_CODE_MAP,
        CmMetricsKind::DIALOG), 29700001);
    EXPECT_EQ(CmGetMetricErrorCodeFromMap(-99999, Dialog::DIALOG_CODE_TO_JS_CODE_MAP,
        CmMetricsKind::DIALOG), 29700001);
}

HWTEST_F(CmMetricsTest, ReportGuard_StartRecordsCalled, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", NATIVE_CODE_TO_JS_CODE_MAP);
    report.Start();
    // 关闭 metrics 宏时,Start 为空操作;这里至少验证不崩溃、可析构
    report.Finish(CM_SUCCESS);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishComputesElapsedMs, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", NATIVE_CODE_TO_JS_CODE_MAP);
    report.Start();
    // 主动 sleep 不少于 1ms,确保 elapsed > 0
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    report.Finish(CM_SUCCESS);
    // 关闭宏时 elapsed 仍应为 0(Finish 中未读取时钟)
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishWithoutStart_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", NATIVE_CODE_TO_JS_CODE_MAP);
    // 不调用 Start,直接 Finish:Finish 内部自动补一次 Start,保证 BOOLEAN+ENUMERATION+TIMES 都上报
    report.Finish(INNER_FAILURE);
    // GetElapsedMs 在 finished_=true 后应返回 0
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishAutoStart_BoundaryValue, TestSize.Level1)
{
    // 异常分支:Start 没调过,Finish 触发自动 Start。验证 finish 后 finished_=true 且第二次 Finish 是 no-op
    CmMetricsReport report("UnitTestApi", NATIVE_CODE_TO_JS_CODE_MAP);
    report.Finish(CM_SUCCESS);
    // 第二次 Finish 应被 finished_ 标志拦截,不重复上报
    report.Finish(INNER_FAILURE);
}

HWTEST_F(CmMetricsTest, ReportGuard_DoubleFinish_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", NATIVE_CODE_TO_JS_CODE_MAP);
    report.Start();
    report.Finish(CM_SUCCESS);
    // 重复 Finish 应被内部 finished_ 标志忽略
    report.Finish(INNER_FAILURE);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishWithBoundaryValue, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", NATIVE_CODE_TO_JS_CODE_MAP);
    report.Start();
    // boundary 取 map size,边界值测试
    int32_t boundary = static_cast<int32_t>(NATIVE_CODE_TO_JS_CODE_MAP.size());
    report.Finish(boundary - 1);
    report.Finish(boundary);
    report.Finish(boundary + 1);
}
} // namespace CertmanagerTest
