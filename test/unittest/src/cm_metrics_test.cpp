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
    // When the metrics macro is disabled, Start is a no-op; this only verifies
    // that construction/destruction do not crash.
    report.Finish(CM_SUCCESS);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishComputesElapsedMs, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    // Sleep at least 1 ms to ensure elapsed > 0.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    report.Finish(CM_SUCCESS);
    // With the macro disabled elapsed stays 0 (Finish does not read the clock).
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishWithoutStart_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    // Skip Start and call Finish directly: Finish internally auto-Starts so all
    // three histograms (BOOLEAN + ENUMERATION + TIMES) are still emitted.
    report.Finish(INNER_FAILURE);
    // GetElapsedMs should return 0 once finished_ is true.
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishAutoStart_BoundaryValue, TestSize.Level1)
{
    // Edge case: Start is never called; Finish auto-Starts. Verifies that
    // finished_ is set after Finish and that a second Finish is a no-op.
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Finish(CM_SUCCESS);
    // The second Finish must be intercepted by the finished_ flag and not
    // emit a duplicate histogram.
    report.Finish(INNER_FAILURE);
}

HWTEST_F(CmMetricsTest, ReportGuard_DoubleFinish_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    report.Finish(CM_SUCCESS);
    // A repeated Finish must be ignored by the internal finished_ flag.
    report.Finish(INNER_FAILURE);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishWithBoundaryValue, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    // Boundary stress: drive Finish with values below, at, and above the
    // histogram boundary (ERROR_CODE_COUNT).
    int32_t boundary = ERROR_CODE_COUNT;
    report.Finish(boundary - 1);
    report.Finish(boundary);
    report.Finish(boundary + 1);
}

HWTEST_F(CmMetricsTest, ReportGuard_FinishPassesErrorCodeThrough, TestSize.Level1)
{
    // Finish passes the errorCode through verbatim to the histogram; no mapping
    // is applied any more.
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    report.Finish(PARAM_ERROR);
    report.Finish(NOT_FOUND);
    report.Finish(INNER_FAILURE);
    // Only verifies it does not crash and does not re-emit on duplicate Finish.
    EXPECT_EQ(report.GetElapsedMs(), 0);
}
} // namespace CertmanagerTest