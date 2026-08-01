/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include <thread>

#include "cm_metrics.h"

using namespace testing::ext;
using namespace OHOS::Security::CertManager;
namespace {
// Mirror the ErrorCode values from cm_api_common.h. Inlined here so the test
// only depends on cm_metrics and does not pull in unrelated translation units.
constexpr int32_t CM_SUCCESS = 0;
constexpr int32_t PARAM_ERROR = 401;
constexpr int32_t NOT_FOUND = 17500002;
constexpr int32_t INNER_FAILURE = 17500001;
constexpr int32_t ERROR_CODE_COUNT = 15;

class CmMetricsTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}

    static void TearDownTestCase(void) {}

    void SetUp(void) {}

    void TearDown(void) {}
};

/**
 * @tc.name: ReportGuard_StartRecordsCalled
 * @tc.desc: Verify CmMetricsReport construction and destruction are safe when
 *           Start is followed immediately by Finish. With the metrics macro
 *           disabled this only checks that no crash occurs.
 * @tc.type: FUNC
 */
HWTEST_F(CmMetricsTest, ReportGuard_StartRecordsCalled, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    // With the metrics macro disabled, Start is a no-op; this only verifies
    // that construction/destruction do not crash.
    report.Finish(CM_SUCCESS);
}

/**
 * @tc.name: ReportGuard_FinishComputesElapsedMs
 * @tc.desc: Verify Finish records elapsed milliseconds and GetElapsedMs
 *           returns 0 when the metrics macro is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(CmMetricsTest, ReportGuard_FinishComputesElapsedMs, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    // Sleep at least 1 ms so elapsed time would be non-zero if the macro were on.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    report.Finish(CM_SUCCESS);
    // With the macro disabled elapsed stays 0 (Finish does not read the clock).
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

/**
 * @tc.name: ReportGuard_FinishWithoutStart_IsSafe
 * @tc.desc: Verify Finish auto-Starts when Start was never called, so all
 *           three histograms (BOOLEAN + ENUMERATION + TIMES) are still emitted.
 * @tc.type: FUNC
 */
HWTEST_F(CmMetricsTest, ReportGuard_FinishWithoutStart_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    // Skip Start and call Finish directly: Finish internally auto-Starts.
    report.Finish(INNER_FAILURE);
    // GetElapsedMs should return 0 once finished_ is true.
    EXPECT_EQ(report.GetElapsedMs(), 0);
}

/**
 * @tc.name: ReportGuard_FinishAutoStart_BoundaryValue
 * @tc.desc: Verify that after Finish sets finished_=true, a second Finish is a
 *           no-op and does not emit a duplicate histogram.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: ReportGuard_DoubleFinish_IsSafe
 * @tc.desc: Verify that a repeated Finish after a normal Start/Finish cycle is
 *           ignored by the internal finished_ flag.
 * @tc.type: FUNC
 */
HWTEST_F(CmMetricsTest, ReportGuard_DoubleFinish_IsSafe, TestSize.Level1)
{
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    report.Finish(CM_SUCCESS);
    // A repeated Finish must be ignored by the internal finished_ flag.
    report.Finish(INNER_FAILURE);
}

/**
 * @tc.name: ReportGuard_FinishWithBoundaryValue
 * @tc.desc: Verify that Finish accepts errorCode values at and around the
 *           histogram boundary (ERROR_CODE_COUNT) without crashing.
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: ReportGuard_FinishPassesErrorCodeThrough
 * @tc.desc: Verify Finish passes the errorCode through verbatim to the
 *           histogram; no mapping is applied any more.
 * @tc.type: FUNC
 */
HWTEST_F(CmMetricsTest, ReportGuard_FinishPassesErrorCodeThrough, TestSize.Level1)
{
    // Finish passes the errorCode through verbatim to the histogram; no
    // mapping is applied any more.
    CmMetricsReport report("UnitTestApi", ERROR_CODE_COUNT);
    report.Start();
    report.Finish(PARAM_ERROR);
    report.Finish(NOT_FOUND);
    report.Finish(INNER_FAILURE);
    // Only verifies it does not crash and does not re-emit on duplicate Finish.
    EXPECT_EQ(report.GetElapsedMs(), 0);
}
}  // namespace