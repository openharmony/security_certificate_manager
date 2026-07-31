/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "cm_metrics.h"

#ifdef CM_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

namespace OHOS::Security::CertManager {

namespace {

/**
 * Histogram-key prefixes, selected by `kind`. Callers append a suffix
 * (".CALL" / ".Time" / ".errcode") at the call site to form the final key.
 */
constexpr const char *kPrefixDialog = "DeviceCertificateKit.certificateManagerDialog.";
constexpr const char *kPrefixNonDialog = "DeviceCertificateKit.certificateManager.";

}  // namespace

CmMetricsReport::CmMetricsReport(const std::string &interfaceName,
    int32_t boundary, CmMetricsKind kind)
    : boundary_(boundary)
{
    const char *prefix = (kind == CmMetricsKind::DIALOG) ? kPrefixDialog : kPrefixNonDialog;
    keyPrefix_ = std::string(prefix) + interfaceName;
}

CmMetricsReport::~CmMetricsReport() = default;

void CmMetricsReport::Start()
{
    if (started_) {
        return;
    }
    started_ = true;
    startTime_ = std::chrono::steady_clock::now();
#ifdef CM_API_METRICS_ENABLE
    /**
     * `finished_` is intentionally NOT set here. If HISTOGRAM_BOOLEAN() throws,
     * the caller can retry via Finish() because `finished_` is still false.
     */
    HISTOGRAM_BOOLEAN((keyPrefix_ + ".CALL").c_str(), true);
#endif
}

void CmMetricsReport::Finish(int32_t errorCode)
{
    if (finished_) {
        return;  // Double-Finish: idempotent, no-op.
    }
    if (!started_) {
        /**
         * Defensive path: caller forgot to call Start(). Auto-Start here so the
         * BOOLEAN histogram is also reported; otherwise the data set would show
         * ENUMERATION + TIMES without a matching BOOLEAN (incomplete record).
         */
        Start();
    }
    finished_ = true;
#ifdef CM_API_METRICS_ENABLE
    auto endTime = std::chrono::steady_clock::now();
    int64_t elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime_).count();
    /**
     * Clamp int64_t -> int32_t to prevent silent overflow (API calls rarely
     * exceed INT32_MAX ms, but a defensive clamp keeps us safe).
     */
    int32_t elapsed = (elapsedMs > INT32_MAX) ? INT32_MAX : static_cast<int32_t>(elapsedMs);
    HISTOGRAM_ENUMERATION((keyPrefix_ + ".errcode").c_str(), errorCode, boundary_);
    HISTOGRAM_TIMES((keyPrefix_ + ".Time").c_str(), elapsed);
#endif
}

int64_t CmMetricsReport::GetElapsedMs() const
{
#ifdef CM_API_METRICS_ENABLE
    if (!started_ || finished_) {
        return 0;
    }
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime_).count();
#else
    return 0;
#endif
}
} // namespace OHOS::Security::CertManager