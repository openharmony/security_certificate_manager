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

#include "cm_metrics.h"

#ifdef CM_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

namespace OHOS::Security::CertManager {

namespace {

/**
 * Histogram-key prefixes, selected by `kind`. Note the trailing '.' is omitted;
 * the leading '.' comes from the suffix (see `kSuffixes`).
 */
constexpr const char *kPrefixDialog = "DeviceCertificateKit.certificateManagerDialog.";
constexpr const char *kPrefixNonDialog = "DeviceCertificateKit.certificateManager.";

/**
 * Histogram-key suffixes, indexed by CmMetricsReport::keys_:
 *   0 -> BOOLEAN    ("Call")
 *   1 -> TIMES      ("Time")
 *   2 -> ENUMERATION ("errorcode")
 */
constexpr const char *kSuffixes[] = { ".CALL", ".Time", ".errcode" };

/**
 * Fallback JS ErrorCode when a native code is not found in `jsCodeMap`.
 *   - DIALOG     -> 29700001 (= Dialog::DIALOG_ERROR_GENERIC)
 *   - non-DIALOG -> 17500001 (= INNER_FAILURE)
 * These values are part of the JS-side ErrorCode enum contract; the metrics
 * module deliberately does NOT depend on cm_api_common.h / cm_dialog_api_common.h.
 */
constexpr int32_t kMetricsFallbackDialog = 29700001;
constexpr int32_t kMetricsFallbackNonDialog = 17500001;

}  // namespace

/**
 * Empty map used as the default `jsCodeMap_` when callers don't supply one.
 */
const CmMetricsReport::JsCodeMap CmMetricsReport::kEmptyJsCodeMap_{};

int32_t CmGetMetricErrorCodeFromMap(int32_t nativeErrorCode,
    const std::unordered_map<int32_t, int32_t> &jsCodeMap, CmMetricsKind kind)
{
    auto iter = jsCodeMap.find(nativeErrorCode);
    if (iter != jsCodeMap.end()) {
        return iter->second;
    }
    return (kind == CmMetricsKind::DIALOG) ? kMetricsFallbackDialog : kMetricsFallbackNonDialog;
}

CmMetricsReport::CmMetricsReport(const std::string &interfaceName,
    const JsCodeMap &jsCodeMap, CmMetricsKind kind)
    : jsCodeMap_(&jsCodeMap), kind_(kind)
{
    const char *prefix = (kind == CmMetricsKind::DIALOG) ? kPrefixDialog : kPrefixNonDialog;
    const std::string base = std::string(prefix) + interfaceName;
    for (size_t i = 0; i < keys_.size(); ++i) {
        keys_[i] = base + kSuffixes[i];
    }
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
    HISTOGRAM_BOOLEAN(keys_[kIdxCall].c_str(), true);
#endif
}

void CmMetricsReport::Finish(int32_t nativeErrorCode)
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
    int32_t metricCode = CmGetMetricErrorCodeFromMap(nativeErrorCode, *jsCodeMap_, kind_);
    int32_t boundary = static_cast<int32_t>(jsCodeMap_->size());
    auto endTime = std::chrono::steady_clock::now();
    int64_t elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime_).count();
    /**
     * Clamp int64_t -> int32_t to prevent silent overflow (API calls rarely
     * exceed INT32_MAX ms, but a defensive clamp keeps us safe).
     */
    int32_t elapsed = (elapsedMs > INT32_MAX) ? INT32_MAX : static_cast<int32_t>(elapsedMs);
    HISTOGRAM_ENUMERATION(keys_[kIdxErrorcode].c_str(), metricCode, boundary);
    HISTOGRAM_TIMES(keys_[kIdxTime].c_str(), elapsed);
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
