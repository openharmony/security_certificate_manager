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

// 空 jsCodeMap,作为默认的 jsCodeMap_ 指向
const CmMetricsReport::JsCodeMap CmMetricsReport::kEmptyJsCodeMap_{};

int32_t CmGetMetricErrorCodeFromMap(int32_t nativeErrorCode,
    const std::unordered_map<int32_t, int32_t> &jsCodeMap, CmMetricsKind kind)
{
    auto iter = jsCodeMap.find(nativeErrorCode);
    if (iter != jsCodeMap.end()) {
        return iter->second;
    }
    // 找不到时按 kind 区分兜底:
    // - DIALOG → 29700001 (= Dialog::DIALOG_ERROR_GENERIC)
    // - 非 DIALOG → 17500001 (= INNER_FAILURE)
    return (kind == CmMetricsKind::DIALOG) ? 29700001 : 17500001;
}

CmMetricsReport::CmMetricsReport(const std::string &interfaceName,
    const JsCodeMap &jsCodeMap, CmMetricsKind kind)
    : jsCodeMap_(&jsCodeMap), kind_(kind)
{
    const char *prefix = (kind == CmMetricsKind::DIALOG)
        ? "DeviceCertificateKit.certificateManagerDialog."
        : "DeviceCertificateKit.certificateManager.";
    keyCall_ = std::string(prefix) + interfaceName + ".CALL";
    keyTime_ = std::string(prefix) + interfaceName + ".Time";
    keyErrorcode_ = std::string(prefix) + interfaceName + ".errorcode";
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
    HISTOGRAM_BOOLEAN(keyCall_.c_str(), true);
#endif
}

void CmMetricsReport::Finish(int32_t nativeErrorCode)
{
    if (!started_ || finished_) {
        return;
    }
    finished_ = true;
    int32_t metricCode = CmGetMetricErrorCodeFromMap(nativeErrorCode, *jsCodeMap_, kind_);
    int32_t boundary = static_cast<int32_t>(jsCodeMap_->size());
#ifdef CM_API_METRICS_ENABLE
    auto endTime = std::chrono::steady_clock::now();
    auto elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime_).count();
    HISTOGRAM_ENUMERATION(keyErrorcode_.c_str(), metricCode, boundary);
    HISTOGRAM_TIMES(keyTime_.c_str(), static_cast<int32_t>(elapsedMs));
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
