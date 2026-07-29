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

// histogram key 前缀(按 kind 区分;不带末尾 '.',由 suffix 的 '.' 衔接)
constexpr const char *kPrefixDialog = "DeviceCertificateKit.certificateManagerDialog";
constexpr const char *kPrefixNonDialog = "DeviceCertificateKit.certificateManager";

// histogram key 后缀,顺序与 CmMetricsReport::keys_ 的索引对应
// 0 → BOOLEAN (Call), 1 → TIMES (Time), 2 → ENUMERATION (errorcode)
constexpr const char *kSuffixes[] = { ".CALL", ".Time", ".errorcode" };

// 查表未命中时的兜底 JS 错误码
// - DIALOG → 29700001 (= Dialog::DIALOG_ERROR_GENERIC)
// - 非 DIALOG → 17500001 (= INNER_FAILURE)
// 这两个值是 JS ErrorCode 枚举里约定好的值,metrics 模块不依赖 cm_api_common.h / cm_dialog_api_common.h
constexpr int32_t kMetricsFallbackDialog = 29700001;
constexpr int32_t kMetricsFallbackNonDialog = 17500001;

}  // namespace

// 空 jsCodeMap,作为默认的 jsCodeMap_ 指向
const CmMetricsReport::JsCodeMap CmMetricsReport::kEmptyJsCodeMap_{};

int32_t CmGetMetricErrorCodeFromMap(int32_t nativeErrorCode,
    const std::unordered_map<int32_t, int32_t> &jsCodeMap, CmMetricsKind kind)
{
    auto iter = jsCodeMap.find(nativeErrorCode);
    if (iter != jsCodeMap.end()) {
        return iter->second;
    }
    // 找不到时按 kind 区分兜底
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
    HISTOGRAM_BOOLEAN(keys_[kIdxCall].c_str(), true);
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
    int64_t elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime_).count();
    // 防止 int64_t 截断到 int32_t 时溢出(API 调用一般不会超过 INT32_MAX ms,但加 clamp 更稳妥)
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
