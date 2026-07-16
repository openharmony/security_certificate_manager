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

#include "cm_api_common.h"
#include "cm_dialog_api_common.h"

#ifdef CM_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

namespace OHOS::Security::CertManager {

int32_t CmGetMetricErrorCode(int32_t nativeErrorCode, CmMetricsKind kind)
{
    // 第一步:native code → JS code,用对应的映射表
    int32_t jsErrorCode = INNER_FAILURE;  // native 0 兜底
    if (kind == CmMetricsKind::DIALOG) {
        auto iter = Dialog::DIALOG_CODE_TO_JS_CODE_MAP.find(nativeErrorCode);
        if (iter != Dialog::DIALOG_CODE_TO_JS_CODE_MAP.end()) {
            jsErrorCode = iter->second;
        }
    } else {
        auto iter = NATIVE_CODE_TO_JS_CODE_MAP.find(nativeErrorCode);
        if (iter != NATIVE_CODE_TO_JS_CODE_MAP.end()) {
            jsErrorCode = iter->second;
        }
    }

    // 第二步:JS code → 紧凑 metric code
    switch (jsErrorCode) {
        case SUCCESS:
            return CM_METRIC_SUCCESS;
        case HAS_NO_PERMISSION:
            return CM_METRIC_HAS_NO_PERMISSION;
        case NOT_SYSTEM_APP:
            return CM_METRIC_NOT_SYSTEM_APP;
        case PARAM_ERROR:
            return CM_METRIC_PARAM_ERROR;
        case CAPABILITY_NOT_SUPPORTED:
            return CM_METRIC_CAPABILITY_NOT_SUPPORTED;
        case INNER_FAILURE:
            return CM_METRIC_INNER_FAILURE;
        case NOT_FOUND:
            return CM_METRIC_NOT_FOUND;
        case INVALID_CERT_FORMAT:
            return CM_METRIC_INVALID_CERT_FORMAT;
        case MAX_CERT_COUNT_REACHED:
            return CM_METRIC_MAX_CERT_COUNT_REACHED;
        case NO_AUTHORIZATION:
            return CM_METRIC_NO_AUTHORIZATION;
        case DEVICE_ENTER_ADVSECMODE:
            return CM_METRIC_DEVICE_ENTER_ADVSECMODE;
        case PASSWORD_IS_ERROR:
            return CM_METRIC_PASSWORD_IS_ERROR;
        case STORE_PATH_NOT_SUPPORTED:
            return CM_METRIC_STORE_PATH_NOT_SUPPORTED;
        case ACCESS_UKEY_SERVICE_FAILED:
            return CM_METRIC_ACCESS_UKEY_SERVICE_FAILED;
        case PARAMETER_VALIDATION_FAILED:
            return CM_METRIC_PARAMETER_VALIDATION_FAILED;
        case Dialog::DIALOG_ERROR_OPERATION_CANCELED:
            return CM_METRIC_DIALOG_OPERATION_CANCELED;
        case Dialog::DIALOG_ERROR_INSTALL_FAILED:
            return CM_METRIC_DIALOG_INSTALL_FAILED;
        case Dialog::DIALOG_ERROR_NOT_COMPLY_SECURITY_POLICY:
            return CM_METRIC_DIALOG_NOT_COMPLY_SECURITY_POLICY;
        case Dialog::DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE:
            return CM_METRIC_DIALOG_NO_AVAILABLE_CERTIFICATE;
        default:
            return CM_METRIC_UNKNOWN_ERROR;
    }
}

CmMetricsReport::CmMetricsReport(const std::string &interfaceName, CmMetricsKind kind)
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
    int32_t metricCode = CmGetMetricErrorCode(nativeErrorCode, kind_);
#ifdef CM_API_METRICS_ENABLE
    auto endTime = std::chrono::steady_clock::now();
    auto elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime_).count();
    HISTOGRAM_ENUMERATION(keyErrorcode_.c_str(), metricCode, CM_METRICS_ENUM_BOUNDARY);
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
