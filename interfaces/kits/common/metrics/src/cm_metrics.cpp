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

#include "cm_metrics.h"

#include <algorithm>
#include <vector>

#ifdef CM_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

namespace OHOS::Security::CertManager {

namespace {
/**
 * Histogram-key prefixes, selected by `kind`. Callers append a suffix
 * (".CALL" / ".Time" / ".errcode") at the call site to form the final key.
 */
constexpr const char *K_PREFIX_DIALOG = "DeviceCertificateKit.certificateManagerDialog.";
constexpr const char *K_PREFIX_NON_DIALOG = "DeviceCertificateKit.certificateManager.";

enum class JSErrorCode {
    SUCCESS = 0,
    HAS_NO_PERMISSION = 201,
    NOT_SYSTEM_APP = 202,
    PARAM_ERROR = 401,
    CAPABILITY_NOT_SUPPORTED = 801,
    INNER_FAILURE = 17500001,
    NOT_FOUND = 17500002,
    INVALID_CERT_FORMAT = 17500003,
    MAX_CERT_COUNT_REACHED = 17500004,
    NO_AUTHORIZATION = 17500005,
    DEVICE_ENTER_ADVSECMODE = 17500007,
    PASSWORD_IS_ERROR = 17500008,
    STORE_PATH_NOT_SUPPORTED = 17500009,
    ACCESS_UKEY_SERVICE_FAILED = 17500010,
    PARAMETER_VALIDATION_FAILED = 17500011
};
enum class JSDialogErrorCode {
    SUCCESS = 0,
    HAS_NO_PERMISSION = 201,
    NOT_SYSTEM_APP = 202,
    PARAM_ERROR = 401,
    DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED = 801,
    DIALOG_ERROR_GENERIC = 29700001,
    DIALOG_ERROR_OPERATION_CANCELED = 29700002,
    DIALOG_ERROR_INSTALL_FAILED = 29700003,
    DIALOG_ERROR_NOT_SUPPORTED = 29700004,
    DIALOG_ERROR_NOT_COMPLY_SECURITY_POLICY = 29700005,
    DIALOG_ERROR_PARAMETER_VALIDATION_FAILED = 29700006,
    DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE = 29700007
};

/**
 * Ordered error-code lists per kind. An input error code is translated to the
 * index of its matching entry in the kind-specific list, so HiView sees a
 * dense, normalised bucket set rather than the sparse raw ErrorCode enum.
 * Leave empty until the bucket policy is finalised; while empty, every
 * Finish() falls through to the kind-specific default index below.
 */
const std::vector<int32_t> NON_DIALOG_ERROR_CODE_LIST = {
    static_cast<int32_t>(JSErrorCode::SUCCESS),
    static_cast<int32_t>(JSErrorCode::HAS_NO_PERMISSION),
    static_cast<int32_t>(JSErrorCode::NOT_SYSTEM_APP),
    static_cast<int32_t>(JSErrorCode::PARAM_ERROR),
    static_cast<int32_t>(JSErrorCode::CAPABILITY_NOT_SUPPORTED),
    static_cast<int32_t>(JSErrorCode::INNER_FAILURE),
    static_cast<int32_t>(JSErrorCode::NOT_FOUND),
    static_cast<int32_t>(JSErrorCode::INVALID_CERT_FORMAT),
    static_cast<int32_t>(JSErrorCode::MAX_CERT_COUNT_REACHED),
    static_cast<int32_t>(JSErrorCode::NO_AUTHORIZATION),
    static_cast<int32_t>(JSErrorCode::DEVICE_ENTER_ADVSECMODE),
    static_cast<int32_t>(JSErrorCode::PASSWORD_IS_ERROR),
    static_cast<int32_t>(JSErrorCode::STORE_PATH_NOT_SUPPORTED),
    static_cast<int32_t>(JSErrorCode::ACCESS_UKEY_SERVICE_FAILED),
    static_cast<int32_t>(JSErrorCode::PARAMETER_VALIDATION_FAILED)
};
const std::vector<int32_t> DIALOG_ERROR_CODE_LIST = {
    static_cast<int32_t>(JSDialogErrorCode::SUCCESS),
    static_cast<int32_t>(JSDialogErrorCode::HAS_NO_PERMISSION),
    static_cast<int32_t>(JSDialogErrorCode::NOT_SYSTEM_APP),
    static_cast<int32_t>(JSDialogErrorCode::PARAM_ERROR),
    static_cast<int32_t>(JSDialogErrorCode::DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED),
    static_cast<int32_t>(JSDialogErrorCode::DIALOG_ERROR_GENERIC),
    static_cast<int32_t>(JSDialogErrorCode::DIALOG_ERROR_OPERATION_CANCELED),
    static_cast<int32_t>(JSDialogErrorCode::DIALOG_ERROR_INSTALL_FAILED),
    static_cast<int32_t>(JSDialogErrorCode::DIALOG_ERROR_NOT_SUPPORTED),
    static_cast<int32_t>(JSDialogErrorCode::DIALOG_ERROR_NOT_COMPLY_SECURITY_POLICY),
    static_cast<int32_t>(JSDialogErrorCode::DIALOG_ERROR_PARAMETER_VALIDATION_FAILED),
    static_cast<int32_t>(JSDialogErrorCode::DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE)
};

/**
 * Indices returned by MapErrorCode when the error code is not present in the
 * kind-specific list. Tune once the bucket policy is finalised; both must
 * stay within [0, boundary_) so HISTOGRAM_ENUMERATION keeps the sample.
 */
constexpr int32_t NON_DIALOG_DEFAULT_INDEX = 5;
constexpr int32_t DIALOG_DEFAULT_INDEX = 5;

constexpr int32_t CM_SUCCESS = 0;

int32_t MapErrorCode(CmMetricsKind kind, int32_t errorCode)
{
    const auto &list = (kind == CmMetricsKind::DIALOG) ? DIALOG_ERROR_CODE_LIST
                                                        : NON_DIALOG_ERROR_CODE_LIST;
    auto it = std::find(list.begin(), list.end(), errorCode);
    if (it != list.end()) {
        return static_cast<int32_t>(std::distance(list.begin(), it));
    }
    return (kind == CmMetricsKind::DIALOG) ? DIALOG_DEFAULT_INDEX : NON_DIALOG_DEFAULT_INDEX;
}

}  // namespace

CmMetricsReport::CmMetricsReport(const std::string &interfaceName,
    CmMetricsKind kind)
    : kind_(kind)
{
    const char *prefix = (kind == CmMetricsKind::DIALOG) ? K_PREFIX_DIALOG : K_PREFIX_NON_DIALOG;
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
}

void CmMetricsReport::Finish([[maybe_unused]] int32_t errorCode)
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
    int32_t mappedErrorCode = MapErrorCode(kind_, errorCode);
    /**
     * The histogram upper bound is the size of the kind-specific error-code
     * list, so the bucket set always matches the mapped index range exactly.
     */
    int32_t boundary = (kind_ == CmMetricsKind::DIALOG)
        ? static_cast<int32_t>(DIALOG_ERROR_CODE_LIST.size())
        : static_cast<int32_t>(NON_DIALOG_ERROR_CODE_LIST.size());
    HISTOGRAM_BOOLEAN((keyPrefix_ + ".CALL").c_str(), errorCode == CM_SUCCESS);
    HISTOGRAM_ENUMERATION((keyPrefix_ + ".errcode").c_str(), mappedErrorCode, boundary);
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