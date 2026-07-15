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

#ifndef CM_METRICS_H
#define CM_METRICS_H

#include <chrono>
#include <cstdint>
#include <string>

namespace OHOS::Security::CertManager {

// 与 cm_api_common.h 中 ErrorCode 一一对应的紧凑枚举,仅用于 histogram 打点
enum CmMetricErrorCode {
    CM_METRIC_SUCCESS = 0,
    CM_METRIC_HAS_NO_PERMISSION = 1,
    CM_METRIC_NOT_SYSTEM_APP = 2,
    CM_METRIC_PARAM_ERROR = 3,
    CM_METRIC_CAPABILITY_NOT_SUPPORTED = 4,
    CM_METRIC_INNER_FAILURE = 5,
    CM_METRIC_NOT_FOUND = 6,
    CM_METRIC_INVALID_CERT_FORMAT = 7,
    CM_METRIC_MAX_CERT_COUNT_REACHED = 8,
    CM_METRIC_NO_AUTHORIZATION = 9,
    CM_METRIC_DEVICE_ENTER_ADVSECMODE = 10,
    CM_METRIC_PASSWORD_IS_ERROR = 11,
    CM_METRIC_STORE_PATH_NOT_SUPPORTED = 12,
    CM_METRIC_ACCESS_UKEY_SERVICE_FAILED = 13,
    CM_METRIC_PARAMETER_VALIDATION_FAILED = 14,
    CM_METRIC_DIALOG_OPERATION_CANCELED = 15,
    CM_METRIC_DIALOG_INSTALL_FAILED = 16,
    CM_METRIC_DIALOG_NOT_COMPLY_SECURITY_POLICY = 17,
    CM_METRIC_DIALOG_NO_AVAILABLE_CERTIFICATE = 18,
    CM_METRIC_UNKNOWN_ERROR = 19,
};

// boundary = enum 元素总数;实际取值范围 [0, CM_METRICS_ENUM_BOUNDARY)
constexpr int32_t CM_METRICS_ENUM_BOUNDARY = 20;

// 把 JS 侧 ErrorCode(包括 dialog 公共码)映射为紧凑 metric code
int32_t CmGetMetricErrorCode(int32_t jsErrorCode);

// 区分 dialog 与非 dialog JS 接口:两者的错误码映射表不同(分别对应
// cm_api_common.h 的 ErrorCode 和 cm_dialog_api_common.h 的 ErrorCode),
// histogram key 也使用不同的前缀以便在 HiView 中区分
enum class CmMetricsKind {
    NON_DIALOG,  // 证书管理普通接口,前缀 "DeviceCertificateKit.certificateManager."
    DIALOG,      // 弹框类接口,前缀 "DeviceCertificateKit.certificateManagerDialog."
};

class CmMetricsReport {
public:
    // 默认是 NON_DIALOG(证书管理普通接口);弹框类接口需显式传 DIALOG
    explicit CmMetricsReport(const std::string &interfaceName,
        CmMetricsKind kind = CmMetricsKind::NON_DIALOG);
    ~CmMetricsReport();

    CmMetricsReport(const CmMetricsReport &) = delete;
    CmMetricsReport &operator=(const CmMetricsReport &) = delete;

    CmMetricsReport(CmMetricsReport &&) = default;
    CmMetricsReport &operator=(CmMetricsReport &&) = default;

    // 在 NAPI/ANI 入口函数最前面调用,idempotent;重复调用为 no-op
    void Start();
    // 入口函数返回前调用,触发剩余两个宏;idempotent;若未 Start 或已 Finish 则 no-op
    void Finish(int32_t jsErrorCode);

    // 仅供测试使用:返回从 Start 到当前时刻的耗时(毫秒)。
    // - 当宏关闭时恒为 0
    // - 当 Start 未调用或已 Finish 时也返回 0
    int64_t GetElapsedMs() const;

private:
    // 三个 histogram key 预先拼好,带前缀(根据 kind)和后缀(CALL/Time/errorcode)
    std::string keyCall_;
    std::string keyTime_;
    std::string keyErrorcode_;
    std::chrono::steady_clock::time_point startTime_;
    bool started_ = false;
    bool finished_ = false;
};

} // namespace OHOS::Security::CertManager

#endif // CM_METRICS_H
