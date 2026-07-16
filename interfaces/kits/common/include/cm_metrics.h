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

// histogram 的 ENUMERATION boundary,根据 kind 选取对应映射表的 size:
// - NON_DIALOG → NATIVE_CODE_TO_JS_CODE_MAP.size()
// - DIALOG → DIALOG_CODE_TO_JS_CODE_MAP.size()
int32_t CmGetMetricErrorBoundary(CmMetricsKind kind);

// 把 native 侧 ErrorCode 映射为 JS 侧 ErrorCode(直接作为 histogram 值上报)
// - 非 dialog 接口走 NATIVE_CODE_TO_JS_CODE_MAP(cm_api_common.h)
// - dialog 接口走 DIALOG_CODE_TO_JS_CODE_MAP(cm_dialog_api_common.h)
// 找不到时兜底返回 INNER_FAILURE
int32_t CmGetMetricErrorCode(int32_t nativeErrorCode, CmMetricsKind kind);

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
    // nativeErrorCode 是 native 侧错误码(如 CMR_ERROR_NOT_FOUND),会被映射为 JS ErrorCode 上报
    void Finish(int32_t nativeErrorCode);

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
