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

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace OHOS::Security::CertManager {

// 把 native 侧 ErrorCode 映射为 JS 侧 ErrorCode(直接作为 histogram 值上报)
// 用调用方传入的 jsCodeMap 查表;找不到时按 kind 区分兜底:
// - DIALOG → 29700001 (= Dialog::DIALOG_ERROR_GENERIC)
// - 非 DIALOG → 17500001 (= INNER_FAILURE)
// 注意:本文件不再直接引用 cm_api_common.h / cm_dialog_api_common.h,
// 这两个常量值是 JS ErrorCode 枚举里约定好的值,直接以 magic number 形式给出
int32_t CmGetMetricErrorCodeFromMap(int32_t nativeErrorCode,
    const std::unordered_map<int32_t, int32_t> &jsCodeMap, CmMetricsKind kind);

// 区分 dialog 与非 dialog JS 接口:两者的错误码映射表不同(分别对应
// cm_api_common.h 的 ErrorCode 和 cm_dialog_api_common.h 的 ErrorCode),
// histogram key 也使用不同的前缀以便在 HiView 中区分
enum class CmMetricsKind {
    NON_DIALOG,  // 证书管理普通接口,前缀 "DeviceCertificateKit.certificateManager."
    DIALOG,      // 弹框类接口,前缀 "DeviceCertificateKit.certificateManagerDialog."
};

class CmMetricsReport {
public:
    using JsCodeMap = std::unordered_map<int32_t, int32_t>;

    // interfaceName: JS 接口名
    // jsCodeMap:    native → JS 错误码映射表(指向全局表的引用,生命周期 >= report)
    // kind:         用于选择 histogram key 前缀(区分 dialog 与非 dialog)
    explicit CmMetricsReport(const std::string &interfaceName,
        const JsCodeMap &jsCodeMap,
        CmMetricsKind kind = CmMetricsKind::NON_DIALOG);
    ~CmMetricsReport();

    CmMetricsReport(const CmMetricsReport &) = delete;
    CmMetricsReport &operator=(const CmMetricsReport &) = delete;

    CmMetricsReport(CmMetricsReport &&) = default;
    CmMetricsReport &operator=(CmMetricsReport &&) = default;

    // 在 NAPI/ANI 入口函数最前面调用,idempotent;重复调用为 no-op
    void Start();
    // 入口函数返回前调用,触发剩余两个宏;idempotent;若未 Start 或已 Finish 则 no-op
    // nativeErrorCode 是 native 侧错误码(如 CMR_ERROR_NOT_FOUND),按传入的 map 映射后上报
    void Finish(int32_t nativeErrorCode);

    // 仅供测试使用:返回从 Start 到当前时刻的耗时(毫秒)。
    // - 当宏关闭时恒为 0
    // - 当 Start 未调用或已 Finish 时也返回 0
    int64_t GetElapsedMs() const;

private:
    // 空 map,作为默认 jsCodeMap_(调用方不传时使用)
    static const JsCodeMap kEmptyJsCodeMap_;
    // keys_ 数组索引,命名常量方便阅读
    static constexpr size_t kIdxCall = 0;        // 对应 HISTOGRAM_BOOLEAN
    static constexpr size_t kIdxTime = 1;        // 对应 HISTOGRAM_TIMES
    static constexpr size_t kIdxErrorcode = 2;  // 对应 HISTOGRAM_ENUMERATION
    std::array<std::string, 3> keys_;
    std::chrono::steady_clock::time_point startTime_;
    const JsCodeMap *jsCodeMap_ = &kEmptyJsCodeMap_;
    CmMetricsKind kind_ = CmMetricsKind::NON_DIALOG;
    bool started_ = false;
    bool finished_ = false;
};

} // namespace OHOS::Security::CertManager

#endif // CM_METRICS_H
