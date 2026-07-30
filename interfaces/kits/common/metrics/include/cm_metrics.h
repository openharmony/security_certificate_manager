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

/**
 * @brief Distinguish dialog vs non-dialog JS interfaces.
 *        The two API families use different error-code mapping tables (defined
 *        in `cm_api_common.h::ErrorCode` and `cm_dialog_api_common.h::ErrorCode`
 *        respectively) and different histogram-key prefixes so they can be
 *        told apart in HiView.
 */
enum CmMetricsKind {
    NON_DIALOG,  // Certificate-manager regular API; prefix "DeviceCertificateKit.certificateManager."
    DIALOG,      // Dialog API; prefix "DeviceCertificateKit.certificateManagerDialog."
};

/**
 * @brief Map a native ErrorCode to a JS-side ErrorCode (used directly as the
 *        histogram value). Looks up the caller's `jsCodeMap`; falls back by
 *        `kind` if the entry is missing:
 *        - DIALOG     -> 29700001 (= Dialog::DIALOG_ERROR_GENERIC)
 *        - non-DIALOG -> 17500001 (= INNER_FAILURE)
 * @note  This file does NOT depend on `cm_api_common.h` / `cm_dialog_api_common.h`.
 *        The two fallback constants above are values defined in the JS-side
 *        ErrorCode enum, inlined here as magic numbers.
 */
int32_t CmGetMetricErrorCodeFromMap(int32_t nativeErrorCode,
    const std::unordered_map<int32_t, int32_t> &jsCodeMap, CmMetricsKind kind);

class CmMetricsReport {
public:
    using JsCodeMap = std::unordered_map<int32_t, int32_t>;

    /**
     * @param interfaceName JS interface name
     * @param jsCodeMap     native -> JS error-code map (reference to a global
     *                       map; lifetime must outlive this report)
     * @param kind          selects histogram-key prefix (dialog vs non-dialog)
     */
    explicit CmMetricsReport(const std::string &interfaceName,
        const JsCodeMap &jsCodeMap,
        CmMetricsKind kind = CmMetricsKind::NON_DIALOG);
    ~CmMetricsReport();

    CmMetricsReport(const CmMetricsReport &) = delete;
    CmMetricsReport &operator=(const CmMetricsReport &) = delete;

    CmMetricsReport(CmMetricsReport &&) = default;
    CmMetricsReport &operator=(CmMetricsReport &&) = default;

    /**
     * @brief Call at the entry of every NAPI/ANI function. Idempotent. 
     */
    void Start();

    /**
     * @brief Call before returning from the entry function. Idempotent. No-op if
     *        Start was never called or Finish was already called.
     * @param nativeErrorCode native-side error code (e.g. CMR_ERROR_NOT_FOUND);
     *        mapped through `jsCodeMap` before reporting.
     */
    void Finish(int32_t nativeErrorCode);

    /**
     * @brief Test-only helper: returns elapsed milliseconds since Start.
     * @return 0 when the metrics macro is disabled, when Start was never called,
     *         or after Finish has already been called.
     */
    int64_t GetElapsedMs() const;

private:
    /**
     * Empty map used as the default `jsCodeMap_` when callers don't supply one.
     */
    static const JsCodeMap kEmptyJsCodeMap_;

    /**
     * keys_ array indices, named here for readability.
     */
    static constexpr size_t kIdxCall = 0;        // maps to HISTOGRAM_BOOLEAN
    static constexpr size_t kIdxTime = 1;        // maps to HISTOGRAM_TIMES
    static constexpr size_t kIdxErrorcode = 2;  // maps to HISTOGRAM_ENUMERATION
    std::array<std::string, 3> keys_;

    std::chrono::steady_clock::time_point startTime_;
    const JsCodeMap *jsCodeMap_ = &kEmptyJsCodeMap_;
    CmMetricsKind kind_ = CmMetricsKind::NON_DIALOG;
    bool started_ = false;
    bool finished_ = false;
};

} // namespace OHOS::Security::CertManager

#endif // CM_METRICS_H
