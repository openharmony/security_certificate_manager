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

#ifndef CM_METRICS_H
#define CM_METRICS_H

#include <chrono>
#include <cstdint>
#include <string>

namespace OHOS::Security::CertManager {

/**
 * @brief Distinguish dialog vs non-dialog JS interfaces.
 *        The two API families use different histogram-key prefixes so they can
 *        be told apart in HiView.
 */
enum CmMetricsKind {
    NON_DIALOG,  // Certificate-manager regular API; prefix "DeviceCertificateKit.certificateManager."
    DIALOG,      // Dialog API; prefix "DeviceCertificateKit.certificateManagerDialog."
};

class CmMetricsReport {
public:
    /**
     * @param interfaceName JS interface name
     * @param kind          selects histogram-key prefix (dialog vs non-dialog)
     *                      and the per-kind error-code list that drives the
     *                      HISTOGRAM_ENUMERATION bucket count and mapping.
     */
    explicit CmMetricsReport(const std::string &interfaceName,
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
     * @param errorCode the JS-side ErrorCode value to record; remapped through
     *        the kind-specific list before being reported.
     */
    void Finish(int32_t errorCode);

    /**
     * @brief Test-only helper: returns elapsed milliseconds since Start.
     * @return 0 when the metrics macro is disabled, when Start was never called,
     *         or after Finish has already been called.
     */
    int64_t GetElapsedMs() const;

private:
    /**
     * Histogram-key prefix resolved once at construction: `<kind-prefix><interfaceName>`,
     * e.g. `DeviceCertificateKit.certificateManager.init`. Each metric report
     * appends its own suffix (".CALL" / ".Time" / ".errcode") on demand.
     */
    std::string keyPrefix_;

    CmMetricsKind kind_ = CmMetricsKind::NON_DIALOG;
    std::chrono::steady_clock::time_point startTime_;
    bool started_ = false;
    bool finished_ = false;
};

} // namespace OHOS::Security::CertManager

#endif // CM_METRICS_H