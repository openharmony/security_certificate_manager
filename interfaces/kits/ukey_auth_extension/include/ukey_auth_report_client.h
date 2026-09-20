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

#ifndef OHOS_ABILITY_RUNTIME_UKEY_AUTH_REPORT_CLIENT_H
#define OHOS_ABILITY_RUNTIME_UKEY_AUTH_REPORT_CLIENT_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace AbilityRuntime {

/**
 * @brief Reports the ukey auth result to the cert manager SA (3512) via a
 * direct CM_MSG_REPORT_UKEY_AUTH_RESULT IPC request, without linking
 * cert_manager_sdk.
 *
 * Wire contract (must stay in sync with the SA-side handler
 * CmIpcServiceReportUkeyAuthResult and the canonical client
 * CmClientReportUkeyAuthResult).
 * 
 * - parcel: [interface token][uint32 paramSetSize][paramSet buffer]
 * - paramSet: CM_TAG_PARAM0_BUFFER = requestId, CM_TAG_PARAM1_UINT32 = resultCode
 * - reply: single int32 result code
 */
int32_t ReportUkeyAuthResultViaIpc(const std::string &requestId, int32_t resultCode);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_UKEY_AUTH_REPORT_CLIENT_H
