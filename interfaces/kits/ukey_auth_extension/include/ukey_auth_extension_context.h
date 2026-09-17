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

#ifndef OHOS_ABILITY_RUNTIME_UKEY_AUTH_UI_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_UKEY_AUTH_UI_EXTENSION_CONTEXT_H

#include "session_info.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {

/**
 * @brief context supply for ukeyAuth UIExtension, with only terminate capabilities.
 *
 * Inherits UIExtensionContext so the shared UIExtension machinery manages the
 * window/token bookkeeping; terminateSelf* additionally reports the auth result
 * to certManager before terminating (spec D2).
 */
class UkeyAuthExtensionContext : public UIExtensionContext {
public:
    UkeyAuthExtensionContext() = default;
    ~UkeyAuthExtensionContext() override = default;

    void SetSessionInfo(const sptr<AAFwk::SessionInfo> &sessionInfo);
    void SetRequestId(const std::string &requestId);

    /**
     * @brief Destroys the current ukeyAuth extension ability, after reporting to certManager.
     */
    ErrCode TerminateSelf() override;

    /**
     * @brief Destroys the current ukeyAuth extension ability with result, after reporting to certManager.
     */
    ErrCode TerminateSelfWithResult(int32_t resultCode, const AAFwk::Want &want);

private:
    sptr<AAFwk::SessionInfo> sessionInfo_ = nullptr;
    std::string requestId_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_UKEY_AUTH_UI_EXTENSION_CONTEXT_H
