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

#ifndef OHOS_ABILITY_RUNTIME_UKEY_AUTH_UI_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_UKEY_AUTH_UI_EXTENSION_H

#include "runtime.h"
#include "ui_extension_base.h"
#include "ukey_auth_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @brief ukey auth UI extension components.
 */
class UkeyAuthExtension
    : public UIExtensionBase<UkeyAuthExtensionContext>, public std::enable_shared_from_this<UkeyAuthExtension> {
public:
    UkeyAuthExtension() = default;

    ~UkeyAuthExtension() override = default;

    /**
     * @brief Create ukey auth UI extension.
     *
     * @param runtime The runtime.
     * @return The ukey auth UI extension instance.
     */
    static UkeyAuthExtension *Create(const std::unique_ptr<Runtime> &runtime);

    /**
     * @brief Keep base window/session dispatch chain, then refresh the dialog
     * session context (requestId/sessionInfo) carried by this want.
     */
    void OnCommandWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
        AAFwk::WindowCommand winCmd) override;

    void OnForeground(const AAFwk::Want &want, sptr<AAFwk::SessionInfo> sessionInfo) override;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_UKEY_AUTH_UI_EXTENSION_H
