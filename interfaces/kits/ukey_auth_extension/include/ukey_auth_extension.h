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

#include "ui_extension_base.h"

namespace OHOS {
namespace AbilityRuntime {
class UIExtensionContext;
class Runtime;
/**
 * @brief ukey auth UI extension components.
 */
class UkeyAuthExtension
    : public UIExtensionBase<UIExtensionContext>, public std::enable_shared_from_this<UkeyAuthExtension> {
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
     * @brief Keep base UIExtensionBase behavior (window/session dispatch chain).
     */
    void OnForeground(const AAFwk::Want &want, sptr<AAFwk::SessionInfo> sessionInfo) override;

    /**
     * @brief Keep base UIExtensionBase behavior (window/session dispatch chain).
     */
    void OnBackground() override;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_UKEY_AUTH_UI_EXTENSION_H
