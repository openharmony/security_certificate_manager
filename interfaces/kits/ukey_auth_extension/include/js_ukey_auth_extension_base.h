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

#ifndef OHOS_ABILITY_RUNTIME_JS_UKEY_AUTH_UI_EXTENSION_BASE_H
#define OHOS_ABILITY_RUNTIME_JS_UKEY_AUTH_UI_EXTENSION_BASE_H

#include <memory>

#include "js_ui_extension_base.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @brief JsUIExtensionBase subclass binding the public UkeyAuthExtensionContext.
 *
 * Window/session/requestId injection is handled by the shared machinery and
 * UkeyAuthExtension itself; only the context class binding differs here.
 */
class JsUkeyAuthExtensionBase : public JsUIExtensionBase {
public:
    explicit JsUkeyAuthExtensionBase(const std::unique_ptr<Runtime> &runtime);
    ~JsUkeyAuthExtensionBase() override = default;

    void BindContext() override;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_UKEY_AUTH_UI_EXTENSION_BASE_H
