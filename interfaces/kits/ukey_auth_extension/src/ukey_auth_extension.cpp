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

#include "ukey_auth_extension.h"

#include "ets_ukey_auth_extension_instance.h"
#include "hilog_tag_wrapper.h"
#include "js_ukey_auth_extension.h"
#include "runtime.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
UkeyAuthExtension *UkeyAuthExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    TAG_LOGD(AAFwkTag::EXT, "called");
    if (runtime == nullptr) {
        return new (std::nothrow) UkeyAuthExtension();
    }
    switch (runtime->GetLanguage()) {
        case Runtime::Language::JS:
            return JsUkeyAuthExtension::Create(runtime);
        case Runtime::Language::ETS:
            return CreateETSUkeyAuthExtension(runtime);
        default:
            return new (std::nothrow) UkeyAuthExtension();
    }
}

void UkeyAuthExtension::OnForeground(const AAFwk::Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    UIExtensionBase<UIExtensionContext>::OnForeground(want, sessionInfo);
}

void UkeyAuthExtension::OnBackground()
{
    UIExtensionBase<UIExtensionContext>::OnBackground();
}
} // namespace AbilityRuntime
} // namespace OHOS
