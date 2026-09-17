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

namespace OHOS {
namespace AbilityRuntime {
namespace {
void InjectDialogSessionContext(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
    const std::shared_ptr<UkeyAuthExtensionContext> &context)
{
    if (sessionInfo == nullptr || context == nullptr) {
        return;
    }
    context->SetSessionInfo(sessionInfo);
    /* requestId must be injected on every foreground path: dialog launches
     * driven by OnCommandWindow never see OnForeground, and an empty
     * requestId silently skips the result report to cert manager */
    context->SetRequestId(want.GetStringParam("requestId"));
}
} // namespace

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

void UkeyAuthExtension::OnCommandWindow(const AAFwk::Want &want,
    const sptr<AAFwk::SessionInfo> &sessionInfo, AAFwk::WindowCommand winCmd)
{
    UIExtensionBase<UkeyAuthExtensionContext>::OnCommandWindow(want, sessionInfo, winCmd);
    if (winCmd == AAFwk::WIN_CMD_FOREGROUND) {
        InjectDialogSessionContext(want, sessionInfo, GetContext());
    }
}

void UkeyAuthExtension::OnForeground(const AAFwk::Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    UIExtensionBase<UkeyAuthExtensionContext>::OnForeground(want, sessionInfo);
    InjectDialogSessionContext(want, sessionInfo, GetContext());
}
} // namespace AbilityRuntime
} // namespace OHOS
