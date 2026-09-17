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

#include "js_ukey_auth_extension_base.h"

#include "ability_info.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_ukey_auth_extension_context.h"
#include "napi/native_api.h"
#include "native_engine/impl/ark/ark_native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr size_t ARGC_ONE = 1;
}
JsUkeyAuthExtensionBase::JsUkeyAuthExtensionBase(const std::unique_ptr<Runtime> &runtime)
    : JsUIExtensionBase(runtime) {}

void JsUkeyAuthExtensionBase::BindContext()
{
    JsUIExtensionBase::BindContext();
    HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    if (jsObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null jsObj_");
        return;
    }
    if (ukeyContext_ == nullptr) {
        ukeyContext_ = std::make_shared<UkeyAuthExtensionContext>();
        ukeyContext_->SetToken(context_ == nullptr ? nullptr : context_->GetToken());
        ukeyContext_->SetAbilityInfo(abilityInfo_);
    }
    napi_value obj = jsObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "not object");
        return;
    }
    napi_value contextObj = JsUkeyAuthExtensionContext::CreateJsUkeyAuthExtensionContext(env, ukeyContext_);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null contextObj");
        return;
    }
    auto ukeyContextRef = JsRuntime::LoadSystemModuleByEngine(
        env, "security.UkeyAuthExtensionContext", &contextObj, ARGC_ONE);
    if (ukeyContextRef == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "get LoadSystemModuleByEngine failed");
        return;
    }
    contextObj = ukeyContextRef->GetNapiValue();
    if (!CheckTypeForNapiValue(env, contextObj, napi_object)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "get object failed");
        return;
    }
    napi_set_named_property(env, obj, "context", contextObj);
}

void JsUkeyAuthExtensionBase::OnCommandWindow(const AAFwk::Want &want,
    const sptr<AAFwk::SessionInfo> &sessionInfo, AAFwk::WindowCommand winCmd)
{
    JsUIExtensionBase::OnCommandWindow(want, sessionInfo, winCmd);
    if (winCmd != AAFwk::WIN_CMD_FOREGROUND || sessionInfo == nullptr || ukeyContext_ == nullptr) {
        return;
    }
    auto it = uiWindowMap_.find(sessionInfo->uiExtensionComponentId);
    if (it != uiWindowMap_.end() && it->second != nullptr) {
        ukeyContext_->SetWindow(it->second);
        ukeyContext_->SetSessionInfo(sessionInfo);
        /* requestId must be injected on every foreground path: dialog launches
         * driven by OnCommandWindow never see OnForeground, and an empty
         * requestId silently skips the result report to cert manager */
        ukeyContext_->SetRequestId(want.GetStringParam("requestId"));
        TAG_LOGI(AAFwkTag::UI_EXT, "ukey OnCommandWindow: window and session injected, componentId=%{public}llu",
            static_cast<unsigned long long>(sessionInfo->uiExtensionComponentId));
    } else {
        TAG_LOGE(AAFwkTag::UI_EXT, "ukey OnCommandWindow: window not found, componentId=%{public}llu,"
            " mapSize=%{public}zu", static_cast<unsigned long long>(sessionInfo->uiExtensionComponentId),
            uiWindowMap_.size());
    }
}

void JsUkeyAuthExtensionBase::OnForeground(const AAFwk::Want &want,
    sptr<AAFwk::SessionInfo> sessionInfo)
{
    JsUIExtensionBase::OnForeground(want, sessionInfo);
    if (sessionInfo == nullptr || ukeyContext_ == nullptr) {
        return;
    }
    auto it = uiWindowMap_.find(sessionInfo->uiExtensionComponentId);
    if (it != uiWindowMap_.end() && it->second != nullptr) {
        ukeyContext_->SetWindow(it->second);
        ukeyContext_->SetSessionInfo(sessionInfo);
        ukeyContext_->SetRequestId(want.GetStringParam("requestId"));
        TAG_LOGI(AAFwkTag::UI_EXT, "ukey OnForeground: window and session injected, componentId=%{public}llu",
            static_cast<unsigned long long>(sessionInfo->uiExtensionComponentId));
    } else {
        TAG_LOGE(AAFwkTag::UI_EXT, "ukey OnForeground: window not found, componentId=%{public}llu,"
            " mapSize=%{public}zu", static_cast<unsigned long long>(sessionInfo->uiExtensionComponentId),
            uiWindowMap_.size());
    }
}

} // namespace AbilityRuntime
} // namespace OHOS
