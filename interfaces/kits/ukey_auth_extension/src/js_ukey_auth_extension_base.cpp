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

#include "cm_log.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_ukey_auth_extension_context.h"
#include "napi/native_api.h"
#include "ukey_auth_extension_context.h"

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
        CM_LOG_E("null env");
        return;
    }
    if (jsObj_ == nullptr) {
        CM_LOG_E("null jsObj_");
        return;
    }
    if (context_ == nullptr) {
        CM_LOG_E("null context_");
        return;
    }
    napi_value obj = jsObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        CM_LOG_E("not object");
        return;
    }
    auto ukeyContext = std::static_pointer_cast<UkeyAuthExtensionContext>(context_);
    napi_value contextObj = JsUkeyAuthExtensionContext::CreateJsUkeyAuthExtensionContext(env, ukeyContext);
    if (contextObj == nullptr) {
        CM_LOG_E("null contextObj");
        return;
    }
    auto ukeyContextRef = JsRuntime::LoadSystemModuleByEngine(
        env, "security.UkeyAuthExtensionContext", &contextObj, ARGC_ONE);
    if (ukeyContextRef == nullptr) {
        CM_LOG_E("get LoadSystemModuleByEngine failed");
        return;
    }
    contextObj = ukeyContextRef->GetNapiValue();
    if (!CheckTypeForNapiValue(env, contextObj, napi_object)) {
        CM_LOG_E("get object failed");
        return;
    }
    napi_set_named_property(env, obj, "context", contextObj);
}
} // namespace AbilityRuntime
} // namespace OHOS
