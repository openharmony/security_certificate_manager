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

#ifndef OHOS_ABILITY_RUNTIME_JS_UKEY_AUTH_UI_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_JS_UKEY_AUTH_UI_EXTENSION_CONTEXT_H

#include <memory>

#include "napi/native_api.h"
#include "ukey_auth_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
struct NapiCallbackInfo;

/**
 * @brief Js wrapper for UkeyAuthExtensionContext, binding only the four public methods.
 */
class JsUkeyAuthExtensionContext {
public:
    explicit JsUkeyAuthExtensionContext(const std::shared_ptr<UkeyAuthExtensionContext> &context)
        : context_(context) {}
    virtual ~JsUkeyAuthExtensionContext() = default;

    static void Finalizer(napi_env env, void *data, void *hint);
    static napi_value TerminateSelf(napi_env env, napi_callback_info info);
    static napi_value TerminateSelfWithResult(napi_env env, napi_callback_info info);
    static napi_value CreateJsUkeyAuthExtensionContext(napi_env env,
        std::shared_ptr<UkeyAuthExtensionContext> context);

protected:
    napi_value OnTerminateSelf(napi_env env, NapiCallbackInfo &info);
    napi_value OnTerminateSelfWithResult(napi_env env, NapiCallbackInfo &info);

protected:
    std::weak_ptr<UkeyAuthExtensionContext> context_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_UKEY_AUTH_UI_EXTENSION_CONTEXT_H
