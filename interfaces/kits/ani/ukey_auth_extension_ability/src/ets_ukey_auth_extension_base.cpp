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

#include "ets_ukey_auth_extension_base.h"

#include <array>

#include "ability_transaction_callback_info.h"
#include "ets_runtime.h"
#include "ets_ukey_auth_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "ukey_auth_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *UKEY_AUTH_EXTENSION_ABILITY_CLASS_NAME =
    "@ohos.security.UkeyAuthExtensionAbility.UkeyAuthExtensionAbility";

void OnDestroyPromiseCallback(ani_env *env, ani_object aniObj)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "OnDestroyPromiseCallback called");
    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env or null aniObj");
        return;
    }
    ani_long destroyCallbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "destroyCallbackPoint", &destroyCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "destroyCallbackPoint GetField status: %{public}d", status);
        return;
    }
    auto *callbackInfo = reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<> *>(destroyCallbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null callbackInfo");
        return;
    }
    callbackInfo->Call();
    AppExecFwk::AbilityTransactionCallbackInfo<>::Destroy(callbackInfo);

    if ((status = env->Object_SetFieldByName_Long(aniObj, "destroyCallbackPoint",
        static_cast<ani_long>(0))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "destroyCallbackPoint SetField status: %{public}d", status);
        return;
    }
}
} // namespace

EtsUkeyAuthExtensionBase::EtsUkeyAuthExtensionBase(const std::unique_ptr<Runtime> &runtime)
    : EtsUIExtensionBase(runtime) {}

bool EtsUkeyAuthExtensionBase::BindNativeMethods()
{
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return false;
    }
    std::array functions = {
        ani_native_function { "nativeOnDestroyCallback", ":", reinterpret_cast<void *>(OnDestroyPromiseCallback) },
    };
    ani_class cls {};
    ani_status status = env->FindClass(UKEY_AUTH_EXTENSION_ABILITY_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass failed status: %{public}d", status);
        return false;
    }
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_BindNativeMethods status: %{public}d", status);
        return false;
    }
    return true;
}

void EtsUkeyAuthExtensionBase::BindContext()
{
    if (!BindNativeMethods()) {
        TAG_LOGE(AAFwkTag::UI_EXT, "BindNativeMethods failed");
    }
    EtsUIExtensionBase::BindContext();
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "env is null");
        return;
    }
    if (etsObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsObj_");
        return;
    }
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context_");
        return;
    }
    auto ukeyContext = std::static_pointer_cast<UkeyAuthExtensionContext>(context_);
    ani_object contextObj = CreateEtsUkeyAuthExtensionContext(env, ukeyContext);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null contextObj");
        return;
    }
    ani_field contextField = nullptr;
    auto status = env->Class_FindField(etsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    ani_ref contextRef = nullptr;
    if ((status = env->GlobalReference_Create(contextObj, &contextRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    if ((status = env->Object_SetField_Ref(etsObj_->aniObj, contextField, contextRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
    }
    env->GlobalReference_Delete(contextRef);
}

} // namespace AbilityRuntime
} // namespace OHOS
