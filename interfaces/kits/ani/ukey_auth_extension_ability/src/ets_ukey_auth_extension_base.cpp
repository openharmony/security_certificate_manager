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
#include "cm_log.h"
#include "ets_runtime.h"
#include "ets_ukey_auth_extension_context.h"
#include "ukey_auth_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *UKEY_AUTH_EXTENSION_ABILITY_CLASS_NAME =
    "@ohos.security.UkeyAuthExtensionAbility.UkeyAuthExtensionAbility";

void OnDestroyPromiseCallback(ani_env *env, ani_object aniObj)
{
    CM_LOG_D("OnDestroyPromiseCallback called");
    if (env == nullptr || aniObj == nullptr) {
        CM_LOG_E("null env or null aniObj");
        return;
    }
    ani_long destroyCallbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "destroyCallbackPoint", &destroyCallbackPoint)) != ANI_OK) {
        CM_LOG_E("destroyCallbackPoint GetField status: %d", status);
        return;
    }
    auto *callbackInfo = reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<> *>(destroyCallbackPoint);
    if (callbackInfo == nullptr) {
        CM_LOG_E("null callbackInfo");
        return;
    }
    callbackInfo->Call();
    AppExecFwk::AbilityTransactionCallbackInfo<>::Destroy(callbackInfo);

    if ((status = env->Object_SetFieldByName_Long(aniObj, "destroyCallbackPoint",
        static_cast<ani_long>(0))) != ANI_OK) {
        CM_LOG_E("destroyCallbackPoint SetField status: %d", status);
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
        CM_LOG_E("null env");
        return false;
    }
    std::array functions = {
        ani_native_function { "nativeOnDestroyCallback", ":", reinterpret_cast<void *>(OnDestroyPromiseCallback) },
    };
    ani_class cls {};
    ani_status status = env->FindClass(UKEY_AUTH_EXTENSION_ABILITY_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        CM_LOG_E("FindClass failed status: %d", status);
        return false;
    }
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        CM_LOG_E("Class_BindNativeMethods status: %d", status);
        return false;
    }
    return true;
}

void EtsUkeyAuthExtensionBase::BindContext()
{
    /* 模式对齐上游 EtsAutoFillExtension::BindContext：不调基类 BindContext，
     * 直接以 ukey 上下文对象绑定 context 字段并接管 shellContextRef_（保留
     * 全局引用，由基类析构释放）——避免产生被替换的基类上下文孤儿对象，且
     * 配置变更通知（EtsExtensionCommon::ConfigurationUpdated）落在 ukey 上下文上 */
    if (!BindNativeMethods()) {
        CM_LOG_E("BindNativeMethods failed");
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        CM_LOG_E("env is null");
        return;
    }
    if (etsObj_ == nullptr) {
        CM_LOG_E("null etsObj_");
        return;
    }
    if (context_ == nullptr) {
        CM_LOG_E("null context_");
        return;
    }
    auto ukeyContext = std::static_pointer_cast<UkeyAuthExtensionContext>(context_);
    ani_object contextObj = CreateEtsUkeyAuthExtensionContext(env, ukeyContext);
    if (contextObj == nullptr) {
        CM_LOG_E("null contextObj");
        return;
    }
    ani_field contextField = nullptr;
    auto status = env->Class_FindField(etsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        CM_LOG_E("status: %d", status);
        return;
    }
    ani_ref contextRef = nullptr;
    if ((status = env->GlobalReference_Create(contextObj, &contextRef)) != ANI_OK) {
        CM_LOG_E("status: %d", status);
        return;
    }
    if ((status = env->Object_SetField_Ref(etsObj_->aniObj, contextField, contextRef)) != ANI_OK) {
        CM_LOG_E("status: %d", status);
        env->GlobalReference_Delete(contextRef);
        return;
    }
    shellContextRef_ = std::make_shared<AppExecFwk::ETSNativeReference>();
    shellContextRef_->aniObj = contextObj;
    shellContextRef_->aniRef = contextRef;
}

} // namespace AbilityRuntime
} // namespace OHOS
