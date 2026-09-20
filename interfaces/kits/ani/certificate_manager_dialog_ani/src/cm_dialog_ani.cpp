/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include <array>

#include "ani.h"
#include "cm_log.h"
#include "cm_open_auth_dialog_with_request.h"
#include "cm_open_certmanager_dialog.h"
#include "cm_open_install_dialog.h"
#include "cm_open_uninstall_dialog.h"
#include "cm_open_cert_detail_dialog.h"
#include "cm_open_auth_dialog.h"
#include "cm_open_ukey_auth_dialog.h"
#include "cm_open_ukey_auth_dialog_sa_session.h"
#include "cm_open_auth_dialog_for_ukey_provider.h"
#include "cm_supports_ca_cert_dialog.h"
#include "cm_dialog_api_common.h"
#include "cm_ukey_dialog_common.h"
#include "cm_ukey_ani_request.h"
#include "cm_ani_common.h"
#include "cm_ani_utils.h"
#include "cm_api_common.h"
#include "cm_metrics.h"
#include "cm_mem.h"
#include "cm_ukey_ability_type.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
static ani_object GenerateResult(ani_env *env, int32_t code, const char *message)
{
    ani_object nativeResult{};
    int32_t ret = AniUtils::GenerateNativeResult(env, code, message, nullptr, nativeResult);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate native result failed, ret = %d", ret);
        return nullptr;
    }
    return nativeResult;
}

static ani_object InvokeCallbackVoid(ani_env *env, ani_object callback)
{
    if (callback == nullptr) {
        CM_LOG_E("callback is null");
        return nullptr;
    }

    ani_object businessError{};
    if (AniUtils::GenerateBusinessError(env, CM_SUCCESS, "", businessError) != CM_SUCCESS) {
        CM_LOG_E("generate businessError failed.");
        return GenerateResult(env, DIALOG_ERROR_GENERIC, DIALOG_GENERIC_MSG.c_str());
    }

    ani_ref nullRef{};
    ani_status status = env->GetNull(&nullRef);
    if (status != ANI_OK) {
        CM_LOG_E("get nullRef failed. status = %d", static_cast<int32_t>(status));
        return GenerateResult(env, DIALOG_ERROR_GENERIC, DIALOG_GENERIC_MSG.c_str());
    }

    status = env->Object_CallMethodByName_Void(callback, "invoke", "C{@ohos.base.BusinessError}Y:",
        businessError, nullRef);
    if (status != ANI_OK) {
        CM_LOG_E("invoke callback failed. status = %d", static_cast<int32_t>(status));
        return GenerateResult(env, DIALOG_ERROR_GENERIC, DIALOG_GENERIC_MSG.c_str());
    }
    return GenerateResult(env, CM_SUCCESS, "");
}

ani_object openCertificateManagerDialogNative(ani_env *env, ani_object context, ani_enum_item pageType,
    ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return InvokeCallbackVoid(env, callback);
    }
    auto openCertmanagerDialogImpl = std::make_shared<CmOpenCertManagerDialog>(env, context, pageType, callback);
    return openCertmanagerDialogImpl->Invoke();
}

ani_object openInstallCertificateDialogNative(ani_env *env, ani_object context, ani_object params,
    ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return GenerateResult(env, DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED,
            Dialog::CAPABILITY_NOT_SUPPORTED_MSG.c_str());
    }
    auto openInstallDialogImpl = std::make_shared<CmOpenInstallDialog>(env, context, callback, params);
    return openInstallDialogImpl->Invoke();
}
ani_object openUninstallCertificateDialogNative(ani_env *env, ani_object context, ani_enum_item certType,
    ani_string certUri, ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return InvokeCallbackVoid(env, callback);
    }
    auto openUninstallDialogImpl = std::make_shared<CmOpenUninstallDialog>(env, context, certType, certUri, callback);
    return openUninstallDialogImpl->Invoke();
}

ani_object openCertificateDetailDialogNative(ani_env *env, ani_object context, ani_string cert,
    ani_boolean showInstallButton,  ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return InvokeCallbackVoid(env, callback);
    }
    auto openCertDetailDialogImpl = std::make_shared<CmOpenCertDetailDialog>(env, context, cert, showInstallButton,
        callback);
    return openCertDetailDialogImpl->Invoke();
}

ani_object openAuthorizeDialogNative(ani_env *env, ani_object context, ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return GenerateResult(env, DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED,
            Dialog::CAPABILITY_NOT_SUPPORTED_MSG.c_str());
    }
    auto openAuthDialogImpl = std::make_shared<CmOpenAuthDialog>(env, context, callback);
    return openAuthDialogImpl->Invoke();
}

ani_object openAuthorizeDialogWithReqNative(ani_env *env, ani_object context, ani_object params, ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return GenerateResult(env, DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED,
            Dialog::CAPABILITY_NOT_SUPPORTED_MSG.c_str());
    }
    auto openAuthDialogWithReqImpl = std::make_shared<CmOpenAuthDialogWithReq>(
        env, context, params, callback);
    return openAuthDialogWithReqImpl->Invoke();
}

ani_object openUkeyAuthDialogNative(ani_env *env, ani_object context, ani_object ukeyAuthRequest,
    ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return InvokeCallbackVoid(env, callback);
    }
    /* The only overload (with context). Branch by the registered ability type:
     * UIExtension + PC -> SA session path; everything else (UIAbility, query
     * failure, UIExtension + non-PC) direct-launches via the caller's context
     * below (driver UIAbility want, or the system default dialog). */
    {
        CmUkeyAniRequest req;
        CmBlob keyUriBlob = { 0, nullptr };
        if (ParseUkeyAniRequest(env, ukeyAuthRequest, req) == CM_SUCCESS &&
            AniUtils::ParseString(env, req.keyUri, keyUriBlob) == CM_SUCCESS) {
            std::string driverBundle;
            std::string driverAbility;
            uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
            int32_t queryRet = GetUkeyAbilityInfo(&keyUriBlob, driverBundle, driverAbility, abilityType);
            CM_FREE_BLOB(keyUriBlob);
            if (queryRet == CM_SUCCESS && abilityType == CM_UKEY_ABILITY_TYPE_UIEXTENSION &&
                CmUkeyIsPcPlatformOrPcMode()) {
                CM_LOG_I("ukey driver registered a UIExtensionAbility pin dialog, go sa session path");
                auto saSessionImpl = std::make_shared<CmOpenUkeyAuthDialogSaSession>(env,
                    ukeyAuthRequest, callback);
                return saSessionImpl->Invoke();
            }
            /* Direct-launch path (original implementation): UIAbility / query
             * failure / UIExtension + non-PC -> context impl below */
        }
    }
    auto openUkeyAuthDialogImpl = std::make_shared<CmOpenUkeyAuthDialog>(env, context,
        ukeyAuthRequest, callback);
    return openUkeyAuthDialogImpl->Invoke();
}

ani_object openAuthDialogForUkeyProviderNative(ani_env *env, ani_object dialogInfo,
    ani_object ukeyAuthRequest, ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return InvokeCallbackVoid(env, callback);
    }
    UkeyProviderDialogParams params;
    params.aniDialogInfo = dialogInfo;
    params.aniRequest = ukeyAuthRequest;
    auto impl = std::make_shared<CmOpenAuthDialogForUkeyProvider>(env, params, callback);
    return impl->Invoke();
}

ani_object supportsCACertDialogNative(ani_env *env)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    auto result = OHOS::Security::CertManager::Ani::SupportsCACertDialog(env);
    return result;
}
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    if (vm == nullptr || result == nullptr) {
        return ANI_INVALID_ARGS;
    }
    ani_env *env;
    auto ret = vm->GetEnv(ANI_VERSION_1, &env);
    if (ret != ANI_OK) {
        CM_LOG_E("GetEnv failed, ret = %d", static_cast<int32_t>(ret));
        return ret;
    }
    ani_module module;
    ret = env->FindModule("@ohos.security.certManagerDialog", &module);
    if (ret != ANI_OK) {
        CM_LOG_E("FindModule failed, ret = %d", static_cast<int32_t>(ret));
        return ret;
    }
    const std::array methods {
        ani_native_function {"openCertificateManagerDialogNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openCertificateManagerDialogNative)},
        ani_native_function {"openInstallCertificateDialogNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openInstallCertificateDialogNative)},
        ani_native_function {"openUninstallCertificateDialogNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openUninstallCertificateDialogNative)},
        ani_native_function {"openCertificateDetailDialogNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openCertificateDetailDialogNative)},
        ani_native_function {"openAuthorizeDialogNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openAuthorizeDialogNative)},
        ani_native_function {"openAuthorizeDialogWithReqNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openAuthorizeDialogWithReqNative)},
        ani_native_function {"openUkeyAuthDialogNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openUkeyAuthDialogNative)},
        ani_native_function {"openAuthDialogForUkeyProviderNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openAuthDialogForUkeyProviderNative)},
        ani_native_function {"supportsCACertDialogNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::supportsCACertDialogNative)},
    };
    ret = env->Module_BindNativeFunctions(module, methods.data(), methods.size());
    if (ret != ANI_OK) {
        CM_LOG_E("Module_BindNativeFunctions failed, ret = %d", static_cast<int32_t>(ret));
        return ret;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}