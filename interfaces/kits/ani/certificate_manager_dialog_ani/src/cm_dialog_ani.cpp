/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

namespace OHOS::Security::CertManager::Ani {
ani_object openCertificateManagerDialogNative(ani_env *env, ani_object context, ani_enum_item pageType,
    ani_object callback)
{
    auto openCertmanagerDialogImpl = std::make_shared<CmOpenCertManagerDialog>(env, context, pageType, callback);
    return openCertmanagerDialogImpl->Invoke();
}

ani_object openInstallCertificateDialogNative(ani_env *env, ani_object context, ani_object params,
    ani_object callback)
{
    auto openInstallDialogImpl = std::make_shared<CmOpenInstallDialog>(env, context, callback, params);
    return openInstallDialogImpl->Invoke();
}
ani_object openUninstallCertificateDialogNative(ani_env *env, ani_object context, ani_enum_item certType,
    ani_string certUri, ani_object callback)
{
    auto openUninstallDialogImpl = std::make_shared<CmOpenUninstallDialog>(env, context, certType, certUri, callback);
    return openUninstallDialogImpl->Invoke();
}

ani_object openCertificateDetailDialogNative(ani_env *env, ani_object context, ani_string cert,
    ani_boolean showInstallButton,  ani_object callback)
{
    auto openCertDetailDialogImpl = std::make_shared<CmOpenCertDetailDialog>(env, context, cert, showInstallButton,
        callback);
    return openCertDetailDialogImpl->Invoke();
}

ani_object openAuthorizeDialogNative(ani_env *env, ani_object context, ani_object callback)
{
    auto openAuthDialogImpl = std::make_shared<CmOpenAuthDialog>(env, context, callback);
    return openAuthDialogImpl->Invoke();
}

ani_object openAuthorizeDialogWithReqNative(ani_env *env, ani_object context, ani_object certTypes,
    ani_enum_item certPurpose, ani_object callback)
{
    auto openAuthDialogWithReqImpl = std::make_shared<CmOpenAuthDialogWithReq>(
        env, context, certTypes, certPurpose, callback);
    return openAuthDialogWithReqImpl->Invoke();
}

ani_object openUkeyAuthDialogNative(ani_env *env, ani_object context, ani_string keyUri, ani_object callback)
{
    auto openUkeyAuthDialogImpl = std::make_shared<CmOpenUkeyAuthDialog>(env, context, keyUri, callback);
    return openUkeyAuthDialogImpl->Invoke();
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
    };
    ret = env->Module_BindNativeFunctions(module, methods.data(), methods.size());
    if (ret != ANI_OK) {
        CM_LOG_E("Module_BindNativeFunctions failed, ret = %d", static_cast<int32_t>(ret));
        return ret;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}