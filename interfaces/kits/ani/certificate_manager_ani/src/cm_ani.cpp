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
#include "cm_install_private_cert_impl.h"
#include "cm_uninstall_private_cert_impl.h"
#include "cm_get_app_cert_impl.h"
#include "cm_get_cred_list_impl.h"
#include "cm_init_impl.h"
#include "cm_update_impl.h"
#include "cm_finish_impl.h"
#include "cm_abort_impl.h"
#include "cm_is_authorized_app_impl.h"
#include "cm_get_ca_list_impl.h"
#include "cm_get_cert_info_impl.h"
#include "cm_install_user_ca_sync_impl.h"
#include "cm_get_cert_store_path.h"
#include "cm_uninstall_user_ca_sync_impl.h"

namespace OHOS::Security::CertManager::Ani {
static ani_object installPrivateCertificateNative(ani_env *env, ani_arraybuffer keystore, ani_string keystorePwd,
    ani_string certAlias)
{
    auto installPrivateCertImpl = std::make_shared<CmInstallPrivateCertImpl>(env, keystore, keystorePwd, certAlias);
    return installPrivateCertImpl->Invoke();
}

static ani_object installPrivateCertWithLevelNative(ani_env *env, ani_arraybuffer keystore, ani_string keystorePwd,
    ani_string certAlias, ani_enum_item level)
{
    auto installPrivateCertImpl = std::make_shared<CmInstallPrivateCertImpl>(env, keystore, keystorePwd, certAlias);
    installPrivateCertImpl->resultCode = installPrivateCertImpl->SetLevel(level);
    if (installPrivateCertImpl->resultCode != CM_SUCCESS) {
        CM_LOG_E("invalid level param");
        return installPrivateCertImpl->GenerateResult();
    }
    return installPrivateCertImpl->Invoke();
}

static ani_object uninstallPrivateCertificateNative(ani_env *env, ani_string keyuri)
{
    auto uninstallPrivateCertImpl = std::make_shared<CmUninstallPrivateCertImpl>(env, keyuri);
    return uninstallPrivateCertImpl->Invoke();
}

static ani_object getAllAppPrivateCertificatesNative(ani_env *env)
{
    auto getAllAppPrivateCertificatesImpl =
        std::make_shared<CmGetCredListImpl>(env, APPLICATION_PRIVATE_CERTIFICATE_STORE);
    return getAllAppPrivateCertificatesImpl->Invoke();
}

static ani_object getPrivateCertificatesNative(ani_env *env)
{
    auto getPrivateCredListImpl =
        std::make_shared<CmGetPrivateCredListImpl>(env, APPLICATION_PRIVATE_CERTIFICATE_STORE);
    return getPrivateCredListImpl->Invoke();
}

static ani_object getAllSystemCredNative(ani_env *env)
{
    auto getAllSystemCredImpl = std::make_shared<CmGetCredListImpl>(env, APPLICATION_SYSTEM_CERTIFICATE_STORE);
    return getAllSystemCredImpl->Invoke();
}

static ani_object getPrivateCertificateNative(ani_env *env, ani_string aniKeyuri)
{
    auto getPrivateCertificateImpl = std::make_shared<CmGetAppPrivateCertImpl>(env, aniKeyuri);
    return getPrivateCertificateImpl->Invoke();
}

static ani_object getPublicCertificateNative(ani_env *env, ani_string aniKeyuri)
{
    auto getPublicCertImpl = std::make_shared<CmGetAppPublicCertImpl>(env, aniKeyuri);
    return getPublicCertImpl->Invoke();
}

static ani_object initNative(ani_env *env, ani_string aniAuthUri, ani_object spec)
{
    auto initImpl = std::make_shared<CmInitImpl>(env, aniAuthUri, spec);
    return initImpl->Invoke();
}

static ani_object updateNative(ani_env *env, ani_arraybuffer aniHandle, ani_arraybuffer aniData)
{
    auto updateImpl = std::make_shared<CmUpdateImpl>(env, aniHandle, aniData);
    return updateImpl->Invoke();
}

static ani_object finishNative(ani_env *env, ani_arraybuffer aniHandle, ani_arraybuffer aniSignature)
{
    auto finishImpl = std::make_shared<CmFinishImplProxy>(env, aniHandle, aniSignature);
    return finishImpl->Invoke();
}

static ani_object abortNative(ani_env *env, ani_arraybuffer aniHandle)
{
    auto abortImpl = std::make_shared<CmAbortImpl>(env, aniHandle);
    return abortImpl->Invoke();
}

static ani_object isAuthorizedAppNative(ani_env *env, ani_string aniKeyUri)
{
    auto isAuthorizedAppImpl = std::make_shared<CmIsAuthorizedAppImpl>(env, aniKeyUri);
    return isAuthorizedAppImpl->Invoke();
}

static ani_object getAllUserCANative(ani_env *env, ani_string aniKeyUri)
{
    auto getAllUserCaImpl = std::make_shared<CmGetAllUserCaImpl>(env);
    return getAllUserCaImpl->Invoke();
}

static ani_object getAllUserCAByScopeNative(ani_env *env, ani_enum_item aniScope)
{
    auto getAllUserCaByScopeImpl = std::make_shared<CmGetAllUserCaByScopeImpl>(env, aniScope);
    return getAllUserCaByScopeImpl->Invoke();
}

static ani_object getUserCANative(ani_env *env, ani_string aniCertUri)
{
    auto getCertInfoImpl = std::make_shared<CmGetCertInfoImpl>(env, aniCertUri, CM_USER_TRUSTED_STORE);
    return getCertInfoImpl->Invoke();
}

static ani_object installUserCASyncNative(ani_env *env, ani_arraybuffer aniCertData, ani_enum_item aniCertScope)
{
    auto installUserCaSyncImpl = std::make_shared<CmInstallUserCaSyncImpl>(env, aniCertData, aniCertScope);
    return installUserCaSyncImpl->Invoke();
}

static ani_object uninstallUserCASyncNative(ani_env *env, ani_string aniCertUri)
{
    auto uninstallUserCaSyncImpl = std::make_shared<CmUninstallUserCaSyncImpl>(env, aniCertUri);
    return uninstallUserCaSyncImpl->Invoke();
}

static ani_object getCertificateStorePathNative(ani_env *env, ani_enum_item aniCertType, ani_enum_item aniCertScope)
{
    auto getCertStorePathImpl = std::make_shared<CmGetCertStorePathImpl>(env, aniCertType, aniCertScope);
    return getCertStorePathImpl->Invoke();
}

static const std::array NATIVE_METHODS {
    ani_native_function {"installPrivateCertificateNative", nullptr,
        reinterpret_cast<void *>(installPrivateCertificateNative)},
    ani_native_function {"installPrivateCertWithLevelNative", nullptr,
        reinterpret_cast<void *>(installPrivateCertWithLevelNative)},
    ani_native_function {"uninstallPrivateCertificateNative", nullptr,
        reinterpret_cast<void *>(uninstallPrivateCertificateNative)},
    ani_native_function {"getAllAppPrivateCertificatesNative", nullptr,
        reinterpret_cast<void *>(getAllAppPrivateCertificatesNative)},
    ani_native_function {"getPrivateCertificateNative", nullptr,
        reinterpret_cast<void *>(getPrivateCertificateNative)},
    ani_native_function {"initNative", nullptr,
        reinterpret_cast<void *>(initNative)},
    ani_native_function {"updateNative", nullptr,
        reinterpret_cast<void *>(updateNative)},
    ani_native_function {"finishNative", nullptr,
        reinterpret_cast<void *>(finishNative)},
    ani_native_function {"abortNative", nullptr,
        reinterpret_cast<void *>(abortNative)},
    ani_native_function {"getPublicCertificateNative", nullptr,
        reinterpret_cast<void *>(getPublicCertificateNative)},
    ani_native_function {"isAuthorizedAppNative", nullptr,
        reinterpret_cast<void *>(isAuthorizedAppNative)},
    ani_native_function {"getAllUserCANative", nullptr,
        reinterpret_cast<void *>(getAllUserCANative)},
    ani_native_function {"getAllUserCAByScopeNative", nullptr,
        reinterpret_cast<void *>(getAllUserCAByScopeNative)},
    ani_native_function {"getUserCANative", nullptr,
        reinterpret_cast<void *>(getUserCANative)},
    ani_native_function {"getAllSystemCredNative", nullptr,
        reinterpret_cast<void *>(getAllSystemCredNative)},
    ani_native_function {"getPrivateCertificatesNative", nullptr,
        reinterpret_cast<void *>(getPrivateCertificatesNative)},
    ani_native_function {"getCertificateStorePathNative", nullptr,
        reinterpret_cast<void *>(getCertificateStorePathNative)},
    ani_native_function {"installUserCASyncNative", nullptr,
        reinterpret_cast<void *>(installUserCASyncNative)},
    ani_native_function {"uninstallUserCASyncNative", nullptr,
        reinterpret_cast<void *>(uninstallUserCASyncNative)},
};
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
    ret = env->FindModule("L@ohos/security/certManager;", &module);
    if (ret != ANI_OK) {
        CM_LOG_E("FindModule failed, ret = %d", static_cast<int32_t>(ret));
        return ret;
    }

    ret = env->Module_BindNativeFunctions(module, OHOS::Security::CertManager::Ani::NATIVE_METHODS.data(),
        OHOS::Security::CertManager::Ani::NATIVE_METHODS.size());
    if (ret != ANI_OK) {
        CM_LOG_E("Module_BindNativeFunctions failed, ret = %d", static_cast<int32_t>(ret));
        return ret;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}