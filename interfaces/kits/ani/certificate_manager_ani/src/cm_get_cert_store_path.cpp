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

#include "cm_get_cert_store_path.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_api_common.h"

namespace OHOS::Security::CertManager::Ani {
CmGetCertStorePathImpl::CmGetCertStorePathImpl(ani_env *env, ani_enum_item aniCertType,
    ani_enum_item aniCertScope, ani_enum_item aniCertAlg) : CertManagerAniImpl(env)
{
    this->aniCertType = aniCertType;
    this->aniCertScope = aniCertScope;
    this->aniCertAlg = aniCertAlg;
}

int32_t CmGetCertStorePathImpl::Init()
{
    return CM_SUCCESS;
}

int32_t CmGetCertStorePathImpl::GetParamsFromEnv()
{
    if (env->EnumItem_GetValue_Int(aniCertType, (ani_int *)&certType) != ANI_OK) {
        CM_LOG_E("get certType enumItem failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (env->EnumItem_GetValue_Int(aniCertScope, (ani_int *)&certScope) != ANI_OK) {
        CM_LOG_E("get certScope enumItem failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (env->EnumItem_GetValue_Int(aniCertAlg, (ani_int *)&certAlg) != ANI_OK) {
        CM_LOG_E("get certAlg enumItem failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

sptr<OHOS::AppExecFwk::BundleMgrProxy> CmGetCertStorePathImpl::GetBundleMgrProxy()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        CM_LOG_E("Failed to get system ability mgr.");
        return nullptr;
    }

    auto remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        CM_LOG_E("Failed to get bundle manager proxy.");
        return nullptr;
    }
    return iface_cast<OHOS::AppExecFwk::BundleMgrProxy>(remoteObject);
}

int32_t CmGetCertStorePathImpl::GetUserCaStorePath()
{
    path = CA_STORE_PATH_USER_SANDBOX_BASE;
    if (certScope == CM_GLOBAL_USER) {
        path += "0";
        return CM_SUCCESS;
    }

    int32_t userId = 0;
    sptr<OHOS::AppExecFwk::BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        CM_LOG_E("Failed to get bundle manager proxy.");
        return CM_FAILURE;
    }

    OHOS::AppExecFwk::BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    int32_t ret = bundleMgrProxy->GetBundleInfoForSelf(flags, bundleInfo);
    if (ret != 0) {
        CM_LOG_E("Failed to get bundle info for self");
        return CM_FAILURE;
    }

    ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleInfo.applicationInfo.uid, userId);
    if (ret != 0) {
        CM_LOG_E("Failed to get userid from uid[%d]", bundleInfo.applicationInfo.uid);
        return CM_FAILURE;
    }

    path += std::to_string(userId);
    return CM_SUCCESS;
}

static bool IsDirExist(const char *fileName)
{
    if (fileName == nullptr) {
        return false;
    }
    if (access(fileName, F_OK) == 0) {
        return true;
    }
    return false;
}

int32_t CmGetCertStorePathImpl::GetSysCaStorePath()
{
    if (this->certAlg == CM_ALG_INTERNATIONAL) {
        path = CA_STORE_PATH_SYSTEM;
        return CM_SUCCESS;
    } else if (this->certAlg == CM_ALG_SM && IsDirExist(SYSTEM_CA_STORE_GM)) {
        path = CA_STORE_PATH_SYSTEM_SM;
    } else {
        CM_LOG_E("not support, certAlg: %u", this->certAlg);
        return CMR_ERROR_STORE_PATH_NOT_SUPPORTED;
    }
    return CM_SUCCESS;
}

int32_t CmGetCertStorePathImpl::InvokeInnerApi()
{
    this->path = "";
    int32_t ret;
    if (this->certType == CM_CA_CERT_SYSTEM) {
        ret = GetSysCaStorePath();
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get system ca path.");
            return ret;
        }
    } else {
        ret = GetUserCaStorePath();
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get user ca path.");
            return ret;
        }
    }
    return CM_SUCCESS;
}

int32_t CmGetCertStorePathImpl::UnpackResult()
{
    this->result = AniUtils::GenerateCharStr(this->env, this->path.c_str(), this->path.size());
    if (this->result == nullptr) {
        CM_LOG_E("generate result error.");
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

void CmGetCertStorePathImpl::OnFinish()
{
    return;
}
}