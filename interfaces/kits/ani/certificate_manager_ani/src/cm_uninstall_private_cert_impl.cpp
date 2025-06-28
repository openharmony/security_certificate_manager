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

#include "cm_uninstall_private_cert_impl.h"
#include "cm_log.h"
#include "cm_ani_utils.h"
#include "cert_manager_api.h"
#include "cm_mem.h"
#include "cm_ani_common.h"

namespace OHOS::Security::CertManager::Ani {
CmUninstallPrivateCertImpl::CmUninstallPrivateCertImpl(ani_env *env, ani_string aniKeyuri) : CertManagerAniImpl(env)
{
    this->aniKeyuri = aniKeyuri;
}

int32_t CmUninstallPrivateCertImpl::Init()
{
    return CM_SUCCESS;
}

int32_t CmUninstallPrivateCertImpl::GetParamsFromEnv()
{
    if (this->env == nullptr) {
        CM_LOG_E("uninstall private cert failed, env is null.");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = AniUtils::ParseString(this->env, this->aniKeyuri, this->keyuri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keyuri failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmUninstallPrivateCertImpl::InvokeInnerApi()
{
    int32_t ret = CmUninstallAppCert(&this->keyuri, APPLICATION_PRIVATE_CERTIFICATE_STORE);
    if (ret == CMR_ERROR_NOT_EXIST) {
        CM_LOG_I("uninstall private cert uri not exist.");
        return CM_SUCCESS;
    }
    return ret;
}

int32_t CmUninstallPrivateCertImpl::UnpackResult()
{
    return CM_SUCCESS;
}

void CmUninstallPrivateCertImpl::OnFinish()
{
    CM_FREE_BLOB(this->keyuri);
}
}