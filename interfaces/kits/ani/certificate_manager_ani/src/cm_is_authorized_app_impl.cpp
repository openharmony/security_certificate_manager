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

#include "cm_is_authorized_app_impl.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cert_manager_api.h"

namespace OHOS::Security::CertManager::Ani {
CmIsAuthorizedAppImpl::CmIsAuthorizedAppImpl(ani_env *env, ani_string aniKeyUri) : CertManagerAniImpl(env)
{
    this->aniKeyUri = aniKeyUri;
}

int32_t CmIsAuthorizedAppImpl::Init()
{
    return CM_SUCCESS;
}

int32_t CmIsAuthorizedAppImpl::GetParamsFromEnv()
{
    int32_t ret = AniUtils::ParseString(this->env, this->aniKeyUri, this->keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keyuri failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmIsAuthorizedAppImpl::InvokeInnerApi()
{
    return CmIsAuthorizedApp(&this->keyUri);
}

int32_t CmIsAuthorizedAppImpl::UnpackResult()
{
    if (this->resultCode == CM_SUCCESS) {
        AniUtils::CreateBooleanObject(this->env, true, this->result);
    } else if (this->resultCode == CMR_ERROR_AUTH_CHECK_FAILED) {
        AniUtils::CreateBooleanObject(this->env, false, this->result);
        this->resultCode = CM_SUCCESS;
    }
    return CM_SUCCESS;
}

void CmIsAuthorizedAppImpl::OnFinish()
{
    CM_FREE_BLOB(this->keyUri);
    return;
}
}