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

#include "cm_abort_impl.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cert_manager_api.h"

namespace OHOS::Security::CertManager::Ani {
CmAbortImpl::CmAbortImpl(ani_env *env, ani_arraybuffer aniHandle) : CertManagerAniImpl(env)
{
    this->aniHandle = aniHandle;
}

int32_t CmAbortImpl::Init()
{
    return CM_SUCCESS;
}

int32_t CmAbortImpl::GetParamsFromEnv()
{
    if (this->env == nullptr) {
        CM_LOG_E("check env is null.");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = AniUtils::ParseUint8Array(this->env, this->aniHandle, this->handle);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse handle failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmAbortImpl::InvokeInnerApi()
{
    return CmAbort(&this->handle);
}

int32_t CmAbortImpl::UnpackResult()
{
    return CM_SUCCESS;
}

void CmAbortImpl::OnFinish()
{
    return;
}
}