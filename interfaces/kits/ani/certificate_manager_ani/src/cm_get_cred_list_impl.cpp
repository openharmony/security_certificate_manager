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

#include "cm_get_cred_list_impl.h"
#include "cm_log.h"
#include "securec.h"
#include "cm_mem.h"
#include "cm_result_builder.h"
#include "cm_ani_common.h"

namespace OHOS::Security::CertManager::Ani {
CmGetCredListImpl::CmGetCredListImpl(ani_env *env, uint32_t store) : CertManagerAniImpl(env)
{
    this->store = store;
}
int32_t CmGetCredListImpl::Init()
{
    return CM_SUCCESS;
}

int32_t CmGetCredListImpl::GetParamsFromEnv()
{
    return CM_SUCCESS;
}

int32_t CmGetCredListImpl::InvokeInnerApi()
{
    return CmGetAppCertList(this->store, &this->credentialList);
}

int32_t CmGetCredListImpl::UnpackResult()
{
    // credentialList
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder
        .setCredentialList(&this->credentialList)
        ->build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

void CmGetCredListImpl::OnFinish()
{
    if (credentialList.credentialAbstract != nullptr) {
        CmFree(credentialList.credentialAbstract);
        credentialList.credentialAbstract = nullptr;
    }
    return;
}
}