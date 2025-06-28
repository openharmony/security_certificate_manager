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

#include "cm_get_ca_list_impl.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "securec.h"
#include "cm_result_builder.h"

namespace OHOS::Security::CertManager::Ani {
CmGetCaListImpl::CmGetCaListImpl(ani_env *env) : CertManagerAniImpl(env) {}

int32_t CmGetCaListImpl::Init()
{
    uint32_t buffSize = MAX_COUNT_CERTIFICATE_ALL * sizeof(struct CertAbstract);
    this->certList.certAbstract = static_cast<CertAbstract *>(CmMalloc(buffSize));
    if (this->certList.certAbstract == nullptr) {
        CM_LOG_E("malloc certificateList certAbstract fail");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(this->certList.certAbstract, buffSize, 0, buffSize);
    this->certList.certsCount = MAX_COUNT_CERTIFICATE_ALL;
    return CM_SUCCESS;
}

int32_t CmGetCaListImpl::GetParamsFromEnv()
{
    return CM_SUCCESS;
}

int32_t CmGetCaListImpl::UnpackResult()
{
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder
        .setCertList(&this->certList)
        ->build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

void CmGetCaListImpl::OnFinish()
{
    CM_FREE_PTR(this->certList.certAbstract);
    this->certList.certsCount = 0;
    return;
}

CmGetAllUserCaByScopeImpl::CmGetAllUserCaByScopeImpl(ani_env *env, ani_enum_item aniScope) : CmGetCaListImpl(env)
{
    this->aniScope = aniScope;
}

int32_t CmGetAllUserCaByScopeImpl::GetParamsFromEnv()
{
    if (env->EnumItem_GetValue_Int(this->aniScope, (ani_int *)&this->scope) != ANI_OK) {
        CM_LOG_E("get scopeEnum value failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CmGetAllUserCaByScopeImpl::InvokeInnerApi()
{
    if (this->scope == CM_CURRENT_USER || this->scope == CM_GLOBAL_USER) {
        struct UserCAProperty prop = { INIT_INVALID_VALUE, this->scope };
        return CmGetUserCACertList(&prop, &this->certList);
    } else {
        return CmGetUserCertList(CM_USER_TRUSTED_STORE, &this->certList);
    }
}
}