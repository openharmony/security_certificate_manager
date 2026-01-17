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

#include "cm_get_cred_list_by_uid_impl.h"
#include "cm_log.h"
#include "securec.h"
#include "cm_mem.h"
#include "cm_result_builder.h"
#include "cm_ani_common.h"

namespace OHOS::Security::CertManager::Ani {
CmGetCredListByUidImpl::CmGetCredListByUidImpl(ani_env *env, uint32_t store, ani_int aniAppUid)
    : CmGetCredListImpl(env, store)
{
    this->aniAppUid = aniAppUid;
}

int32_t CmGetCredListByUidImpl::GetParamsFromEnv()
{
    this->appUid = static_cast<uint32_t>(this->aniAppUid);
    return CM_SUCCESS;
}

int32_t CmGetCredListByUidImpl::InvokeInnerApi()
{
    return CmGetAppCertListByUid(this->store, this->appUid, &this->credentialList);
}
}