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

#include "cm_init_impl.h"
#include "cm_log.h"
#include "securec.h"
#include "cm_mem.h"
#include "cert_manager_api.h"
#include "cm_result_builder.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"

namespace OHOS::Security::CertManager::Ani {
CmInitImpl::CmInitImpl(ani_env *env, ani_string aniAuthUri, ani_object spec) : CertManagerAniImpl(env)
{
    this->aniAuthUri = aniAuthUri;
    this->spec = spec;
}

int32_t CmInitImpl::Init()
{
    this->handle.data = static_cast<uint8_t *>(CmMalloc(OUT_HANDLE_SIZE));
    if (this->handle.data == nullptr) {
        CM_LOG_E("malloc credData buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(this->handle.data, OUT_HANDLE_SIZE, 0, OUT_HANDLE_SIZE);
    this->handle.size = OUT_HANDLE_SIZE;
    return CM_SUCCESS;
}

int32_t CmInitImpl::GetParamsFromEnv()
{
    int32_t ret = AniUtils::ParseString(this->env, this->aniAuthUri, this->authUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse authUri failed, ret = %d", ret);
        return ret;
    }
    ret = AniUtils::ParseSignatureSpec(this->env, this->spec, &this->signatureSpec);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse signatureSpec failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmInitImpl::InvokeInnerApi()
{
    return CmInit(&this->authUri, &this->signatureSpec, &this->handle);
}

int32_t CmInitImpl::UnpackResult()
{
    int32_t ret = AniUtils::GenerateCMHandle(this->env, &this->handle, this->result);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate cmHandle failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

void CmInitImpl::OnFinish()
{
    CM_FREE_BLOB(this->authUri);
    CM_FREE_BLOB(this->handle);
    return;
}
}