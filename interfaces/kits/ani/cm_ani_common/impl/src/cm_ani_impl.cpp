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

#include "cm_ani_impl.h"
#include "cm_log.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"

namespace OHOS::Security::CertManager::Ani {

CertManagerAniImpl::CertManagerAniImpl(ani_env *env)
{
    this->env = env;
}

CertManagerAniImpl::~CertManagerAniImpl() {}

ani_object CertManagerAniImpl::GenerateResult()
{
    int32_t ret;
    if (this->resultCode != CM_SUCCESS) {
        return GetAniErrorResult(this->env, this->resultCode);
    }
    ani_object nativeResult{};
    ret = AniUtils::GenerateNativeResult(env, this->resultCode, nullptr, this->result, nativeResult);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate native result failed, ret = %d", ret);
        return nullptr;
    }
    return nativeResult;
}

ani_object CertManagerAniImpl::Invoke()
{
    CM_LOG_I("ani invoke start.");
    if (this->env == nullptr) {
        CM_LOG_E("ani invoke failed.");
        return nullptr;
    }

    int32_t ret = CM_SUCCESS;
    do {
        ret = this->Init();
        if (ret != CM_SUCCESS) {
            CM_LOG_E("init failed.");
            break;
        }
        ret = this->GetParamsFromEnv();
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get params failed.");
            break;
        }
        ret = this->InvokeInnerApi();
        if (ret != CM_SUCCESS) {
            CM_LOG_E("ani send request failed.");
            break;
        }
        ret = this->UnpackResult();
        if (ret != CM_SUCCESS) {
            CM_LOG_E("ani unpack result failed.");
            break;
        }
    } while (0);
    this->OnFinish();
    this->resultCode = ret;
    CM_LOG_I("ani invoke end. ret = %d", this->resultCode);
    return this->GenerateResult();
}
} // OHOS::Security::CertManager::Ani
