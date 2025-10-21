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

#include "cm_ani_async_impl.h"
#include "cm_log.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "ability_context.h"

namespace OHOS::Security::CertManager::Ani {
using namespace OHOS::AbilityRuntime;

CertManagerAsyncImpl::CertManagerAsyncImpl(ani_env *env, ani_object aniContext,
    ani_object callback) : CertManagerAniImpl(env)
{
    this->env = env;
    this->callback = callback;
    this->aniContext = aniContext;
}

CertManagerAsyncImpl::~CertManagerAsyncImpl() {}

int32_t CertManagerAsyncImpl::Init()
{
    return CM_SUCCESS;
}

int32_t CertManagerAsyncImpl::GetParamsFromEnv()
{
    ani_boolean stageMode = false;
    ani_status status = IsStageContext(env, this->aniContext, stageMode);
    if (status != ANI_OK || !stageMode) {
        CM_LOG_E("check not stage mode.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    auto context = GetStageModeContext(env, this->aniContext);
    if (context == nullptr) {
        CM_LOG_E("get stageMode context failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    this->abilityContext = Context::ConvertTo<AbilityContext>(context);
    if (this->abilityContext == nullptr) {
        CM_LOG_E("convert context to abilityContext failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    status = env->GlobalReference_Create(reinterpret_cast<ani_ref>(this->callback), &this->globalCallback);
    if (status != ANI_OK) {
        CM_LOG_E("failed to create global callback.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CertManagerAsyncImpl::InvokeAsyncWork()
{
    return CM_SUCCESS;
}

int32_t CertManagerAsyncImpl::InvokeInnerApi()
{
    int32_t ret = this->InvokeAsyncWork();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("failed to InvokeAsyncWork. ret = %d", ret);
        env->GlobalReference_Delete(this->globalCallback);
        return ret;
    }
    return CM_SUCCESS;
}

ani_object CertManagerAsyncImpl::GenerateResult()
{
    int32_t ret;
    if (this->resultCode != CM_SUCCESS) {
        return GetAniDialogNativeResult(this->env, this->resultCode);
    }

    ani_object nativeResult{};
    ret = AniUtils::GenerateNativeResult(this->env, this->resultCode, nullptr, this->result, nativeResult);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate native result failed, ret = %d", ret);
        return nullptr;
    }
    return nativeResult;
}
} // OHOS::Security::CertManager::Ani
