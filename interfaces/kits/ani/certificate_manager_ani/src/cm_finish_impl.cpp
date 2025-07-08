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

#include "cm_finish_impl.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cert_manager_api.h"
#include "cm_ani_common.h"
#include "cm_result_builder.h"
#include "securec.h"

namespace OHOS::Security::CertManager::Ani {
// CmFinishImpl
CmFinishImpl::CmFinishImpl(ani_env *env) : CertManagerAniImpl(env) {}

int32_t CmFinishImpl::GetParamsFromEnv()
{
    if (this->env == nullptr) {
        CM_LOG_E("Install private cert failed, env is null.");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = AniUtils::ParseUint8Array(this->env, this->aniHandle, this->handle);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse handle failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

void CmFinishImpl::OnFinish()
{
    CM_FREE_BLOB(this->signature);
    return;
}

// CmSignatureFinishImpl
CmSignatureFinishImpl::CmSignatureFinishImpl(ani_env *env, ani_arraybuffer aniHandle) : CmFinishImpl(env)
{
    this->aniHandle = aniHandle;
}

int32_t CmSignatureFinishImpl::Init()
{
    this->signature.data = static_cast<uint8_t *>(CmMalloc(OUT_SIGNATURE_SIZE));
    if (this->signature.data == nullptr) {
        CM_LOG_E("malloc signature data failed.");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(this->signature.data, OUT_SIGNATURE_SIZE, 0, OUT_SIGNATURE_SIZE);
    this->signature.size = OUT_SIGNATURE_SIZE;
    return CM_SUCCESS;
}

int32_t CmSignatureFinishImpl::InvokeInnerApi()
{
    CmBlob inData = { 0, nullptr };
    return CmFinish(&this->handle, &inData, &this->signature);
}

int32_t CmSignatureFinishImpl::UnpackResult()
{
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder
        .setOutData(&this->signature)
        ->build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

// CmVerifyFinishImpl
CmVerifyFinishImpl::CmVerifyFinishImpl(ani_env *env, ani_arraybuffer aniHandle,
    ani_arraybuffer aniSignature) : CmFinishImpl(env)
{
    this->aniHandle = aniHandle;
    this->aniSignature = aniSignature;
}

int32_t CmVerifyFinishImpl::Init()
{
    return CM_SUCCESS;
}

int32_t CmVerifyFinishImpl::GetParamsFromEnv()
{
    int32_t ret  = CmFinishImpl::GetParamsFromEnv();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("verify finish parse handle failed, ret = %d", ret);
        return ret;
    }
    ret = AniUtils::ParseUint8Array(this->env, this->aniSignature, this->signature);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse signature failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmVerifyFinishImpl::InvokeInnerApi()
{
    CmBlob outData = { 0, nullptr };
    return CmFinish(&this->handle, &this->signature, &outData);
}

int32_t CmVerifyFinishImpl::UnpackResult()
{
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder.build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

CmFinishImplProxy::CmFinishImplProxy(ani_env *env, ani_arraybuffer aniHandle,
    ani_arraybuffer aniSignature) : CertManagerAniImpl(env)
{
    if (AniUtils::IsUndefined(env, aniSignature)) {
        this->finishImpl = std::make_shared<CmSignatureFinishImpl>(env, aniHandle);
    } else {
        this->finishImpl = std::make_shared<CmVerifyFinishImpl>(env, aniHandle, aniSignature);
    }
}

int32_t CmFinishImplProxy::Init()
{
    if (this->finishImpl == nullptr) {
        CM_LOG_E("finishImpl is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    return this->finishImpl->Init();
}

int32_t CmFinishImplProxy::GetParamsFromEnv()
{
    if (this->finishImpl == nullptr) {
        CM_LOG_E("finishImpl is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    return this->finishImpl->GetParamsFromEnv();
}

int32_t CmFinishImplProxy::InvokeInnerApi()
{
    if (this->finishImpl == nullptr) {
        CM_LOG_E("finishImpl is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    return this->finishImpl->InvokeInnerApi();
}

int32_t CmFinishImplProxy::UnpackResult()
{
    if (this->finishImpl == nullptr) {
        CM_LOG_E("finishImpl is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    return this->finishImpl->UnpackResult();
}

void CmFinishImplProxy::OnFinish()
{
    if (this->finishImpl == nullptr) {
        CM_LOG_E("finishImpl is nullptr");
        return;
    }
    this->finishImpl->OnFinish();
}
}