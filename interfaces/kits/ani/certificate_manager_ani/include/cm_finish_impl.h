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

#ifndef CM_FINISH_IMPL_H
#define CM_FINISH_IMPL_H

#include <memory>
#include "cm_ani_impl.h"
#include "cm_log.h"

namespace OHOS::Security::CertManager::Ani {
class CmFinishImpl : public CertManagerAniImpl {
public:
    /* ani params */
    ani_arraybuffer aniHandle = nullptr;
    ani_arraybuffer aniSignature = nullptr;
    /* parsed params */
    CmBlob handle;
    CmBlob signature;
    CmFinishImpl(ani_env *env);
    ~CmFinishImpl() {};

    int32_t GetParamsFromEnv() override;
    void OnFinish() override;
};

class CmSignatureFinishImpl : public CmFinishImpl {
public:
    CmSignatureFinishImpl(ani_env *env, ani_arraybuffer aniHandle);
    ~CmSignatureFinishImpl() {};

    int32_t Init() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
};

class CmVerifyFinishImpl : public CmFinishImpl {
public:
    CmVerifyFinishImpl(ani_env *env, ani_arraybuffer aniHandle, ani_arraybuffer aniSignature);
    ~CmVerifyFinishImpl() {};

    int32_t Init() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    int32_t GetParamsFromEnv() override;
};

class CmFinishImplProxy : public CertManagerAniImpl {
private:
    std::shared_ptr<CmFinishImpl> finishImpl = nullptr;
public:
    CmFinishImplProxy(ani_env *env, ani_arraybuffer aniHandle, ani_arraybuffer aniSignature);
    ~CmFinishImplProxy() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
};
}
#endif // CM_FINISH_IMPL_H