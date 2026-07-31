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

#ifndef CM_ANI_ASYNC_IMPL_H
#define CM_ANI_ASYNC_IMPL_H

#include "cm_ani_impl.h"
#include "cm_type.h"
#include "ani_base_context.h"
#include "ability_context.h"

namespace OHOS::Security::CertManager::Ani {
using namespace OHOS::AbilityRuntime;

class CertManagerAsyncImpl : public CertManagerAniImpl {
public:
    ani_vm *vm = nullptr;
    ani_object callback = nullptr;
    ani_ref globalCallback = nullptr;
    ani_object aniContext = nullptr;

    std::shared_ptr<AbilityContext> abilityContext = nullptr;
public:
    CertManagerAsyncImpl(ani_env *env, ani_object aniContext, ani_object callback,
        const char *interfaceName);
    virtual ~CertManagerAsyncImpl();

    virtual int32_t InvokeAsyncWork() = 0;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t Init() override;
    ani_object GenerateResult() override;
    // Async scenario: when Invoke() returns synchronously, only report the finish
    // histogram when errorCode != CM_SUCCESS. CM_SUCCESS means the Ability has
    // been launched successfully and the actual outcome is delivered through
    // the UIExtension callback, where CmAniUIExtensionCallback::invokeCallback()
    // is responsible for emitting the finish histogram.
    void OnInvokeEnd(int32_t errorCode) override;
};

} // OHOS::Security::CertManager::Ani

#endif // CM_ANI_ASYNC_IMPL_H
