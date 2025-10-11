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

#ifndef CM_INIT_IMPL_H
#define CM_INIT_IMPL_H

#include "cm_ani_impl.h"
#include "cm_log.h"

namespace OHOS::Security::CertManager::Ani {
class CmInitImpl : public CertManagerAniImpl {
private:
    ani_string aniAuthUri = nullptr;
    ani_object spec = nullptr;
    CmBlob authUri = { 0 };
    CmSignatureSpec signatureSpec = { 0 };
    CmBlob handle = { 0 };
public:
    CmInitImpl(ani_env *env, ani_string aniAuthUri, ani_object spec);
    ~CmInitImpl() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
};
}
#endif // CM_INIT_IMPL_H