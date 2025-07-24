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

#ifndef CM_INSTALL_USER_CA_SYNC_IMPL_H
#define CM_INSTALL_USER_CA_SYNC_IMPL_H

#include "cm_ani_impl.h"
#include "cm_log.h"

namespace OHOS::Security::CertManager::Ani {
class CmInstallUserCaSyncImpl : public CertManagerAniImpl {
private:
    /* ani params */
    ani_arraybuffer aniCertData = nullptr;
    ani_enum_item aniCertScope = nullptr;
    /* parsed params */
    CmBlob certData = { 0 };
    uint32_t certScope = 0;

    CmBlob certUri = { 0 };
public:
    CmInstallUserCaSyncImpl(ani_env *env, ani_arraybuffer aniCertData, ani_enum_item aniCertScope);
    ~CmInstallUserCaSyncImpl() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
};
}
#endif // CM_INSTALL_USER_CA_SYNC_IMPL_H