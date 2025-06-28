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

#ifndef CM_INSTALL_PRIVATE_CERT_IMPL_H
#define CM_INSTALL_PRIVATE_CERT_IMPL_H

#include "cm_ani_impl.h"
#include "cm_log.h"
#include "cert_manager_api.h"

namespace OHOS::Security::CertManager::Ani {
class CmInstallPrivateCertImpl : public CertManagerAniImpl {
private:
    /* ani params */
    ani_arraybuffer aniKeystore = nullptr;
    ani_string aniKeystorePwd = nullptr;
    ani_string aniCertAlias = nullptr;
    /* parsed params */
    CmBlob keystore = {};
    CmBlob keystorePwd = {};
    CmBlob certAlias = {};
    CmBlob retUri = {};

    enum CmAuthStorageLevel level = CM_AUTH_STORAGE_LEVEL_EL1;
public:
    CmInstallPrivateCertImpl(ani_env *env, ani_arraybuffer aniKeystore, ani_string aniKeystorePwd,
        ani_string aniCertAlias);
    ~CmInstallPrivateCertImpl() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    int32_t SetLevel(ani_enum_item aniLevel);
};
}
#endif