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

#ifndef CM_GET_UKEY_LIST_IMPL_H
#define CM_GET_UKEY_LIST_IMPL_H

#include "cm_ani_impl.h"
#include "cm_log.h"
#include "cert_manager_api.h"

namespace OHOS::Security::CertManager::Ani {
class CmGetUkeyCertListImpl : public CertManagerAniImpl {
private:
    /* ani params */
    ani_string aniStrParam = nullptr;
    ani_enum_item aniCertPurpose = nullptr;
    /* parsed params */
    CmBlob strParam = { 0 };
    uint32_t certPurpose = 0;
    uint32_t mode = 0;

    CredentialDetailList *certificateList = nullptr;
public:
    CmGetUkeyCertListImpl(ani_env *env, ani_string aniStrParam, ani_enum_item aniCertPurpose,
        uint32_t mode);
    ~CmGetUkeyCertListImpl() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
};
}
#endif // CM_GET_UKEY_LIST_IMPL_H