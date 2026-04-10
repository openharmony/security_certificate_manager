/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CM_IMPORT_UKEY_CERT_IMPL_H
#define CM_IMPORT_UKEY_CERT_IMPL_H

#include "cm_ani_impl.h"
#include "cm_log.h"
#include "cert_manager_api.h"

namespace OHOS::Security::CertManager::Ani {
class CmImportUkeyCertImpl : public CertManagerAniImpl {
private:
    ani_string aniKeyUri_ = nullptr;
    ani_object aniCert_ = nullptr;
    ani_object aniUkeyInfo_ = nullptr;
    
    struct CmBlob keyUri_ = { 0 };
    struct CmBlob cert_ = { 0 };
    uint32_t certPurpose_ = 0;

public:
    CmImportUkeyCertImpl(ani_env *env, ani_string aniKeyUri, ani_object aniCert, ani_object aniUkeyInfo);
    ~CmImportUkeyCertImpl() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
};
}  // namespace OHOS::Security::CertManager::Ani

#endif
