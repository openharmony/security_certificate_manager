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

#ifndef CM_GET_CERT_STORE_PATH_H
#define CM_GET_CERT_STORE_PATH_H

#include <string>

#include "cm_ani_impl.h"
#include "cm_log.h"

#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

namespace OHOS::Security::CertManager::Ani {
class CmGetCertStorePathImpl : public CertManagerAniImpl {
private:
    /* ani params */
    ani_enum_item aniCertType = nullptr;
    ani_enum_item aniCertScope = nullptr;
    ani_enum_item aniCertAlg = nullptr;
    /* parsed params */
    uint32_t certType = 0;
    uint32_t certScope = 1;
    uint32_t certAlg = 1;

    std::string path = "";

    sptr<OHOS::AppExecFwk::BundleMgrProxy> GetBundleMgrProxy();
    int32_t GetUserCaStorePath();
    int32_t GetSysCaStorePath();

public:
    CmGetCertStorePathImpl(ani_env *env, ani_enum_item aniCertType, ani_enum_item aniCertScope,
        ani_enum_item aniCertAlg);
    ~CmGetCertStorePathImpl() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
};
}
#endif // CM_GET_CERT_STORE_PATH_H