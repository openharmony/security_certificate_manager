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

#ifndef CM_GET_ALL_APP_PRIVATE_CERTS_BY_UID_IMPL_H
#define CM_GET_ALL_APP_PRIVATE_CERTS_BY_UID_IMPL_H

#include "cm_get_cred_list_impl.h"
#include "cm_log.h"
#include "cert_manager_api.h"

namespace OHOS::Security::CertManager::Ani {
class CmGetCredListByUidImpl : public CmGetCredListImpl {
private:
    /* ani params */
    ani_int aniAppUid = 0;
    /* parsed params */
    uint32_t appUid = 0;

public:
    CmGetCredListByUidImpl(ani_env *env, uint32_t store, ani_int aniAppUid);
    ~CmGetCredListByUidImpl() {};

    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
};
}
#endif // CM_GET_ALL_APP_PRIVATE_CERTS_BY_UID_IMPL_H