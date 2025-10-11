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

#include "cm_get_app_cert_impl.h"
#include "cm_log.h"
#include "securec.h"
#include "cm_mem.h"
#include "cert_manager_api.h"
#include "cm_result_builder.h"
#include "cm_ani_utils.h"

namespace OHOS::Security::CertManager::Ani {
CmGetAppCertImpl::CmGetAppCertImpl(ani_env *env, ani_string aniKeyUri, uint32_t store) : CertManagerAniImpl(env)
{
    this->aniKeyUri = aniKeyUri;
    this->store = store;
}

int32_t CmGetAppCertImpl::Init()
{
    this->credential = static_cast<Credential *>(CmMalloc(sizeof(Credential)));
    if (this->credential == nullptr) {
        CM_LOG_E("malloc credential buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(this->credential, sizeof(Credential), 0, sizeof(Credential));
    this->credential->credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    if (this->credential->credData.data == nullptr) {
        CM_LOG_E("malloc credData buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(this->credential->credData.data, MAX_LEN_CERTIFICATE_CHAIN, 0, MAX_LEN_CERTIFICATE_CHAIN);
    this->credential->credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    return CM_SUCCESS;
}

int32_t CmGetAppCertImpl::GetParamsFromEnv()
{
    int32_t ret = AniUtils::ParseString(this->env, this->aniKeyUri, this->keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keyUri failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmGetAppCertImpl::InvokeInnerApi()
{
    return CmGetAppCert(&this->keyUri, this->store, this->credential);
}

int32_t CmGetAppCertImpl::UnpackResult()
{
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder
        .setCredential(this->credential)
        ->build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

void CmGetAppCertImpl::OnFinish()
{
    CM_FREE_BLOB(keyUri);
    if (this->credential == nullptr) {
        return;
    }
    if (this->credential->credData.data != nullptr) {
        CmFree(this->credential->credData.data);
        this->credential->credData.data = nullptr;
    }
    CmFree(this->credential);
    this->credential = nullptr;
    return;
}
}