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

#include "cm_get_cert_info_impl.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "securec.h"
#include "cert_manager_api.h"
#include "cm_result_builder.h"

namespace OHOS::Security::CertManager::Ani {
CmGetCertInfoImpl::CmGetCertInfoImpl(ani_env *env, ani_string aniCertUri, uint32_t store) : CertManagerAniImpl(env)
{
    this->aniCertUri = aniCertUri;
    this->store = store;
}

int32_t CmGetCertInfoImpl::Init()
{
    this->certificate = static_cast<struct CertInfo *>(CmMalloc(sizeof(struct CertInfo)));
    if (this->certificate == nullptr) {
        CM_LOG_E("malloc certificate fail");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(this->certificate, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));

    this->certificate->certInfo.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE));
    if (this->certificate->certInfo.data == nullptr) {
        CM_LOG_E("malloc certificate certInfo data fail");
        return CMR_ERROR_MALLOC_FAIL;
    }
    this->certificate->certInfo.size = MAX_LEN_CERTIFICATE;
    return CM_SUCCESS;
}

int32_t CmGetCertInfoImpl::GetParamsFromEnv()
{
    int32_t ret = AniUtils::ParseString(this->env, this->aniCertUri, this->certUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse certUri failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmGetCertInfoImpl::InvokeInnerApi()
{
    if (this->store == CM_SYSTEM_TRUSTED_STORE) {
        return CmGetCertInfo(&this->certUri, this->store, this->certificate);
    } else {
        return CmGetUserCertInfo(&this->certUri, this->store, this->certificate);
    }
}

int32_t CmGetCertInfoImpl::UnpackResult()
{
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder
        .setCertInfo(this->certificate)
        ->build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

void CmGetCertInfoImpl::OnFinish()
{
    CM_FREE_BLOB(this->certUri);
    if (this->certificate == nullptr) {
        return;
    }
    CM_FREE_BLOB(this->certificate->certInfo);
    CM_FREE_PTR(this->certificate);
    return;
}
}