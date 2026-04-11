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

#include "cm_import_ukey_cert_impl.h"
#include "cert_manager_api.h"
#include "cm_log.h"
#include "securec.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"

namespace OHOS::Security::CertManager::Ani {
CmImportUkeyCertImpl::CmImportUkeyCertImpl(ani_env *env, ani_string aniKeyUri, ani_object aniCert,
    ani_object aniUkeyInfo) : CertManagerAniImpl(env)
{
    this->aniKeyUri_ = aniKeyUri;
    this->aniCert_ = aniCert;
    this->aniUkeyInfo_ = aniUkeyInfo;
}

int32_t CmImportUkeyCertImpl::Init()
{
    return CM_SUCCESS;
}

int32_t CmImportUkeyCertImpl::GetParamsFromEnv()
{
    int32_t ret = AniUtils::ParseString(this->env, this->aniKeyUri_, this->keyUri_);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse aniKeyUri failed, ret = %d", ret);
        return ret;
    }

    ret = AniUtils::ParseUint8Array(this->env, reinterpret_cast<ani_arraybuffer>(this->aniCert_), this->cert_);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse aniCert failed, ret = %d", ret);
        return ret;
    }

    if (this->aniUkeyInfo_ == nullptr) {
        this->certPurpose_ = CM_CERT_PURPOSE_DEFAULT;
        return CM_SUCCESS;
    }

    ani_enum_item certPurposeItem = nullptr;
    if (this->env->Object_GetPropertyByName_Ref(this->aniUkeyInfo_, "certPurpose",
        reinterpret_cast<ani_ref *>(&certPurposeItem)) != ANI_OK) {
        this->certPurpose_ = CM_CERT_PURPOSE_DEFAULT;
        return CM_SUCCESS;
    }

    if (this->env->EnumItem_GetValue_Int(certPurposeItem, (ani_int *)&this->certPurpose_) != ANI_OK) {
        CM_LOG_E("get certPurpose enumItem failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    switch (this->certPurpose_) {
        case CM_CERT_PURPOSE_DEFAULT:
        case CM_CERT_PURPOSE_SIGN:
        case CM_CERT_PURPOSE_ENCRYPT:
            return CM_SUCCESS;
        default:
            CM_LOG_E("invalid cert purpose: %d", this->certPurpose_);
            return CMR_ERROR_INVALID_ARGUMENT;
    }
}

int32_t CmImportUkeyCertImpl::InvokeInnerApi()
{
    struct UkeyInfo ukeyInfo = {
        .certPurpose = static_cast<enum CmCertificatePurpose>(this->certPurpose_)
    };
    return CmImportUkeyCert(&this->keyUri_, &this->cert_, &ukeyInfo);
}

int32_t CmImportUkeyCertImpl::UnpackResult()
{
    return CM_SUCCESS;
}

void CmImportUkeyCertImpl::OnFinish()
{
    CM_FREE_BLOB(this->keyUri_);
}
}  // namespace OHOS::Security::CertManager::Ani
