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

#include "cm_install_private_cert_impl.h"
#include "cm_log.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cert_manager_api.h"
#include "cm_result_builder.h"
#include "cm_mem.h"

namespace OHOS::Security::CertManager::Ani {
CmInstallPrivateCertImpl::CmInstallPrivateCertImpl(ani_env *env, ani_arraybuffer aniKeystore,
    ani_string aniKeystorePwd, ani_string aniCertAlias) : CertManagerAniImpl(env)
{
    this->aniKeystore = aniKeystore;
    this->aniKeystorePwd = aniKeystorePwd;
    this->aniCertAlias = aniCertAlias;
}

int32_t CmInstallPrivateCertImpl::Init()
{
    this->retUri.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_URI));
    if (this->retUri.data == nullptr) {
        CM_LOG_E("init uri failed.");
        return CMR_ERROR_MALLOC_FAIL;
    }
    this->retUri.size = MAX_LEN_URI;
    return CM_SUCCESS;
}

int32_t CmInstallPrivateCertImpl::GetParamsFromEnv()
{
    if (this->env == nullptr) {
        CM_LOG_E("Install private cert failed, env is null.");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = AniUtils::ParseUint8Array(this->env, this->aniKeystore, this->keystore);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keystore failed, ret = %d", ret);
        return ret;
    }
    ret = AniUtils::ParseString(this->env, this->aniKeystorePwd, this->keystorePwd);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keystorePwd failed, ret = %d", ret);
        return ret;
    }
    ret = AniUtils::ParseString(this->env, this->aniCertAlias, this->certAlias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse certAlias failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmInstallPrivateCertImpl::InvokeInnerApi()
{
    struct CmBlob privKey = { 0, NULL };
    struct CmAppCertParam certParam = {
        &this->keystore,
        &this->keystorePwd,
        &this->certAlias,
        APPLICATION_PRIVATE_CERTIFICATE_STORE,
        INIT_INVALID_VALUE,
        level,
        FILE_P12,
        &privKey,
        DEFAULT_FORMAT
    };

    int32_t ret = CmInstallAppCertEx(&certParam, &this->retUri);
    if (ret == CMR_ERROR_PASSWORD_IS_ERR) {
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }
    return ret;
}

int32_t CmInstallPrivateCertImpl::UnpackResult()
{
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder
        .setUri(&this->retUri)
        ->build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

void CmInstallPrivateCertImpl::OnFinish()
{
    CM_FREE_BLOB(this->keystorePwd);
    CM_FREE_BLOB(this->certAlias);
    CM_FREE_BLOB(this->retUri);
}

int32_t CmInstallPrivateCertImpl::SetLevel(ani_enum_item aniLevel)
{
    uint32_t levelValue = 0;
    if (env->EnumItem_GetValue_Int(aniLevel, (ani_int *)&levelValue) != ANI_OK) {
        CM_LOG_E("get certType enumItem failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    level = static_cast<enum CmAuthStorageLevel>(levelValue);
    return CM_SUCCESS;
}
}