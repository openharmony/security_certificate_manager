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

#include "cm_install_user_ca_sync_impl.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cert_manager_api.h"
#include "cm_ani_common.h"
#include "cm_result_builder.h"

namespace OHOS::Security::CertManager::Ani {
CmInstallUserCaSyncImpl::CmInstallUserCaSyncImpl(ani_env *env, ani_arraybuffer aniCertData,
    ani_enum_item aniCertScope) : CertManagerAniImpl(env)
{
    this->aniCertData = aniCertData;
    this->aniCertScope = aniCertScope;
}

int32_t CmInstallUserCaSyncImpl::Init()
{
    this->certUri.data = static_cast<uint8_t *>(CmMalloc(OUT_AUTH_URI_SIZE));
    if (this->certUri.data == nullptr) {
        CM_LOG_E("init certUri failed.");
        return CMR_ERROR_MALLOC_FAIL;
    }
    this->certUri.size = OUT_AUTH_URI_SIZE;
    return CM_SUCCESS;
}

int32_t CmInstallUserCaSyncImpl::GetParamsFromEnv()
{
    int32_t ret = AniUtils::ParseUint8Array(env, aniCertData, certData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse certData failed, ret = %d", ret);
        return ret;
    }
    if (env->EnumItem_GetValue_Int(aniCertScope, (ani_int *)&certScope) != ANI_OK) {
        CM_LOG_E("get certScope enumItem failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CmInstallUserCaSyncImpl::InvokeInnerApi()
{
    // alias is empty string
    uint8_t alias[1] = { 0 };
    CmBlob certAlias = { .size = sizeof(alias), .data = alias };

    uint32_t userId = 0;
    if (certScope == CM_CURRENT_USER) {
        userId = INIT_INVALID_VALUE;
    } else if (certScope == CM_GLOBAL_USER) {
        userId = 0;
    } else {
        CM_LOG_E("invalid certificate certScope");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    return CmInstallUserCACert(&certData, &certAlias, userId, true, &certUri);
}

int32_t CmInstallUserCaSyncImpl::UnpackResult()
{
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder
        .setUri(&this->certUri)
        ->build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

void CmInstallUserCaSyncImpl::OnFinish()
{
    CM_FREE_BLOB(certUri);
    return;
}
}