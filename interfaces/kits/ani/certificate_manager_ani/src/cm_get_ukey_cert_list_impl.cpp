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

#include "cm_get_ukey_cert_list_impl.h"
#include "cert_manager_api.h"
#include "cm_log.h"
#include "securec.h"
#include "cm_mem.h"
#include "cm_result_builder.h"
#include "cm_ani_common.h"
#include "cm_ani_utils.h"

namespace OHOS::Security::CertManager::Ani {
CmGetUkeyCertListImpl::CmGetUkeyCertListImpl(ani_env *env, ani_string aniStrParam, ani_enum_item aniCertPurpose,
    uint32_t mode) : CertManagerAniImpl(env)
{
    this->aniStrParam = aniStrParam;
    this->aniCertPurpose = aniCertPurpose;
    this->mode = mode;
}

int32_t CmGetUkeyCertListImpl::Init()
{
    this->certificateList = static_cast<struct CredentialDetailList *>(CmMalloc(sizeof(struct CredentialDetailList)));
    if (this->certificateList == nullptr) {
        CM_LOG_E("malloc credentialList failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    uint32_t buffSize = (MAX_COUNT_UKEY_CERTIFICATE * sizeof(struct Credential));
    this->certificateList->credential = static_cast<struct Credential *>(CmMalloc(buffSize));
    if (this->certificateList->credential == nullptr) {
        CM_LOG_E("malloc file buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(this->certificateList->credential, buffSize, 0, buffSize);
    this->certificateList->credentialCount = MAX_COUNT_UKEY_CERTIFICATE;
    for (uint32_t i = 0; i < MAX_COUNT_UKEY_CERTIFICATE; ++i) {
        this->certificateList->credential[i].credData.data = static_cast<uint8_t *>(
            CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
        if (this->certificateList->credential[i].credData.data == nullptr) {
            CM_LOG_E("malloc file buffer failed");
            return CMR_ERROR_MALLOC_FAIL;
        }
        (void)memset_s(this->certificateList->credential[i].credData.data, MAX_LEN_CERTIFICATE_CHAIN,
            0, MAX_LEN_CERTIFICATE_CHAIN);
        this->certificateList->credential[i].credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    }
    return CM_SUCCESS;
}

int32_t CmGetUkeyCertListImpl::GetParamsFromEnv()
{
    int32_t ret = AniUtils::ParseString(env, this->aniStrParam, this->strParam);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse aniStrParam failed, ret = %d", ret);
        return ret;
    }
    if (env->EnumItem_GetValue_Int(this->aniCertPurpose, (ani_int *)&this->certPurpose) != ANI_OK) {
        CM_LOG_E("get certPurpose enumItem failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CmGetUkeyCertListImpl::InvokeInnerApi()
{
    struct UkeyInfo ukeyInfo = {
        .certPurpose = static_cast<enum CmCertificatePurpose>(this->certPurpose)
    };
    if (this->mode == LIST_UKEY) {
        return CmGetUkeyCertList(&this->strParam, &ukeyInfo, this->certificateList);
    } else {
        return CmGetUkeyCert(&this->strParam, &ukeyInfo, this->certificateList);
    }
}

int32_t CmGetUkeyCertListImpl::UnpackResult()
{
    // credentialList
    CMResultBuilder resultBuilder(this->env);
    int32_t ret = resultBuilder
        .setCredentialDetailList(this->certificateList)
        ->build();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack result failed.");
        return ret;
    }
    this->result = resultBuilder.cmResult;
    return CM_SUCCESS;
}

void CmGetUkeyCertListImpl::OnFinish()
{
    if (this->certificateList == nullptr) {
        return;
    }
    if (this->certificateList->credential != nullptr) {
        for (uint32_t i = 0; i < MAX_COUNT_UKEY_CERTIFICATE; ++i) {
            CM_FREE_BLOB(this->certificateList->credential[i].credData);
        }
        CM_FREE_PTR(this->certificateList->credential);
    }
    this->certificateList->credentialCount = 0;
    CM_FREE_PTR(this->certificateList);
    this->certificateList = nullptr;
    return;
}
}