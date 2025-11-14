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

#include "cm_open_auth_dialog_with_request.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_log.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
CmOpenAuthDialogWithReq::CmOpenAuthDialogWithReq(ani_env *env, ani_object aniContext, ani_object aniCertTypes,
    ani_enum_item aniCertPurpose, ani_object callback) : CertManagerAsyncImpl(env, aniContext, callback)
{
    this->aniCertTypes = aniCertTypes;
    this->aniCertPurpose = aniCertPurpose;
}


int32_t CmOpenAuthDialogWithReq::GetParamsFromEnv()
{
    int32_t ret = CertManagerAsyncImpl::GetParamsFromEnv();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse params failed. ret = %d", ret);
        return ret;
    }
    ani_env *vmEnv = GetEnv(this->vm);
    if (vmEnv == nullptr) {
        CM_LOG_E("get env failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ret = AniUtils::ParseIntArray(vmEnv, this->aniCertTypes, this->certTypes);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse cert types failed, ret = %d", ret);
        return ret;
    }

    if (vmEnv->EnumItem_GetValue_Int(this->aniCertPurpose, static_cast<ani_int*>(&this->certPurpose)) != ANI_OK) {
        CM_LOG_E("get certPurpose value failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CmOpenAuthDialogWithReq::InvokeAsyncWork()
{
    CM_LOG_D("InvokeAsyncWork start");
    std::string labelName = "";
    int32_t ret = GetCallerLabelName(this->abilityContext, labelName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get caller labelName failed, ret = %d", ret);
        return ret;
    }

    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_CALLER_BUNDLENAME, labelName);
    want.SetParam(CERT_MANAGER_CALLER_UID, static_cast<int32_t>(getuid()));
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(PAGE_REQUEST_AUTHORIZE));
    want.SetParam(CERT_MANAGER_CERT_TYPES, this->certTypes);
    want.SetParam(CERT_MANAGER_CERT_PURPOSE, this->certPurpose);

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallbackCertReference>(this->vm, this->abilityContext,
        this->globalCallback);

    return StartUIExtensionAbility(this->abilityContext, want, uiExtensionCallback);
}

int32_t CmOpenAuthDialogWithReq::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenAuthDialogWithReq::OnFinish()
{
    return;
}
}