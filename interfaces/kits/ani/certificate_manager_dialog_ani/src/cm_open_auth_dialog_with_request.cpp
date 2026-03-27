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
CmOpenAuthDialogWithReq::CmOpenAuthDialogWithReq(ani_env *env, ani_object aniContext, ani_object params,
    ani_object callback) : CertManagerAsyncImpl(env, aniContext, callback)
{
    this->params = params;
}

int32_t CmOpenAuthDialogWithReq::GetAniParams()
{
    if (env == nullptr) {
        return CMR_ERROR_NULL_POINTER;
    }
    ani_status status = env->Object_GetPropertyByName_Ref(params, CERT_MANAGER_CERT_TYPES.c_str(),
        reinterpret_cast<ani_ref *>(&this->certTypes));
    if (status != ANI_OK) {
        CM_LOG_E("get param certTypes error. status = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((status = env->Object_GetPropertyByName_Ref(params, CERT_MANAGER_CERT_PURPOSE.c_str(),
        reinterpret_cast<ani_ref *>(&this->certPurpose))) != ANI_OK) {
        CM_LOG_E("get param certPurpose error. status = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((status = env->Object_GetPropertyByName_Ref(params, CERT_MANAGER_KEY_ALG_IDS.c_str(),
        reinterpret_cast<ani_ref *>(&this->keyAlgIds))) != ANI_OK) {
        CM_LOG_E("get param keyAlgIds error. status = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((status = env->Object_GetPropertyByName_Ref(params, CERT_MANAGER_ISSUERS.c_str(),
        reinterpret_cast<ani_ref *>(&this->issuers))) != ANI_OK) {
        CM_LOG_E("get param issuers error. status = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((status = env->Object_GetPropertyByName_Ref(params, CERT_MANAGER_SERVER_URL.c_str(),
        reinterpret_cast<ani_ref *>(&this->serverUrl))) != ANI_OK) {
        CM_LOG_E("get param serverUrl error. status = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    return CM_SUCCESS;
}

int32_t CmOpenAuthDialogWithReq::GetParamsFromEnv()
{
    if (env == nullptr) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = this->GetAniParams();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get ani parmas failed. ret = %d", ret);
        return ret;
    }

    if ((ret = CertManagerAsyncImpl::GetParamsFromEnv()) != CM_SUCCESS) {
        CM_LOG_E("parse params failed. ret = %d", ret);
        return ret;
    }

    if ((ret = AniUtils::ParseIntArray(env, this->aniCertTypes, this->certTypes)) != CM_SUCCESS) {
        CM_LOG_E("parse cert types failed, ret = %d", ret);
        return ret;
    }

    if (env->EnumItem_GetValue_Int(this->aniCertPurpose, static_cast<ani_int*>(&this->certPurpose)) != ANI_OK) {
        CM_LOG_E("get certPurpose value failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((ret = AniUtils::ParseStringArray(env, this->aniKeyAlgIds, this->keyAlgIds)) != CM_SUCCESS) {
        CM_LOG_E("get keyAlgIds value failed, ret = %d", ret);
        return ret;
    }

    if ((ret = AniUtils::ParseStringArray(env, this->aniIssuers, this->issuers)) != CM_SUCCESS) {
        CM_LOG_E("get issuers value failed, ret = %d", ret);
        return ret;
    }

    if ((ret = AniUtils::ParseString(env, this->aniServerUrl, this->serverUrl)) != CM_SUCCESS) {
        CM_LOG_E("get serverUrl value failed, ret = %d", ret);
        return ret;
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
    if (!this->keyAlgIds.empty()) {
        want.SetParam(CERT_MANAGER_KEY_ALG_IDS, this->keyAlgIds);
    }
    if (!this->issuers.empty()) {
        want.SetParam(CERT_MANAGER_ISSUERS, this->issuers);
    }
    if (!this->serverUrl.empty()) {
        want.SetParam(CERT_MANAGER_SERVER_URL, this->serverUrl);
    }

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