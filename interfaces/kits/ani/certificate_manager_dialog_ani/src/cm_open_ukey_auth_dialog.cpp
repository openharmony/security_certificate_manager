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

#include "cm_open_ukey_auth_dialog.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_log.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
CmOpenUkeyAuthDialog::CmOpenUkeyAuthDialog(ani_env *env, ani_object aniContext, ani_string aniKeyUri,
    ani_object callback) : CertManagerAsyncImpl(env, aniContext, callback)
{
    this->aniKeyUri = aniKeyUri;
}


int32_t CmOpenUkeyAuthDialog::GetParamsFromEnv()
{
    int32_t ret = CertManagerAsyncImpl::GetParamsFromEnv();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse params failed. ret = %d", ret);
        return ret;
    }

    ret = AniUtils::ParseString(env, this->aniKeyUri, this->keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keyUri failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmOpenUkeyAuthDialog::InvokeAsyncWork()
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
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(PAGE_UKEY_PIN_AUTHORIZE));
    std::string keyUriStr(reinterpret_cast<char *>(this->keyUri.data), this->keyUri.size);
    want.SetParam(CERT_MANAGER_CERT_KEY_URI, keyUriStr);

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallback>(this->vm, this->abilityContext,
        this->globalCallback);

    return StartUIExtensionAbility(this->abilityContext, want, uiExtensionCallback);
}

int32_t CmOpenUkeyAuthDialog::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenUkeyAuthDialog::OnFinish()
{
    return;
}
}