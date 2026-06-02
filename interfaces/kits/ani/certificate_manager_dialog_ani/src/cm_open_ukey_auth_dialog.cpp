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

int32_t CmOpenUkeyAuthDialog::StartUkeyPinAbility(std::shared_ptr<AbilityContext> context, OHOS::AAFwk::Want& want,
    std::shared_ptr<CmAniUIExtensionCallback> uiExtCallback)
{
    std::string action = want.GetAction();
    if (action.empty() || action != ACTION_UKEY_PIN_AUTH) {
        return StartUIExtensionAbility(context, want, uiExtCallback);
    } else {
        return StartUIAbility(context, want, uiExtCallback);
    }
}

int32_t CmOpenUkeyAuthDialog::InvokeAsyncWork()
{
    CM_LOG_D("InvokeAsyncWork start");
    OHOS::AAFwk::Want want{};
    int32_t ret = GetCustomerAuthCertWant(&this->keyUri, want);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get customer auth cert want failed. ret = %d", ret);
        return ret;
    }

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallback>(this->vm, this->abilityContext,
        this->globalCallback);

    return this->StartUkeyPinAbility(this->abilityContext, want, uiExtensionCallback);
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