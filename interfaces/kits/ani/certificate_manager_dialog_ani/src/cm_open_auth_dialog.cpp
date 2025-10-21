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

#include "cm_open_auth_dialog.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "syspara/parameters.h"
#include "cm_log.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
CmOpenAuthDialog::CmOpenAuthDialog(ani_env *env, ani_object aniContext, ani_object callback)
    : CertManagerAsyncImpl(env, aniContext, callback) {}

int32_t CmOpenAuthDialog::InvokeAsyncWork()
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

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallbackString>(this->vm, this->abilityContext,
        this->globalCallback);

    return StartUIExtensionAbility(this->abilityContext, want, uiExtensionCallback);
}

int32_t CmOpenAuthDialog::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenAuthDialog::OnFinish()
{
    return;
}
}