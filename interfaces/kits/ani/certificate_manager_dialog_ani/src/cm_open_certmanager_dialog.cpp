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

#include "cm_open_certmanager_dialog.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"

namespace OHOS::Security::CertManager::Ani {
CmOpenCertManagerDialog::CmOpenCertManagerDialog(ani_env *env, ani_object aniContext,
    ani_enum_item aniPageType, ani_object callback) : CertManagerAsyncImpl(env, aniContext, callback)
{
    this->aniPageType = aniPageType;
}

int32_t CmOpenCertManagerDialog::GetParamsFromEnv()
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
    int32_t pageTypeValue = 0;
    if (vmEnv->EnumItem_GetValue_Int(this->aniPageType, (ani_int *)&pageTypeValue) != ANI_OK) {
        CM_LOG_E("get pageType value failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    this->pageType = static_cast<CmDialogPageType>(pageTypeValue);
    return CM_SUCCESS;
}

int32_t CmOpenCertManagerDialog::InvokeAsyncWork()
{
    CM_LOG_D("InvokeAsyncWork start");
    OHOS::AAFwk::Want want;

    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(this->pageType));
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallback>(this->vm, this->abilityContext,
        this->globalCallback);

    return StartUIExtensionAbility(this->abilityContext, want, uiExtensionCallback);
}

int32_t CmOpenCertManagerDialog::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenCertManagerDialog::OnFinish()
{
    return;
}
}