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

#include "cm_open_uninstall_dialog.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "syspara/parameters.h"
#include "cm_log.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
CmOpenUninstallDialog::CmOpenUninstallDialog(ani_env *env, ani_object aniContext, ani_enum_item aniCertType,
    ani_string aniCertUri, ani_object callback) : CertManagerAsyncImpl(env, aniContext, callback)
{
    this->aniCertType = aniCertType;
    this->aniCertUri = aniCertUri;
}

int32_t CmOpenUninstallDialog::GetParamsFromEnv()
{
    if (OHOS::system::GetParameter("const.product.devicetype", "") != "2in1") {
        CM_LOG_E("deviceType is not 2in1");
        return CMR_DIALOG_ERROR_NOT_SUPPORTED;
    }
    int32_t ret = CertManagerAsyncImpl::GetParamsFromEnv();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse params failed. ret = %d", ret);
        return ret;
    }

    int32_t aniCertType = 0;
    if (env->EnumItem_GetValue_Int(this->aniCertType, (ani_int *)&aniCertType) != ANI_OK) {
        CM_LOG_E("get certType value failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    switch (static_cast<CmCertificateType>(aniCertType)) {
        case CmCertificateType::CA_CERT:
            this->pageType = CmDialogPageType::PAGE_INSTALL_CA_GUIDE;
            break;
        default:
            return CMR_ERROR_INVALID_ARGUMENT;
    }

    ret = AniUtils::ParseString(env, this->aniCertUri, this->certUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse aniCertUri failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmOpenUninstallDialog::InvokeAsyncWork()
{
    CM_LOG_D("InvokeAsyncWork start");
    std::string uriStr(reinterpret_cast<char *>(this->certUri.data), this->certUri.size);

    std::string labelName = "";
    int32_t ret = GetCallerLabelName(this->abilityContext, labelName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get caller labelName failed, ret = %d", ret);
        return ret;
    }

    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(this->pageType));
    want.SetParam(CERT_MANAGER_CALLER_BUNDLENAME, labelName);
    want.SetParam(CERT_MANAGER_CERT_URI, uriStr);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_OPERATION_TYPE, DIALOG_OPERATION_UNINSTALL);

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallback>(this->vm, this->abilityContext,
        this->globalCallback);

    return StartUIExtensionAbility(this->abilityContext, want, uiExtensionCallback);
}

int32_t CmOpenUninstallDialog::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenUninstallDialog::OnFinish()
{
    CM_FREE_BLOB(this->certUri);
    return;
}
}