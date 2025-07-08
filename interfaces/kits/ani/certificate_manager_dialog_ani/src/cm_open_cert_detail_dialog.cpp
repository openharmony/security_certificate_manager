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

#include "cm_open_cert_detail_dialog.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "syspara/parameters.h"
#include "cm_log.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
CmOpenCertDetailDialog::CmOpenCertDetailDialog(ani_env *env, ani_object aniContext, ani_string aniCert,
    ani_boolean showInstallButton, ani_object callback) : CertManagerAsyncImpl(env, aniContext, callback)
{
    this->showInstallButton = showInstallButton;
    this->aniCert = aniCert;
}

int32_t CmOpenCertDetailDialog::GetParamsFromEnv()
{
    if (OHOS::system::GetParameter("const.product.devicetype", "") != "2in1") {
        CM_LOG_E("deviceType is not 2in1");
        return DIALOG_ERROR_NOT_SUPPORTED;
    }
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

    ret = AniUtils::ParseString(vmEnv, this->aniCert, this->cert);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse cert failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmOpenCertDetailDialog::InvokeAsyncWork()
{
    CM_LOG_D("InvokeAsyncWork start");
    std::string certStr(reinterpret_cast<char *>(this->cert.data), this->cert.size);

    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_CERTIFICATE_DATA, certStr);
    want.SetParam(CERT_MANAGER_OPERATION_TYPE, DIALOG_OPERATION_DETAIL);
    want.SetParam(CERT_MANAGER_SHOW_INSTALL_BUTTON, static_cast<bool>(this->showInstallButton));
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(PAGE_INSTALL_CA_GUIDE));

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallback>(this->vm, this->abilityContext,
        this->globalCallback);

    return StartUIExtensionAbility(this->abilityContext, want, uiExtensionCallback);
}

int32_t CmOpenCertDetailDialog::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenCertDetailDialog::OnFinish()
{
    CM_FREE_BLOB(this->cert);
    return;
}
}