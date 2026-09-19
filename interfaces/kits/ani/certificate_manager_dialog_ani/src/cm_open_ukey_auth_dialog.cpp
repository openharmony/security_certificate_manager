/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "securec.h"

#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_log.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
CmOpenUkeyAuthDialog::CmOpenUkeyAuthDialog(ani_env *env, ani_object aniContext, ani_string aniKeyUri,
    ani_object aniCustomData, ani_object callback)
    : CertManagerAsyncImpl(env, aniContext, callback, "openUkeyAuthDialog")
{
    this->aniKeyUri = aniKeyUri;
    this->aniCustomData = aniCustomData;
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
    if (this->keyUri.size <= 1) {
        /* blob carries the terminating zero, size 1 means an empty keyUri;
         * align with the SA session path (empty keyUri is a param error) */
        CM_LOG_E("keyUri is empty");
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    if (this->keyUri.size > MAX_LEN_URI) {
        /* blob carries the terminating zero; over-length keyUri maps to 29700006 */
        CM_LOG_E("keyUri is too long, max length: %d", MAX_LEN_URI);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }

    /* optional customData; Uint8Array <= 2048 raw bytes (D19), ets layer normalized */
    ret = AniUtils::ParseUint8Array(env, reinterpret_cast<ani_arraybuffer>(this->aniCustomData),
        this->customData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse customData failed. ret = %d", ret);
        return ret;
    }
    if (this->customData.size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("customData is too long, max: %d", CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE);
        CM_FREE_BLOB(this->customData);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    return CM_SUCCESS;
}

int32_t CmOpenUkeyAuthDialog::StartUkeyPinAbility(std::shared_ptr<AbilityContext> context,
    OHOS::AAFwk::Want& want, std::shared_ptr<CmAniUIExtensionCallback> uiExtCallback)
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
    /* 直启路径（原有实现恢复）：UIAbility（驱动弹框）/ 查询失败（默认弹框）/
     * UIExtension+非PC（默认弹框）。PC + UIExtension 已在 cm_dialog_ani.cpp
     * 前置分流委托 SA 会话，此处必为直启。 */
    OHOS::AAFwk::Want want{};
    int32_t ret = GetCustomerAuthCertWant(&this->keyUri,
        (this->customData.data != nullptr && this->customData.size > 0) ? &this->customData : nullptr,
        want);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get customer auth cert want failed. ret = %d", ret);
        return ret;
    }

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallback>(this->vm, this->abilityContext,
        this->globalCallback, this->metricsReport_);

    return this->StartUkeyPinAbility(this->abilityContext, want, uiExtensionCallback);
}

int32_t CmOpenUkeyAuthDialog::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenUkeyAuthDialog::OnFinish()
{
    CM_FREE_BLOB(this->keyUri);
    if (this->customData.data != nullptr && this->customData.size > 0) {
        /* customData 为调用方不透明数据，释放前擦除（spec R10） */
        (void)memset_s(this->customData.data, this->customData.size, 0, this->customData.size);
    }
    CM_FREE_BLOB(this->customData);
    return;
}
}