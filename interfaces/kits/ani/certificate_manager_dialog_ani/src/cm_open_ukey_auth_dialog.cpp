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
#include "cm_ukey_dialog_common.h"

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
    if (this->keyUri.size > MAX_LEN_URI + 1) {
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

int32_t CmOpenUkeyAuthDialog::InvokeAsyncWork()
{
    CM_LOG_D("InvokeAsyncWork start");
    /* 非回退路径（PC + UIExtension 委托 SA）已在 cm_dialog_ani.cpp 前置分流，
     * 此处必为系统默认弹框直启（spec v4 D22/D25 v2）。 */
    OHOS::AAFwk::Want want{};
    int32_t ret = GetDefaultUkeyAuthCertWant(&this->keyUri, want);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get default ukey auth cert want failed. ret = %d", ret);
        return ret;
    }
    if (this->customData.data != nullptr && this->customData.size > 0) {
        /* D18：默认弹框无 customData 消费方，静默丢弃（仅记录长度，spec R10） */
        CM_LOG_I("custom data dropped for default dialog, size: %u", this->customData.size);
    }

    auto uiExtensionCallback = std::make_shared<CmAniUIExtensionCallback>(this->vm, this->abilityContext,
        this->globalCallback, this->metricsReport_);

    return StartUIExtensionAbility(this->abilityContext, want, uiExtensionCallback);
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