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

#ifndef CM_OPEN_UKEY_AUTH_DIALOG_H
#define CM_OPEN_UKEY_AUTH_DIALOG_H

#include "cm_ani_async_impl.h"
#include "cm_log.h"
#include "cm_open_dialog.h"

namespace OHOS::Security::CertManager::Ani {
/* Context-carrying direct-launch implementation (original implementation
 * restored, spec v4.2): handles direct launch of the driver UIAbility dialog
 * and of the system default dialog (UIAbility / query failure /
 * UIExtension + non-PC; PC + UIExtension already delegates to the SA session
 * in cm_dialog_ani.cpp). aniRequest is the caller-provided UkeyAuthRequest
 * ets object (field unpacking in cm_ukey_ani_request.h). */
class CmOpenUkeyAuthDialog : public CertManagerAsyncImpl {
private:
    /* ani params */
    ani_object aniRequest = nullptr;
    /* parsed params */
    CmBlob keyUri = { 0 };
    CmBlob customData = { 0 }; /* raw bytes <= 2048; size 0 = absent (D19) */
    int32_t StartUkeyPinAbility(std::shared_ptr<AbilityContext> context, OHOS::AAFwk::Want& want,
        std::shared_ptr<CmAniUIExtensionCallback> uiExtCallback);

public:
    CmOpenUkeyAuthDialog(ani_env *env, ani_object aniContext, ani_object aniRequest,
        ani_object callback);
    ~CmOpenUkeyAuthDialog() {};

    int32_t GetParamsFromEnv() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    int32_t InvokeAsyncWork() override;
};
}
#endif // CM_OPEN_UKEY_AUTH_DIALOG_H