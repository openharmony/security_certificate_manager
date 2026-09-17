/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CM_OPEN_AUTH_DIALOG_FOR_UKEY_DRIVER_H
#define CM_OPEN_AUTH_DIALOG_FOR_UKEY_DRIVER_H

#include "cm_ani_async_impl.h"
#include "cm_log.h"
#include "cm_open_dialog.h"

namespace OHOS::Security::CertManager::Ani {
class CmOpenAuthDialogForUkeyDriver : public CertManagerAsyncImpl {
private:
    /* ani params */
    ani_string aniAbilityName = nullptr;
    ani_double aniAbilityType = 0;
    ani_string aniKeyUri = nullptr;
    ani_double aniTimeout = 0;
    ani_object aniCustomData = nullptr;
    /* parsed params */
    CmBlob abilityName = { 0 }; /* driver dialog extension name, 1..128 bytes + NUL */
    uint32_t abilityType = 0; /* only CM_UKEY_ABILITY_TYPE_UIEXTENSION (D24) */
    CmBlob keyUri = { 0 };
    uint32_t timeoutMs = 0; /* 0 = server default */
    CmBlob customData = { 0 }; /* raw bytes <= 2048; size 0 = absent (D19) */

public:
    CmOpenAuthDialogForUkeyDriver(ani_env *env, ani_string aniAbilityName, ani_double aniAbilityType,
        ani_string aniKeyUri, ani_double aniTimeout, ani_object aniCustomData, ani_object callback);
    ~CmOpenAuthDialogForUkeyDriver() {};

    int32_t GetParamsFromEnv() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    int32_t InvokeAsyncWork() override;
};
}
#endif // CM_OPEN_AUTH_DIALOG_FOR_UKEY_DRIVER_H
