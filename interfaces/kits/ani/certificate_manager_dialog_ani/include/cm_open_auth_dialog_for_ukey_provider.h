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

#ifndef CM_OPEN_AUTH_DIALOG_FOR_UKEY_PROVIDER_H
#define CM_OPEN_AUTH_DIALOG_FOR_UKEY_PROVIDER_H

#include "cm_ani_async_impl.h"
#include "cm_log.h"
#include "cm_open_dialog.h"

namespace OHOS::Security::CertManager::Ani {
/* ets input object set of openAuthDialogForUkeyProvider (dialogInfo /
 * ukeyAuthRequest aligned one-by-one with the d.ts signature, spec v4
 * D23/D24): the native binding entry takes objects as parameters to cap the
 * argument count; field unpacking lives in cm_ukey_ani_request.h */
struct UkeyProviderDialogParams {
    ani_object aniDialogInfo = nullptr;
    ani_object aniRequest = nullptr;
};

class CmOpenAuthDialogForUkeyProvider : public CertManagerAsyncImpl {
private:
    /* ani params */
    UkeyProviderDialogParams aniParams;
    /* parsed params */
    CmBlob abilityName = { 0 }; /* driver dialog extension name, 1..256 bytes + NUL */
    uint32_t abilityType = 0; /* only CM_UKEY_ABILITY_TYPE_UIEXTENSION (D24) */
    CmBlob keyUri = { 0 };
    uint32_t timeoutSec = 0; /* 0 = server default */
    CmBlob customData = { 0 }; /* raw bytes <= 2048; size 0 = absent (D19) */

public:
    CmOpenAuthDialogForUkeyProvider(ani_env *env, const UkeyProviderDialogParams &params,
        ani_object callback);
    ~CmOpenAuthDialogForUkeyProvider() {};

    int32_t GetParamsFromEnv() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    int32_t InvokeAsyncWork() override;
    /* dialogInfo object unpacking and validation (spec v4 D23/D24), split out of GetParamsFromEnv */
    int32_t ParseDialogInfoFromEnv();
};
}
#endif // CM_OPEN_AUTH_DIALOG_FOR_UKEY_PROVIDER_H
