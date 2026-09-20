/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CM_OPEN_UKEY_AUTH_DIALOG_SA_SESSION_H
#define CM_OPEN_UKEY_AUTH_DIALOG_SA_SESSION_H

#include "cm_ani_async_impl.h"
#include "cm_log.h"
#include "cm_open_dialog.h"

namespace OHOS::Security::CertManager::Ani {
/* SA session path implementation (spec v4 D21/D22): no context, no direct
 * dialog launch; the result is asynchronously reported back via the SA. The
 * sole caller is openUkeyAuthDialog (delegated by the context-carrying
 * overload), so the D8-revised -1017/-1018 folding always applies.
 * aniRequest is the caller-provided UkeyAuthRequest ets object (field
 * unpacking in cm_ukey_ani_request.h). */
class CmOpenUkeyAuthDialogSaSession : public CertManagerAsyncImpl {
private:
    /* ani params */
    ani_object aniRequest = nullptr;
    /* parsed params */
    CmBlob keyUri = { 0 };
    uint32_t timeoutSec = 0; /* 0 = server default */
    CmBlob customData = { 0 }; /* raw bytes <= 2048; size 0 = absent (D19) */

public:
    CmOpenUkeyAuthDialogSaSession(ani_env *env, ani_object aniRequest, ani_object callback);
    ~CmOpenUkeyAuthDialogSaSession() {};

    int32_t GetParamsFromEnv() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    int32_t InvokeAsyncWork() override;
};
}
#endif // CM_OPEN_UKEY_AUTH_DIALOG_SA_SESSION_H
