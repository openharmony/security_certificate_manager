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

#ifndef CM_OPEN_UKEY_AUTH_DIALOG_NO_CONTEXT_H
#define CM_OPEN_UKEY_AUTH_DIALOG_NO_CONTEXT_H

#include "cm_ani_async_impl.h"
#include "cm_log.h"
#include "cm_open_dialog.h"

namespace OHOS::Security::CertManager::Ani {
class CmOpenUkeyAuthDialogNoContext : public CertManagerAsyncImpl {
private:
    /* ani params */
    ani_string aniKeyUri = nullptr;
    ani_double aniTimeout = 0;
    /* parsed params */
    CmBlob keyUri = { 0 };
    uint32_t timeoutMs = 0; /* 0 = server default */

public:
    CmOpenUkeyAuthDialogNoContext(ani_env *env, ani_string aniKeyUri,
        ani_double aniTimeout, ani_object callback);
    ~CmOpenUkeyAuthDialogNoContext() {};

    int32_t GetParamsFromEnv() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    int32_t InvokeAsyncWork() override;
};
}
#endif // CM_OPEN_UKEY_AUTH_DIALOG_NO_CONTEXT_H
