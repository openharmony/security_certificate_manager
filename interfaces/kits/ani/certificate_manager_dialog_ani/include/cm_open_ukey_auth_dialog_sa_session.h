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
/* SA 会话路径实现（spec v4 D21/D22）：无 context、不直启弹框，结果经 SA 异步
 * 回投。唯一调用方为 openUkeyAuthDialog（带 context 重载委托），D8 修订的
 * -1017/-1018 折叠恒生效。aniRequest 为调用方传入的 UkeyAuthRequest ets 对象
 * （字段解包见 cm_ukey_ani_request.h）。 */
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
