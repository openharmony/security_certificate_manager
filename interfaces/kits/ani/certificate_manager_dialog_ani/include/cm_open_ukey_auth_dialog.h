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
/* 带 context 直启实现（spec v4 D25 v2）：仅承接非 PC 设备的系统默认弹框
 * 回退路径（PC + UIExtension 已在 cm_dialog_ani.cpp 委托 SA 会话）。 */
class CmOpenUkeyAuthDialog : public CertManagerAsyncImpl {
private:
    /* ani params */
    ani_string aniKeyUri = nullptr;
    ani_object aniCustomData = nullptr;
    /* parsed params */
    CmBlob keyUri = { 0 };
    CmBlob customData = { 0 }; /* raw bytes <= 2048; size 0 = absent (D19) */

public:
    CmOpenUkeyAuthDialog(ani_env *env, ani_object aniContext, ani_string aniKeyUri,
        ani_object aniCustomData, ani_object callback);
    ~CmOpenUkeyAuthDialog() {};

    int32_t GetParamsFromEnv() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    int32_t InvokeAsyncWork() override;
};
}
#endif // CM_OPEN_UKEY_AUTH_DIALOG_H