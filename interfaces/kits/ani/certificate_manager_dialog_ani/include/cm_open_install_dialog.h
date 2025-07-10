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

#ifndef CM_OPEN_INSTALL_DIALOG_H
#define CM_OPEN_INSTALL_DIALOG_H

#include "cm_ani_async_impl.h"
#include "cm_log.h"
#include "cm_open_dialog.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
class CmOpenInstallDialog : public CertManagerAsyncImpl {
private:
    /* ani params */
    ani_enum_item aniCertType = nullptr;
    ani_enum_item aniCertScope = nullptr;
    ani_string aniCert = nullptr;
    /* parsed params */
    CmDialogPageType pageType = PAGE_MAIN;
    CertificateScope certScope = NOT_SPECIFIED;
    CmBlob cert = { 0 };
public:
    CmOpenInstallDialog(ani_env *env, ani_object aniContext, ani_object callback, ani_object params);
    ~CmOpenInstallDialog() {};

    int32_t GetParamsFromEnv() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    int32_t InvokeAsyncWork() override;
};
}
#endif // CM_OPEN_INSTALL_DIALOG_H