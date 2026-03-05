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

#include "cm_supports_ca_cert_dialog.h"
#include "cm_log.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
ani_object supportsCACertDialogNative(ani_env *env)
{
    CM_LOG_I("supportsCACertDialog enter");
    bool isSupport = IsEnableCACertDialog();
    ani_boolean result;
    auto ret = env->CreateBooleanANI(isSupport, &result);
    if (ret != ANI_OK) {
        CM_LOG_E("CreateBooleanANI failed, ret = %d", static_cast<int32_t>(ret));
        return nullptr;
    }
    CM_LOG_I("supportsCACertDialog end, isSupport = %d", isSupport);
    return result;
}
}  // namespace OHOS::Security::CertManager::Ani
