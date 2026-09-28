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

#ifndef CM_UKEY_ANI_REQUEST_H
#define CM_UKEY_ANI_REQUEST_H

#include "ani.h"

namespace OHOS::Security::CertManager::Ani {

/* Native-side parse result of the ets input objects of openUkeyAuthDialog /
 * openAuthDialogForUkeyProvider (after switching from a flat multi-arg
 * native signature to object passing, field unpacking is centralized here to
 * cap the argument count of the native binding entry) */
struct CmUkeyAniRequest {
    ani_string keyUri = nullptr;      /* required string (undefined already 401-checked at the ets layer) */
    ani_double timeout = 0;           /* optional number, default 0 = server default 300s */
    ani_object customData = nullptr;  /* optional Uint8Array, nullptr = absent */
};

/* Parse the UkeyAuthRequest ets object: keyUri missing/undefined -> 401
 * (PARAM_INVALID); timeoutDuration / customData are optional
 * (undefined/missing keeps the default value) */
int32_t ParseUkeyAniRequest(ani_env *env, ani_object request, CmUkeyAniRequest &out);

/* Parse the UkeyAuthDialogInfo ets object (abilityName required string,
 * abilityType required number; missing/undefined -> 401) */
int32_t ParseUkeyAniDialogInfo(ani_env *env, ani_object dialogInfo, ani_string &abilityName,
    ani_double &abilityType);

} // namespace OHOS::Security::CertManager::Ani

#endif // CM_UKEY_ANI_REQUEST_H
