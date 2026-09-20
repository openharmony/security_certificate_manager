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

/* openUkeyAuthDialog / openAuthDialogForUkeyProvider 的 ets 入参对象在 native
 * 侧的解析结果（自扁平多参 native 签名改为对象传参后，字段解包收口于此，
 * 控制原生绑定入口的入参数量） */
struct CmUkeyAniRequest {
    ani_string keyUri = nullptr;      /* 必填 string（ets 层已 401 校验 undefined） */
    ani_double timeout = 0;           /* 可选 number，缺省 0 = 服务端默认 300s */
    ani_object customData = nullptr;  /* 可选 Uint8Array，nullptr = 缺省 */
};

/* 解析 UkeyAuthRequest ets 对象：keyUri 缺失/undefined → 401（PARAM_INVALID）；
 * timeoutDuration / customData 可选（undefined/缺失保持缺省值） */
int32_t ParseUkeyAniRequest(ani_env *env, ani_object request, CmUkeyAniRequest &out);

/* 解析 UkeyAuthDialogInfo ets 对象（abilityName 必填 string，abilityType 必填
 * number；缺失/undefined → 401） */
int32_t ParseUkeyAniDialogInfo(ani_env *env, ani_object dialogInfo, ani_string &abilityName,
    ani_double &abilityType);

} // namespace OHOS::Security::CertManager::Ani

#endif // CM_UKEY_ANI_REQUEST_H
