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

#ifndef CM_ANI_COMMON_H
#define CM_ANI_COMMON_H

#include "ani.h"
#include "cm_type.h"

namespace OHOS::Security::CertManager::Ani {
static const uint32_t OUT_SIGNATURE_SIZE = 1000;
static const uint32_t APPLICATION_CERTIFICATE_STORE = 0;
static const uint32_t APPLICATION_PRIVATE_CERTIFICATE_STORE = 3;
static const uint32_t APPLICATION_SYSTEM_CERTIFICATE_STORE = 4;
static const uint32_t OUT_HANDLE_SIZE = 8;
static const uint32_t OUT_AUTH_URI_SIZE = 1000;
static const uint32_t SINGLE_UKEY = 1;
static const uint32_t LIST_UKEY = 2;

ani_object GetAniErrorResult(ani_env *env, int32_t resultCode);

ani_object GetDialogAniErrorResult(ani_env *env, int32_t resultCode);

ani_object GetAniDialogNativeResult(ani_env *env, int32_t resultCode);

ani_env *GetCurrentThreadEnv(ani_vm *vm);

ani_status DetachCurrentThreadEnv(ani_vm *vm);
}

#endif