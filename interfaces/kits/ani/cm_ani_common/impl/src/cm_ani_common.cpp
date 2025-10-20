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

#include "cm_ani_common.h"
#include "cm_api_common.h"
#include "cm_dialog_api_common.h"
#include "cm_ani_utils.h"
#include "cm_log.h"

namespace OHOS::Security::CertManager::Ani {
using namespace OHOS::Security::CertManager;

static int32_t TransformErrorCode(int32_t errorCode)
{
    auto iter = NATIVE_CODE_TO_JS_CODE_MAP.find(errorCode);
    if (iter != NATIVE_CODE_TO_JS_CODE_MAP.end()) {
        return iter->second;
    }
    return INNER_FAILURE;
}

static int32_t TransformDialogErrorCode(int32_t errorCode)
{
    auto iter = Dialog::DIALOG_CODE_TO_JS_CODE_MAP.find(errorCode);
    if (iter != Dialog::DIALOG_CODE_TO_JS_CODE_MAP.end()) {
        return iter->second;
    }
    return Dialog::DIALOG_ERROR_GENERIC;
}

static const char *GetJsErrorMsg(int32_t errCode)
{
    auto iter = NATIVE_CODE_TO_MSG_MAP.find(errCode);
    if (iter != NATIVE_CODE_TO_MSG_MAP.end()) {
        return (iter->second).c_str();
    }
    return GENERIC_MSG.c_str();
}

static const char *GetDialogJsErrorMsg(int32_t errCode)
{
    auto iter = Dialog::DIALOG_CODE_TO_MSG_MAP.find(errCode);
    if (iter != Dialog::DIALOG_CODE_TO_MSG_MAP.end()) {
        return (iter->second).c_str();
    }
    return Dialog::DIALOG_GENERIC_MSG.c_str();
}

ani_object GetAniErrorResult(ani_env *env, int32_t resultCode)
{
    int32_t jsRet = TransformErrorCode(resultCode);
    const char *msg = GetJsErrorMsg(resultCode);
    ani_object retObj{};
    int32_t ret = AniUtils::GenerateNativeResult(env, jsRet, msg, nullptr, retObj);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate err result failed, ret = %d", ret);
        return nullptr;
    }
    return retObj;
}

ani_object GetAniDialogNativeResult(ani_env *env, int32_t resultCode)
{
    int32_t jsRet = TransformDialogErrorCode(resultCode);
    const char *msg = GetDialogJsErrorMsg(resultCode);
    ani_object retObj{};
    int32_t ret = AniUtils::GenerateNativeResult(env, jsRet, msg, nullptr, retObj);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate err result failed, ret = %d", ret);
        return nullptr;
    }
    return retObj;
}

ani_object GetDialogAniErrorResult(ani_env *env, int32_t resultCode)
{
    int32_t jsRet = TransformDialogErrorCode(resultCode);
    const char *msg = GetDialogJsErrorMsg(resultCode);
    ani_object retObj{};
    int32_t ret = AniUtils::GenerateBusinessError(env, jsRet, msg, retObj);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate businessError failed, ret = %d", ret);
        return nullptr;
    }
    return retObj;
}

ani_env *GetEnv(ani_vm *vm)
{
    if (vm == nullptr) {
        CM_LOG_E("aniVm is nullptr.");
        return nullptr;
    }
    ani_env *env = nullptr;
    ani_option interopEnabled {"--interop=enable", nullptr};
    ani_options aniArgs {1, &interopEnabled};
    ani_status status = vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        status = vm->GetEnv(ANI_VERSION_1, &env);
        if (status != ANI_OK) {
            CM_LOG_E("get aniEnv failed, status = %d", static_cast<int32_t>(status));
        }
    }
    return env;
}
}