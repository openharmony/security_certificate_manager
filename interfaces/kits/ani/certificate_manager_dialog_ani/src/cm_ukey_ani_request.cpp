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

#include "cm_ukey_ani_request.h"

#include "cm_log.h"
#include "cm_type.h"

namespace OHOS::Security::CertManager::Ani {
namespace {
/* Read an object reference field: false means the field is missing; when
 * outRef is undefined, returns true with isUndefined set (the caller applies
 * its own default semantics) */
bool GetRefField(ani_env *env, ani_object obj, const char *fieldName, ani_ref &outRef,
    bool &isUndefined)
{
    outRef = nullptr;
    isUndefined = true;
    if (env->Object_GetFieldByName_Ref(obj, fieldName, &outRef) != ANI_OK || outRef == nullptr) {
        return false;
    }
    ani_boolean undef = ANI_TRUE;
    if (env->Reference_IsUndefined(outRef, &undef) != ANI_OK) {
        CM_LOG_E("check field %s undefined failed", fieldName);
        return false;
    }
    isUndefined = static_cast<bool>(undef);
    return true;
}
} // namespace

int32_t ParseUkeyAniRequest(ani_env *env, ani_object request, CmUkeyAniRequest &out)
{
    if (env == nullptr || request == nullptr) {
        CM_LOG_E("invalid request object");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    bool isUndefined = true;
    ani_ref keyUriRef = nullptr;
    if (!GetRefField(env, request, "keyUri", keyUriRef, isUndefined) || isUndefined) {
        CM_LOG_E("keyUri is missing or undefined");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    out.keyUri = static_cast<ani_string>(keyUriRef);

    ani_ref timeoutRef = nullptr;
    if (GetRefField(env, request, "timeoutDuration", timeoutRef, isUndefined) && !isUndefined) {
        if (env->Object_GetFieldByName_Double(request, "timeoutDuration", &out.timeout) != ANI_OK) {
            CM_LOG_E("read timeoutDuration failed");
            return CMR_DIALOG_ERROR_PARAM_INVALID;
        }
    } /* absent/undefined keeps 0 (= server default 300s) */

    ani_ref customRef = nullptr;
    if (GetRefField(env, request, "customData", customRef, isUndefined) && !isUndefined) {
        out.customData = static_cast<ani_object>(customRef);
    } /* absent/undefined keeps nullptr (not carried) */
    return CM_SUCCESS;
}

int32_t ParseUkeyAniDialogInfo(ani_env *env, ani_object dialogInfo, ani_string &abilityName,
    ani_double &abilityType)
{
    if (env == nullptr || dialogInfo == nullptr) {
        CM_LOG_E("invalid dialog info object");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    bool isUndefined = true;
    ani_ref nameRef = nullptr;
    if (!GetRefField(env, dialogInfo, "abilityName", nameRef, isUndefined) || isUndefined) {
        CM_LOG_E("abilityName is missing or undefined");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    abilityName = static_cast<ani_string>(nameRef);

    ani_ref typeRef = nullptr;
    if (!GetRefField(env, dialogInfo, "abilityType", typeRef, isUndefined) || isUndefined) {
        CM_LOG_E("abilityType is missing or undefined");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    if (env->Object_GetFieldByName_Double(dialogInfo, "abilityType", &abilityType) != ANI_OK) {
        CM_LOG_E("read abilityType failed");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    return CM_SUCCESS;
}
} // namespace OHOS::Security::CertManager::Ani
