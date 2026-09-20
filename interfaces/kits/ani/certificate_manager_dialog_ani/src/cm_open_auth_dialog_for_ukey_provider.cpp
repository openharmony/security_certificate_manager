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

#include "cm_open_auth_dialog_for_ukey_provider.h"
#include "cert_manager_api.h"
#include "securec.h"

#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_log.h"
#include "cm_ukey_dialog_common.h"
#include "cm_ukey_ani_request.h"
#include "cm_ukey_ani_result_context.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;

CmOpenAuthDialogForUkeyProvider::CmOpenAuthDialogForUkeyProvider(ani_env *env,
    const UkeyProviderDialogParams &params, ani_object callback)
    : CertManagerAsyncImpl(env, nullptr, callback, "openAuthDialogForUkeyProvider")
{
    this->aniParams = params;
}

/* dialogInfo object unpacking and validation (spec v4 D23/D24, split out of
 * GetParamsFromEnv): abilityName/abilityType required (undefined already
 * 401-checked at the ets layer; a missing value is defended against here) */
int32_t CmOpenAuthDialogForUkeyProvider::ParseDialogInfoFromEnv()
{
    ani_string aniAbilityName = nullptr;
    ani_double aniAbilityType = 0;
    int32_t ret = ParseUkeyAniDialogInfo(env, this->aniParams.aniDialogInfo, aniAbilityName,
        aniAbilityType);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse dialog info object failed, ret = %d", ret);
        return ret;
    }
    /* abilityName: non-empty, <= 256 bytes (the blob carries the terminating
     * zero, size 1 means an empty name); AniUtils::ParseString allocates the
     * exact-size buffer so an over-long name is rejected here, not truncated */
    ret = AniUtils::ParseString(env, aniAbilityName, this->abilityName);
    if (ret != CM_SUCCESS || this->abilityName.size <= 1 ||
        this->abilityName.size > CM_UKEY_ABILITY_NAME_MAX_LEN + 1) {
        CM_LOG_E("invalid driver dialog ability name, ret = %d", ret);
        CM_FREE_BLOB(this->abilityName);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    /* abilityType: the enum's only legal value is 1 (UKEY_AUTH_EXTENSION_ABILITY);
     * a number that is not the valid enum value maps to 29700006 (v4.1 user
     * ruling; ANI type errors are compile-time in ets, the wrapper's
     * undefined-check stays 401) */
    if (aniAbilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("invalid driver dialog ability type");
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    this->abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    return CM_SUCCESS;
}

/* keyUri field parse (per-field helper split out of GetParamsFromEnv):
 * blob carries the terminating NUL; empty and over-long values are rejected
 * here so the error maps to 29700006 instead of the unmapped generic error */
static int32_t ParseUkeyKeyUriField(ani_env *env, const CmUkeyAniRequest &req, struct CmBlob &keyUri)
{
    int32_t ret = AniUtils::ParseString(env, req.keyUri, keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keyUri failed, ret = %d", ret);
        return ret;
    }
    if (keyUri.size <= 1) {
        /* blob carries the terminating zero, size 1 means an empty keyUri */
        CM_LOG_E("keyUri is empty");
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    if (keyUri.size > MAX_LEN_URI) {
        /* blob carries the terminating zero; the SA rejects a keyUri blob
         * longer than MAX_LEN_URI (NUL included), reject here so the error
         * maps to 29700006 instead of the unmapped generic error */
        CM_LOG_E("keyUri is too long, max length: %d", MAX_LEN_URI);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    return CM_SUCCESS;
}

/* optional customData field (D19): Uint8Array <= 2048 raw bytes; nullptr = absent */
static int32_t ParseUkeyCustomDataField(ani_env *env, const CmUkeyAniRequest &req,
    struct CmBlob &customData)
{
    if (req.customData == nullptr) {
        return CM_SUCCESS;
    }
    int32_t ret = AniUtils::ParseUint8Array(env, reinterpret_cast<ani_arraybuffer>(req.customData),
        customData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse customData failed, ret = %d", ret);
        return ret;
    }
    if (customData.size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("customData is too long, max: %d", CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE);
        CM_FREE_BLOB(customData);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    return CM_SUCCESS;
}

int32_t CmOpenAuthDialogForUkeyProvider::GetParamsFromEnv()
{
    int32_t ret = ParseDialogInfoFromEnv();
    if (ret != CM_SUCCESS) {
        return ret;
    }

    CmUkeyAniRequest req;
    ret = ParseUkeyAniRequest(env, this->aniParams.aniRequest, req);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse ukey auth request object failed, ret = %d", ret);
        return ret;
    }
    ret = ParseUkeyKeyUriField(env, req, this->keyUri);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    /* optional timeout in seconds; non-number/NaN maps to a param error
     * (NaN fails both bounds, so the negated form rejects it) */
    if (!(req.timeout >= 0 && req.timeout <= UINT32_MAX)) {
        CM_LOG_E("invalid timeout value");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    this->timeoutSec = static_cast<uint32_t>(req.timeout);

    ret = ParseUkeyCustomDataField(env, req, this->customData);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ani_status status = env->GlobalReference_Create(reinterpret_cast<ani_ref>(this->callback),
        &this->globalCallback);
    if (status != ANI_OK) {
        CM_LOG_E("failed to create global callback. status = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

/* Build the businessError from the result code (split out of
 * UkeyAuthDialogResultCallback): success -> no error object; anything else
 * (including the 29700009/29700010 pass-through codes, not folded per D8 v4)
 * -> regular mapping */
static bool GenerateProviderResultBusinessError(ani_env *env, int32_t resultCode,
    ani_object &businessError)
{
    if (resultCode == CM_SUCCESS) {
        return AniUtils::GenerateBusinessError(env, CM_SUCCESS, "", businessError) == CM_SUCCESS;
    }
    businessError = GetDialogAniErrorResult(env, resultCode);
    return businessError != nullptr;
}

/* C callback running on an IPC thread: attach the thread to the VM and settle
 * the AsyncCallbackWrapper exactly once with the dialog result delivered by
 * the SA (same mechanism as CmAniUIExtensionCallback::invokeCallback).
 * ForProvider: error codes pass through unfolded (D8 v4). */
static void UkeyAuthDialogResultCallback(int32_t resultCode, void *userData)
{
    auto context = static_cast<CmUkeyAuthDialogAniResultContext *>(userData);
    if (context == nullptr) {
        CM_LOG_E("result context is null");
        return;
    }

    if (context->metricsReport != nullptr) {
        context->metricsReport->Finish(TransformDialogErrorCode(resultCode));
    }

    ani_env *env = GetCurrentThreadEnv(context->vm);
    if (env == nullptr) {
        CM_LOG_E("get env failed, drop ukey auth dialog result, code = %d", resultCode);
        /* the global reference cannot be released without an env, same
         * behavior as CmAniUIExtensionCallback when GetCurrentThreadEnv fails */
        delete context;
        return;
    }

    ani_object businessError{};
    if (!GenerateProviderResultBusinessError(env, resultCode, businessError)) {
        CM_LOG_E("generate businessError failed, code = %d", resultCode);
        ReleaseUkeyAuthResultResources(env, context);
        return;
    }

    ani_ref nullRef{};
    ani_status status = env->GetNull(&nullRef);
    if (status != ANI_OK) {
        CM_LOG_E("get nullRef failed. status = %d", static_cast<int32_t>(status));
        ReleaseUkeyAuthResultResources(env, context);
        return;
    }

    status = env->Object_CallMethodByName_Void(reinterpret_cast<ani_object>(context->globalCallback), "invoke",
        "C{@ohos.base.BusinessError}Y:", businessError, nullRef);
    if (status != ANI_OK) {
        CM_LOG_E("invoke callback failed. status = %d", static_cast<int32_t>(status));
    }
    ReleaseUkeyAuthResultResources(env, context);
}

int32_t CmOpenAuthDialogForUkeyProvider::InvokeAsyncWork()
{
    CM_LOG_D("InvokeAsyncWork start");
    auto resultContext = new (std::nothrow) CmUkeyAuthDialogAniResultContext();
    if (resultContext == nullptr) {
        CM_LOG_E("alloc ukey auth result context failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    resultContext->vm = this->vm;
    resultContext->globalCallback = this->globalCallback;
    resultContext->metricsReport = this->metricsReport_;

    /* the abilityName/keyUri/customData blobs are consumed synchronously inside
     * CmOpenUkeyAuthDialogForDriver, so they only need to live until the call
     * returns */
    struct UkeyAuthDialogInfo dialogInfo = {};
    dialogInfo.abilityName = this->abilityName;
    dialogInfo.abilityType = this->abilityType;
    struct UkeyAuthRequest ukeyAuthRequest = {};
    ukeyAuthRequest.keyUri.data = this->keyUri.data;
    ukeyAuthRequest.timeoutDuration = this->timeoutSec;
    ukeyAuthRequest.keyUri.size = this->keyUri.size;
    ukeyAuthRequest.customData = this->customData;

    int32_t ret = CmOpenUkeyAuthDialogForDriver(&dialogInfo, &ukeyAuthRequest,
        UkeyAuthDialogResultCallback, resultContext);
    if (ret != CM_SUCCESS) {
        /* sync failure: the result callback never fires (inner API contract),
         * release the context here; the global callback reference is deleted
         * by the base class on the InvokeInnerApi failure path */
        CM_LOG_E("open auth dialog for ukey provider failed, ret = %d", ret);
        delete resultContext;
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmOpenAuthDialogForUkeyProvider::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenAuthDialogForUkeyProvider::OnFinish()
{
    CM_FREE_BLOB(this->abilityName);
    CM_FREE_BLOB(this->keyUri);
    if (this->customData.data != nullptr && this->customData.size > 0) {
        /* customData is caller-opaque data; scrub before free (spec R10); a
         * scrub failure only logs and does not block the free (dst/size are
         * self-consistent, so a failure can only come from the inputs) */
        if (memset_s(this->customData.data, this->customData.size, 0, this->customData.size) != EOK) {
            CM_LOG_E("clear customData before free failed");
        }
    }
    CM_FREE_BLOB(this->customData);
    return;
}
}
