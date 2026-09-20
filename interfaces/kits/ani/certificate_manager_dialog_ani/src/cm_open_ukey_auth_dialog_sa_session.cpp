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

#include "cm_open_ukey_auth_dialog_sa_session.h"
#include "cert_manager_api.h"
#include "securec.h"

#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_log.h"
#include "cm_ukey_dialog_common.h"
#include "cm_ukey_ani_request.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
namespace {
/* Result context kept alive from the CmOpenUkeyAuthDialog call until the
 * AsyncCallbackWrapper is invoked on the IPC thread; ownership is handed to
 * the result callback which deletes it after settling. */
struct CmUkeyAuthDialogAniResultContext {
    ani_vm *vm = nullptr;
    ani_ref globalCallback = nullptr;
    std::shared_ptr<CmMetricsReport> metricsReport = nullptr;
};

/* D8 revision: the SA session is delegated from the legacy openUkeyAuthDialog
 * (published since-22; no since-26 error codes are added to its throws
 * surface) - timeout folds to 29700002, single-flight folds to 29700003,
 * and the message keeps the specific reason. */
static bool IsLegacyFoldCode(int32_t resultCode)
{
    return resultCode == CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT ||
        resultCode == CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
}

static int32_t TransformLegacyFoldCode(int32_t resultCode)
{
    if (resultCode == CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT) {
        return DIALOG_ERROR_OPERATION_CANCELED; /* 29700002 */
    }
    return DIALOG_ERROR_INSTALL_FAILED; /* 29700003 */
}

void ReleaseUkeyAuthResultResources(ani_env *env, CmUkeyAuthDialogAniResultContext *context)
{
    ani_status status = env->GlobalReference_Delete(context->globalCallback);
    if (status != ANI_OK) {
        CM_LOG_E("delete global reference failed. status = %d", static_cast<int32_t>(status));
    }
    status = DetachCurrentThreadEnv(context->vm);
    if (status != ANI_OK) {
        CM_LOG_E("DetachCurrentThreadEnv failed. status = %d", static_cast<int32_t>(status));
    }
    delete context;
}
} // namespace

CmOpenUkeyAuthDialogSaSession::CmOpenUkeyAuthDialogSaSession(ani_env *env, ani_object aniRequest,
    ani_object callback)
    : CertManagerAsyncImpl(env, nullptr, callback, "openUkeyAuthDialog")
{
    this->aniRequest = aniRequest;
}

int32_t CmOpenUkeyAuthDialogSaSession::GetParamsFromEnv()
{
    CmUkeyAniRequest req;
    int32_t ret = ParseUkeyAniRequest(env, this->aniRequest, req);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse ukey auth request object failed, ret = %d", ret);
        return ret;
    }
    ret = AniUtils::ParseString(env, req.keyUri, this->keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keyUri failed, ret = %d", ret);
        return ret;
    }
    if (this->keyUri.size <= 1) {
        /* blob carries the terminating zero, size 1 means an empty keyUri */
        CM_LOG_E("keyUri is empty");
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    if (this->keyUri.size > MAX_LEN_URI) {
        /* blob carries the terminating zero; the SA rejects a keyUri blob
         * longer than MAX_LEN_URI (NUL included), reject here so the error
         * maps to 29700006 instead of the unmapped generic error */
        CM_LOG_E("keyUri is too long, max length: %d", MAX_LEN_URI);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    /* optional timeout in seconds; non-number/NaN maps to a param error
     * (NaN fails both bounds, so the negated form rejects it) */
    if (!(req.timeout >= 0 && req.timeout <= UINT32_MAX)) {
        CM_LOG_E("invalid timeout value");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    this->timeoutSec = static_cast<uint32_t>(req.timeout);

    /* optional customData; Uint8Array <= 2048 raw bytes (D19); nullptr = absent */
    if (req.customData != nullptr) {
        ret = AniUtils::ParseUint8Array(env, reinterpret_cast<ani_arraybuffer>(req.customData),
            this->customData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("parse customData failed, ret = %d", ret);
            return ret;
        }
        if (this->customData.size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
            CM_LOG_E("customData is too long, max: %d", CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE);
            CM_FREE_BLOB(this->customData);
            return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
        }
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
 * UkeyAuthDialogResultCallback): success -> no error object; D8-revised
 * folded codes -> folded code + specific-reason message; anything else ->
 * regular mapping */
static bool GenerateUkeyResultBusinessError(ani_env *env, int32_t resultCode, ani_object &businessError)
{
    if (resultCode == CM_SUCCESS) {
        return AniUtils::GenerateBusinessError(env, CM_SUCCESS, "", businessError) == CM_SUCCESS;
    }
    if (IsLegacyFoldCode(resultCode)) {
        int32_t jsCode = TransformLegacyFoldCode(resultCode);
        const std::string &msg = (resultCode == CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT)
            ? UKEY_AUTH_REPORT_TIMEOUT_MSG : UKEY_DIALOG_IN_PROGRESS_MSG;
        return AniUtils::GenerateBusinessError(env, jsCode, msg.c_str(), businessError) == CM_SUCCESS;
    }
    businessError = GetDialogAniErrorResult(env, resultCode);
    return businessError != nullptr;
}

/* C callback running on an IPC thread: attach the thread to the VM and settle
 * the AsyncCallbackWrapper exactly once with the dialog result delivered by
 * the SA (same mechanism as CmAniUIExtensionCallback::invokeCallback). */
static void UkeyAuthDialogResultCallback(int32_t resultCode, void *userData)
{
    auto context = static_cast<CmUkeyAuthDialogAniResultContext *>(userData);
    if (context == nullptr) {
        CM_LOG_E("result context is null");
        return;
    }

    if (context->metricsReport != nullptr) {
        int32_t metricsCode = TransformDialogErrorCode(resultCode);
        if (IsLegacyFoldCode(resultCode)) {
            metricsCode = TransformLegacyFoldCode(resultCode);
        }
        context->metricsReport->Finish(metricsCode);
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
    if (!GenerateUkeyResultBusinessError(env, resultCode, businessError)) {
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

int32_t CmOpenUkeyAuthDialogSaSession::InvokeAsyncWork()
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

    /* the keyUri/customData blobs are consumed synchronously inside
     * CmOpenUkeyAuthDialog, so they only need to live until the call returns */
    struct UkeyAuthRequest ukeyAuthRequest = {};
    ukeyAuthRequest.keyUri.data = this->keyUri.data;
    ukeyAuthRequest.timeoutDuration = this->timeoutSec;
    ukeyAuthRequest.keyUri.size = this->keyUri.size;
    ukeyAuthRequest.customData = this->customData;

    int32_t ret = CmOpenUkeyAuthDialog(&ukeyAuthRequest, UkeyAuthDialogResultCallback, resultContext);
    if (ret != CM_SUCCESS) {
        /* sync failure: the result callback never fires (inner API contract),
         * release the context here; the global callback reference is deleted
         * by the base class on the InvokeInnerApi failure path */
        CM_LOG_E("open ukey auth dialog failed, ret = %d", ret);
        delete resultContext;
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmOpenUkeyAuthDialogSaSession::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenUkeyAuthDialogSaSession::OnFinish()
{
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
