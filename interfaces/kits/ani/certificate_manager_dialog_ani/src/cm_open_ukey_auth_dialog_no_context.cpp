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

#include "cm_open_ukey_auth_dialog_no_context.h"
#include "cert_manager_api.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_log.h"

namespace OHOS::Security::CertManager::Ani {
namespace {
/* Result context kept alive from the CmOpenUkeyAuthDialog call until the
 * AsyncCallbackWrapper is invoked on the IPC thread; ownership is handed to
 * the result callback which deletes it after settling. */
struct CmUkeyAuthDialogAniResultContext {
    ani_vm *vm = nullptr;
    ani_ref globalCallback = nullptr;
    std::shared_ptr<CmMetricsReport> metricsReport = nullptr;
};

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

CmOpenUkeyAuthDialogNoContext::CmOpenUkeyAuthDialogNoContext(ani_env *env, ani_string aniKeyUri,
    ani_object callback) : CertManagerAsyncImpl(env, nullptr, callback, "openUkeyAuthDialog")
{
    this->aniKeyUri = aniKeyUri;
}

int32_t CmOpenUkeyAuthDialogNoContext::GetParamsFromEnv()
{
    int32_t ret = AniUtils::ParseString(env, this->aniKeyUri, this->keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse keyUri failed, ret = %d", ret);
        return ret;
    }
    if (this->keyUri.size <= 1) {
        /* blob carries the terminating zero, size 1 means an empty keyUri */
        CM_LOG_E("keyUri is empty");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    if (this->keyUri.size > MAX_LEN_URI + 1) {
        /* blob carries the terminating zero; reject before the SA does so the
         * error maps to 29700006 instead of the unmapped generic error */
        CM_LOG_E("keyUri is too long, max length: %d", MAX_LEN_URI);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }

    ani_status status = env->GlobalReference_Create(reinterpret_cast<ani_ref>(this->callback),
        &this->globalCallback);
    if (status != ANI_OK) {
        CM_LOG_E("failed to create global callback. status = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
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
    if (resultCode == CM_SUCCESS) {
        int32_t ret = AniUtils::GenerateBusinessError(env, CM_SUCCESS, "", businessError);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("generate businessError failed, ret = %d", ret);
            ReleaseUkeyAuthResultResources(env, context);
            return;
        }
    } else {
        businessError = GetDialogAniErrorResult(env, resultCode);
        if (businessError == nullptr) {
            CM_LOG_E("generate businessError failed");
            ReleaseUkeyAuthResultResources(env, context);
            return;
        }
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

int32_t CmOpenUkeyAuthDialogNoContext::InvokeAsyncWork()
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

    /* the keyUri blob is consumed synchronously inside CmOpenUkeyAuthDialog,
     * so it only needs to live until the call returns */
    struct UkeyAuthRequest ukeyAuthRequest = {};
    ukeyAuthRequest.keyUri.data = this->keyUri.data;
    ukeyAuthRequest.keyUri.size = this->keyUri.size;

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

int32_t CmOpenUkeyAuthDialogNoContext::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenUkeyAuthDialogNoContext::OnFinish()
{
    CM_FREE_BLOB(this->keyUri);
    return;
}
}
