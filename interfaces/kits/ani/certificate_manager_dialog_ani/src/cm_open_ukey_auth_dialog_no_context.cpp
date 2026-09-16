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
#include "securec.h"

#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_log.h"
#include "cm_ukey_dialog_common.h"

namespace OHOS::Security::CertManager::Ani {
using namespace Dialog;
namespace {
/* Result context kept alive from the CmOpenUkeyAuthDialog call until the
 * AsyncCallbackWrapper is invoked on the IPC thread; ownership is handed to
 * the result callback which deletes it after settling. */
struct CmUkeyAuthDialogAniResultContext {
    ani_vm *vm = nullptr;
    ani_ref globalCallback = nullptr;
    bool legacyOverload = false; /* D8 修订：-1017/-1018 折叠标记 */
    std::shared_ptr<CmMetricsReport> metricsReport = nullptr;
};

/* D8 修订：老接口（带 context 重载）委托 SA 会话后可能产生 -1017/-1018，老接口
 * throws 面不新增 since-26 错误码——超时折叠 29700002、单飞折叠 29700003，
 * 消息保留具体原因。 */
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

CmOpenUkeyAuthDialogNoContext::CmOpenUkeyAuthDialogNoContext(ani_env *env, ani_string aniKeyUri,
    ani_double aniTimeout, ani_string aniScene, ani_object aniCustomData, ani_object callback)
    : CertManagerAsyncImpl(env, nullptr, callback, "openUkeyAuthDialog")
{
    this->aniKeyUri = aniKeyUri;
    this->aniTimeout = aniTimeout;
    this->aniScene = aniScene;
    this->aniCustomData = aniCustomData;
}

void CmOpenUkeyAuthDialogNoContext::SetLegacyOverload()
{
    this->legacyOverload = true;
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
    /* optional timeout in ms; negative / non-finite maps to a param error */
    if (this->aniTimeout < 0 || this->aniTimeout > UINT32_MAX) {
        CM_LOG_E("invalid timeout value");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    this->timeoutMs = static_cast<uint32_t>(this->aniTimeout);

    /* optional scene; must be exactly 'Login' or 'Custom' (D9/D11) */
    CmBlob sceneBlob = { 0 };
    ret = AniUtils::ParseString(env, this->aniScene, sceneBlob);
    if (ret != CM_SUCCESS || sceneBlob.size == 0) {
        CM_LOG_E("parse scene failed, ret = %d", ret);
        CM_FREE_BLOB(sceneBlob);
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    std::string sceneStr(reinterpret_cast<char *>(sceneBlob.data), sceneBlob.size - 1);
    CM_FREE_BLOB(sceneBlob);
    if (sceneStr == CM_UKEY_SCENE_LOGIN_STR) {
        this->scene = CM_UKEY_AUTH_SCENE_LOGIN;
    } else if (sceneStr == CM_UKEY_SCENE_CUSTOM_STR) {
        this->scene = CM_UKEY_AUTH_SCENE_CUSTOM;
    } else {
        CM_LOG_E("scene is not a valid UkeyAuthScene value");
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }

    /* optional customData; Uint8Array <= 2048 raw bytes (D19)，ets 层已归一化为
     * 非 undefined 对象（空数组表示缺省） */
    ret = AniUtils::ParseUint8Array(env, reinterpret_cast<ani_arraybuffer>(this->aniCustomData),
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
        int32_t metricsCode = TransformDialogErrorCode(resultCode);
        if (context->legacyOverload && IsLegacyFoldCode(resultCode)) {
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
    if (resultCode == CM_SUCCESS) {
        int32_t ret = AniUtils::GenerateBusinessError(env, CM_SUCCESS, "", businessError);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("generate businessError failed, ret = %d", ret);
            ReleaseUkeyAuthResultResources(env, context);
            return;
        }
    } else if (context->legacyOverload && IsLegacyFoldCode(resultCode)) {
        /* D8 修订：折叠码 + 具体原因消息 */
        int32_t jsCode = TransformLegacyFoldCode(resultCode);
        const std::string &msg = (resultCode == CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT)
            ? UKEY_AUTH_REPORT_TIMEOUT_MSG : UKEY_DIALOG_IN_PROGRESS_MSG;
        int32_t ret = AniUtils::GenerateBusinessError(env, jsCode, msg.c_str(), businessError);
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
    resultContext->legacyOverload = this->legacyOverload;
    resultContext->metricsReport = this->metricsReport_;

    /* the keyUri/customData blobs are consumed synchronously inside
     * CmOpenUkeyAuthDialog, so they only need to live until the call returns */
    struct UkeyAuthRequest ukeyAuthRequest = {};
    ukeyAuthRequest.keyUri.data = this->keyUri.data;
    ukeyAuthRequest.timeoutDuration = this->timeoutMs;
    ukeyAuthRequest.keyUri.size = this->keyUri.size;
    ukeyAuthRequest.scene = this->scene;
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

int32_t CmOpenUkeyAuthDialogNoContext::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenUkeyAuthDialogNoContext::OnFinish()
{
    CM_FREE_BLOB(this->keyUri);
    if (this->customData.data != nullptr && this->customData.size > 0) {
        /* customData 为调用方不透明数据，释放前擦除（spec R10） */
        (void)memset_s(this->customData.data, this->customData.size, 0, this->customData.size);
    }
    CM_FREE_BLOB(this->customData);
    return;
}
}
