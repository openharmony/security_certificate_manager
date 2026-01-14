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
#include "cm_open_dialog.h"

#include <unordered_map>
#include <mutex>
#include <thread>
#include "securec.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"

#include "cm_log.h"

namespace OHOS::Security::CertManager::Ani {
using namespace OHOS::AbilityRuntime;

CmAniUIExtensionCallback::CmAniUIExtensionCallback(ani_vm *vm, std::shared_ptr<AbilityContext> context,
    ani_ref aniCallback)
{
    this->vm = vm;
    this->context = context;
    this->aniCallback = aniCallback;
}

CmAniUIExtensionCallback::~CmAniUIExtensionCallback() {}

void CmAniUIExtensionCallback::SetSessionId(const int32_t sessionId)
{
    this->sessionId = sessionId;
}

ani_object CmAniUIExtensionCallback::GetDefaultResult(ani_env *env)
{
    ani_ref nullRef;
    env->GetNull(&nullRef);
    return reinterpret_cast<ani_object>(nullRef);
}

void CmAniUIExtensionCallback::invokeCallback(ani_env *env, const int32_t code, ani_object result)
{
    CM_LOG_D("CmAniUIExtensionCallback::invokeCallback");
    {
        std::lock_guard<std::mutex> lock(this->lockIsReleased);
        if (this->isReleased) {
            CM_LOG_W("callback has invoked.");
            return;
        }
        this->isReleased = true;
    }
    if (this->context != nullptr) {
        auto uiContent = this->context->GetUIContent();
        if (uiContent != nullptr) {
            CM_LOG_D("close ModalUIExtension");
            uiContent->CloseModalUIExtension(this->sessionId);
        }
    }

    int32_t ret;
    ani_object businessError{};
    if (code != CM_SUCCESS) {
        CM_LOG_E("invokeCallback with error, code: %d", code);
        businessError = GetDialogAniErrorResult(env, code);
        if (businessError == nullptr) {
            CM_LOG_E("get businessError failed.");
            return;
        }
    } else {
        ret = AniUtils::GenerateBusinessError(env, CM_SUCCESS, "", businessError);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("generate businessError failed.");
            return;
        }
    }

    ani_status status = env->Object_CallMethodByName_Void(reinterpret_cast<ani_object>(this->aniCallback), "invoke",
        "C{@ohos.base.BusinessError}Y:", businessError, result);
    if (status != ANI_OK) {
        CM_LOG_E("invoke callback failed. status = %d", static_cast<int32_t>(status));
        return;
    }
    env->GlobalReference_Delete(this->aniCallback);
    DetachCurrentThreadEnv(this->vm);
    return;
}

void CmAniUIExtensionCallback::OnRelease(const int32_t releaseCode)
{
    CM_LOG_D("UIExtensionComponent OnRelease, releaseCode: %d", releaseCode);
    ani_env *env = GetEnv(this->vm);
    if (env == nullptr) {
        CM_LOG_E("get env failed.");
        return;
    }
    this->invokeCallback(env, releaseCode, this->GetDefaultResult(env));
}

void CmAniUIExtensionCallback::OnResult(const int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    CM_LOG_D("UIExtensionComponent OnResult, resultCode: %d", resultCode);
    ani_env *env = GetEnv(this->vm);
    if (env == nullptr) {
        CM_LOG_E("get env failed.");
        return;
    }
    this->invokeCallback(env, resultCode, this->GetDefaultResult(env));
}

void CmAniUIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    CM_LOG_D("UIExtensionComponent OnReceive");
    ani_env *env = GetEnv(this->vm);
    if (env == nullptr) {
        CM_LOG_E("get env failed.");
        return;
    }
    this->invokeCallback(env, CM_SUCCESS, this->GetDefaultResult(env));
}

void CmAniUIExtensionCallback::OnError(const int32_t code, const std::string &name, const std::string &message)
{
    CM_LOG_D("UIExtensionComponent OnError, code: %d, name: %s, message: %s", code, name.c_str(), message.c_str());
    ani_env *env = GetEnv(this->vm);
    if (env == nullptr) {
        CM_LOG_E("get env failed.");
        return;
    }
    this->invokeCallback(env, code, this->GetDefaultResult(env));
}

void CmAniUIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy)
{
    CM_LOG_D("UIExtensionComponent OnRemoteReady");
}

void CmAniUIExtensionCallback::OnDestroy()
{
    CM_LOG_D("UIExtensionComponent OnDestroy");
    ani_env *env = GetEnv(this->vm);
    if (env == nullptr) {
        CM_LOG_E("get env failed.");
        return;
    }
    this->invokeCallback(env, CM_SUCCESS, this->GetDefaultResult(env));
}

CmAniUIExtensionCallbackString::CmAniUIExtensionCallbackString(
    ani_vm *vm,
    std::shared_ptr<AbilityContext> context,
    ani_ref aniCallback
) : CmAniUIExtensionCallback(vm, context, aniCallback) {}

ani_object CmAniUIExtensionCallbackString::GetDefaultResult(ani_env *env)
{
    ani_string aniResult = AniUtils::GenerateCharStr(env, "", 0);
    return reinterpret_cast<ani_object>(aniResult);
}

void CmAniUIExtensionCallbackString::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    CM_LOG_D("UIExtensionComponent OnReceive");
    ani_env *env = GetEnv(this->vm);
    if (env == nullptr) {
        CM_LOG_E("get env failed.");
        return;
    }
    std::string result = request.GetStringParam("uri");
    ani_string aniResult = AniUtils::GenerateCharStr(env, result.c_str(), result.size());
    if (aniResult == nullptr) {
        aniResult = reinterpret_cast<ani_string>(GetDefaultResult(env));
    }
    this->invokeCallback(env, CM_SUCCESS, reinterpret_cast<ani_object>(aniResult));
}

CmAniUIExtensionCallbackCertReference::CmAniUIExtensionCallbackCertReference(
    ani_vm *vm,
    std::shared_ptr<AbilityContext> context,
    ani_ref aniCallback
) : CmAniUIExtensionCallback(vm, context, aniCallback) {}

ani_object CmAniUIExtensionCallbackCertReference::GetDefaultResult(ani_env *env)
{
    ani_int aniIntResult = 0;
    ani_string aniStrResult = AniUtils::GenerateCharStr(env, "", 0);
    ani_object aniResult = AniUtils::GenerateCertReference(env, aniIntResult, aniStrResult);
    if (aniResult == nullptr) {
        CM_LOG_E("generate keyUri failed");
        return nullptr;
    }
    return reinterpret_cast<ani_object>(aniResult);
}

void CmAniUIExtensionCallbackCertReference::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    CM_LOG_D("UIExtensionComponent OnReceive");
    ani_env *env = GetEnv(this->vm);
    if (env == nullptr) {
        CM_LOG_E("get env failed.");
        return;
    }
    uint32_t certificateType = static_cast<uint32_t>(request.GetIntParam("certType", 0));
    ani_int aniCertType = static_cast<ani_int>(certificateType);

    std::string keyUri = request.GetStringParam("uri");
    ani_string aniKeyUri = AniUtils::GenerateCharStr(env, keyUri.c_str(), keyUri.size());

    ani_object aniResult{};
    if (aniKeyUri == nullptr) {
        aniResult = GetDefaultResult(env);
    } else {
        aniResult = AniUtils::GenerateCertReference(env, aniCertType, aniKeyUri);
    }
    this->invokeCallback(env, CM_SUCCESS, reinterpret_cast<ani_object>(aniResult));
}

static bool CheckBasicPermission(void)
{
    AccessToken::AccessTokenID tokenId = OHOS::IPCSkeleton::GetCallingTokenID();

    int result = AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, "ohos.permission.ACCESS_CERT_MANAGER");
    if (result == AccessToken::PERMISSION_GRANTED) {
        return true;
    }

    return false;
}

int32_t StartUIExtensionAbility(std::shared_ptr<AbilityContext> context, OHOS::AAFwk::Want want,
    std::shared_ptr<CmAniUIExtensionCallback> uiExtCallback)
{
    /*
     * Before starting the UIExtension, the permission is verified for interception.
     * The verification will be performed again in the process of starting the com.ohos.certmanager application.
     */
    CM_LOG_D("begin StartUIExtensionAbility");
    if (!CheckBasicPermission()) {
        CM_LOG_E("not has basic permission");
        return CMR_DIALOG_ERROR_PERMISSION_DENIED;
    }

    if (context == nullptr) {
        CM_LOG_E("check context is nullptr");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }

    auto uiContent = context->GetUIContent();
    if (uiContent == nullptr) {
        CM_LOG_E("uiContent is null");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }

    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](int32_t resultCode, const OHOS::AAFwk::Want &result) {
            uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const OHOS::AAFwk::WantParams &request) { uiExtCallback->OnReceive(request); },
        [uiExtCallback](int32_t errorCode, const std::string &name, const std::string &message) {
            uiExtCallback->OnError(errorCode, name, message); },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy); },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); }
    };

    OHOS::Ace::ModalUIExtensionConfig uiExtConfig;
    uiExtConfig.isProhibitBack = false;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, extensionCallbacks, uiExtConfig);
    if (sessionId == 0) {
        CM_LOG_E("CreateModalUIExtension failed");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    uiExtCallback->SetSessionId(sessionId);
    return CM_SUCCESS;
}
}