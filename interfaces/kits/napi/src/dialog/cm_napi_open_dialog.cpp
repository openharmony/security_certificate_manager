/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cm_napi_open_dialog.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"

#include "cm_napi_dialog_common.h"
#include "want.h"
#include "want_params_wrapper.h"

namespace CMNapi {

CommonAsyncContext::CommonAsyncContext(napi_env env)
{
    CM_LOG_D("CommonAsyncContext");
    this->env = env;
}

CommonAsyncContext::~CommonAsyncContext()
{
    CM_LOG_D("~CommonAsyncContext");
}

CmUIExtensionCallback::CmUIExtensionCallback(std::shared_ptr<CmUIExtensionRequestContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

CmUIExtensionCallback::~CmUIExtensionCallback()
{
    CM_LOG_D("~CmUIExtensionCallback");
}

void CmUIExtensionCallback::SetSessionId(const int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

bool CmUIExtensionCallback::SetErrorCode(int32_t code)
{
    if (this->reqContext_ == nullptr) {
        CM_LOG_E("OnError reqContext is nullptr");
        return false;
    }
    if (this->alreadyCallback_) {
        CM_LOG_D("alreadyCallback");
        return false;
    }
    this->alreadyCallback_ = true;
    this->reqContext_->errCode = code;
    return true;
}

void CmUIExtensionCallback::OnRelease(const int32_t releaseCode)
{
    CM_LOG_D("UIExtensionComponent OnRelease(), releaseCode = %d", releaseCode);
    if (SetErrorCode(releaseCode)) {
        SendMessageBack();
    }
}

void CmUIExtensionCallback::OnResult(const int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    CM_LOG_D("UIExtensionComponent OnResult(), resultCode = %d", resultCode);
    this->resultCode_ = resultCode;
    this->resultWant_ = result;
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void CmUIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    CM_LOG_D("UIExtensionComponent OnReceive()");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void CmUIExtensionCallback::OnError(const int32_t errorCode, const std::string& name, const std::string& message)
{
    CM_LOG_E("UIExtensionComponent OnError(), errorCode = %d, name = %s, message = %s",
        errorCode, name.c_str(), message.c_str());
    if (SetErrorCode(errorCode)) {
        SendMessageBack();
    }
}

void CmUIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy)
{
    CM_LOG_D("UIExtensionComponent OnRemoteReady()");
}

void CmUIExtensionCallback::OnDestroy()
{
    CM_LOG_D("UIExtensionComponent OnDestroy()");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void CmUIExtensionCallback::ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext)
{
    napi_value args[PARAM_SIZE_TWO] = {nullptr};

    if (asyncContext->errCode == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &args[PARAM0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, true, &args[PARAM1]));
    } else {
        args[PARAM0] = GenerateBusinessError(env, asyncContext->errCode);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &args[PARAM1]));
    }

    if (asyncContext->deferred != nullptr) {
        GeneratePromise(env, asyncContext->deferred, asyncContext->errCode, args, CM_ARRAY_SIZE(args));
    }
}

void CmUIExtensionCallback::SendMessageBack()
{
    CM_LOG_I("start SendMessageBack");
    if (this->reqContext_ == nullptr) {
        CM_LOG_E("reqContext is nullptr");
        return;
    }

    auto abilityContext = this->reqContext_->context;
    if (abilityContext != nullptr) {
        auto uiContent = abilityContext->GetUIContent();
        if (uiContent != nullptr) {
            CM_LOG_D("CloseModalUIExtension");
            uiContent->CloseModalUIExtension(this->sessionId_);
        }
    }

    CM_LOG_D("ProcessCallback");
    ProcessCallback(this->reqContext_->env, this->reqContext_.get());
}

static bool IsCmDialogPageTypeEnum(const uint32_t value)
{
    switch (static_cast<CmDialogPageType>(value)) {
        case CmDialogPageType::PAGE_MAIN:
        case CmDialogPageType::PAGE_CA_CERTIFICATE:
        case CmDialogPageType::PAGE_CREDENTIAL:
        case CmDialogPageType::PAGE_INSTALL_CERTIFICATE:
            return true;
        default:
            return false;
    }
}

napi_value CMNapiOpenCertManagerDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert manager dialog enter");
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = { nullptr };
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != PARAM_SIZE_TWO) {
        CM_LOG_E("params number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need " + std::to_string(PARAM_SIZE_TWO)
            + ", given " + std::to_string(argc);
        ThrowError(env, PARAM_ERROR, errMsg);
        return result;
    }

    // Parse first argument for context.
    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    if (!ParseCmUIAbilityContextReq(env, argv[PARAM0], asyncContext->context)) {
        CM_LOG_E("ParseUIAbilityContextReq failed");
        ThrowError(env, PARAM_ERROR, "Get context failed.");
        return result;
    }

    // Parse second argument for page type.
    result = ParseUint32(env, argv[PARAM1], asyncContext->pageType);
    if (result == nullptr) {
        CM_LOG_E("parse type failed");
        ThrowError(env, PARAM_ERROR, "parse type failed");
        return result;
    }

    if (!IsCmDialogPageTypeEnum(asyncContext->pageType)) {
        CM_LOG_E("pageType invalid");
        ThrowError(env, PARAM_ERROR, "pageType invalid");
        return nullptr;
    }

    asyncContext->env = env;
    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(asyncContext->pageType));
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));

    auto uiExtCallback = std::make_shared<CmUIExtensionCallback>(asyncContext);
    // Start ui extension by context.
    StartUIExtensionAbility(asyncContext, want, uiExtCallback);
    CM_LOG_I("cert manager dialog end");
    return result;
}
}  // namespace CMNapi