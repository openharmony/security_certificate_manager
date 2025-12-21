/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cm_napi_dialog_callback.h"

#include "cm_napi_dialog_common.h"
#include "cm_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace CMNapi {
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
    if (SetErrorCode(resultCode)) {
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
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(this->reqContext_->env, &scope);
    if (scope == nullptr) {
        CM_LOG_E("open handle scope failed.");
    }
    ProcessCallback(this->reqContext_->env, this->reqContext_.get());
    if (scope != nullptr) {
        napi_close_handle_scope(this->reqContext_->env, scope);
    }
}
}  // namespace CMNapi
