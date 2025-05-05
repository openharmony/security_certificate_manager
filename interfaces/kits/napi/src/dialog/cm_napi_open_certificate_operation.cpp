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

#include "cm_napi_open_certificate_operation.h"

#include "cm_napi_dialog_common.h"
#include "cm_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace CMNapi {
CmOperationUIExtensionCallback::CmOperationUIExtensionCallback(
    std::shared_ptr<CmUIExtensionRequestContext>& reqContext) : CmUIExtensionCallback(reqContext)
{
    this->reqContext_ = reqContext;
}

CmOperationUIExtensionCallback::~CmOperationUIExtensionCallback()
{
    CM_LOG_D("~CmOperationUIExtensionCallback");
}

void CmOperationUIExtensionCallback::OnRelease(const int32_t releaseCode)
{
    CM_LOG_D("OperationUIExtensionComponent OnRelease(), releaseCode = %d", releaseCode);
    if (SetErrorCode(CMR_DIALOG_ERROR_OPERATION_CANCELS)) {
        SendMessageBack();
    }
}

void CmOperationUIExtensionCallback::OnResult(const int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    CM_LOG_D("OperationUIExtensionComponent OnResult(), resultCode = %d", resultCode);
    this->resultCode_ = resultCode;
    this->resultWant_ = result;
    if (SetErrorCode(this->resultCode_)) {
        SendMessageBack();
    }
}

void CmOperationUIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    CM_LOG_D("OperationUIExtensionComponent OnReceive()");
    this->reqContext_->uri = request.GetStringParam("uri");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void CmOperationUIExtensionCallback::ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext)
{
    napi_value args = nullptr;
    if (asyncContext->errCode == CM_SUCCESS) {
        if (asyncContext->opType == DIALOG_OPERATION_INSTALL || asyncContext->opType == DIALOG_OPERATION_AUTHORIZE) {
            NAPI_CALL_RETURN_VOID(env,
                napi_create_string_utf8(env, asyncContext->uri.c_str(), NAPI_AUTO_LENGTH, &args));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args));
        }
    } else {
        args = GenerateBusinessError(env, asyncContext->errCode);
    }

    if (asyncContext->deferred != nullptr) {
        if (asyncContext->errCode == CM_SUCCESS) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, args));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred, args));
        }
    }
}

void CmOperationUIExtensionCallback::OnDestroy()
{
    CM_LOG_D("OperationUIExtensionComponent OnDestroy()");
}


bool CmOperationUIExtensionCallback::SetErrorCode(int32_t errCode)
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
    this->reqContext_->errCode = errCode;
    return true;
}
}  // namespace CMNapi
