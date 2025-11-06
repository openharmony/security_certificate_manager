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

#include "cm_napi_dialog_callback_cert_index.h"

#include "cm_napi_dialog_common.h"
#include "cm_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace CMNapi {
CmUIExtensionCertReferenceCallback::CmUIExtensionCertReferenceCallback(
    std::shared_ptr<CmUIExtensionRequestContext>& reqContext) : CmUIExtensionCallback(reqContext) {}

CmUIExtensionCertReferenceCallback::~CmUIExtensionCertReferenceCallback()
{
    CM_LOG_D("~CmUIExtensionCertReferenceCallback");
}

void CmUIExtensionCertReferenceCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    CM_LOG_D("CmUIExtensionCertReferenceCallback OnReceive()");
    this->reqContext_->certificateType = static_cast<uint32_t>(request.GetIntParam("certType", 0));
    this->reqContext_->uri = request.GetStringParam("uri");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void CmUIExtensionCertReferenceCallback::ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext)
{
    napi_value args = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &args));
    if (asyncContext->errCode == CM_SUCCESS) {
        napi_value keyUri = nullptr;
        napi_value certificateType = nullptr;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(env, asyncContext->uri.c_str(), NAPI_AUTO_LENGTH, &keyUri));
        NAPI_CALL_RETURN_VOID(env,
            napi_create_uint32(env, asyncContext->certificateType, &certificateType));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, args, CERT_MANAGER_CERT_TYPE.c_str(),
            certificateType));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, args, CERT_MANAGER_CERT_KEY_URI.c_str(), keyUri));
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
}  // namespace CMNapi
