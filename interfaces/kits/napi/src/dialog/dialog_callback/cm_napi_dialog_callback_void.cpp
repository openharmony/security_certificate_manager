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

#include "cm_napi_dialog_callback_void.h"

#include "cm_napi_dialog_common.h"
#include "cm_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace CMNapi {
CmUIExtensionVoidCallback::CmUIExtensionVoidCallback(
    std::shared_ptr<CmUIExtensionRequestContext>& reqContext) : CmUIExtensionCallback(reqContext) {}

CmUIExtensionVoidCallback::~CmUIExtensionVoidCallback()
{
    CM_LOG_D("~CmUIExtensionVoidCallback");
}


void CmUIExtensionVoidCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    CM_LOG_D("CmUIExtensionVoidCallback OnReceive()");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void CmUIExtensionVoidCallback::ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext)
{
    napi_value args = nullptr;
    if (asyncContext->errCode == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args));
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
