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

#include "cm_napi_dialog_callback_int_bool.h"

#include "cm_napi_dialog_common.h"
#include "cm_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace CMNapi {
CmUIExtensionIntBoolCallback::CmUIExtensionIntBoolCallback(
    std::shared_ptr<CmUIExtensionRequestContext>& reqContext) : CmUIExtensionCallback(reqContext) {}

CmUIExtensionIntBoolCallback::~CmUIExtensionIntBoolCallback()
{
    CM_LOG_D("~CmUIExtensionIntBoolCallback");
}

void CmUIExtensionIntBoolCallback::OnDestroy()
{
    CM_LOG_D("CmUIExtensionIntBoolCallback OnDestroy()");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void CmUIExtensionIntBoolCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    CM_LOG_D("CmUIExtensionIntBoolCallback OnReceive()");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void CmUIExtensionIntBoolCallback::ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext)
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
}  // namespace CMNapi
