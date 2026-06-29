/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "cm_napi_supports_ca_cert_dialog.h"

#include "cm_log.h"
#include "cm_napi_dialog_common.h"

namespace CMNapi {
using namespace OHOS::Security::CertManager::Dialog;

napi_value CMNapiSupportsCACertDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_I("supportsCACertDialog enter");
    napi_value result = nullptr;
    bool isSupport = IsEnableCACertDialog();
    if (napi_get_boolean(env, isSupport, &result) != napi_ok) {
        ThrowError(env, DIALOG_ERROR_GENERIC, "napi get boolean result error.");
        return nullptr;
    }
    CM_LOG_I("supportsCACertDialog end, isSupport = %d", isSupport);
    return result;
}
}  // namespace CMNapi
