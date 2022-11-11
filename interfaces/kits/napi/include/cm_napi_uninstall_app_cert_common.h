/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CM_NAPI_UNINSTALL_APP_CERT_COMMON_H
#define CM_NAPI_UNINSTALL_APP_CERT_COMMON_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

struct UninstallAppCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct CmBlob *keyUri = nullptr;
    uint32_t store = 0;
};
using UninstallAppCertAsyncContext = UninstallAppCertAsyncContextT *;

namespace CMNapi {
UninstallAppCertAsyncContext CreateUninstallAppCertAsyncContext();

void DeleteUninstallAppCertAsyncContext(napi_env env, UninstallAppCertAsyncContext &context);

napi_value UninstallAppCertParseParams(
    napi_env env, napi_callback_info info, UninstallAppCertAsyncContext context);

napi_value UninstallAppCertAsyncWork(napi_env env, UninstallAppCertAsyncContext asyncContext);

napi_value CMNapiUninstallAppCertCommon(napi_env env, napi_callback_info info, uint32_t store);
}  // namespace CertManagerNapi

#endif  // CM_NAPI_UNINSTALL_APP_CERT_COMMON_H