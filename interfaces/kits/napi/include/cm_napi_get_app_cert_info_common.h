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

#ifndef CM_NAPI_GET_APP_CERT_INFO_COMMON_H
#define CM_NAPI_GET_APP_CERT_INFO_COMMON_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

struct GetAppCertInfoAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;

    struct CmBlob *keyUri = nullptr;
    uint32_t store = 0;
    struct Credential *credential = nullptr;
};
using GetAppCertInfoAsyncContext = GetAppCertInfoAsyncContextT *;

namespace CMNapi {
GetAppCertInfoAsyncContext CreateGetAppCertInfoAsyncContext();

void DeleteGetAppCertInfoAsyncContext(napi_env env, GetAppCertInfoAsyncContext &context);

napi_value GetAppCertInfoParseParams(
    napi_env env, napi_callback_info info, GetAppCertInfoAsyncContext context);

napi_value GetAppCertInfoWriteResult(napi_env env, GetAppCertInfoAsyncContext context);

napi_value GetAppCertInfoAsyncWork(napi_env env, GetAppCertInfoAsyncContext asyncContext);

napi_value CMNapiGetAppCertInfoCommon(napi_env env, napi_callback_info info, uint32_t store);
}  // namespace CertManagerNapi

#endif  // CM_NAPI_GET_APP_CERT_INFO_COMMON_H