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

#ifndef CM_NAPI_GET_APP_CERTIFICATE_LIST_COMMON_H
#define CM_NAPI_GET_APP_CERTIFICATE_LIST_COMMON_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi/native_node_api.h"

struct GetAppCertListAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    uint32_t store = 0;
    struct CredentialList *credentialList = nullptr;
};
using GetAppCertListAsyncContext = GetAppCertListAsyncContextT *;

namespace CMNapi {
GetAppCertListAsyncContext CreateGetAppCertListAsyncContext();

void DeleteGetAppCertListAsyncContext(napi_env env, GetAppCertListAsyncContext &context);

napi_value GetAppCertListParseParams(
    napi_env env, napi_callback_info info, GetAppCertListAsyncContext context);

napi_value GetAppCertListWriteResult(napi_env env, GetAppCertListAsyncContext context);

napi_value GetAppCertListAsyncWork(napi_env env, GetAppCertListAsyncContext asyncContext);

napi_value CMNapiGetAppCertListCommon(napi_env env, napi_callback_info info, uint32_t store);
}  // namespace CertManagerNapi

#endif  // CM_NAPI_GET_APP_CERTIFICATE_LIST_COMMON_H