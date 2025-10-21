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

#ifndef CM_NAPI_GET_APP_CERTIFICATE_LIST_BY_UID_COMMON_H
#define CM_NAPI_GET_APP_CERTIFICATE_LIST_BY_UID_COMMON_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

struct GetAppCertListByUidAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    uint32_t appUid = 0;
    int32_t result = 0;
    uint32_t store = 0;
    struct CredentialList *credentialList = nullptr;
};
using GetAppCertListByUidAsyncContext = GetAppCertListByUidAsyncContextT *;

namespace CMNapi {
GetAppCertListByUidAsyncContext CreateGetAppCertListByUidAsyncContext();

void DeleteGetAppCertListByUidAsyncContext(napi_env env, GetAppCertListByUidAsyncContext &context);

napi_value GetAppCertListByUidParseParams(
    napi_env env, napi_callback_info info, GetAppCertListByUidAsyncContext context);

napi_value GetAppCertListByUidWriteResult(napi_env env, GetAppCertListByUidAsyncContext context);

napi_value GetAppCertListByUidAsyncWork(napi_env env, GetAppCertListByUidAsyncContext asyncContext);

napi_value CMNapiGetAppCertListByUidCommon(napi_env env, napi_callback_info info, uint32_t store);
}  // namespace CertManagerNapi

#endif  // CM_NAPI_GET_APP_CERTIFICATE_LIST_BY_UID_COMMON_H