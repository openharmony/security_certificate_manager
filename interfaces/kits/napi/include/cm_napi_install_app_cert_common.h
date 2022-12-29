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

#ifndef CM_NAPI_INSTALL_APP_CERT_COMMON_H
#define CM_NAPI_INSTALL_APP_CERT_COMMON_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

struct InstallAppCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct CmBlob *keystore = nullptr;
    struct CmBlob *keystorePwd = nullptr;
    struct CmBlob *keyAlias = nullptr;
    struct CmBlob *keyUri = nullptr;
    uint32_t store = 0;
};
using InstallAppCertAsyncContext = InstallAppCertAsyncContextT *;

namespace CMNapi {
InstallAppCertAsyncContext CreateInstallAppCertAsyncContext();

void DeleteInstallAppCertAsyncContext(napi_env env, InstallAppCertAsyncContext &context);

napi_value InstallAppCertParseParams(
    napi_env env, napi_callback_info info, InstallAppCertAsyncContext context);

napi_value InstallAppCertAsyncWork(napi_env env, InstallAppCertAsyncContext asyncContext);

napi_value CMNapiInstallAppCertCommon(napi_env env, napi_callback_info info, uint32_t store);
}  // namespace CertManagerNapi

#endif  // CM_NAPI_INSTALL_APP_CERT_COMMON_H