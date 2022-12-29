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

#include "cm_napi_uninstall_app_cert.h"
#include "cm_napi_uninstall_app_cert_common.h"
#include "cm_napi_common.h"
#include "cm_log.h"

namespace CMNapi {
napi_value CMNapiUninstallAppCert(napi_env env, napi_callback_info info)
{
    return CMNapiUninstallAppCertCommon(env, info, APPLICATION_CERTIFICATE_STORE);
}

napi_value CMNapiUninstallPrivateAppCert(napi_env env, napi_callback_info info)
{
    return CMNapiUninstallAppCertCommon(env, info, APPLICATION_PRIVATE_CERTIFICATE_STORE);
}
}  // namespace CertManagerNapi
