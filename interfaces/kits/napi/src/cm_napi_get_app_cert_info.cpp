/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "cm_napi_get_app_cert_info.h"
#include "cm_napi_get_app_cert_info_common.h"
#include "cm_napi_common.h"
#include "cm_log.h"
#include "cm_metrics.h"

namespace CMNapi {
napi_value CMNapiGetPublicCertInfo(napi_env env, napi_callback_info info)
{
    OHOS::Security::CertManager::CmMetricsReport report("CMNapiGetPublicCertInfo");
    report.Start();
    napi_value result = CMNapiGetAppCertInfoCommon(env, info, APPLICATION_CERTIFICATE_STORE);
    report.Finish(OHOS::Security::CertManager::CM_SUCCESS);
    return result;
}

napi_value CMNapiGetPrivateAppCertInfo(napi_env env, napi_callback_info info)
{
    OHOS::Security::CertManager::CmMetricsReport report("CMNapiGetPrivateAppCertInfo");
    report.Start();
    napi_value result = CMNapiGetAppCertInfoCommon(env, info, APPLICATION_PRIVATE_CERTIFICATE_STORE);
    report.Finish(OHOS::Security::CertManager::CM_SUCCESS);
    return result;
}

napi_value CMNapiGetSystemAppCertInfo(napi_env env, napi_callback_info info)
{
    OHOS::Security::CertManager::CmMetricsReport report("CMNapiGetSystemAppCertInfo");
    report.Start();
    napi_value result = CMNapiGetAppCertInfoCommon(env, info, APPLICATION_SYSTEM_CERTIFICATE_STORE);
    report.Finish(OHOS::Security::CertManager::CM_SUCCESS);
    return result;
}
}  // namespace CertManagerNapi
