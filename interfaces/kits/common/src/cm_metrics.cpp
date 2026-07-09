/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "cm_metrics.h"

#include "cm_api_common.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager {

int32_t CmGetMetricErrorCode(int32_t jsErrorCode)
{
    switch (jsErrorCode) {
        case SUCCESS:
            return CM_METRIC_SUCCESS;
        case HAS_NO_PERMISSION:
            return CM_METRIC_HAS_NO_PERMISSION;
        case NOT_SYSTEM_APP:
            return CM_METRIC_NOT_SYSTEM_APP;
        case PARAM_ERROR:
            return CM_METRIC_PARAM_ERROR;
        case CAPABILITY_NOT_SUPPORTED:
            return CM_METRIC_CAPABILITY_NOT_SUPPORTED;
        case INNER_FAILURE:
            return CM_METRIC_INNER_FAILURE;
        case NOT_FOUND:
            return CM_METRIC_NOT_FOUND;
        case INVALID_CERT_FORMAT:
            return CM_METRIC_INVALID_CERT_FORMAT;
        case MAX_CERT_COUNT_REACHED:
            return CM_METRIC_MAX_CERT_COUNT_REACHED;
        case NO_AUTHORIZATION:
            return CM_METRIC_NO_AUTHORIZATION;
        case DEVICE_ENTER_ADVSECMODE:
            return CM_METRIC_DEVICE_ENTER_ADVSECMODE;
        case PASSWORD_IS_ERROR:
            return CM_METRIC_PASSWORD_IS_ERROR;
        case STORE_PATH_NOT_SUPPORTED:
            return CM_METRIC_STORE_PATH_NOT_SUPPORTED;
        case ACCESS_UKEY_SERVICE_FAILED:
            return CM_METRIC_ACCESS_UKEY_SERVICE_FAILED;
        case PARAMETER_VALIDATION_FAILED:
            return CM_METRIC_PARAMETER_VALIDATION_FAILED;
        case Dialog::DIALOG_ERROR_GENERIC:
            return CM_METRIC_INNER_FAILURE;
        case Dialog::DIALOG_ERROR_OPERATION_CANCELED:
            return CM_METRIC_DIALOG_OPERATION_CANCELED;
        case Dialog::DIALOG_ERROR_INSTALL_FAILED:
            return CM_METRIC_DIALOG_INSTALL_FAILED;
        case Dialog::DIALOG_ERROR_NOT_SUPPORTED:
            return CM_METRIC_CAPABILITY_NOT_SUPPORTED;
        case Dialog::DIALOG_ERROR_NOT_COMPLY_SECURITY_POLICY:
            return CM_METRIC_DIALOG_NOT_COMPLY_SECURITY_POLICY;
        case Dialog::DIALOG_ERROR_PARAMETER_VALIDATION_FAILED:
            return CM_METRIC_PARAMETER_VALIDATION_FAILED;
        case Dialog::DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE:
            return CM_METRIC_DIALOG_NO_AVAILABLE_CERTIFICATE;
        case Dialog::DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED:
            return CM_METRIC_CAPABILITY_NOT_SUPPORTED;
        default:
            return CM_METRIC_UNKNOWN_ERROR;
    }
}
} // namespace OHOS::Security::CertManager
