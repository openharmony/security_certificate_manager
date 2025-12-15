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

#ifndef CM_DIALOG_API_COMMON_H
#define CM_DIALOG_API_COMMON_H

#include <string>
#include "cm_type.h"
#include "ability_context.h"
#include "cm_type.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS::Security::CertManager::Dialog {
using namespace OHOS::AbilityRuntime;

enum ErrorCode {
    SUCCESS = 0,
    HAS_NO_PERMISSION = 201,
    NOT_SYSTEM_APP = 202,
    PARAM_ERROR = 401,
    DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED = 801,
    DIALOG_ERROR_GENERIC = 29700001,
    DIALOG_ERROR_OPERATION_CANCELED = 29700002,
    DIALOG_ERROR_INSTALL_FAILED = 29700003,
    DIALOG_ERROR_NOT_SUPPORTED = 29700004,
    DIALOG_ERROR_NOT_COMPLY_SECURITY_POLICY = 29700005,
    DIALOG_ERROR_PARAMETER_VALIDATION_FAILED = 29700006,
    DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE = 29700007,
};
static const std::string DIALOG_NO_PERMISSION_MSG = "the caller has no permission";
static const std::string DIALOG_INVALID_PARAMS_MSG = "the input parameters is invalid";
static const std::string DIALOG_GENERIC_MSG = "there is an internal error";
static const std::string DIALOG_OPERATION_CANCELS_MSG = "the user cancels the installation operation";
static const std::string DIALOG_INSTALL_FAILED_MSG = "the user install certificate failed"
    " in the certificate manager dialog";
static const std::string DIALOG_NOT_SUPPORTED_MSG = "the API is not supported on this device";

static const std::string DIALOG_OPERATION_FAILED_MSG = "the user operation failed "
    "in the certification manager dialog: ";
static const std::string PARSE_CERT_FAILED_MSG = "parse the certificate failed.";
static const std::string ADVANCED_SECURITY_MSG = "the device enters advanced security mode.";
static const std::string INCORRECT_FORMAT_MSG = "the certificate is in an invalid format.";
static const std::string MAX_QUANTITY_REACHED_MSG = "the number of certificates or credentials "
    "reaches the maxinum allowed.";
static const std::string SA_INTERNAL_ERROR_MSG = "sa internal error.";
static const std::string NOT_EXIST_MSG = "the certificate dose not exist.";
static const std::string NOT_ENTERPRISE_DEVICE_MSG = "The operation does not comply with the device security policy,"
    "such as the device does not allow users to manage the ca certificate of the global user.";
static const std::string CAPABILITY_NOT_SUPPORTED_MSG = "the capability not supported.";
static const std::string NO_AVAILABLE_CERTIFICATE_MSG = "no available certificate for authorization"

static const std::unordered_map<int32_t, int32_t> DIALOG_CODE_TO_JS_CODE_MAP = {
    // no permission
    { CMR_DIALOG_ERROR_PERMISSION_DENIED, HAS_NO_PERMISSION },
    // internal error
    { CMR_DIALOG_ERROR_INTERNAL, DIALOG_ERROR_GENERIC },
    // the user cancels the installation operation
    { CMR_DIALOG_ERROR_OPERATION_CANCELS, DIALOG_ERROR_OPERATION_CANCELED },
    // the user install certificate failed in the certificate manager dialog
    { CMR_DIALOG_ERROR_INSTALL_FAILED, DIALOG_ERROR_INSTALL_FAILED },
    // the API is not supported on this device
    { CMR_DIALOG_ERROR_NOT_SUPPORTED, DIALOG_ERROR_NOT_SUPPORTED },
    // The input parameter is invalid
    { CMR_DIALOG_ERROR_PARAM_INVALID, PARAM_ERROR },
    // The device is not supported
    { CMR_DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED, DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED },
    // The device has no available cert
    { CMR_DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE, DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE },

    { CMR_DIALOG_ERROR_PARSE_CERT_FAILED, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_ADVANCED_SECURITY, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_INCORRECT_FORMAT, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_MAX_QUANTITY_REACHED, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_SA_INTERNAL_ERROR, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_NOT_EXIST, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_NOT_ENTERPRISE_DEVICE, DIALOG_ERROR_NOT_COMPLY_SECURITY_POLICY },
};

static const std::unordered_map<int32_t, std::string> DIALOG_CODE_TO_MSG_MAP = {
    { CMR_DIALOG_ERROR_PERMISSION_DENIED, DIALOG_NO_PERMISSION_MSG },
    { CMR_DIALOG_ERROR_INTERNAL, DIALOG_GENERIC_MSG },
    { CMR_DIALOG_ERROR_OPERATION_CANCELS, DIALOG_OPERATION_CANCELS_MSG },
    { CMR_DIALOG_ERROR_INSTALL_FAILED, DIALOG_INSTALL_FAILED_MSG },
    { CMR_DIALOG_ERROR_NOT_SUPPORTED, DIALOG_NOT_SUPPORTED_MSG },
    { CMR_DIALOG_ERROR_NOT_ENTERPRISE_DEVICE, NOT_ENTERPRISE_DEVICE_MSG },
    { CMR_DIALOG_ERROR_PARAM_INVALID, DIALOG_INVALID_PARAMS_MSG },
    { CMR_DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED, CAPABILITY_NOT_SUPPORTED_MSG},
    { CMR_DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE, NO_AVAILABLE_CERTIFICATE_MSG},

    { CMR_DIALOG_ERROR_PARSE_CERT_FAILED, DIALOG_OPERATION_FAILED_MSG + PARSE_CERT_FAILED_MSG },
    { CMR_DIALOG_ERROR_ADVANCED_SECURITY, DIALOG_OPERATION_FAILED_MSG + ADVANCED_SECURITY_MSG },
    { CMR_DIALOG_ERROR_INCORRECT_FORMAT, DIALOG_OPERATION_FAILED_MSG + INCORRECT_FORMAT_MSG },
    { CMR_DIALOG_ERROR_MAX_QUANTITY_REACHED, DIALOG_OPERATION_FAILED_MSG + MAX_QUANTITY_REACHED_MSG },
    { CMR_DIALOG_ERROR_SA_INTERNAL_ERROR, DIALOG_OPERATION_FAILED_MSG + SA_INTERNAL_ERROR_MSG },
    { CMR_DIALOG_ERROR_NOT_EXIST, DIALOG_OPERATION_FAILED_MSG + NOT_EXIST_MSG },
};

int32_t GetCallerLabelName(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext,
    std::string &labelName);
}  // namespace
#endif