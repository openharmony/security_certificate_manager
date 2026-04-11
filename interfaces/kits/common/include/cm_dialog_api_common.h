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
static const std::string DIALOG_GENERIC_MSG = "There is an internal error. Possible causes: "
    "1.IPC communication failed. 2.Memory operation error.";
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
static const std::string NO_AVAILABLE_CERTIFICATE_MSG = "no available certificate for authorization.";

static const std::string CERT_MGR_DIALOG_SYSCAP = "SystemCapability.Security.CertificateManagerDialog";
static const std::string CONST_NAME_DEVICETYPE = "const.product.devicetype";
static const std::string CONST_NAME_ENABLE_CA_DIALOG = "const.certManager.enableOpenCACertDialog";
static const std::string DEVICETYPE_PC = "2in1";

static const std::string CERT_MANAGER_BUNDLENAME = "com.ohos.certmanager";
static const std::string CERT_MANAGER_ABILITYNAME = "CertPickerUIExtAbility";
static const std::string CERT_MANAGER_CALLER_UID = "appUid";
static const std::string PARAM_UI_EXTENSION_TYPE = "ability.want.params.uiExtensionType";
static const std::string SYS_COMMON_UI = "sys/commonUI";
static const std::string CERT_MANAGER_PAGE_TYPE = "pageType";
static const std::string CERT_MANAGER_CERT_KEY_URI = "keyUri";
static const std::string CERT_MANAGER_CERTSCOPE_TYPE = "certScope";
static const std::string CERT_MANAGER_CERTIFICATE_DATA = "cert";
static const std::string CERT_MANAGER_CALLER_BUNDLENAME = "bundleName";
static const std::string CERT_MANAGER_CERT_URI = "certUri";
static const std::string CERT_MANAGER_OPERATION_TYPE = "operationType";
static const std::string CERT_MANAGER_SHOW_INSTALL_BUTTON = "showInstallButton";
static const std::string CERT_MANAGER_CERT_TYPE = "certType";
static const std::string CERT_MANAGER_CERT_TYPES = "certTypes";
static const std::string CERT_MANAGER_CERT_PURPOSE = "certPurpose";
static const std::string CERT_MANAGER_KEY_ALG_IDS = "keyAlgIDs";
static const std::string CERT_MANAGER_ISSUERS = "issuers";
static const std::string CERT_MANAGER_SERVER_URL = "uri";
static const std::string ACTION_UKEY_PIN_AUTH = "UkeyPINAuth";

constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr int32_t PARAM3 = 3;
constexpr int32_t PARAM_SIZE_ONE = 1;
constexpr int32_t PARAM_SIZE_TWO = 2;
constexpr int32_t PARAM_SIZE_THREE = 3;
constexpr int32_t PARAM_SIZE_FOUR = 4;

enum CmDialogPageType {
    PAGE_MAIN = 1,
    PAGE_CA_CERTIFICATE = 2,
    PAGE_CREDENTIAL = 3,
    PAGE_INSTALL_CERTIFICATE = 4,
    PAGE_INSTALL_CA_GUIDE = 5,
    PAGE_REQUEST_AUTHORIZE = 6,
    PAGE_UKEY_PIN_AUTHORIZE = 7,
};

enum CmCertificateType {
    CREDENTIAL_INVALID_TYPE = 0, // invalid type
    CA_CERT = 1,
    CREDENTIAL_USER = 2, // private type
    CREDENTIAL_APP = 3, // app type
    CREDENTIAL_UKEY = 4, // ukey type
    CREDENTIAL_SYSTEM = 5, // system cred type
};

enum CertificateScope {
    NOT_SPECIFIED = 0,
    CURRENT_USER = 1,
    GLOBAL_USER = 2
};

enum OperationType {
    DIALOG_OPERATION_INSTALL = 1,
    DIALOG_OPERATION_UNINSTALL = 2,
    DIALOG_OPERATION_DETAIL = 3,
    DIALOG_OPERATION_AUTHORIZE = 4,
    DIALOG_OPERATION_AUTHORIZE_UKEY = 5,
};

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
    { CMR_DIALOG_ERROR_NO_PARAMETER_VALIDATION_FAILED, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED },
};

static const std::unordered_map<int32_t, std::string> DIALOG_CODE_TO_MSG_MAP = {
    { CMR_DIALOG_ERROR_PERMISSION_DENIED, DIALOG_NO_PERMISSION_MSG },
    { CMR_DIALOG_ERROR_INTERNAL, DIALOG_GENERIC_MSG },
    { CMR_DIALOG_ERROR_OPERATION_CANCELS, DIALOG_OPERATION_CANCELS_MSG },
    { CMR_DIALOG_ERROR_INSTALL_FAILED, DIALOG_INSTALL_FAILED_MSG },
    { CMR_DIALOG_ERROR_NOT_SUPPORTED, DIALOG_NOT_SUPPORTED_MSG },
    { CMR_DIALOG_ERROR_NOT_ENTERPRISE_DEVICE, NOT_ENTERPRISE_DEVICE_MSG },
    { CMR_DIALOG_ERROR_PARAM_INVALID, DIALOG_INVALID_PARAMS_MSG },
    { CMR_DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED, CAPABILITY_NOT_SUPPORTED_MSG },
    { CMR_DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE, NO_AVAILABLE_CERTIFICATE_MSG },

    { CMR_DIALOG_ERROR_PARSE_CERT_FAILED, DIALOG_OPERATION_FAILED_MSG + PARSE_CERT_FAILED_MSG },
    { CMR_DIALOG_ERROR_ADVANCED_SECURITY, DIALOG_OPERATION_FAILED_MSG + ADVANCED_SECURITY_MSG },
    { CMR_DIALOG_ERROR_INCORRECT_FORMAT, DIALOG_OPERATION_FAILED_MSG + INCORRECT_FORMAT_MSG },
    { CMR_DIALOG_ERROR_MAX_QUANTITY_REACHED, DIALOG_OPERATION_FAILED_MSG + MAX_QUANTITY_REACHED_MSG },
    { CMR_DIALOG_ERROR_SA_INTERNAL_ERROR, DIALOG_OPERATION_FAILED_MSG + SA_INTERNAL_ERROR_MSG },
    { CMR_DIALOG_ERROR_NOT_EXIST, DIALOG_OPERATION_FAILED_MSG + NOT_EXIST_MSG },
    { CMR_DIALOG_ERROR_NO_PARAMETER_VALIDATION_FAILED, DIALOG_OPERATION_FAILED_MSG + DIALOG_INVALID_PARAMS_MSG },
};

int32_t GetCallerLabelName(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext,
    std::string &labelName);

bool IsEnableCACertDialog();

int32_t GetCustomerAuthCertWant(const CmBlob *keyUri, OHOS::AAFwk::Want &want);
}  // namespace
#endif