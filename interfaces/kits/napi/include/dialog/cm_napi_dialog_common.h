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

#ifndef CM_NAPI_DIALOG_COMMON_H
#define CM_NAPI_DIALOG_COMMON_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "cm_napi_dialog_callback.h"

#include "cm_napi_open_dialog.h"
#include "cm_mem.h"
#include "cm_type.h"

namespace CMNapi {

static const std::string BUSINESS_ERROR_PROPERTY_CODE = "code";
static const std::string BUSINESS_ERROR_PROPERTY_MESSAGE = "message";
static const int32_t RESULT_NUMBER = 2;

void StartUIExtensionAbility(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    OHOS::AAFwk::Want want, std::shared_ptr<CmUIExtensionCallback> uiExtCallback);
bool ParseCmUIAbilityContextReq(
    napi_env env, const napi_value& obj, std::shared_ptr<OHOS::AbilityRuntime::AbilityContext>& abilityContext);
napi_value ParseUint32(napi_env env, napi_value object, uint32_t &store);
napi_value ParseBoolean(napi_env env, napi_value object, bool &status);
napi_value ParseString(napi_env env, napi_value object, CmBlob *&blob);
napi_value GetUint8ArrayToBase64Str(napi_env env, napi_value object, std::string &certArray);
napi_value GetCertTypeArray(napi_env env, napi_value object, std::vector<int32_t> &certTypes);

void ThrowError(napi_env env, int32_t errorCode, const std::string errMsg);
napi_value GenerateBusinessError(napi_env env, int32_t errorCode);

void GeneratePromise(napi_env env, napi_deferred deferred, int32_t resultCode,
    napi_value *result, int32_t length);
int32_t GetCallerLabelName(std::shared_ptr<CmUIExtensionRequestContext> asyncContext);

bool IsParamNull(napi_env env, napi_value obj);

inline napi_value GetInt32(napi_env env, int32_t value)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &result));
    return result;
}

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
    CA_CERT = 1,
    CREDENTIAL_USER = 2, // private type
    CREDENTIAL_APP = 3, // app type
    CREDENTIAL_UKEY = 4, // ukey type
    CREDENTIAL_SYSTEM = 5,
    CREDENTIAL_INVLAID_TYPE, // invalid type
};

enum CertificateScope {
    NOT_SPECIFIED = 0,
    CURRENT_USER = 1,
    GLOBAL_USER = 2
};

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

enum OperationType {
    DIALOG_OPERATION_INSTALL = 1,
    DIALOG_OPERATION_UNINSTALL = 2,
    DIALOG_OPERATION_DETAIL = 3,
    DIALOG_OPERATION_AUTHORIZE = 4,
    DIALOG_OPERATION_AUTHORIZE_UKEY = 5,
};
}  // namespace CertManagerNapi

#endif
