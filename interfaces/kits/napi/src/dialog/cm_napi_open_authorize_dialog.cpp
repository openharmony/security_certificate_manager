/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cm_napi_open_authorize_dialog.h"

#include "cm_log.h"
#include "cm_napi_dialog_common.h"
#include "cm_napi_dialog_callback_string.h"
#include "cm_napi_dialog_callback_cert_reference.h"
 
namespace CMNapi {

static OHOS::AAFwk::Want CMGetAuthCertWant(std::shared_ptr<CmUIExtensionRequestContext> asyncContext)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_CALLER_BUNDLENAME, asyncContext->labelName);
    want.SetParam(CERT_MANAGER_CALLER_UID, asyncContext->appUid);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(CmDialogPageType::PAGE_REQUEST_AUTHORIZE));
    if (!asyncContext->certTypes.empty()) {
        want.SetParam(CERT_MANAGER_CERT_TYPES, asyncContext->certTypes);
    }
    if (asyncContext->certPurpose != 0 && asyncContext->certPurpose != CREDENTIAL_INVLAID_TYPE) {
        want.SetParam(CERT_MANAGER_CERT_PURPOSE, static_cast<int32_t>(asyncContext->certPurpose));
    }
    return want;
}

static int32_t GetCertTypes(napi_env env, napi_value arg, std::vector<int32_t> &certTypes)
{
    bool hasProperty = false;
    napi_status status = napi_has_named_property(env, arg, CERT_MANAGER_CERT_TYPES.c_str(), &hasProperty);
    if (status != napi_ok || !hasProperty) {
        CM_LOG_E("Failed to check certTypes");
        return CM_FAILURE;
    }

    napi_value value = nullptr;
    status = napi_get_named_property(env, arg, CERT_MANAGER_CERT_TYPES.c_str(), &value);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get certTypes");
        return CM_FAILURE;
    }

    napi_value result = GetCertTypeArray(env, value, certTypes);
    if (result == nullptr) {
        CM_LOG_E("Failed to get certTypes value");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

static int32_t GetCertPurpose(napi_env env, napi_value arg, uint32_t &certPurpose)
{
    bool hasProperty = false;
    napi_value value = nullptr;
    
    napi_status status = napi_has_named_property(env, arg, CERT_MANAGER_CERT_PURPOSE.c_str(), &hasProperty);
    if (status != napi_ok) {
        CM_LOG_E("Failed to check certPurpose");
        return CM_FAILURE;
    }
    if (!hasProperty) {
        certPurpose = CREDENTIAL_INVLAID_TYPE;
        return CM_SUCCESS;
    }

    status = napi_get_named_property(env, arg, CERT_MANAGER_CERT_PURPOSE.c_str(), &value);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get certPurpose");
        return CM_FAILURE;
    }

    napi_value result = ParseUint32(env, value, certPurpose);
    if (result == nullptr) {
        CM_LOG_E("Failed to get certPurpose value");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

static int32_t GetAuthorizeRequest(std::shared_ptr<CmUIExtensionRequestContext> asyncContext, napi_value arg)
{
    int32_t ret = GetCertTypes(asyncContext->env, arg, asyncContext->certTypes);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get property certTypes failed");
        return CM_FAILURE;
    }

    ret = GetCertPurpose(asyncContext->env, arg, asyncContext->certPurpose);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get property certPurpose failed");
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

static int32_t CheckAndGetAuthorizeRequest(std::shared_ptr<CmUIExtensionRequestContext> asyncContext, napi_value arg)
{
    if (!IsParamNotNull(asyncContext->env, arg)) {
        ThrowError(env, PARAM_ERROR, "AuthorizeRequest is null");
        return PARAM_ERROR;
    }
    asyncContext->opType = static_cast<int32_t>(DIALOG_OPERATION_AUTHORIZE_UKEY);
    if (GetAuthorizeRequest(asyncContext, arg) != CM_SUCCESS) {
        CM_LOG_E("parse AuthorizeRequest failed");
        ThrowError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "parse AuthorizeRequest failed");
        return DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    return CM_SUCCESS;
}

napi_value CMNapiOpenAuthorizeDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert authorize dialog enter");
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != PARAM_SIZE_ONE && argc != PARAM_SIZE_TWO) {
        CM_LOG_E("params number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need " + std::to_string(PARAM_SIZE_ONE)
            + " or" + std::to_string(PARAM_SIZE_TWO) + ", given " + std::to_string(argc);
        ThrowError(env, PARAM_ERROR, errMsg);
        return result;
    }
    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    asyncContext->opType = static_cast<int32_t>(DIALOG_OPERATION_AUTHORIZE);
    size_t index = 0;
    if (!ParseCmUIAbilityContextReq(asyncContext->env, argv[index], asyncContext->context)) {
        CM_LOG_E("parse abilityContext failed");
        ThrowError(env, PARAM_ERROR, "parse abilityContext failed");
        return nullptr;
    }
    ++index;
    if (index < argc) {
        asyncContext->opType = static_cast<int32_t>(DIALOG_OPERATION_AUTHORIZE_UKEY);
        if (CheckAndGetAuthorizeRequest(asyncContext, argv[index]) != CM_SUCCESS) {
            CM_LOG_E("parse AuthorizeRequest failed");
            return nullptr;
        }
    }
    if (GetCallerLabelName(asyncContext) != CM_SUCCESS) {
        CM_LOG_E("get caller labelName faild");
        ThrowError(env, DIALOG_ERROR_GENERIC, "get caller labelName faild");
        return nullptr;
    }
    asyncContext->appUid = static_cast<int32_t>(getuid());
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    if (argc == PARAM_SIZE_ONE) {
        auto uiExtCallback = std::make_shared<CmUIExtensionStringCallback>(asyncContext);
        StartUIExtensionAbility(asyncContext, CMGetAuthCertWant(asyncContext), uiExtCallback);
    } else if (argc == PARAM_SIZE_TWO) {
        auto uiExtCallback = std::make_shared<CmUIExtensionCertReferenceCallback>(asyncContext);
        StartUIExtensionAbility(asyncContext, CMGetAuthCertWant(asyncContext), uiExtCallback);
    }
    CM_LOG_I("cert authorize dialog end");
    return result;
}
}  // namespace CMNapi