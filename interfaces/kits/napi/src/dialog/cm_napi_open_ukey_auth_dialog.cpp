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

#include "cm_napi_open_ukey_auth_dialog.h"

#include "cm_log.h"
#include "cm_napi_dialog_common.h"
#include "cm_napi_dialog_callback_void.h"
 
namespace CMNapi {

static OHOS::AAFwk::Want CMGetAuthCertWant(std::shared_ptr<CmUIExtensionRequestContext> asyncContext)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_CALLER_BUNDLENAME, asyncContext->labelName);
    want.SetParam(CERT_MANAGER_CALLER_UID, asyncContext->appUid);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(CmDialogPageType::PAGE_UKEY_PIN_AUTHORIZE));
    CmBlob *ukeyCertIndex = asyncContext->ukeyCertIndex;
    std::string uriStr(reinterpret_cast<char *>(ukeyCertIndex->data), ukeyCertIndex->size);
    want.SetParam(CERT_MANAGER_CERT_UKEY_INDEX, uriStr);
    return want;
}

static napi_value GetUkeyAuthRequest(std::shared_ptr<CmUIExtensionRequestContext> asyncContext, napi_value arg)
{
    bool hasProperty = false;
    napi_status status = napi_has_named_property(asyncContext->env, arg, CERT_MANAGER_CERT_UKEY_INDEX.c_str(), &hasProperty);
    if (status != napi_ok || !hasProperty) {
        CM_LOG_E("Failed to check ukeyCertIndex");
        return nullptr;
    }

    napi_value value = nullptr;
    status = napi_get_named_property(asyncContext->env, arg, CERT_MANAGER_CERT_UKEY_INDEX.c_str(),
        &value);
    if (status != napi_ok || value == nullptr) {
        CM_LOG_E("Failed to get ukeyCertIndex");
        return nullptr;
    }

    napi_valuetype type = napi_undefined;
    NAPI_CALL(asyncContext->env, napi_typeof(asyncContext->env, value, &type));
    if (type != napi_string) {
        CM_LOG_E("type of param ukeyIndex is not string");
        return nullptr;
    }

    napi_value result = ParseString(asyncContext->env, value, asyncContext->ukeyCertIndex);
    if (result == nullptr) {
        CM_LOG_E("Failed to get certPurpose value");
        return nullptr;
    }
    return GetInt32(asyncContext->env, 0);
}

napi_value CMNapiOpenUkeyAuthorizeDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert ukey authorize dialog enter");
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));

    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != PARAM_SIZE_TWO) {
        CM_LOG_E("params number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need " + std::to_string(PARAM_SIZE_ONE)
            + ", given " + std::to_string(argc);
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
    asyncContext->opType = static_cast<int32_t>(DIALOG_OPERATION_AUTHORIZE_UKEY);
    if (GetUkeyAuthRequest(asyncContext, argv[index]) == nullptr) {
        CM_LOG_E("parse UkeyAuthRequest failed");
        ThrowError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "parse UkeyAuthRequest failed");
        return nullptr;
    }
    if (GetCallerLabelName(asyncContext) != CM_SUCCESS) {
        CM_LOG_E("get caller labelName faild");
        ThrowError(env, DIALOG_ERROR_GENERIC, "get caller labelName faild");
        return nullptr;
    }
    asyncContext->appUid = static_cast<int32_t>(getuid());
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    auto uiExtCallback = std::make_shared<CmUIExtensionVoidCallback>(asyncContext);
    StartUIExtensionAbility(asyncContext, CMGetAuthCertWant(asyncContext), uiExtCallback);

    CM_LOG_I("cert authorize dialog end");
    return result;
}
}  // namespace CMNapi