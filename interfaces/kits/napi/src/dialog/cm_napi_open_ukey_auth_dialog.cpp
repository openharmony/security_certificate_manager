/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include <memory>

#include "cm_log.h"
#include "cm_metrics.h"
#include "cm_napi_dialog_common.h"
#include "cm_napi_dialog_callback_void.h"

namespace CMNapi {
static napi_value GetUkeyAuthRequest(std::shared_ptr<CmUIExtensionRequestContext> asyncContext, napi_value arg)
{
    bool hasProperty = false;
    napi_status status = napi_has_named_property(asyncContext->env, arg, CERT_MANAGER_CERT_KEY_URI.c_str(),
        &hasProperty);
    if (status != napi_ok || !hasProperty) {
        CM_LOG_E("Failed to check keyUri");
        return nullptr;
    }

    napi_value value = nullptr;
    status = napi_get_named_property(asyncContext->env, arg, CERT_MANAGER_CERT_KEY_URI.c_str(),
        &value);
    if (status != napi_ok || value == nullptr) {
        CM_LOG_E("Failed to get keyUri");
        return nullptr;
    }

    napi_valuetype type = napi_undefined;
    NAPI_CALL(asyncContext->env, napi_typeof(asyncContext->env, value, &type));
    if (type != napi_string) {
        CM_LOG_E("type of param ukeyIndex is not string");
        return nullptr;
    }

    int32_t result = ParseString(asyncContext->env, value, asyncContext->certUri);
    if (result != CM_SUCCESS) {
        CM_LOG_E("Failed to get certPurpose value");
        return nullptr;
    }
    return GetInt32(asyncContext->env, 0);
}

static void StartUkeyPinAbility(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    OHOS::AAFwk::Want& want, std::shared_ptr<CmUIExtensionCallback> uiExtCallback)
{
    std::string action = want.GetAction();
    if (action.empty() || action != ACTION_UKEY_PIN_AUTH) {
        StartUIExtensionAbility(asyncContext, want, uiExtCallback);
    } else {
        StartUIAbility(asyncContext, want, uiExtCallback);
    }
}

// Validate that argc equals the expected PARAM_SIZE_TWO and emit ThrowError if not.
static bool CheckUkeyAuthDialogArgc(napi_env env, size_t argc,
    OHOS::Security::CertManager::CmMetricsReport *report)
{
    if (argc == PARAM_SIZE_TWO) {
        return true;
    }
    CM_LOG_E("params number mismatch");
    std::string errMsg = "Parameter Error. Params number mismatch, need " +
        std::to_string(PARAM_SIZE_TWO) + ", given " + std::to_string(argc);
    ThrowError(env, PARAM_ERROR, errMsg, report);
    return false;
}

napi_value CMNapiOpenUkeyAuthorizeDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert ukey authorize dialog enter");
    OHOS::Security::CertManager::CmMetricsReport report("openUkeyAuthDialog",
        OHOS::Security::CertManager::CmMetricsKind::DIALOG);
    report.Start();
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    if (CheckSyscapReturnVoid(env, &result) != CM_SUCCESS) {
        report.Finish(DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED);
        return result;
    }

    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (!CheckUkeyAuthDialogArgc(env, argc, &report)) {
        return result;
    }
    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    if (!ParseCmUIAbilityContextReq(asyncContext->env, argv[0], asyncContext->context)) {
        CM_LOG_E("parse abilityContext failed");
        ThrowError(env, PARAM_ERROR, "parse abilityContext failed", &report);
        return nullptr;
    }
    if (IsParamNull(asyncContext->env, argv[1])) {
        ThrowError(env, PARAM_ERROR, "UkeyAuthRequest is null", &report);
        return nullptr;
    }
    if (GetUkeyAuthRequest(asyncContext, argv[1]) == nullptr) {
        CM_LOG_E("parse UkeyAuthRequest failed");
        ThrowError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "parse UkeyAuthRequest failed", &report);
        return nullptr;
    }
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    auto reportHolder = std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(std::move(report));
    asyncContext->metricsReport = reportHolder;
    auto uiExtCallback = std::make_shared<CmUIExtensionVoidCallback>(asyncContext);
    OHOS::AAFwk::Want want{};
    int32_t ret = GetCustomerAuthCertWant(asyncContext->certUri, want);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get customer auth cert want failed. ret = %d", ret);
        ThrowError(env, DIALOG_ERROR_GENERIC, "get customer auth cert want failed.", reportHolder.get());
        return nullptr;
    }
    StartUkeyPinAbility(asyncContext, want, uiExtCallback);

    CM_LOG_I("cert authorize dialog end");
    return result;
}
}  // namespace CMNapi
