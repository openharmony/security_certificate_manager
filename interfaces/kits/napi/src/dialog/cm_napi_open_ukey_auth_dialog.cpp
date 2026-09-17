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

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_metrics.h"
#include "cm_ukey_ability_type.h"
#include "cm_ukey_dialog_common.h"
#include "cm_napi_dialog_common.h"
#include "cm_napi_dialog_callback_void.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

namespace CMNapi {
using OHOS::Security::CertManager::CM_UKEY_SCENE_LOGIN_STR;
using OHOS::Security::CertManager::CM_UKEY_SCENE_CUSTOM_STR;
using OHOS::Security::CertManager::CM_UKEY_ABILITY_NAME_MAX_LEN;
using OHOS::Security::AccessToken::AccessTokenID;

/* Result context kept alive from the CmOpenUkeyAuthDialog call until the
 * promise is settled on the JS thread; ownership is handed to the threadsafe
 * function finalizer. */
struct CmUkeyAuthResultContext {
    napi_env env = nullptr;
    napi_deferred deferred = nullptr;
    napi_threadsafe_function tsfn = nullptr;
    int32_t resultCode = 0;
    /* D8 修订：老接口（argc==2）委托 SA 会话时不向已发布 throws 面新增
     * since-26 错误码，-1017/-1018 在此标记下折叠为 29700002/29700003 */
    bool legacyOverload = false;
    std::shared_ptr<OHOS::Security::CertManager::CmMetricsReport> metricsReport = nullptr;
};

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
    /* blob carries the terminating zero; SA rejects keyUri longer than
     * MAX_LEN_URI, validate here so the caller reports 29700006 instead of
     * the unmapped generic error */
    if (asyncContext->certUri->size > MAX_LEN_URI + 1) {
        CM_LOG_E("keyUri is too long, max length: %d", MAX_LEN_URI);
        return nullptr;
    }

    /* optional timeoutDuration (ms): absent/undefined keeps 0 (= server default 300s);
     * present but non-number is a parameter error */
    bool hasTimeout = false;
    status = napi_has_named_property(asyncContext->env, arg, "timeoutDuration", &hasTimeout);
    if (status == napi_ok && hasTimeout) {
        napi_value timeoutValue = nullptr;
        status = napi_get_named_property(asyncContext->env, arg, "timeoutDuration", &timeoutValue);
        if (status == napi_ok && timeoutValue != nullptr) {
            napi_valuetype timeoutType = napi_undefined;
            if (napi_typeof(asyncContext->env, timeoutValue, &timeoutType) == napi_ok &&
                timeoutType != napi_undefined && timeoutType != napi_null) {
                if (timeoutType != napi_number) {
                    CM_LOG_E("type of param timeout is not number");
                    return nullptr;
                }
                double timeoutDouble = 0;
                if (napi_get_value_double(asyncContext->env, timeoutValue, &timeoutDouble) != napi_ok ||
                    timeoutDouble < 0 || timeoutDouble > UINT32_MAX) {
                    CM_LOG_E("invalid timeout value");
                    return nullptr;
                }
                asyncContext->authTimeoutMs = static_cast<uint32_t>(timeoutDouble);
            }
        }
    }
    /* optional scene (D9/D11): absent/undefined/null keeps LOGIN; present value must be
     * exactly 'Login' or 'Custom' (case sensitive), otherwise a parameter error */
    bool hasScene = false;
    status = napi_has_named_property(asyncContext->env, arg, "scene", &hasScene);
    if (status == napi_ok && hasScene) {
        napi_value sceneValue = nullptr;
        status = napi_get_named_property(asyncContext->env, arg, "scene", &sceneValue);
        if (status == napi_ok && sceneValue != nullptr) {
            napi_valuetype sceneType = napi_undefined;
            if (napi_typeof(asyncContext->env, sceneValue, &sceneType) == napi_ok &&
                sceneType != napi_undefined && sceneType != napi_null) {
                if (sceneType != napi_string) {
                    CM_LOG_E("type of param scene is not string");
                    return nullptr;
                }
                char sceneBuf[16] = { 0 };
                size_t copied = 0;
                if (napi_get_value_string_utf8(asyncContext->env, sceneValue, sceneBuf,
                    sizeof(sceneBuf), &copied) != napi_ok) {
                    CM_LOG_E("scene value too long or invalid");
                    return nullptr;
                }
                std::string sceneStr(sceneBuf, copied);
                if (sceneStr == CM_UKEY_SCENE_LOGIN_STR) {
                    asyncContext->authScene = CM_UKEY_AUTH_SCENE_LOGIN;
                } else if (sceneStr == CM_UKEY_SCENE_CUSTOM_STR) {
                    asyncContext->authScene = CM_UKEY_AUTH_SCENE_CUSTOM;
                } else {
                    CM_LOG_E("scene is not a valid UkeyAuthScene value");
                    return nullptr;
                }
            }
        }
    }

    /* optional customData (D19): absent/undefined/null keeps none; must be a
     * Uint8Array of at most 2048 raw bytes */
    bool hasCustomData = false;
    status = napi_has_named_property(asyncContext->env, arg, "customData", &hasCustomData);
    if (status == napi_ok && hasCustomData) {
        napi_value customDataValue = nullptr;
        status = napi_get_named_property(asyncContext->env, arg, "customData", &customDataValue);
        if (status == napi_ok && customDataValue != nullptr) {
            napi_valuetype customDataType = napi_undefined;
            if (napi_typeof(asyncContext->env, customDataValue, &customDataType) == napi_ok &&
                customDataType != napi_undefined && customDataType != napi_null) {
                napi_typedarray_type arrayType = napi_int8_array;
                size_t length = 0;
                void *data = nullptr;
                if (napi_get_typedarray_info(asyncContext->env, customDataValue, &arrayType,
                    &length, &data, nullptr, nullptr) != napi_ok || arrayType != napi_uint8_array) {
                    CM_LOG_E("type of param customData is not Uint8Array");
                    return nullptr;
                }
                if (length > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
                    CM_LOG_E("customData is too long, max: %d", CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE);
                    return nullptr;
                }
                if (length > 0) {
                    asyncContext->authCustomData = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
                    if (asyncContext->authCustomData == nullptr) {
                        CM_LOG_E("alloc customData blob failed");
                        return nullptr;
                    }
                    asyncContext->authCustomData->data = static_cast<uint8_t *>(CmMalloc(length));
                    if (asyncContext->authCustomData->data == nullptr) {
                        CM_FREE_PTR(asyncContext->authCustomData);
                        CM_LOG_E("alloc customData buffer failed");
                        return nullptr;
                    }
                    if (memcpy_s(asyncContext->authCustomData->data, length, data, length) != EOK) {
                        CM_FREE_PTR(asyncContext->authCustomData->data);
                        CM_FREE_PTR(asyncContext->authCustomData);
                        CM_LOG_E("copy customData failed");
                        return nullptr;
                    }
                    asyncContext->authCustomData->size = static_cast<uint32_t>(length);
                }
            }
        }
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

// Validate that argc equals PARAM_SIZE_ONE (new SA-path overload) or
// PARAM_SIZE_TWO (legacy ability-context overload) and emit ThrowError if not.
static bool CheckUkeyAuthDialogArgc(napi_env env, size_t argc,
    OHOS::Security::CertManager::CmMetricsReport *report)
{
    if (argc == PARAM_SIZE_ONE || argc == PARAM_SIZE_TWO) {
        return true;
    }
    CM_LOG_E("params number mismatch");
    std::string errMsg = "Parameter Error. Params number mismatch, need " +
        std::to_string(PARAM_SIZE_ONE) + " or " + std::to_string(PARAM_SIZE_TWO) +
        ", given " + std::to_string(argc);
    ThrowError(env, PARAM_ERROR, errMsg, report);
    return false;
}

static void UvTsfnFinalize(napi_env env, void *finalizeData, void *finalizeHint)
{
    (void)env;
    (void)finalizeHint;
    delete static_cast<CmUkeyAuthResultContext *>(finalizeData);
}

// fold -1017/-1018 to 29700002/29700003 for the legacy overload (D8 修订)
static napi_value GenerateUkeyResultError(napi_env env, int32_t resultCode, bool legacyOverload,
    OHOS::Security::CertManager::CmMetricsReport *metricsReport);

// JS-thread callback invoked through the threadsafe function: settle the
// promise exactly once with the dialog result delivered by the SA.
static void UvTsfnCallback(napi_env env, napi_value jsCallback, void *context, void *data)
{
    (void)jsCallback;
    (void)context;
    auto resultContext = static_cast<CmUkeyAuthResultContext *>(data);
    if (resultContext == nullptr || env == nullptr) {
        // env == nullptr means the environment is tearing down: nothing left
        // to settle, the finalizer releases the context.
        return;
    }

    if (resultContext->resultCode == CM_SUCCESS) {
        if (resultContext->metricsReport != nullptr) {
            resultContext->metricsReport->Finish(CM_SUCCESS);
        }
        napi_value undefined = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, resultContext->deferred, undefined));
    } else {
        napi_value error = GenerateUkeyResultError(env, resultContext->resultCode,
            resultContext->legacyOverload, resultContext->metricsReport.get());
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, resultContext->deferred, error));
    }
    // The result is delivered exactly once per open call (inner API contract),
    // so the threadsafe function can be released right after settling.
    napi_release_threadsafe_function(resultContext->tsfn, napi_tsfn_release);
}

// C callback running on an IPC thread: marshal the result code to the JS
// thread through the threadsafe function.
static void UkeyAuthDialogResultCallback(int32_t resultCode, void *userData)
{
    auto resultContext = static_cast<CmUkeyAuthResultContext *>(userData);
    if (resultContext == nullptr) {
        return;
    }
    resultContext->resultCode = resultCode;
    napi_status status = napi_call_threadsafe_function(resultContext->tsfn, resultContext,
        napi_tsfn_blocking);
    if (status != napi_ok) {
        CM_LOG_E("call threadsafe function failed, status = %d", static_cast<int32_t>(status));
        napi_release_threadsafe_function(resultContext->tsfn, napi_tsfn_release);
    }
}

/* D8 修订：老接口（argc==2）委托 SA 会话后可能产生 -1017/-1018。老接口 since-22
 * 已发布，不新增 since-26 错误码至其 throws 面——超时折叠 29700002、单飞折叠
 * 29700003，错误消息保留具体原因（超时未上报 / 已有挂起会话）。 */
static bool IsLegacyFoldCode(int32_t resultCode)
{
    return resultCode == CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT ||
        resultCode == CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
}

static napi_value GenerateLegacyFoldedBusinessError(napi_env env, int32_t resultCode,
    OHOS::Security::CertManager::CmMetricsReport *metricsReport)
{
    int32_t jsCode = DIALOG_ERROR_GENERIC;
    const std::string *msg = &DIALOG_GENERIC_MSG;
    if (resultCode == CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT) {
        jsCode = DIALOG_ERROR_OPERATION_CANCELED; /* 29700002 */
        msg = &UKEY_AUTH_REPORT_TIMEOUT_MSG;
    } else if (resultCode == CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS) {
        jsCode = DIALOG_ERROR_INSTALL_FAILED; /* 29700003 */
        msg = &UKEY_DIALOG_IN_PROGRESS_MSG;
    }

    napi_value code = nullptr;
    NAPI_CALL(env, napi_create_int32(env, jsCode, &code));
    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg->c_str(), NAPI_AUTO_LENGTH, &message));
    napi_value businessError = nullptr;
    NAPI_CALL(env, napi_create_error(env, nullptr, message, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, BUSINESS_ERROR_PROPERTY_CODE.c_str(), code));
    if (metricsReport != nullptr) {
        metricsReport->Finish(jsCode);
    }
    return businessError;
}

static napi_value GenerateUkeyResultError(napi_env env, int32_t resultCode, bool legacyOverload,
    OHOS::Security::CertManager::CmMetricsReport *metricsReport)
{
    if (legacyOverload && IsLegacyFoldCode(resultCode)) {
        return GenerateLegacyFoldedBusinessError(env, resultCode, metricsReport);
    }
    return GenerateBusinessError(env, resultCode, metricsReport);
}

// argc == PARAM_SIZE_ONE overload: no caller ability context, the dialog is
// driven by the SA-side ukey session and the final result arrives
// asynchronously on an IPC thread. legacyOverload marks calls delegated from
// the argc == 2 overload (error-code folding, D8 修订).
static napi_value OpenUkeyAuthDialogNoContext(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    OHOS::Security::CertManager::CmMetricsReport &&report, bool legacyOverload = false)
{
    napi_env env = asyncContext->env;
    napi_value result = nullptr;
    napi_deferred deferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &result));

    auto resultContext = new (std::nothrow) CmUkeyAuthResultContext();
    if (resultContext == nullptr) {
        CM_LOG_E("alloc ukey auth result context failed");
        napi_value error = GenerateBusinessError(env, DIALOG_ERROR_GENERIC, &report);
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        return result;
    }
    resultContext->env = env;
    resultContext->deferred = deferred;
    resultContext->legacyOverload = legacyOverload;
    resultContext->metricsReport =
        std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(std::move(report));

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "CmUkeyAuthDialogResult", NAPI_AUTO_LENGTH,
        &resourceName));
    napi_status status = napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 0, 1,
        resultContext, UvTsfnFinalize, resultContext, UvTsfnCallback, &resultContext->tsfn);
    if (status != napi_ok) {
        CM_LOG_E("create threadsafe function failed, status = %d", static_cast<int32_t>(status));
        napi_value error = GenerateBusinessError(env, DIALOG_ERROR_GENERIC,
            resultContext->metricsReport.get());
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        delete resultContext;
        return result;
    }

    // the keyUri blob is consumed synchronously inside CmOpenUkeyAuthDialog,
    // so asyncContext->certUri only needs to live until the call returns
    struct UkeyAuthRequest ukeyAuthRequest = {};
    ukeyAuthRequest.keyUri.size = asyncContext->certUri->size;
    ukeyAuthRequest.keyUri.data = asyncContext->certUri->data;
    ukeyAuthRequest.timeoutDuration = asyncContext->authTimeoutMs;
    ukeyAuthRequest.scene = asyncContext->authScene;
    if (asyncContext->authCustomData != nullptr) {
        ukeyAuthRequest.customData.size = asyncContext->authCustomData->size;
        ukeyAuthRequest.customData.data = asyncContext->authCustomData->data;
    }
    int32_t ret = CmOpenUkeyAuthDialog(&ukeyAuthRequest, UkeyAuthDialogResultCallback, resultContext);
    if (ret != CM_SUCCESS) {
        // sync failure: the result callback never fires (inner API contract),
        // so settle the promise here and drop the threadsafe function
        CM_LOG_E("open ukey auth dialog failed, ret = %d", ret);
        napi_value error = GenerateUkeyResultError(env, ret, legacyOverload,
            resultContext->metricsReport.get());
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        napi_release_threadsafe_function(resultContext->tsfn, napi_tsfn_release);
    }
    return result;
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
    if (argc == PARAM_SIZE_TWO && !ParseCmUIAbilityContextReq(asyncContext->env, argv[0],
        asyncContext->context)) {
        CM_LOG_E("parse abilityContext failed");
        ThrowError(env, PARAM_ERROR, "parse abilityContext failed", &report);
        return nullptr;
    }
    napi_value requestArg = argv[argc - 1];
    if (IsParamNull(asyncContext->env, requestArg)) {
        ThrowError(env, PARAM_ERROR, "UkeyAuthRequest is null", &report);
        return nullptr;
    }
    if (GetUkeyAuthRequest(asyncContext, requestArg) == nullptr) {
        CM_LOG_E("parse UkeyAuthRequest failed");
        ThrowError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "parse UkeyAuthRequest failed", &report);
        return nullptr;
    }
    if (argc == PARAM_SIZE_ONE) {
        // new overload: always go through the SA-side session
        return OpenUkeyAuthDialogNoContext(asyncContext, std::move(report));
    }

    // argc == PARAM_SIZE_TWO (legacy overload): branch by the registered ability
    // type (spec §4.1) — UIExtensionAbility registrations take the SA-side
    // session path (error codes folded per D8 修订); UIAbility / unregistered
    // keep the legacy direct-launch flow below, with scene + customData
    // (base64) added to the custom-dialog want (D9/D18).
    {
        std::string driverBundle;
        std::string driverAbility;
        uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
        int32_t queryRet = GetUkeyAbilityInfo(asyncContext->certUri, driverBundle, driverAbility,
            abilityType);
        if (queryRet == CM_SUCCESS && abilityType == CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
            CM_LOG_I("ukey driver registered a UIExtensionAbility pin dialog, go sa session path");
            return OpenUkeyAuthDialogNoContext(asyncContext, std::move(report), true);
        }
        if (queryRet != CM_SUCCESS && asyncContext->authScene == CM_UKEY_AUTH_SCENE_CUSTOM) {
            // rule 3: Custom scene with nothing registered, sync reject (29700003, no IPC)
            ThrowError(env, DIALOG_ERROR_INSTALL_FAILED,
                UKEY_DEFAULT_NOT_SUPPORTED_MSG, &report);
            return nullptr;
        }
        if (queryRet == CM_SUCCESS && abilityType == CM_UKEY_ABILITY_TYPE_UIABILITY) {
            // spec v4: no-context interface does not support UIAbility dialogs (29700003)
            ThrowError(env, DIALOG_ERROR_INSTALL_FAILED,
                UKEY_UIABILITY_NOT_SUPPORTED_MSG, &report);
            return nullptr;
        }
    }

    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    auto reportHolder = std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(std::move(report));
    asyncContext->metricsReport = reportHolder;
    auto uiExtCallback = std::make_shared<CmUIExtensionVoidCallback>(asyncContext);
    OHOS::AAFwk::Want want{};
    int32_t ret = GetCustomerAuthCertWant(asyncContext->certUri, asyncContext->authScene,
        asyncContext->authCustomData, want);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get customer auth cert want failed. ret = %d", ret);
        ThrowError(env, DIALOG_ERROR_GENERIC, "get customer auth cert want failed.", reportHolder.get());
        return nullptr;
    }
    StartUkeyPinAbility(asyncContext, want, uiExtCallback);

    CM_LOG_I("cert authorize dialog end");
    return result;
}

/* CRYPTO_EXTENSION_REGISTER 进程内预检（spec v4 D23：失败同步 201） */
static bool CheckUkeyDriverPermission(void)
{
    AccessTokenID tokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    return OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        tokenId, "ohos.permission.CRYPTO_EXTENSION_REGISTER") == 0 /* PERMISSION_GRANTED */;
}

/* ForDriver 的 SA 路径 promise 包装：错误码不折叠（29700009/29700010 直通，D8 v4） */
static napi_value OpenAuthDialogForUkeyDriverViaSa(
    std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    OHOS::Security::CertManager::CmMetricsReport &&report, std::string abilityName,
    uint32_t abilityType)
{
    napi_env env = asyncContext->env;
    napi_value result = nullptr;
    napi_deferred deferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &result));

    auto resultContext = new (std::nothrow) CmUkeyAuthResultContext();
    if (resultContext == nullptr) {
        CM_LOG_E("alloc ukey auth result context failed");
        napi_value error = GenerateBusinessError(env, DIALOG_ERROR_GENERIC, &report);
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        return result;
    }
    resultContext->env = env;
    resultContext->deferred = deferred;
    resultContext->legacyOverload = false; /* ForDriver：专属码直通 */
    resultContext->metricsReport =
        std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(std::move(report));

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "CmUkeyAuthDialogResult", NAPI_AUTO_LENGTH,
        &resourceName));
    napi_status status = napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 0, 1,
        resultContext, UvTsfnFinalize, resultContext, UvTsfnCallback, &resultContext->tsfn);
    if (status != napi_ok) {
        CM_LOG_E("create threadsafe function failed, status = %d", static_cast<int32_t>(status));
        napi_value error = GenerateBusinessError(env, DIALOG_ERROR_GENERIC,
            resultContext->metricsReport.get());
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        delete resultContext;
        return result;
    }

    struct UkeyAuthDialogInfo dialogInfo = {};
    dialogInfo.abilityName.size = static_cast<uint32_t>(abilityName.size() + 1); /* 含 NUL */
    dialogInfo.abilityName.data = reinterpret_cast<uint8_t *>(const_cast<char *>(abilityName.c_str()));
    dialogInfo.abilityType = abilityType;
    struct UkeyAuthRequest ukeyAuthRequest = {};
    ukeyAuthRequest.keyUri.size = asyncContext->certUri->size;
    ukeyAuthRequest.keyUri.data = asyncContext->certUri->data;
    ukeyAuthRequest.timeoutDuration = asyncContext->authTimeoutMs;
    if (asyncContext->authCustomData != nullptr) {
        ukeyAuthRequest.customData.size = asyncContext->authCustomData->size;
        ukeyAuthRequest.customData.data = asyncContext->authCustomData->data;
    }
    int32_t ret = CmOpenUkeyAuthDialogForDriver(&dialogInfo, &ukeyAuthRequest,
        UkeyAuthDialogResultCallback, resultContext);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open auth dialog for ukey driver failed, ret = %d", ret);
        napi_value error = GenerateBusinessError(env, ret, resultContext->metricsReport.get());
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        napi_release_threadsafe_function(resultContext->tsfn, napi_tsfn_release);
        return result;
    }
    return result;
}

/* UkeyAuthDialogInfo 解析（spec v4 D23/D24）：dialogInfo 非对象、abilityType 非数值
 * 或 ≠1 → 401；abilityName 非字符串 / 空串 / >128 字节 → 29700006 */
static int32_t GetUkeyDialogInfo(napi_env env, napi_value arg, uint32_t &abilityType,
    std::string &abilityName)
{
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, arg, &type) != napi_ok || type != napi_object) {
        return PARAM_ERROR;
    }
    napi_value abilityTypeValue = nullptr;
    if (napi_get_named_property(env, arg, "abilityType", &abilityTypeValue) != napi_ok ||
        abilityTypeValue == nullptr) {
        return PARAM_ERROR;
    }
    napi_valuetype abilityTypeType = napi_undefined;
    if (napi_typeof(env, abilityTypeValue, &abilityTypeType) != napi_ok ||
        abilityTypeType != napi_number) {
        return PARAM_ERROR;
    }
    double abilityTypeDouble = 0;
    if (napi_get_value_double(env, abilityTypeValue, &abilityTypeDouble) != napi_ok ||
        abilityTypeDouble != CM_UKEY_ABILITY_TYPE_UIEXTENSION) { /* 枚举唯一合法值 = 1 */
        return PARAM_ERROR;
    }
    abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;

    napi_value abilityNameValue = nullptr;
    if (napi_get_named_property(env, arg, "abilityName", &abilityNameValue) != napi_ok ||
        abilityNameValue == nullptr) {
        return DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    napi_valuetype abilityNameType = napi_undefined;
    if (napi_typeof(env, abilityNameValue, &abilityNameType) != napi_ok ||
        abilityNameType != napi_string) {
        return DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    char nameBuf[CM_UKEY_ABILITY_NAME_MAX_LEN + 1] = { 0 };
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, abilityNameValue, nameBuf, sizeof(nameBuf), &copied)
        != napi_ok || copied == 0) {
        return DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    abilityName.assign(nameBuf, copied);
    return CM_SUCCESS;
}

napi_value CMNapiOpenAuthDialogForUkeyDriver(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert open auth dialog for ukey driver enter");
    OHOS::Security::CertManager::CmMetricsReport report("openAuthDialogForUkeyDriver",
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
    if (argc != PARAM_SIZE_TWO) {
        ThrowError(env, PARAM_ERROR, "Parameter Error. Params number mismatch, need 2", &report);
        return result;
    }
    uint32_t abilityType = 0;
    std::string abilityName;
    int32_t dialogInfoErr = GetUkeyDialogInfo(env, argv[0], abilityType, abilityName);
    if (dialogInfoErr != CM_SUCCESS) {
        CM_LOG_E("parse UkeyAuthDialogInfo failed, err = %d", dialogInfoErr);
        ThrowError(env, dialogInfoErr, "parse UkeyAuthDialogInfo failed", &report);
        return result;
    }
    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    if (IsParamNull(env, argv[1])) {
        ThrowError(env, PARAM_ERROR, "UkeyAuthRequest is null", &report);
        return result;
    }
    if (GetUkeyAuthRequest(asyncContext, argv[1]) == nullptr) {
        CM_LOG_E("parse UkeyAuthRequest failed");
        ThrowError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "parse UkeyAuthRequest failed",
            &report);
        return result;
    }
    if (!CheckUkeyDriverPermission()) {
        CM_LOG_E("caller has no CRYPTO_EXTENSION_REGISTER permission");
        ThrowError(env, HAS_NO_PERMISSION, DIALOG_NO_PERMISSION_MSG, &report);
        return result;
    }
    return OpenAuthDialogForUkeyDriverViaSa(asyncContext, std::move(report),
        std::move(abilityName), abilityType);
}
}  // namespace CMNapi
