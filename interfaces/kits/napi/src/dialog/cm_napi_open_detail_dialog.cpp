/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cm_napi_open_uninstall_dialog.h"

#include "cm_log.h"
#include "cm_napi_dialog_common.h"
#include "cm_napi_dialog_callback_void.h"

#include "securec.h"
#include "syspara/parameters.h"
#include "want.h"
#include "want_params_wrapper.h"

namespace CMNapi {
static int32_t GetInstallButtonState(napi_env env, napi_value arg, bool &showInstallButton)
{
    napi_value value = nullptr;
    napi_status status = napi_get_named_property(env, arg, CERT_MANAGER_SHOW_INSTALL_BUTTON.c_str(), &value);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get showInstallBotton");
        return CM_FAILURE;
    }

    napi_value result = ParseBoolean(env, value, showInstallButton);
    if (result == nullptr) {
        CM_LOG_E("Failed to get showInstallBotton value");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

static int32_t CheckDetailParamsAndInitContext(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    napi_value argv[], size_t length)
{
    /* parse context */
    bool parseRet = ParseCmUIAbilityContextReq(asyncContext->env, argv[PARAM0], asyncContext->context);
    if (!parseRet) {
        CM_LOG_E("ParseUIAbilityContextReq failed");
        return CM_FAILURE;
    }

    /* parse cert */
    napi_value value = GetUint8ArrayToBase64Str(asyncContext->env, argv[PARAM1], asyncContext->certStr);
    if (value == nullptr) {
        CM_LOG_E("cert is not a uint8Array or the length is 0 or too long.");
        return CM_FAILURE;
    }

    /* parse property */
    int32_t ret = GetInstallButtonState(asyncContext->env, argv[PARAM2], asyncContext->showInstallButton);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get property showInstallBotton failed");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

static OHOS::AAFwk::Want CMGetCertDetailWant(std::shared_ptr<CmUIExtensionRequestContext> asyncContext)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_CERTIFICATE_DATA, asyncContext->certStr);
    want.SetParam(CERT_MANAGER_OPERATION_TYPE, asyncContext->opType);
    want.SetParam(CERT_MANAGER_SHOW_INSTALL_BUTTON, asyncContext->showInstallButton);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(CmDialogPageType::PAGE_INSTALL_CA_GUIDE));
    return want;
}

napi_value CMNapiOpenDetailDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert open detail dialog enter");
    if (OHOS::system::GetParameter("const.product.devicetype", "") != "2in1") {
        CM_LOG_E("deviceType is not 2in1");
        ThrowError(env, DIALOG_ERROR_NOT_SUPPORTED, "DeviceType Error. deviceType is not 2in1");
        return nullptr;
    }

    size_t argc = PARAM_SIZE_THREE;
    napi_value argv[PARAM_SIZE_THREE] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok || argc != PARAM_SIZE_THREE) {
        CM_LOG_E("params number mismatch");
        ThrowError(env, PARAM_ERROR, "Parameter Error. Params number mismatch.");
        return nullptr;
    }

    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    asyncContext->env = env;
    asyncContext->opType = static_cast<int32_t>(DIALOG_OPERATION_DETAIL);

    int32_t ret = CheckDetailParamsAndInitContext(asyncContext, argv, argc);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("failed to check params and init.");
        ThrowError(env, PARAM_ERROR, "failed to check params and init.");
        return nullptr;
    }

    napi_value result = nullptr;
    status = napi_create_promise(env, &asyncContext->deferred, &result);
    if (status != napi_ok) {
        CM_LOG_E("failed to create promise.");
        ThrowError(env, DIALOG_ERROR_GENERIC, "failed to create promise.");
        return nullptr;
    }

    auto uiExtCallback = std::make_shared<CmUIExtensionVoidCallback>(asyncContext);
    StartUIExtensionAbility(asyncContext, CMGetCertDetailWant(asyncContext), uiExtCallback);
    CM_LOG_I("cert open detail dialog end");
    return result;
}
} // namespace CMNapi
