/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
static bool CMIsCertificateType(const uint32_t value, uint32_t &pageType)
{
    switch (static_cast<CmCertificateType>(value)) {
        case CmCertificateType::CA_CERT:
            pageType = CmDialogPageType::PAGE_INSTALL_CA_GUIDE;
            return true;
        default:
            return false;
    }
}

static napi_value CMInitAsyncContext(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    napi_value argv[], size_t length)
{
    // Parse the first param: context
    if (!ParseCmUIAbilityContextReq(asyncContext->env, argv[PARAM0], asyncContext->context)) {
        CM_LOG_E("ParseUIAbilityContextReq failed");
        return nullptr;
    }

    // Parse the second param: certType
    uint32_t certificateType = 0;
    if (ParseUint32(asyncContext->env, argv[PARAM1], certificateType) == nullptr) {
        CM_LOG_E("parse type failed");
        return nullptr;
    }
    if (!CMIsCertificateType(certificateType, asyncContext->certificateType)) {
        CM_LOG_E("certificateType invalid");
        return nullptr;
    }

    // Parse the third param: certUri
    if (ParseString(asyncContext->env, argv[PARAM2], asyncContext->certUri) == nullptr) {
        CM_LOG_E("certUri is invalid");
        return nullptr;
    }
    // return 0
    return GetInt32(asyncContext->env, 0);
}

static OHOS::AAFwk::Want CMGetUninstallCertWant(std::shared_ptr<CmUIExtensionRequestContext> asyncContext)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(asyncContext->certificateType));
    want.SetParam(CERT_MANAGER_CALLER_BUNDLENAME, asyncContext->labelName);
    CmBlob *certUri = asyncContext->certUri;
    std::string uriStr(reinterpret_cast<char *>(certUri->data), certUri->size);
    want.SetParam(CERT_MANAGER_CERT_URI, uriStr);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_OPERATION_TYPE, asyncContext->opType);
    return want;
}

napi_value CMNapiOpenUninstallCertDialog(napi_env env, napi_callback_info info)
{
    // determine the type of device
    CM_LOG_I("enter uninstall cert dialog");
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    if (OHOS::system::GetParameter("const.product.devicetype", "") != "2in1") {
        CM_LOG_E("device type is not 2in1");
        std::string errMsg = "Device type error, device type is not 2in1";
        ThrowError(env, DIALOG_ERROR_NOT_SUPPORTED, errMsg);
        return result;
    }

    // determine the number of parameters
    size_t argc = PARAM_SIZE_THREE;
    napi_value argv[PARAM_SIZE_THREE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != PARAM_SIZE_THREE) {
        CM_LOG_E("param number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need " + std::to_string(PARAM_SIZE_THREE)
            + ", given " + std::to_string(argc);
        ThrowError(env, PARAM_ERROR, errMsg);
        return result;
    }

    // parse and init context
    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    asyncContext->env = env;
    asyncContext->opType = static_cast<int32_t>(DIALOG_OPERATION_UNINSTALL);
    if (CMInitAsyncContext(asyncContext, argv, argc) == nullptr) {
        CM_LOG_E("Parse param and init asyncContext failed");
        ThrowError(env, PARAM_ERROR, "Parse param and init asyncContext failed");
        return nullptr;
    }

    // get lable name
    if (GetCallerLabelName(asyncContext) != CM_SUCCESS) {
        CM_LOG_E("get caller labelName faild");
        ThrowError(env, DIALOG_ERROR_GENERIC, "get caller labelName faild");
        return nullptr;
    }
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));

    // set want params
    auto uiExtCallback = std::make_shared<CmUIExtensionVoidCallback>(asyncContext);
    StartUIExtensionAbility(asyncContext, CMGetUninstallCertWant(asyncContext), uiExtCallback);
    CM_LOG_I("cert uninstall dialog end");
    return result;
}
} // namespace CMNapi