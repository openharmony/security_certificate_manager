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

#include "cm_napi_open_install_dialog.h"

#include "cm_log.h"
#include "cm_napi_dialog_common.h"
#include "cm_napi_dialog_callback_string.h"

#include "securec.h"
#include "syspara/parameters.h"
#include "want.h"
#include "want_params_wrapper.h"

namespace CMNapi {
static bool IsCmCertificateScopeEnum(const uint32_t value)
{
    return value >= NOT_SPECIFIED && value <= GLOBAL_USER;
}

static bool IsCmCertificateTypeAndConvert(const uint32_t value, uint32_t &pageType)
{
    switch (static_cast<CmCertificateType>(value)) {
        case CmCertificateType::CA_CERT:
            pageType = CmDialogPageType::PAGE_INSTALL_CA_GUIDE;
            return true;
        case CmCertificateType::CREDENTIAL_USER:
            pageType = CmDialogPageType::PAGE_INSTALL_CA_GUIDE;
            return true;
        case CmCertificateType::CREDENTIAL_SYSTEM:
            pageType = CmDialogPageType::PAGE_INSTALL_CA_GUIDE;
            return true;
        default:
            return false;
    }
}

static napi_value CMCheckArgvAndInitContext(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    napi_value argv[], size_t length)
{
    if (length != PARAM_SIZE_FOUR) {
        CM_LOG_E("params number vaild failed");
        return nullptr;
    }
    // Parse first argument for context.
    if (!ParseCmUIAbilityContextReq(asyncContext->env, argv[PARAM0], asyncContext->context)) {
        CM_LOG_E("ParseUIAbilityContextReq failed");
        return nullptr;
    }

    // Parse second argument for certificate type.
    uint32_t certificateType = 0;
    if (ParseUint32(asyncContext->env, argv[PARAM1], certificateType) == nullptr) {
        CM_LOG_E("parse type failed");
        return nullptr;
    }
    if (!IsCmCertificateTypeAndConvert(certificateType, asyncContext->pageType)) {
        CM_LOG_E("certificateType invalid");
        return nullptr;
    }
    asyncContext->certificateType = certificateType;

    // Parse third argument for certificateScope.
    if (ParseUint32(asyncContext->env, argv[PARAM2], asyncContext->certificateScope) == nullptr) {
        CM_LOG_E("parse type failed");
        return nullptr;
    }
    if (!IsCmCertificateScopeEnum(asyncContext->certificateScope)) {
        CM_LOG_E("certificateScope invalid");
        return nullptr;
    }

    // Parse fourth argument for cert.
    if (GetUint8ArrayToBase64Str(asyncContext->env, argv[PARAM3], asyncContext->certStr) == nullptr) {
        CM_LOG_E("cert is not a uint8Array or the length is 0 or too long.");
        return nullptr;
    }
    return GetInt32(asyncContext->env, 0);
}

static OHOS::AAFwk::Want CMGetInstallCertWant(std::shared_ptr<CmUIExtensionRequestContext> asyncContext)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(asyncContext->pageType));
    want.SetParam(CERT_MANAGER_CERT_TYPE, static_cast<int32_t>(asyncContext->certificateType));
    want.SetParam(CERT_MANAGER_CERTIFICATE_DATA, asyncContext->certStr);
    want.SetParam(CERT_MANAGER_CERTSCOPE_TYPE, static_cast<int32_t>(asyncContext->certificateScope));
    want.SetParam(CERT_MANAGER_CALLER_BUNDLENAME, asyncContext->labelName);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_OPERATION_TYPE, asyncContext->opType);
    return want;
}

napi_value CMNapiOpenInstallCertDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert install dialog enter");
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    if (OHOS::system::GetParameter("const.product.devicetype", "") != "2in1") {
        CM_LOG_E("deviceType is not 2in1");
        std::string errMsg = "DeviceType Error. deviceType is not 2in1";
        ThrowError(env, DIALOG_ERROR_NOT_SUPPORTED, errMsg);
        return result;
    }

    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != PARAM_SIZE_FOUR) {
        CM_LOG_E("params number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need " + std::to_string(PARAM_SIZE_FOUR)
            + ", given " + std::to_string(argc);
        ThrowError(env, PARAM_ERROR, errMsg);
        return result;
    }

    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    asyncContext->env = env;
    asyncContext->opType = static_cast<int32_t>(DIALOG_OPERATION_INSTALL);
    if (CMCheckArgvAndInitContext(asyncContext, argv, sizeof(argv) / sizeof(argv[0])) == nullptr) {
        CM_LOG_E("check argv vaild and init faild");
        ThrowError(env, PARAM_ERROR, "check argv vaild and init faild");
        return nullptr;
    }

    if (GetCallerLabelName(asyncContext) != CM_SUCCESS) {
        CM_LOG_E("get caller labelName faild");
        ThrowError(env, DIALOG_ERROR_GENERIC, "get caller labelName faild");
        return nullptr;
    }
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));

    auto uiExtCallback = std::make_shared<CmUIExtensionStringCallback>(asyncContext);
    StartUIExtensionAbility(asyncContext, CMGetInstallCertWant(asyncContext), uiExtCallback);
    CM_LOG_I("cert install dialog end");
    return result;
}
}  // namespace CMNapi

