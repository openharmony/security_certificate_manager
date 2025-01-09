/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "cm_napi_open_dialog.h"
#include "cm_napi_dialog_common.h"

#include "cm_log.h"

#include "syspara/parameters.h"
#include "securec.h"
#include "want.h"
#include "want_params_wrapper.h"

namespace CMNapi {

class CmUninstallUIExtensionCallback : public CmUIExtensionCallback {
public:
    explicit CmUninstallUIExtensionCallback(
        std::shared_ptr<CmUIExtensionRequestContext>& reqContext) : CmUIExtensionCallback(reqContext)
    {
        this->reqContext_ = reqContext;
    }

    ~CmUninstallUIExtensionCallback() override
    {
        CM_LOG_D("~CmUninstallUIExtensionCallback");
    }

    void OnRelease(const int32_t releaseCode) override
    {
        CM_LOG_D("UninstallUIExtensionComponent OnRelease(), releaseCode = %d", releaseCode);
        if (SetErrorCode(CMR_DIALOG_ERROR_OPERATION_CANCELS)) {
            SendMessageBack();
        }
    }

    void OnResult(const int32_t resultCode, const OHOS::AAFwk::Want& result) override
    {
        CM_LOG_D("UninstallUIExtensionComponent OnResult(), resultCode = %d", resultCode);
        this->resultCode_ = resultCode;
        this->resultWant_ = result;
        if (SetErrorCode(this->resultCode_)) {
            SendMessageBack();
        }
    }

    void OnReceive(const OHOS::AAFwk::WantParams& request) override
    {
        CM_LOG_D("UninstallUIExtensionComponent OnReceive()");
        if (SetErrorCode(0)) {
            SendMessageBack();
        }
    }

    void ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext) override
    {
        napi_value args = nullptr;
        if (asyncContext->errCode == CM_SUCCESS) {
            NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args));
        } else {
            args = GenerateBusinessError(env, asyncContext->errCode);
        }

        if (asyncContext->deferred != nullptr) {
            if (asyncContext->errCode == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, args));
            } else {
                NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred, args));
            }
        }
    }

    void OnDestroy() override
    {
        CM_LOG_D("UninstallUIExtensionComponent OnDestroy()");
    }

private:
    bool SetErrorCode(int32_t errCode)
    {
        if (this->reqContext_ == nullptr) {
            CM_LOG_E("OnError reqContext is nullptr");
            return false;
        }
        if (this->alreadyCallback_) {
            CM_LOG_D("alreadyCallback");
            return false;
        }
        this->alreadyCallback_ = true;
        this->reqContext_->errCode = errCode;
        return true;
    };
    int32_t resultCode_ = 0;
    OHOS::AAFwk::Want resultWant_;
    std::shared_ptr<CmUIExtensionRequestContext> reqContext_ = nullptr;
    bool alreadyCallback_ = false;
};

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
    //Parse the first param: context
    if (!ParseCmUIAbilityContextReq(asyncContext->env, argv[PARAM0], asyncContext->context)) {
        CM_LOG_E("ParseUIAbilityContextReq failed");
        return nullptr;
    }

    //Parse the second param: certType
    uint32_t certificateType = 0;
    if (ParseUint32(asyncContext->env, argv[PARAM1], certificateType) == nullptr) {
        CM_LOG_E("parse type failed");
        return nullptr;
    }
    if (!CMIsCertificateType(certificateType, asyncContext->certificateType)) {
        CM_LOG_E("certificateType invalid");
        return nullptr;
    }

    //Parse the third param: certUri
    if (ParseString(asyncContext->env, argv[PARAM2], asyncContext->certUri) == nullptr) {
        CM_LOG_E("certUri is invalid");
        return nullptr;
    }
    //return 0
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
    want.SetParam(CERT_MANAGER_OPERATION_TYPE, static_cast<int32_t>(DIALOG_OPERATION_UNINSTALL));
    return want;
}

napi_value CMNapiOpenUninstallCertDialog(napi_env env, napi_callback_info info)
{
    //determine the type of device
    CM_LOG_D("enter uninstall cert dialog");
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    if (OHOS::system::GetParameter("const.product.devicetype", "") != "2in1") {
        CM_LOG_E("device type is not 2in1");
        std::string errMsg = "Device type error, device type is not 2in1";
        ThrowError(env, DIALOG_ERROR_NOT_SUPPORTED, errMsg);
        return result;
    }

    //determine the number of parameters
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
    
    //parse and init context
    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    asyncContext->env = env;
    if (CMInitAsyncContext(asyncContext, argv, argc) == nullptr) {
        CM_LOG_E("Parse param and init asyncContext failed");
        ThrowError(env, PARAM_ERROR, "Parse param and init asyncContext failed");
        return nullptr;
    }

    //get lable name
    if (GetCallerLabelName(asyncContext) != CM_SUCCESS) {
        CM_LOG_E("get caller labelName faild");
        ThrowError(env, DIALOG_ERROR_GENERIC, "get caller labelName faild");
        return nullptr;
    }
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));

    //set want params
    auto uiExtCallback = std::make_shared<CmUninstallUIExtensionCallback>(asyncContext);
    StartUIExtensionAbility(asyncContext, CMGetUninstallCertWant(asyncContext), uiExtCallback);
    CM_LOG_D("cert install dialog end");
    return result;
}
} // namespace CMNapi