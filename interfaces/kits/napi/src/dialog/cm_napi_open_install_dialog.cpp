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

#include "syspara/parameters.h"
#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "iservice_registry.h"
#include "bundle_mgr_proxy.h"
#include "system_ability_definition.h"

#include "cm_napi_dialog_common.h"
#include "want.h"
#include "want_params_wrapper.h"

namespace CMNapi {

class CmInstallUIExtensionCallback : public CmUIExtensionCallback {
public:
    explicit CmInstallUIExtensionCallback(
        std::shared_ptr<CmUIExtensionRequestContext>& reqContext) : CmUIExtensionCallback(reqContext)
    {
        this->reqContext_ = reqContext;
    }

    ~CmInstallUIExtensionCallback() override
    {
        CM_LOG_D("~CmInstallUIExtensionCallback");
    }

    void OnRelease(const int32_t releaseCode) override
    {
        CM_LOG_D("InstallUIExtensionComponent OnRelease(), releaseCode = %d", releaseCode);
        if (SetErrorCode(CMR_DIALOG_ERROR_OPERATION_CANCELS)) {
            SendMessageBack();
        }
    }

    void OnResult(const int32_t resultCode, const OHOS::AAFwk::Want& result) override
    {
        CM_LOG_D("InstallUIExtensionComponent OnResult(), resultCode = %d", resultCode);
        this->resultCode_ = resultCode;
        this->resultWant_ = result;
        if (SetErrorCode(CMR_DIALOG_ERROR_INSTALL_FAILED)) {
            SendMessageBack();
        }
    }

    void OnReceive(const OHOS::AAFwk::WantParams& request) override
    {
        CM_LOG_D("InstallUIExtensionComponent OnReceive()");
        this->reqContext_->uri = request.GetStringParam("uri");
        if (SetErrorCode(0)) {
            SendMessageBack();
        }
    }

    void ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext) override
    {
        napi_value args = nullptr;
        if (asyncContext->errCode == CM_SUCCESS) {
            NAPI_CALL_RETURN_VOID(env,
                napi_create_string_utf8(env, asyncContext->uri.c_str(), NAPI_AUTO_LENGTH, &args));
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
        CM_LOG_D("InstallUIExtensionComponent OnDestroy()");
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

static bool IsCmCertificateScopeEnum(const uint32_t value)
{
    switch (static_cast<CertificateScope>(value)) {
        case CertificateScope::CURRENT_USER:
            return true;
        default:
            return false;
    }
}

static bool IsCmCertificateTypeAndConvert(const uint32_t value, uint32_t &pageType)
{
    switch (static_cast<CmCertificateType>(value)) {
        case CmCertificateType::CA_CERT:
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
    if (!IsCmCertificateTypeAndConvert(certificateType, asyncContext->certificateType)) {
        CM_LOG_E("certificateType invalid");
        return nullptr;
    }

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
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(asyncContext->certificateType));
    want.SetParam(CERT_MANAGER_CERTIFICATE_DATA, asyncContext->certStr);
    want.SetParam(CERT_MANAGER_CERTSCOPE_TYPE, static_cast<int32_t>(asyncContext->certificateScope));
    want.SetParam(CERT_MANAGER_CALLER_BUNDLENAME, asyncContext->labelName);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    return want;
}

static OHOS::sptr<OHOS::AppExecFwk::BundleMgrProxy> GetBundleMgrProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        CM_LOG_E("fail to get system ability mgr.");
        return nullptr;
    }

    auto remoteObject = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        CM_LOG_E("fail to get bundle manager proxy.");
        return nullptr;
    }
    return OHOS::iface_cast<OHOS::AppExecFwk::BundleMgrProxy>(remoteObject);
}

static int32_t GetCallerLabelName(std::shared_ptr<CmUIExtensionRequestContext> asyncContext)
{
    OHOS::sptr<OHOS::AppExecFwk::BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        CM_LOG_E("Failed to get bundle manager proxy.");
        return CM_FAILURE;
    }

    OHOS::AppExecFwk::BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
    int32_t resCode = bundleMgrProxy->GetBundleInfoForSelf(flags, bundleInfo);
    if (resCode != CM_SUCCESS) {
        CM_LOG_E("Failed to get bundleInfo, resCode is %d", resCode);
        return CM_FAILURE;
    }

    if (asyncContext->context->GetResourceManager() == nullptr) {
        CM_LOG_E("context get resourcemanager faild");
        return CMR_ERROR_NULL_POINTER;
    }

    resCode = asyncContext->context->GetResourceManager()->GetStringById(bundleInfo.applicationInfo.labelId,
        asyncContext->labelName);
    if (resCode != CM_SUCCESS) {
        CM_LOG_E("getStringById is faild, resCode is %d", resCode);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

napi_value CMNapiOpenInstallCertDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_D("cert install dialog enter");
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

    auto uiExtCallback = std::make_shared<CmInstallUIExtensionCallback>(asyncContext);
    StartUIExtensionAbility(asyncContext, CMGetInstallCertWant(asyncContext), uiExtCallback);
    CM_LOG_D("cert install dialog end");
    return result;
}
}  // namespace CMNapi

