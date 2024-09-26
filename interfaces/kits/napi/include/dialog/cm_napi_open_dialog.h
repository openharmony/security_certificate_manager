/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CM_NAPI_OPEN_DIALOG_H
#define CM_NAPI_OPEN_DIALOG_H

#include "ability_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_base_context.h"
#include "napi_common_want.h"
#include "ui_content.h"

namespace CMNapi {
const std::string PARAM_UI_EXTENSION_TYPE = "ability.want.params.uiExtensionType";
const std::string SYS_COMMON_UI = "sys/commonUI";
const std::string CERT_MANAGER_BUNDLENAME = "com.ohos.certmanager";
const std::string CERT_MANAGER_ABILITYNAME = "CertPickerUIExtAbility";
const std::string CERT_MANAGER_PAGE_TYPE = "pageType";
const std::string CERT_MANAGER_CERTSCOPE_TYPE = "certScope";
const std::string CERT_MANAGER_CERTIFICATE_DATA = "cert";
const std::string CERT_MANAGER_CALLER_BUNDLENAME = "bundleName";
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr int32_t PARAM3 = 3;
constexpr int32_t PARAM_SIZE_TWO = 2;
constexpr int32_t PARAM_SIZE_FOUR = 4;
constexpr int32_t ERROR_STR_LEN = 256;

napi_value CMNapiOpenCertManagerDialog(napi_env env, napi_callback_info info);
napi_value CMNapiOpenInstallCertManagerDialog(napi_env env, napi_callback_info info);

struct CommonAsyncContext {
    explicit CommonAsyncContext(napi_env env);
    virtual ~CommonAsyncContext();
    napi_env env = nullptr;
    napi_status status = napi_invalid_arg;
    int32_t errCode = 0;
    napi_deferred deferred = nullptr;  // promise handle
    std::string uri = "";
};

struct CmUIExtensionRequestContext : public CommonAsyncContext {
    explicit CmUIExtensionRequestContext(napi_env env) : CommonAsyncContext(env) {};
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> context = nullptr;
    uint32_t pageType = 0;
    uint32_t certificateType = 0;
    uint32_t certificateScope = 0;
    std::string certStr = "";
};

class CmUIExtensionCallback {
public:
    explicit CmUIExtensionCallback(std::shared_ptr<CmUIExtensionRequestContext>& reqContext);
    virtual ~CmUIExtensionCallback();
    virtual void SetSessionId(const int32_t sessionId);
    virtual void OnRelease(const int32_t releaseCode);
    virtual void OnResult(const int32_t resultCode, const OHOS::AAFwk::Want& result);
    virtual void OnReceive(const OHOS::AAFwk::WantParams& request);
    virtual void OnError(const int32_t code, const std::string& name, const std::string& message);
    virtual void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    virtual void OnDestroy();
    virtual void SendMessageBack();
    virtual void ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext);

private:
    bool SetErrorCode(int32_t errCode);
    int32_t sessionId_ = 0;
    int32_t resultCode_ = 0;
    OHOS::AAFwk::Want resultWant_;
    std::shared_ptr<CmUIExtensionRequestContext> reqContext_ = nullptr;
    bool alreadyCallback_ = false;
};

}  // namespace CertManagerNapi
#endif  // CM_NAPI_OPEN_DIALOG_H
