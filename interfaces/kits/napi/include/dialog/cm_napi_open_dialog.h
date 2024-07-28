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

#include "cm_napi_common.h"

namespace CMNapi {
napi_value CMNapiOpenCertManagerDialog(napi_env env, napi_callback_info info);

enum CmDialogErrorCode {
    DIALOG_ERROR_GENERIC = 29700001,
    DIALOG_ERROR_OPERATION_CANCELED = 29700002,
};

enum CmDialogPageType {
    PAGE_MAIN = 1,
    PAGE_CA_CERTIFICATE = 2,
    PAGE_CREDENTIAL = 3,
    PAGE_INSTALL_CERTIFICATE = 4
};

struct CommonAsyncContext {
    explicit CommonAsyncContext(napi_env env);
    virtual ~CommonAsyncContext();
    napi_env env = nullptr;
    napi_status status = napi_invalid_arg;
    int32_t errCode = 0;
    napi_deferred deferred = nullptr;  // promise handle
};

struct CmUIExtensionRequestContext : public CommonAsyncContext {
    explicit CmUIExtensionRequestContext(napi_env env) : CommonAsyncContext(env) {};
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> context = nullptr;
    OHOS::AAFwk::Want want;
    uint32_t pageType;
};

class CmUIExtensionCallback {
public:
    explicit CmUIExtensionCallback(std::shared_ptr<CmUIExtensionRequestContext>& reqContext);
    void SetSessionId(const int32_t sessionId);
    void OnRelease(const int32_t releaseCode);
    void OnResult(const int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(const int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void SendMessageBack();

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
