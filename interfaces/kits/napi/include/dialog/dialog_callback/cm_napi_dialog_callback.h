/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CM_NAPI_DIALOG_CALLBACK_H
#define CM_NAPI_DIALOG_CALLBACK_H

#include "cm_napi_open_dialog.h"

namespace CMNapi {
class CmUIExtensionCallback {
public:
    explicit CmUIExtensionCallback(std::shared_ptr<CmUIExtensionRequestContext>& reqContext);
    virtual ~CmUIExtensionCallback();
    virtual void SetSessionId(const int32_t sessionId);
    virtual void OnRelease(const int32_t releaseCode);
    virtual void OnResult(const int32_t resultCode, const OHOS::AAFwk::Want& result);
    virtual void OnReceive(const OHOS::AAFwk::WantParams& request) = 0;
    virtual void OnError(const int32_t code, const std::string& name, const std::string& message);
    virtual void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    virtual void OnDestroy();
    virtual void SendMessageBack();
    virtual void ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext) = 0;

public:
    bool SetErrorCode(int32_t errCode);
    int32_t sessionId_ = 0;
    int32_t resultCode_ = 0;
    OHOS::AAFwk::Want resultWant_;
    std::shared_ptr<CmUIExtensionRequestContext> reqContext_ = nullptr;
    bool alreadyCallback_ = false;
};
} // namespace CMNapi

#endif  // CM_NAPI_DIALOG_CALLBACK_H
