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

#ifndef CM_NAPI_OPEN_CERTIFICATE_OPERATION_H
#define CM_NAPI_OPEN_CERTIFICATE_OPERATION_H

#include "cm_napi_open_dialog.h"

namespace CMNapi {
class CmOperationUIExtensionCallback : public CmUIExtensionCallback {
public:
    explicit CmOperationUIExtensionCallback(std::shared_ptr<CmUIExtensionRequestContext>& reqContext);
    ~CmOperationUIExtensionCallback() override;
    void OnRelease(const int32_t releaseCode) override;
    void OnResult(const int32_t resultCode, const OHOS::AAFwk::Want& result) override;
    void OnReceive(const OHOS::AAFwk::WantParams& request) override;
    void ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext) override;
    void OnDestroy() override;

private:
    bool SetErrorCode(int32_t errCode);
    int32_t resultCode_ = 0;
    OHOS::AAFwk::Want resultWant_;
    std::shared_ptr<CmUIExtensionRequestContext> reqContext_ = nullptr;
    bool alreadyCallback_ = false;
};
} // namespace CMNapi

#endif  // CM_NAPI_OPEN_CERTIFICATE_OPERATION_H
