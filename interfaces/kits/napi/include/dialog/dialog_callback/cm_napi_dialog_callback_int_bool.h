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

#ifndef CM_NAPI_DIALOG_CALLBACK_INTBOOL_H
#define CM_NAPI_DIALOG_CALLBACK_INTBOOL_H

#include "cm_napi_dialog_callback.h"

namespace CMNapi {
class CmUIExtensionIntBoolCallback : public CmUIExtensionCallback {
public:
    explicit CmUIExtensionIntBoolCallback(std::shared_ptr<CmUIExtensionRequestContext>& reqContext);
    ~CmUIExtensionIntBoolCallback();

    void OnDestroy() override;
    void OnReceive(const OHOS::AAFwk::WantParams& request) override;
    void ProcessCallback(napi_env env, const CommonAsyncContext* asyncContext) override;
};
} // namespace CMNapi

#endif  // CM_NAPI_DIALOG_CALLBACK_INTBOOL_H