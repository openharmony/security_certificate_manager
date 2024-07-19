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

#ifndef CM_SCOPE_GUARD_H
#define CM_SCOPE_GUARD_H

namespace OHOS {
namespace Security {
namespace CertManager {
class CmScoprGuard final {
public:
    using Function = std::function<void()>;
    explicit CmScoprGuard(Function fn) : fn_(fn), dismissed_(false) {}

    ~CmScoprGuard()
    {
        if (!dismissed_) {
            fn_();
        }
    }

    void Dismiss()
    {
        dismissed_ = true;
    }

private:
    Function fn_;
    bool dismissed_;
};
} // namespace CertManager
} // namespace Security
} // namespace OHOS
#endif // CM_SCOPE_GUARD_H