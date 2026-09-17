/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "js_ukey_auth_extension.h"

#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "js_ukey_auth_extension_base.h"

namespace OHOS {
namespace AbilityRuntime {
JsUkeyAuthExtension *JsUkeyAuthExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    return new JsUkeyAuthExtension(runtime);
}

JsUkeyAuthExtension::JsUkeyAuthExtension(const std::unique_ptr<Runtime> &runtime)
{
    std::shared_ptr<UIExtensionBaseImpl> uiExtensionBaseImpl = std::make_shared<JsUkeyAuthExtensionBase>(runtime);
    SetUIExtensionBaseImpl(uiExtensionBaseImpl);
}

JsUkeyAuthExtension::~JsUkeyAuthExtension()
{
    TAG_LOGD(AAFwkTag::EXT, "destructor");
}
} // namespace AbilityRuntime
} // namespace OHOS
