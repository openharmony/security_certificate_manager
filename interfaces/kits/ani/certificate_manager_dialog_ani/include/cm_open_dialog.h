/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CM_OPEN_DIALOG_H
#define CM_OPEN_DIALOG_H

#include "ani.h"
#include "cm_type.h"
#include "ability_context.h"
#include "ui_content.h"
#include "iservice_registry.h"
#include "bundle_mgr_proxy.h"
#include "system_ability_definition.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "cm_dialog_api_common.h"

namespace OHOS::Security::CertManager::Ani {
using namespace OHOS::Security::CertManager::Dialog;
using namespace OHOS::AbilityRuntime;

struct CmOpeonInstallDialogParams {
    ani_enum_item aniCertType;
    ani_enum_item aniCertScope;
    ani_string aniCert;
};

class CmAniUIExtensionCallback {
public:
    CmAniUIExtensionCallback(ani_vm *vm, std::shared_ptr<AbilityContext> context, ani_ref aniCallback);
    virtual ~CmAniUIExtensionCallback();
    void SetSessionId(const int32_t sessionId);
    void OnRelease(const int32_t releaseCode);
    void OnResult(const int32_t resultCode, const OHOS::AAFwk::Want &result);
    void OnError(const int32_t code, const std::string &name, const std::string &message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy);
    void OnDestroy();
    void invokeCallback(ani_env *env, int32_t code, ani_object result);
    virtual void OnReceive(const OHOS::AAFwk::WantParams &request);
    virtual ani_object GetDefaultResult(ani_env *env);

protected:
    ani_vm *vm = nullptr;
    ani_ref aniCallback = nullptr;
    bool isReleased = false;
    int32_t sessionId = 0;
    std::shared_ptr<AbilityContext> context = nullptr;
    std::mutex lockIsReleased;
};

class CmAniUIExtensionCallbackString : public CmAniUIExtensionCallback {
public:
    CmAniUIExtensionCallbackString(ani_vm *vm, std::shared_ptr<AbilityContext> context, ani_ref aniCallback);
    ~CmAniUIExtensionCallbackString() {}
    void OnReceive(const OHOS::AAFwk::WantParams &request) override;
    ani_object GetDefaultResult(ani_env *env) override;
};

class CmAniUIExtensionCallbackCertReference : public CmAniUIExtensionCallback {
public:
    CmAniUIExtensionCallbackCertReference(ani_vm *vm, std::shared_ptr<AbilityContext> context, ani_ref aniCallback);
    ~CmAniUIExtensionCallbackCertReference() {}
    void OnReceive(const OHOS::AAFwk::WantParams &request) override;
    ani_object GetDefaultResult(ani_env *env) override;
};

int32_t StartUIExtensionAbility(std::shared_ptr<AbilityContext> context, OHOS::AAFwk::Want& want,
    std::shared_ptr<CmAniUIExtensionCallback> uiExtCallback);

int32_t StartUIAbility(std::shared_ptr<AbilityContext> context, OHOS::AAFwk::Want& want,
    std::shared_ptr<CmAniUIExtensionCallback> uiExtCallback);

};
#endif